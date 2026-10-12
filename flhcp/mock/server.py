"""Authoritative mock DHCP server for the isolated lab (stdlib only).

Binds to an explicit address (loopback by default: never touches real
networks unless pointed at a lab interface on purpose). Tracks leases by
client MAC, answers DISCOVER→OFFER and REQUEST→ACK/NAK with real packets.
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
import time
from typing import Any, Callable

from flhcp.dhcp import codec


def _mac_str(chaddr: bytes) -> str:
    return ":".join(f"{b:02X}" for b in chaddr[:6])


class MockDhcpServer:
    def __init__(
        self,
        bind_address: str = "127.0.0.1",
        port: int = 6767,
        client_port: int = 6768,
        *,
        pool_base: str = "10.200.0.10",
        pool_size: int = 241,
        lease_time: int = 3600,
        server_id: str = "10.200.0.1",
        netmask: str = "255.255.255.0",
        logger: logging.Logger | None = None,
        on_event: Callable[[str, dict], None] | None = None,
        event_log: str = "",
    ) -> None:
        self.bind_address = bind_address
        self.port = port
        self.client_port = client_port
        self.pool_start = struct.unpack("!I", socket.inet_aton(pool_base))[0]
        self.pool_size = pool_size
        self.lease_time = lease_time
        self.server_id = server_id
        self.netmask = netmask
        self.log = logger or logging.getLogger("flhcp.mock")
        self.on_event = on_event
        self.event_log = event_log
        self.leases: dict[bytes, str] = {}
        self.next_free = 0
        self._free_slots: list[int] = list(range(pool_size))
        self.served = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None

    def _ip_at(self, index: int) -> str:
        return socket.inet_ntoa(struct.pack("!I", self.pool_start + index))

    def _allocate(self) -> int | None:
        """Pop the next free pool slot (None when exhausted)."""
        if self._free_slots:
            return self._free_slots.pop(0)
        return None

    def _release_slot(self, ip: str) -> None:
        """Return a lease slot to the free list (reuse on next DISCOVER)."""
        try:
            index = struct.unpack("!I", socket.inet_aton(ip))[0] - self.pool_start
        except OSError:
            return
        if 0 <= index < self.pool_size and index not in self._free_slots:
            self._free_slots.append(index)
            self._free_slots.sort()

    def _emit(self, kind: str, payload: dict) -> None:
        if self.on_event is not None:
            try:
                self.on_event(kind, payload)
            except Exception:
                pass
        if self.event_log:
            try:
                import datetime as _dt

                with open(self.event_log, "a", encoding="utf-8") as handle:
                    handle.write(f"{_dt.datetime.now().isoformat(timespec='seconds')} {kind} {payload}\n")
            except OSError as exc:
                self.log.debug("server event log failed: %s", exc)

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.bind_address, self.port))
        sock.settimeout(0.5)
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.log.info("mock DHCP serving on %s:%d", self.bind_address, self.port)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None

    def reply_to(self) -> tuple[str, int]:
        # kept for compatibility; live replies always go to the request source
        return (self.bind_address, self.client_port)

    def _loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            msg = codec.decode(data)
            if msg is None or msg["op"] != 1:
                continue
            mtype = msg["msgtype"]
            mac = _mac_str(msg["chaddr"])
            if mtype == codec.DISCOVER:
                if msg["chaddr"] not in self.leases:
                    # Real DHCP behavior: allocate a new address only while the
                    # pool has capacity. When the pool is exhausted, the server
                    # has nothing left to offer — stay silent (no OFFER).
                    slot = self._allocate()
                    if slot is not None:
                        self.leases[msg["chaddr"]] = self._ip_at(slot)
                        self.next_free += 1
                offered = self.leases.get(msg["chaddr"])
                if offered is None:
                    # Pool exhausted: this MAC already holds nothing and the
                    # server has no free address. Real servers stay silent.
                    self._emit("pool_exhausted", {"mac": mac})
                    self.log.debug("DISCOVER %s -> no OFFER (pool exhausted)", mac)
                    continue
                # Honor the client's requested lease (option 51) when present;
                # otherwise fall back to the server's configured lease time.
                granted = msg["lease"] if msg["lease"] > 0 else self.lease_time
                self._send(codec.build_reply(
                    msg["xid"], msg["chaddr"], offered, codec.OFFER,
                    server_id=self.server_id, lease_time=granted, netmask=self.netmask,
                ), addr)
                self.served += 1
                self._emit("offer", {"mac": mac, "ip": offered})
                self.log.debug("DISCOVER %s -> OFFER %s", mac, offered)
            elif mtype == codec.REQUEST:
                req_ip = msg["requested_ip"] or msg["ciaddr"]
                offered = self.leases.get(msg["chaddr"])
                if offered and req_ip == offered:
                    granted = msg["lease"] if msg["lease"] > 0 else self.lease_time
                    self._send(codec.build_reply(
                        msg["xid"], msg["chaddr"], offered, codec.ACK,
                        server_id=self.server_id, lease_time=granted, netmask=self.netmask,
                    ), addr)
                    self._emit("ack", {"mac": mac, "ip": offered})
                    self.log.debug("REQUEST %s %s -> ACK", mac, req_ip)
                else:
                    self._send(codec.build_reply(msg["xid"], msg["chaddr"], "0.0.0.0", codec.NAK), addr)
                    self._emit("nak", {"mac": mac, "ip": req_ip})
            elif mtype == codec.RELEASE:
                if msg["chaddr"] in self.leases:
                    ip = self.leases.pop(msg["chaddr"])
                    self._release_slot(ip)
                    self._emit("release", {"mac": mac, "ip": ip})

    def _send(self, payload: bytes, addr: tuple[str, int] | None = None) -> None:
        assert self._sock is not None
        try:
            self._sock.sendto(payload, addr or self.reply_to())
        except OSError as exc:
            self.log.debug("mock send failed: %s", exc)

    def pool_status(self) -> dict[str, Any]:
        """Server-side pool truth: size, leased count, free count, mapping."""
        leased = len(self.leases)
        free = max(0, self.pool_size - leased)
        return {
            "pool_size": self.pool_size,
            "leased": leased,
            "free": free,
            "utilization_pct": round(100.0 * leased / self.pool_size, 1) if self.pool_size else 0.0,
            "leases": {_mac_str(mac): ip for mac, ip in self.leases.items()},
        }

    def stats(self) -> dict[str, Any]:
        return {"leases": len(self.leases), "served": self.served, "time": time.time()}
