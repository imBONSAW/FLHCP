"""DHCP client engine: real state machines over real UDP sockets.

Each simulated client owns its own UDP socket with a unique source port,
so concurrent clients never race over a shared port — real routers get
confused when many DISCOVERs share one source port. Packets are
demultiplexed by transaction ID (xid). Standard library only.
"""

from __future__ import annotations

import concurrent.futures
import logging
import queue
import random
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from flhcp.dhcp import codec

INIT = "INIT"
DISCOVER_SENT = "DISCOVER_SENT"
OFFER_RECEIVED = "OFFER_RECEIVED"
REQUEST_SENT = "REQUEST_SENT"
ACK_RECEIVED = "ACK_RECEIVED"
FAILED = "FAILED"


@dataclass(frozen=True)
class SimClient:
    index: int
    mac: str
    hostname: str


@dataclass
class ClientResult:
    client: SimClient
    state: str = INIT
    offered_ip: str = ""
    assigned_ip: str = ""
    lease: int = 0
    server_id: str = ""
    error: str = ""
    rtt: float = 0.0
    source_port: int = 0
    packets_sent: int = 0
    discovers_sent: int = 0
    requests_sent: int = 0
    naks: int = 0
    timestamps: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.client.index,
            "mac": self.client.mac,
            "hostname": self.client.hostname,
            "state": self.state,
            "offered_ip": self.offered_ip,
            "assigned_ip": self.assigned_ip,
            "lease": self.lease,
            "server_id": self.server_id,
            "error": self.error,
            "rtt": round(self.rtt, 4),
            "source_port": self.source_port,
            "packets_sent": self.packets_sent,
            "discovers_sent": self.discovers_sent,
            "requests_sent": self.requests_sent,
            "naks": self.naks,
            "timestamps": self.timestamps,
        }


class _ClientSocket:
    """One UDP socket per simulated client, with a unique source port."""

    def __init__(
        self,
        bind_address: str,
        bind_port: int,
        interface: str | None,
    ) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # No SO_REUSEADDR here: with it, a client socket can silently bind onto
        # an already-used port (e.g. the server port) and packets get split
        # between sockets. Each client must get its own truly-free port.
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if interface and hasattr(socket, "SO_BINDTODEVICE"):
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\x00")
            except OSError:
                pass
        self.sock.bind((bind_address, bind_port))
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]
        self._boxes: dict[int, queue.Queue] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._rx, daemon=True)
        self._thread.start()

    def _rx(self) -> None:
        while not self._stop.is_set():
            try:
                data, _addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            msg = codec.decode(data)
            if msg is None:
                continue
            with self._lock:
                box = self._boxes.get(msg["xid"])
            if box is not None:
                try:
                    box.put_nowait(msg)
                except queue.Full:
                    pass

    def register(self, xid: int) -> queue.Queue:
        box: queue.Queue = queue.Queue(maxsize=16)
        with self._lock:
            self._boxes[xid] = box
        return box

    def unregister(self, xid: int) -> None:
        with self._lock:
            self._boxes.pop(xid, None)

    def sendto(self, payload: bytes, server: tuple[str, int], sport: int = 0) -> None:
        # Socket path: source port is fixed by bind(); sport is ignored.
        self.sock.sendto(payload, server)

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        try:
            self.sock.close()
        except OSError:
            pass


class Engine:
    """Run N client state machines against a DHCP server address."""

    def __init__(
        self,
        server_address: str,
        server_port: int = 67,
        *,
        client_port: int = 68,
        bind_address: str = "",
        interface: str | None = None,
        offer_timeout: float = 3.0,
        ack_timeout: float = 3.0,
        attempts: int = 2,
        workers: int = 32,
        lease_request: int = 0,
        transport: str = "auto",
        logger: logging.Logger | None = None,
        on_event: Callable[[str, dict], None] | None = None,
    ) -> None:
        self.server = (server_address, server_port)
        self.client_port = client_port
        self.bind_address = bind_address
        self.interface = interface
        self.offer_timeout = offer_timeout
        self.ack_timeout = ack_timeout
        self.attempts = max(1, attempts)
        self.workers = max(1, workers)
        self.lease_request = max(0, lease_request)
        self.transport = transport if transport in ("auto", "scapy", "socket") else "auto"
        self.log = logger or logging.getLogger("flhcp.engine")
        self.on_event = on_event
        self._stop = threading.Event()
        self._count_lock = threading.Lock()
        self._port_lock = threading.Lock()
        self._used_ports: set[int] = set()
        self._port_cursor = 49152
        self.packets_sent = 0
        self.offers_received = 0
        self.acks_received = 0
        self.last_results: list[ClientResult] = []

    def _resolve_transport(self) -> str:
        """Decide the wire transport: scapy (live real networks) vs socket."""
        if self.transport == "socket":
            return "socket"
        if self.transport == "scapy":
            return "scapy"
        # auto: use scapy only when it is actually installed.
        from flhcp.dhcp.scapy_transport import scapy_available

        return "scapy" if scapy_available() else "socket"

    # -- per-client socket -------------------------------------------------
    def _next_source_port(self) -> int:
        """Reserve the next unused ephemeral source port."""
        with self._port_lock:
            candidate = self._port_cursor
            self._port_cursor += 1
            while candidate in self._used_ports:
                candidate = self._port_cursor
                self._port_cursor += 1
            self._used_ports.add(candidate)
            return candidate

    def _new_client_socket(self) -> Any:
        """Allocate a per-client transport on a fresh source port.

        Uses the scapy L2 transport on live (non-loopback) runs when scapy is
        available — some NetHunter kernels silently drop Python UDP broadcasts
        that never reach the wire. Falls back to a bound UDP socket otherwise
        (loopback lab, or when scapy is absent).
        """
        last_err: OSError | None = None
        use_scapy = (
            self._resolve_transport() == "scapy"
            and self.interface is not None
            and not self._is_loopback()
        )
        for _ in range(60000):
            port = self._next_source_port()
            if use_scapy:
                try:
                    from flhcp.dhcp.scapy_transport import ScapyTransport

                    return ScapyTransport(self.interface, port, logger=self.log)
                except Exception as exc:  # noqa: BLE001 - fall back to socket
                    self._release_port(port)
                    last_err = exc
                    use_scapy = False
                    continue
            try:
                cs = _ClientSocket(self.bind_address, port, self.interface)
            except OSError as exc:
                # Bind failed (port taken by another process): release and retry.
                self._release_port(port)
                last_err = exc
                continue
            cs.start()
            return cs
        raise OSError(f"could not allocate a client source port: {last_err}")

    def _is_loopback(self) -> bool:
        return self.server[0] == "localhost" or self.server[0].startswith("127.")

    def _release_port(self, port: int) -> None:
        with self._port_lock:
            self._used_ports.discard(port)

    def _emit(self, kind: str, payload: dict) -> None:
        if self.on_event is not None:
            try:
                self.on_event(kind, payload)
            except Exception:
                pass

    def _wait_box(self, cs: _ClientSocket, box: queue.Queue, xid: int, msgtype: int, timeout: float) -> dict | None:
        try:
            end = time.monotonic() + timeout
            while time.monotonic() < end and not self._stop.is_set():
                remaining = end - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    msg = box.get(timeout=min(0.5, remaining))
                except queue.Empty:
                    continue
                if msg["msgtype"] == msgtype:
                    return msg
                if msg["msgtype"] == codec.NAK:
                    return msg
            return None
        finally:
            cs.unregister(xid)

    # -- one client ------------------------------------------------------
    def run_client(self, client: SimClient, rng: random.Random) -> ClientResult:
        result = ClientResult(client=client)
        mac = bytes.fromhex(client.mac.replace(":", ""))
        t0 = time.monotonic()
        result.timestamps["start"] = t0

        cs = self._new_client_socket()
        result.source_port = cs.port
        try:
            offer = None
            for _ in range(self.attempts):
                if self._stop.is_set():
                    break
                xid = rng.randrange(1, 2 ** 31)
                result.state = DISCOVER_SENT
                result.timestamps["discover"] = time.monotonic()
                # Register the xid inbox BEFORE sending, or an OFFER arriving
                # between sendto and register gets dropped (a lost-reply race).
                box = cs.register(xid)
                cs.sendto(codec.build_discover(xid, mac, hostname=client.hostname,
                                               lease_time=self.lease_request), self.server, cs.port)
                with self._count_lock:
                    self.packets_sent += 1
                result.packets_sent += 1
                result.discovers_sent += 1
                self._emit("discover", {"client": client.index})
                offer = self._wait_box(cs, box, xid, codec.OFFER, self.offer_timeout)
                if offer is not None:
                    break
            if offer is None:
                result.state = FAILED
                result.error = "no OFFER received (timeout)"
                return result
            result.state = OFFER_RECEIVED
            result.offered_ip = offer["yiaddr"]
            result.server_id = offer["server_id"]
            with self._count_lock:
                self.offers_received += 1
            self._emit("offer", {"client": client.index, "ip": offer["yiaddr"]})

            ack = None
            for _ in range(self.attempts):
                if self._stop.is_set():
                    break
                xid = rng.randrange(1, 2 ** 31)
                result.state = REQUEST_SENT
                result.timestamps["request"] = time.monotonic()
                box = cs.register(xid)
                cs.sendto(codec.build_request(
                    xid, mac, requested_ip=offer["yiaddr"],
                    server_id=offer["server_id"], hostname=client.hostname,
                    lease_time=self.lease_request,
                ), self.server, cs.port)
                with self._count_lock:
                    self.packets_sent += 1
                result.packets_sent += 1
                result.requests_sent += 1
                self._emit("request", {"client": client.index})
                ack = self._wait_box(cs, box, xid, codec.ACK, self.ack_timeout)
                if ack is not None and ack["msgtype"] == codec.NAK:
                    result.naks += 1
                if ack is not None:
                    break
            if ack is None or ack["msgtype"] != codec.ACK:
                result.state = FAILED
                result.error = "no ACK received (timeout)" if ack is None else f"received NAK from {ack['server_id']}"
                return result
            result.state = ACK_RECEIVED
            result.assigned_ip = ack["yiaddr"]
            result.lease = ack["lease"]
            result.server_id = ack["server_id"]
            result.rtt = time.monotonic() - t0
            result.timestamps["ack"] = time.monotonic()
            with self._count_lock:
                self.acks_received += 1
            self._emit("ack", {"client": client.index, "ip": ack["yiaddr"]})
            return result
        finally:
            cs.close()
            self._release_port(cs.port)

    # -- run many ----------------------------------------------------------
    def run(self, clients: list[SimClient], *, seed: int | None = None) -> list[ClientResult]:
        base = random.Random(seed)
        self._stop.clear()

        def _worker(c: SimClient) -> ClientResult:
            return self.run_client(c, random.Random(base.randrange(2 ** 31)))

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.workers, max(1, len(clients)))) as pool:
            futures = [pool.submit(_worker, c) for c in clients]
            self.last_results = [f.result() for f in futures]
        return self.last_results

    def stop(self) -> None:
        self._stop.set()

    def release_all(self, results: list[ClientResult]) -> int:
        """Send DHCPRELEASE for every leased client (lab hygiene)."""
        count = 0
        for result in results:
            if result.state != ACK_RECEIVED or not result.assigned_ip:
                continue
            mac = bytes.fromhex(result.client.mac.replace(":", ""))
            xid = random.randrange(1, 2 ** 31)
            try:
                cs = self._new_client_socket()
                try:
                    cs.sendto(codec.build_release(xid, mac, ciaddr=result.assigned_ip,
                                                  server_id=result.server_id), self.server, cs.port)
                    count += 1
                finally:
                    cs.close()
                    self._release_port(cs.port)
            except OSError:
                break
        return count
