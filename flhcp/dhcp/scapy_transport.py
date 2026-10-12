"""Optional scapy transport layer for live DHCP on real networks.

The stdlib UDP socket path (see engine._ClientSocket) works on loopback and
in the mock lab, but on some NetHunter kernels a Python UDP `sendto` to
255.255.255.255 never reaches the wire for DHCP — the kernel silently drops
it. scapy builds a raw L2 frame and injects it directly, which those
kernels/drivers do forward. This module is imported lazily so FLHCP keeps
working with zero dependencies when scapy is absent.
"""

from __future__ import annotations

import logging
import queue
import threading
from typing import Any

from flhcp.dhcp import codec


def scapy_available() -> bool:
    try:
        import scapy.all  # noqa: F401
        return True
    except Exception:
        return False


class ScapyWire:
    """One shared L2 receiver + per-client sender for an interface.

    A single AsyncSniffer serves all clients (one receiver thread on the NIC,
    not one per client). Replies are demultiplexed per client by xid.
    """

    def __init__(self, interface: str, logger: logging.Logger | None = None) -> None:
        from scapy.all import AsyncSniffer, Ether, IP, UDP, Raw, get_if_hwaddr, sendp

        self._sendp = sendp
        self._Ether = Ether
        self._IP = IP
        self._UDP = UDP
        self._Raw = Raw
        self.interface = interface
        self.log = logger or logging.getLogger("flhcp.scapy")
        self.src_mac = get_if_hwaddr(interface)
        self._boxes: dict[int, queue.Queue] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sniffer = AsyncSniffer(
            iface=interface,
            filter="udp and (port 67 or port 68)",
            prn=self._on_packet,
        )
        self._sniffer.start()

    def _on_packet(self, pkt: Any) -> None:
        try:
            # Only inbound replies: sport 67 (bootps, the server). Our own
            # outgoing frames are dport 67, so filtering on sport==67 keeps
            # only what the server sent back (sniffer sees both directions).
            if self._UDP not in pkt:
                return
            if int(pkt[self._UDP].sport) != 67:
                return
            # The reply's BOOTP/DHCP payload may be parsed by scapy into its
            # own layers; re-serialize the UDP payload back to raw bytes.
            payload = bytes(pkt[self._UDP].payload)
            msg = codec.decode(payload)
        except Exception:
            return
        if msg is None:
            return
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

    def sendto(self, payload: bytes, server: tuple[str, int], sport: int) -> None:
        frame = (
            self._Ether(dst="ff:ff:ff:ff:ff:ff", src=self.src_mac)
            / self._IP(src="0.0.0.0", dst="255.255.255.255", flags=0)
            / self._UDP(sport=sport, dport=server[1])
            / self._Raw(load=payload)
        )
        self._sendp(frame, iface=self.interface, verbose=0)

    def close(self) -> None:
        self._stop.set()
        try:
            self._sniffer.stop()
        except Exception:
            pass


class ScapyTransport:
    """Per-client handle over a shared ScapyWire (one receiver for all)."""

    _shared: dict[str, ScapyWire] = {}
    _shared_lock = threading.Lock()

    def __init__(self, interface: str, sport: int, logger: logging.Logger | None = None) -> None:
        self.interface = interface
        self.port = sport
        self.log = logger or logging.getLogger("flhcp.scapy")
        with ScapyTransport._shared_lock:
            wire = ScapyTransport._shared.get(interface)
            if wire is None:
                wire = ScapyWire(interface, logger=self.log)
                ScapyTransport._shared[interface] = wire
            self._wire = wire

    def register(self, xid: int) -> queue.Queue:
        return self._wire.register(xid)

    def unregister(self, xid: int) -> None:
        self._wire.unregister(xid)

    def sendto(self, payload: bytes, server: tuple[str, int], sport: int = 0) -> None:
        self._wire.sendto(payload, server, sport or self.port)

    def close(self) -> None:
        # Per-client handle is cheap; the shared wire lives for the process.
        pass
