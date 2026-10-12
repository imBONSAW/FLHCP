"""DHCP packet codec (RFC 2131): encode client messages, decode replies.

Standard library only (struct + socket). No Scapy required.
"""

from __future__ import annotations

import socket
import struct

# RFC 2131 magic cookie: 0x63 0x82 0x53 0x63 (decimal 99.130.83.99).
# Written as hex literals — the common mistake is [63, 82, 53, 63] which
# produces 0x3F 0x52 0x35 0x3F and real routers silently drop it.
MAGIC_COOKIE = bytes([0x63, 0x82, 0x53, 0x63])
HEADER_LEN = 236

# DHCP message types (option 53)
DISCOVER = 1
OFFER = 2
REQUEST = 3
DECLINE = 4
ACK = 5
NAK = 6
RELEASE = 7
INFORM = 8

MSG_NAMES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}

# Common option codes
OPT_PAD = 0
OPT_SUBNET = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_HOSTNAME = 12
OPT_DOMAIN = 15
OPT_REQUESTED_IP = 50
OPT_LEASE_TIME = 51
OPT_MSG_TYPE = 53
OPT_SERVER_ID = 54
OPT_PARAM_LIST = 55
OPT_CLIENT_ID = 61
OPT_END = 255

BROADCAST_FLAG = 0x8000


def _ip(raw: bytes) -> str:
    return socket.inet_ntoa(raw[:4])


def _ip_bytes(addr: str) -> bytes:
    return socket.inet_aton(addr)


def encode_options(options: list[tuple[int, bytes]]) -> bytes:
    out = bytearray()
    for code, data in options:
        if code == OPT_PAD:
            out.append(0)
            continue
        out.append(code)
        out.append(len(data))
        out += data
    out.append(OPT_END)
    return bytes(out)


def decode_options(blob: bytes) -> dict[int, bytes]:
    opts: dict[int, bytes] = {}
    i = 0
    while i < len(blob):
        code = blob[i]
        i += 1
        if code == OPT_END:
            break
        if code == OPT_PAD:
            continue
        if i >= len(blob):
            break
        length = blob[i]
        i += 1
        opts.setdefault(code, blob[i:i + length])
        i += length
    return opts


def build_discover(
    xid: int,
    chaddr: bytes,
    *,
    hostname: str = "",
    broadcast: bool = True,
    param_list: bytes = bytes([1, 3, 6, 51]),
    lease_time: int = 0,
) -> bytes:
    pkt = struct.pack("!BBBBIHH", 1, 1, 6, 0, xid, 0, BROADCAST_FLAG if broadcast else 0)
    pkt += b"\x00" * 16
    pkt += chaddr[:16].ljust(16, b"\x00") + b"\x00" * 64 + b"\x00" * 128
    pkt += MAGIC_COOKIE
    opts = [(OPT_MSG_TYPE, bytes([DISCOVER])), (OPT_CLIENT_ID, b"\x01" + chaddr[:6])]
    if hostname:
        opts.append((OPT_HOSTNAME, hostname.encode()[:32]))
    if lease_time > 0:
        opts.append((OPT_LEASE_TIME, struct.pack("!I", lease_time)))
    opts.append((OPT_PARAM_LIST, param_list))
    return pkt + encode_options(opts)


def build_request(
    xid: int,
    chaddr: bytes,
    *,
    requested_ip: str = "0.0.0.0",
    server_id: str = "",
    ciaddr: str = "0.0.0.0",
    hostname: str = "",
    broadcast: bool = True,
    lease_time: int = 0,
) -> bytes:
    pkt = struct.pack("!BBBBIHH", 1, 1, 6, 0, xid, 0, BROADCAST_FLAG if broadcast else 0)
    pkt += _ip_bytes(ciaddr) + b"\x00" * 12
    pkt += chaddr[:16].ljust(16, b"\x00") + b"\x00" * 64 + b"\x00" * 128
    pkt += MAGIC_COOKIE
    opts = [(OPT_MSG_TYPE, bytes([REQUEST])), (OPT_CLIENT_ID, b"\x01" + chaddr[:6])]
    if requested_ip != "0.0.0.0":
        opts.append((OPT_REQUESTED_IP, _ip_bytes(requested_ip)))
    if server_id:
        opts.append((OPT_SERVER_ID, _ip_bytes(server_id)))
    if hostname:
        opts.append((OPT_HOSTNAME, hostname.encode()[:32]))
    if lease_time > 0:
        opts.append((OPT_LEASE_TIME, struct.pack("!I", lease_time)))
    return pkt + encode_options(opts)


def build_release(xid: int, chaddr: bytes, *, ciaddr: str, server_id: str) -> bytes:
    pkt = struct.pack("!BBBBIHH", 1, 1, 6, 0, xid, 0, 0)
    pkt += _ip_bytes(ciaddr) + b"\x00" * 12
    pkt += chaddr[:16].ljust(16, b"\x00") + b"\x00" * 64 + b"\x00" * 128
    pkt += MAGIC_COOKIE
    opts = [(OPT_MSG_TYPE, bytes([RELEASE])), (OPT_SERVER_ID, _ip_bytes(server_id))]
    return pkt + encode_options(opts)


def build_reply(
    xid: int,
    chaddr: bytes,
    yiaddr: str,
    msgtype: int,
    *,
    server_id: str = "10.200.0.1",
    lease_time: int = 3600,
    netmask: str = "255.255.255.0",
    router: str = "",
    dns: str = "",
) -> bytes:
    """Build a server reply (OFFER/ACK/NAK). Used by the mock lab server."""
    pkt = struct.pack("!BBBBIHH", 2, 1, 6, 0, xid, 0, 0)
    pkt += _ip_bytes("0.0.0.0") + _ip_bytes(yiaddr)
    pkt += _ip_bytes(server_id) + _ip_bytes("0.0.0.0")
    pkt += chaddr[:16].ljust(16, b"\x00") + b"\x00" * 64 + b"\x00" * 128
    pkt += MAGIC_COOKIE
    opts = [(OPT_MSG_TYPE, bytes([msgtype]))]
    if msgtype != NAK:
        opts.append((OPT_SERVER_ID, _ip_bytes(server_id)))
        opts.append((OPT_LEASE_TIME, struct.pack("!I", lease_time)))
        opts.append((OPT_SUBNET, _ip_bytes(netmask)))
        if router:
            opts.append((OPT_ROUTER, _ip_bytes(router)))
        if dns:
            opts.append((OPT_DNS, _ip_bytes(dns)))
    return pkt + encode_options(opts)


def decode(data: bytes) -> dict | None:
    """Decode any DHCP message; None when malformed."""
    if len(data) < HEADER_LEN + 4 or data[236:240] != MAGIC_COOKIE:
        return None
    op, htype, hlen, hops, xid, secs, flags = struct.unpack("!BBBBIHH", data[:12])
    ciaddr, yiaddr, siaddr, giaddr = (_ip(data[o:o + 4]) for o in (12, 16, 20, 24))
    chaddr = data[28:44]
    options = decode_options(data[240:])
    msgtype = options.get(OPT_MSG_TYPE, b"\x00")[0] if OPT_MSG_TYPE in options else 0
    lease = struct.unpack("!I", options[OPT_LEASE_TIME])[0] if OPT_LEASE_TIME in options else 0
    server = _ip(options[OPT_SERVER_ID]) if OPT_SERVER_ID in options else ""
    requested = _ip(options[OPT_REQUESTED_IP]) if OPT_REQUESTED_IP in options else ""
    hostname = options.get(OPT_HOSTNAME, b"").decode("utf-8", errors="replace")
    return {
        "op": op, "htype": htype, "hlen": hlen, "hops": hops, "xid": xid,
        "secs": secs, "flags": flags, "ciaddr": ciaddr, "yiaddr": yiaddr,
        "siaddr": siaddr, "giaddr": giaddr, "chaddr": chaddr,
        "msgtype": msgtype, "msgname": MSG_NAMES.get(msgtype, f"UNKNOWN({msgtype})"),
        "lease": lease, "server_id": server, "requested_ip": requested,
        "hostname": hostname, "options": options,
    }
