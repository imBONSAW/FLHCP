"""Client identity generation for the starvation tool: seeded, deterministic,
collision-free. Lab traffic stays locally-administered (02:xx) so it never
impersonates a real vendor OUI.

Deliberately lean: no vendor profiles, no client files, no MAC ranges —
just N unique random identities for starving a DHCP pool.
"""

from __future__ import annotations

import random
import re
import string

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

_SUFFIX = string.ascii_uppercase + string.digits


def make_rng(seed: int | None) -> random.Random:
    return random.Random() if seed is None else random.Random(int(seed))


def normalize_mac(raw: str) -> str:
    text = str(raw or "").strip().upper().replace("-", ":")
    if not _MAC_RE.match(text):
        raise ValueError(f"invalid MAC address: {raw!r}")
    return text


def random_mac(rng: random.Random) -> str:
    """Random locally-administered unicast MAC (02:xx:xx:xx:xx:xx)."""
    first = rng.randrange(256) & 0xFC | 0x02
    parts = [first] + [rng.randrange(256) for _ in range(5)]
    return ":".join(f"{b:02X}" for b in parts)


def unique_macs(
    count: int,
    rng: random.Random,
    *,
    taken: set[str] | None = None,
) -> tuple[list[str], int]:
    """Generate `count` collision-free random MACs.

    `taken` holds already-used addresses (mutated in place). Returns
    (macs, collisions_skipped). Raises ValueError after a bounded number of
    attempts (never an infinite loop).
    """
    if count < 0:
        raise ValueError("count must be >= 0")
    taken = taken if taken is not None else set()
    out: list[str] = []
    skipped = 0
    attempts = 0
    cap = max(count * 50 + 1000, 1000)
    while len(out) < count:
        attempts += 1
        if attempts > cap:
            raise ValueError(
                f"MAC space exhausted: {len(out)}/{count} unique after {cap} attempts"
            )
        mac = random_mac(rng)
        if mac in taken:
            skipped += 1
            continue
        taken.add(mac)
        out.append(mac)
    return out, skipped


def render_hostname(rng: random.Random) -> str:
    """Random lab hostname (host-XXXX), ≤32 chars."""
    return "host-" + "".join(rng.choice(_SUFFIX) for _ in range(4))


def generate_clients(count: int, rng: random.Random) -> tuple[list[dict], dict]:
    """Generate `count` starvation client identities: unique MAC + hostname.

    Returns (clients, meta) where each client is
    {index, mac, hostname} and meta reports collisions skipped.
    """
    if count <= 0:
        raise ValueError("clients must be >= 1")
    macs, skipped = unique_macs(count, rng)
    clients = [
        {"index": i + 1, "mac": mac, "hostname": render_hostname(rng)}
        for i, mac in enumerate(macs)
    ]
    return clients, {"collisions_skipped": skipped, "source": "generated"}
