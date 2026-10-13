<div align="center">

<img width="1280" height="720" alt="flhcp" src="https://github.com/user-attachments/assets/f135f5ba-8aaa-452b-80b3-48b9cc6c73d6" />

# ⚡ FLHCP

**DHCP Starvation Tool for Authorized Lab Environments**

*Part of the WiPwn network security toolkit*

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-39%2F39-brightgreen.svg)](#testing)
[![Stdlib Only](https://img.shields.io/badge/loopback-stdlib--only-orange.svg)](#requirements)

---

Stop spraying DHCPDISCOVERs that routers cancel in minutes.
**FLHCP completes the full DORA handshake** so every reservation becomes a
committed lease — and requests a long lease to hold each address for the
maximum duration.

</div>

## 🎯 What It Does

FLHCP starves a DHCP server's IP pool by generating many client identities
that each complete the **full DHCP handshake** (DISCOVER → OFFER → REQUEST →
ACK), then requesting a long lease so every address stays reserved. Pool
exhaustion is verified with **server-side evidence** — never fabricated.

```
┌─────────┐   DISCOVER   ┌──────────┐
│ FLHCP   │ ───────────▶ │          │
│ client  │              │  DHCP    │
│ #042    │ ◀─────────── │  server  │
└─────────┘     OFFER    │          │
     │                   │  pool:   │
     │      REQUEST      │  10.200  │
     │ ─────────────────▶│  .0.x    │
     │                   │          │
     │ ◀─────────────────│          │
     └────── ACK ────────└──────────┘
              (lease committed!)
```

## 🔥 Why Not Just DISCOVER Spam?

| Naive DISCOVER spam | FLHCP |
|---|---|
| Blasts DHCPDISCOVER, never finishes | Completes **DORA** handshake |
| Router cancels un-completed offers in minutes | Every reservation is a **committed lease** |
| Busy for a few minutes | Busy for the **full lease duration** |
| No proof anything was held | Server-side exhaustion evidence |

## ✨ Features

- **Real RFC 2131 protocol** — proper packets on the wire, not fake JSON
- **Long-lease starvation** — `--lease-time 8d` requests 8-day holds
- **Pool exhaustion detection** — asserts exhaustion only with server evidence
- **Per-client sockets** — unique source ports, no shared-socket races
- **Deterministic** — `--seed` for reproducible client identities
- **Zero-config lab** — built-in mock DHCP server on loopback
- **Optional scapy transport** — raw L2 for live networks on kernels that
  drop Python UDP broadcasts (NetHunter)

## 📦 Requirements

Tools that only blast DHCPDISCOVERs and never finish the handshake keep a
network busy for only a few minutes — routers cancel un-completed offers
on timeout. FLHCP completes the handshake so every reservation becomes a
**committed lease**, and requests a long lease (`--lease-time 8d`) to hold
each address for the maximum duration.

## 🛡️ Safety First

- Default mode is an **isolated loopback lab** (`127.0.0.1`): nothing
  leaves your machine.
- Live runs **require** `--interface` **and** `--confirm-live`, and print
  a warning. There is no default that sprays your home router.
- Never target networks you do not own or have explicit permission
  to test.

## 🔌 Wire transport

`--transport` selects how packets reach the wire:

| mode | behavior |
|---|---|
| `auto` (default) | scapy on live non-loopback runs, stdlib socket on loopback |
| `scapy` | force scapy L2 injection |
| `socket` | force stdlib UDP sockets |

Each client runs on its own source port; replies are demultiplexed by
transaction ID (xid). On the loopback lab the built-in mock server answers,
so no scapy is required.

## ⚡ Quick Start

```bash
# Zero-config lab demo (auto-starts a mock DHCP server on loopback)
python -m flhcp start --clients 10

# Starvation: exhaust a small pool — 50 clients vs 20 addresses
python -m flhcp start --starvation --clients 50 --pool-size 20 --seed 7

# Long-lease starvation: hold every address for 8 days
python -m flhcp start --starvation --clients 50 --pool-size 20 --lease-time 8d --seed 7

# Live run against a real lab router (needs scapy + explicit confirmation)
python -m flhcp start --interface wlan1 --server-address 192.168.10.1 \
    --clients 50 --confirm-live
```

## 🎮 CLI Commands

| Command | Description |
|---|---|
| `start` | run a starvation test |
| `doctor` | check lab readiness (no network changes) |
| `lab-server` | run the isolated mock DHCP server |
| `status` | latest session summary |
| `stop` | stop a running session |
| `sessions` | list stored sessions |
| `report` | render a session report (terminal/json/csv) |
| `interfaces` | list detected network interfaces |

## ✅ What Starvation Mode Guarantees

- The lab server enforces a **real pool size** (`--pool-size`). Addresses
  are allocated only while capacity exists; when exhausted, the server
  stays silent (no OFFER) — real DHCP behavior, not a mock that
  fabricates success.
- Each client runs the full DORA handshake and is accounted as
  **success** (ACK), **timeout** (no OFFER/ACK), or **NAK**.
- `pool_exhausted: true` is asserted **only** when the server pool shows
  zero free AND at least one client failed — no fabricated success.
- With `--release-after`, all leases are released and the pool returns to
  its full free count, proving slots are reused.

## ⏱️ Long-Lease Requests

The requested lease travels as DHCP option 51 in both DISCOVER and
REQUEST. The session report records `Lease requested` and `Leases granted`
so you can verify what the server actually committed. On the loopback lab
server the requested lease is honored exactly (evidence for end-to-end
tests); a real router may grant its own max lease — the report shows the
truth either way.

**Example output:**

```text
FLHCP SESSION
Interface: wlan0

Client #001
MAC: 82:B7:0E:EE:7F:1A
Hostname: host-LYKE
DHCP State:
DISCOVER  OK
OFFER     OK
REQUEST   OK
ACK       OK
Assigned IP: 192.168.1.188
Lease: 7200 seconds

SESSION SUMMARY
Clients: 100
Successful: 142
Failed: 8
Success: 94.7%
Lease requested: 691200 seconds
Leases granted: 7200s
```

## 💾 Sessions and Reports

Each run creates `sessions/YYYY-MM-DD-HH-MM/` with `session.json`,
`clients.json`, `leases.json`, and `events.log`. Reports render as
`terminal` (default), `json`, or `csv`.

```bash
python -m flhcp status
python -m flhcp sessions
python -m flhcp report latest --format csv --output report.csv
```

## 🧪 The Isolated Test Lab

`flhcp lab-server` runs a minimal authoritative DHCP server in the
foreground (default `127.0.0.1:6767`, pool `10.200.0.10/241`). The
built-in lab mode of `flhcp start` launches one automatically, so the
default command never needs any external infrastructure.

On Linux you can additionally use network namespaces or `dnsmasq` for
L2-realistic labs; see `scripts/isolated_lab.sh`.

## 📱 A51 / NetHunter Deployment

Pure-Python + stdlib runs as-is on ARM64. Copy the tree into the Kali
chroot, then:

```bash
python3 -m flhcp interfaces   # lists wlan0/wlan1/wlan2
python3 -m flhcp start --interface wlan1 --clients 50 --confirm-live
```

## 🧪 Testing

```bash
python -m unittest discover -s tests/unit         # codec, generator, stats, reports
python -m unittest discover -s tests/integration  # engine + starvation vs mock lab
```

39 tests: codec round-trips, MAC generation, DORA exchanges, pool exhaustion,
long leases, negative/timeout paths, release/reuse, and the scapy transport
fallback.

## 🏗️ Project Layout

```
flhcp/
├── cli/          CLI (start, doctor, lab-server, status, ...)
├── dhcp/         codec (RFC 2131), engine (state machines), scapy_transport
├── starvation/   StarvationEngine: pool-exhaustion analysis + evidence
├── clients/      identity generation (unique MACs, hostnames)
├── mock/         isolated mock DHCP server for the lab
├── reports/      terminal / json / csv renderers
├── storage/      session persistence
└── core/         config, logging, stats
tests/            unit + integration (loopback lab, no router needed)
scripts/          isolated_lab.sh, publish.sh
```

## 📜 License

[MIT](LICENSE) — for authorized lab and research use only.

---

<div align="center">

**Built for security professionals who finish what they start.**

*FLHCP — full handshake, full congestion.*

</div>
