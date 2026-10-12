"""FLHCP command line interface."""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import socket
import sys
import time
import time

from flhcp import __version__
from flhcp.clients.generator import generate_clients, make_rng
from flhcp.core.config import Config
from flhcp.core.docs import dump_json
from flhcp.core.logging import setup_logging
from flhcp.core.stats import summarize
from flhcp.dhcp.engine import Engine, SimClient
from flhcp.reports.render import render_csv, render_json, render_terminal
from flhcp.storage.store import Storage


def _project_root() -> str:
    """Project root: directory containing the flhcp package + config.

    FLHCP_HOME overrides (used by tests and standalone installs); otherwise
    resolve from the installed package location.
    """
    env = os.environ.get("FLHCP_HOME")
    if env:
        return env
    import flhcp

    # flhcp/__init__.py lives in <root>/flhcp/, so the root is one level up.
    return os.path.dirname(os.path.dirname(os.path.abspath(flhcp.__file__)))


def _detect_interfaces() -> list[dict]:
    """List host interfaces with wireless flags (Linux sysfs; portable fallback)."""
    found: list[dict] = []
    net = "/sys/class/net"
    try:
        names = sorted(os.listdir(net))
    except OSError:
        names = []
    for name in names:
        if name == "lo":
            continue
        wireless = os.path.isdir(os.path.join(net, name, "wireless"))
        found.append({"name": name, "wireless": wireless})
    return found


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="flhcp", description="FLHCP — DHCP client simulation for authorized labs")
    parser.add_argument("--version", action="version", version=f"flhcp {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    start = sub.add_parser("start", help="run a DHCP starvation test")
    start.add_argument("--interface", default="", help="network interface for live runs (required off-loopback)")
    start.add_argument("--clients", type=int, default=10, help="number of starvation clients (default: 10)")
    start.add_argument("--seed", type=int, default=None, help="deterministic seed")
    start.add_argument("--config", default="", help="config file (JSON)")
    start.add_argument("--server-address", default="", help="DHCP server address (default: 127.0.0.1 lab)")
    start.add_argument("--server-port", type=int, default=0, help="DHCP server port (default: 67 live / 6767 lab)")
    start.add_argument("--client-port", type=int, default=0, help="local client port (default: 68 live / 6768 lab)")
    start.add_argument("--workers", type=int, default=32)
    start.add_argument("--pool-size", type=int, default=241, help="lab server pool size (default: 241)")
    start.add_argument("--starvation", action="store_true",
                       help="starvation test mode: exhaust the lab pool, verify with server-side evidence")
    start.add_argument("--release-after", action="store_true",
                       help="release all leases at end of starvation test (frees pool for post-release verification)")
    start.add_argument("--lease-time", default="",
                       help="requested lease in seconds, or with suffix: 30m 8h 8d (default: server default)")
    start.add_argument("--transport", default="auto", choices=["auto", "scapy", "socket"],
                       help="wire transport: auto (scapy for live, socket for loopback), scapy, or socket")
    start.add_argument("--attempts", type=int, default=2)
    start.add_argument("--timeout", type=float, default=3.0, help="per-step timeout seconds")
    start.add_argument("--output", default="terminal", help="terminal|json|csv (comma-separated allowed)")
    start.add_argument("--release", action="store_true", help="send DHCPRELEASE for leased clients at the end")
    start.add_argument("--no-lab-server", action="store_true", help="do not auto-start the loopback lab server")
    start.add_argument("--confirm-live", action="store_true", help="acknowledge a non-loopback live run (required off-loopback)")
    start.add_argument("--json", action="store_true", help="machine-readable final summary")

    status = sub.add_parser("status", help="show latest session summary")
    status.add_argument("--json", action="store_true")

    stop = sub.add_parser("stop", help="stop a running session engine")
    stop.add_argument("session", nargs="?", default="latest")
    stop.add_argument("--json", action="store_true")

    sessions = sub.add_parser("sessions", help="list stored sessions")
    sessions.add_argument("--json", action="store_true")

    report = sub.add_parser("report", help="render a stored session report")
    report.add_argument("session", help="session stamp or 'latest'")
    report.add_argument("--format", default="terminal", help="terminal|json|csv")
    report.add_argument("--output", default="", help="write to file instead of stdout")

    lab = sub.add_parser("lab-server", help="run the isolated mock DHCP server (foreground)")
    lab.add_argument("--bind", default="127.0.0.1")
    lab.add_argument("--port", type=int, default=6767)
    lab.add_argument("--pool", default="10.200.0.10/241", help="base/size, e.g. 10.200.0.10/241")

    ifaces = sub.add_parser("interfaces", help="list detected network interfaces")
    ifaces.add_argument("--json", action="store_true")

    doctor = sub.add_parser("doctor", help="check lab readiness (no network changes)")
    doctor.add_argument("--json", action="store_true")
    return parser


def _is_loopback(address: str) -> bool:
    return address == "localhost" or address.startswith("127.")


def _parse_duration(text: str) -> int:
    """Parse '691200', '30m', '8h', '8d' into seconds (0 when empty)."""
    if not text:
        return 0
    raw = str(text).strip().lower()
    try:
        if raw.endswith("d"):
            return int(float(raw[:-1]) * 86400)
        if raw.endswith("h"):
            return int(float(raw[:-1]) * 3600)
        if raw.endswith("m"):
            return int(float(raw[:-1]) * 60)
        if raw.endswith("s"):
            return int(float(raw[:-1]))
        return int(float(raw))
    except ValueError as exc:
        raise ValueError(f"bad --lease-time {text!r} (use seconds, or 30m/8h/8d)") from exc


def _default_config_path(root: str) -> str:
    """Pick the shipped config file: JSON (always works) before YAML."""
    for ext in ("json", "yaml", "yml"):
        path = os.path.join(root, f"config.{ext}")
        if os.path.isfile(path):
            return path
    return ""


def _cmd_start(args, root: str) -> int:
    cfg_path = args.config or _default_config_path(root)
    cfg = Config(cfg_path if cfg_path else None)
    cfg.load()
    rng = make_rng(args.seed)

    server_address = args.server_address or cfg.get("server_address", "127.0.0.1")
    lab_mode = _is_loopback(server_address)
    # Live (non-loopback) runs default to real DHCP ports 67/68; the lab
    # server port from config only applies to loopback lab mode.
    server_port = args.server_port or (6767 if lab_mode else 67)
    client_port = args.client_port or (6768 if lab_mode else 68)
    interface = args.interface or cfg.get("interface", "")
    if not lab_mode and not interface:
        print("error: live runs need --interface (refusing to spray the default route)", file=sys.stderr)
        print("hint: use loopback lab (default) or pass --interface <lab-iface>", file=sys.stderr)
        return 2
    if not lab_mode and not args.confirm_live:
        print("error: non-loopback run blocked - pass --confirm-live to acknowledge lab-only testing", file=sys.stderr)
        print("hint: the target must be an owned/isolated network, never a home router", file=sys.stderr)
        return 2
    if interface:
        known = {i["name"] for i in _detect_interfaces()}
        if known and interface not in known and interface != "lo":
            print(f"warning: interface {interface} not detected on this host", file=sys.stderr)
    if not lab_mode:
        print(f"WARNING: live run against {server_address} via '{interface or 'default route'}' — lab use only", file=sys.stderr)

    identities, identity = generate_clients(args.clients, rng)
    clients = [SimClient(c["index"], c["mac"], c["hostname"]) for c in identities]
    print("FLHCP pre-session summary", file=sys.stderr)
    print(f"  environment : {'isolated loopback lab' if lab_mode else 'LIVE network (lab use only)'}", file=sys.stderr)
    print(f"  server      : {server_address}:{server_port}", file=sys.stderr)
    print(f"  interface   : {interface or ('lo' if lab_mode else 'default route')}", file=sys.stderr)
    if lab_mode and not args.no_lab_server:
        print(f"  pool        : {max(1, args.pool_size or 241)} leases (mock lab server)", file=sys.stderr)
    else:
        print("  pool        : unknown (external server)", file=sys.stderr)
    print(f"  clients     : {len(clients)} (seed {args.seed})", file=sys.stderr)
    print(f"  limits      : attempts={args.attempts} timeout={args.timeout}s workers={args.workers}", file=sys.stderr)
    storage = Storage(os.path.join(root, cfg.get("output.dir", "sessions")))
    session_dir = storage.new_session_dir()
    logger = setup_logging(cfg.get("logging.level", "INFO"), cfg.get("logging.file", ""))

    lab_server = None
    pool_known = False
    lab_pool = max(1, args.pool_size or 241)
    if lab_mode and not args.no_lab_server:
        from flhcp.mock.server import MockDhcpServer

        if len(clients) > lab_pool:
            print(f"starvation test: {len(clients)} clients vs pool of {lab_pool} "
                  f"— pool exhaustion expected", file=sys.stderr)
        lab_server = MockDhcpServer(
            bind_address=server_address, port=server_port,
            pool_size=lab_pool,
            event_log=os.path.join(str(session_dir), "server-events.log"),
        )
        lab_server.start()
        pool_known = True

    session = {
        "tool": "flhcp", "version": __version__, "mode": "lab" if lab_mode else "live",
        "interface": interface or ("lo" if lab_mode else ""),
        "server": {"address": server_address, "port": server_port},
        "seed": args.seed, "clients_requested": len(clients),
        "lease_requested": _parse_duration(args.lease_time),
        "identity": identity,
        "started": _dt.datetime.now().isoformat(timespec="seconds"),
    }
    pidfile = os.path.join(str(session_dir), "engine.pid")
    with open(pidfile, "w", encoding="utf-8") as handle:
        handle.write(str(os.getpid()))

    def on_event(kind: str, payload: dict) -> None:
        storage.append_event(session_dir, f"{kind} {dump_json(payload)}")

    engine = Engine(
        server_address, server_port, client_port=client_port,
        bind_address="127.0.0.1" if lab_mode else "",
        interface=interface or None,
        offer_timeout=args.timeout, ack_timeout=args.timeout,
        attempts=args.attempts, workers=args.workers,
        lease_request=_parse_duration(args.lease_time),
        transport=args.transport,
        logger=logger, on_event=on_event,
    )
    t0 = time.monotonic()
    starv_result = None
    try:
        if args.starvation:
            from flhcp.starvation.engine import StarvationEngine

            se = StarvationEngine(engine, pool_size=lab_pool if lab_server is not None else 0,
                                  logger=logger)
            starv_result = se.run(clients, seed=args.seed,
                                  server_pool_status=lab_server.pool_status if lab_server is not None else None)
            results = engine.last_results or []
        else:
            results = engine.run(clients, seed=args.seed)
        elapsed = time.monotonic() - t0
        # Release leases while the lab server is still running so pool slots
        # are actually returned (post-exhaustion reuse test).
        if (args.release or (args.starvation and args.release_after)) and results:
            released = engine.release_all(results)
            if starv_result is not None:
                starv_result.release_count = released
            print(f"released {released} leases", file=sys.stderr)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        results = []
        elapsed = time.monotonic() - t0
    finally:
        if lab_server is not None:
            lab_server.stop()
    try:
        os.unlink(pidfile)
    except OSError:
        pass

    dicts = [r.to_dict() for r in results]
    stats = summarize(results, elapsed)
    if starv_result is not None:
        stats["starvation"] = starv_result.to_dict()
        session["starvation"] = starv_result.to_dict()
    if lab_server is not None:
        pool = lab_server.pool_status()
        pool["exhausted"] = bool(pool_known) and stats["failed"] > 0 and pool["free"] == 0
        stats["pool"] = {k: v for k, v in pool.items() if k != "leases"}
        session["pool"] = stats["pool"]
    else:
        stats["pool"] = {"known": False}
        session["pool"] = {"known": False}
    session.update({"ended": _dt.datetime.now().isoformat(timespec="seconds"),
                    "state": "done", "stats": stats})
    storage.write_json(os.path.join(str(session_dir), "session.json"), session)
    storage.write_json(os.path.join(str(session_dir), "clients.json"), {"clients": dicts})
    storage.write_json(os.path.join(str(session_dir), "leases.json"), {
        "leases": [{"mac": d["mac"], "ip": d["assigned_ip"], "lease": d["lease"],
                    "server": d["server_id"]} for d in dicts if d["state"] == "ACK_RECEIVED"],
    })
    formats = [f.strip() for f in str(args.output).split(",") if f.strip()] or ["terminal"]
    # When --json is passed, emit ONLY the JSON summary (machine-readable mode).
    if args.json:
        formats = ["json"]
    if "terminal" in formats:
        print(render_terminal(session, dicts, stats))
    if "json" in formats:
        print(render_json(session, dicts, stats))
    if "csv" in formats:
        print(render_csv(dicts))
    return 0 if stats["failed"] == 0 else 1


def _latest_session_dir(root: str, ref: str) -> str:
    storage = Storage(os.path.join(root, "sessions"))
    names = storage.list_sessions()
    if not names:
        raise ValueError("no sessions yet")
    if ref in ("latest", ""):
        return os.path.join(root, "sessions", names[-1])
    path = os.path.join(root, "sessions", ref)
    if not os.path.isdir(path):
        raise ValueError(f"unknown session: {ref}")
    return path


def _cmd_status(args, root: str) -> int:
    try:
        session_dir = _latest_session_dir(root, "latest")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    session = json.loads(open(os.path.join(session_dir, "session.json"), encoding="utf-8").read())
    stats = session.get("stats", {})
    if args.json:
        print(dump_json({"session": os.path.basename(session_dir), **session}))
        return 0
    print(f"session: {os.path.basename(session_dir)}")
    print(f"state:   {session.get('state', '?')}")
    print(f"clients: {stats.get('clients', '?')}  success: {stats.get('successful', '?')} "
          f"({stats.get('success_pct', '?')}%)  avg_rtt: {stats.get('avg_rtt', '?')}s")
    return 0


def _cmd_stop(args, root: str) -> int:
    try:
        session_dir = _latest_session_dir(root, args.session)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    pidfile = os.path.join(session_dir, "engine.pid")
    killed = False
    if os.path.isfile(pidfile):
        try:
            pid = int(open(pidfile, encoding="utf-8").read().strip())
        except (OSError, ValueError):
            pid = 0
        if pid > 0:
            try:
                import signal

                os.kill(pid, signal.SIGTERM)
                killed = True
            except (OSError, PermissionError):
                pass
        try:
            os.unlink(pidfile)
        except OSError:
            pass
    session_path = os.path.join(session_dir, "session.json")
    try:
        session = json.loads(open(session_path, encoding="utf-8").read())
        session["state"] = "stopped"
        with open(session_path, "w", encoding="utf-8") as handle:
            json.dump(session, handle, indent=2, sort_keys=True)
    except OSError:
        pass
    if args.json:
        print(dump_json({"session": os.path.basename(session_dir), "killed": killed}))
        return 0
    print(f"stopped {os.path.basename(session_dir)}" + (" (engine killed)" if killed else ""))
    return 0


def _cmd_sessions(args, root: str) -> int:
    storage = Storage(os.path.join(root, "sessions"))
    rows = []
    for name in storage.list_sessions():
        try:
            session = storage.read_json(os.path.join(root, "sessions", name, "session.json"))
            rows.append({"session": name, "state": session.get("state"),
                         "clients": session.get("clients_requested"),
                         "success": (session.get("stats") or {}).get("successful")})
        except (OSError, ValueError):
            rows.append({"session": name, "state": "?"})
    if args.json:
        print(dump_json(rows))
        return 0
    if not rows:
        print("no sessions")
        return 0
    for row in rows:
        print(f"{row['session']}  state={row.get('state')} clients={row.get('clients')} success={row.get('success')}")
    return 0


def _cmd_report(args, root: str) -> int:
    try:
        session_dir = _latest_session_dir(root, args.session)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    try:
        session = json.loads(open(os.path.join(session_dir, "session.json"), encoding="utf-8").read())
        clients = json.loads(open(os.path.join(session_dir, "clients.json"), encoding="utf-8").read())["clients"]
    except (OSError, ValueError) as exc:
        print(f"error: cannot read session: {exc}", file=sys.stderr)
        return 1
    stats = session.get("stats", {})
    fmt = args.format
    text = {"terminal": render_terminal, "json": render_json}.get(fmt, render_terminal)(session, clients, stats) if fmt != "csv" else render_csv(clients)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text if text.endswith("\n") else text + "\n")
        print(f"wrote {args.output}")
        return 0
    print(text)
    return 0


def _cmd_lab_server(args, root: str) -> int:
    from flhcp.mock.server import MockDhcpServer

    base, _, size = args.pool.partition("/")
    server = MockDhcpServer(bind_address=args.bind, port=args.port, pool_base=base,
                            pool_size=int(size or 241))
    print(f"mock DHCP on {args.bind}:{args.port} (Ctrl+C to stop)", file=sys.stderr)
    server.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    print(f"served={server.served} leases={len(server.leases)}", file=sys.stderr)
    return 0


def _cmd_interfaces(args, root: str) -> int:
    ifaces = _detect_interfaces()
    if args.json:
        print(dump_json(ifaces))
        return 0
    if not ifaces:
        print("no non-loopback interfaces detected")
        return 0
    for iface in ifaces:
        print(f"{iface['name']}" + ("  [wireless]" if iface["wireless"] else ""))
    return 0


def _cmd_doctor(args, root: str) -> int:
    import platform

    checks = []
    py_ok = sys.version_info >= (3, 11)
    checks.append(("python>=3.11", py_ok, platform.python_version()))
    try:
        from flhcp.dhcp.scapy_transport import scapy_available

        has_scapy = scapy_available()
        # scapy is optional: loopback lab works without it, live runs need it.
        # Report as PASS (informational) so a stdlib-only install stays "ready".
        checks.append(("scapy", True,
                       "present (live real-network transport)" if has_scapy
                       else "absent (loopback lab works; live runs need scapy)"))
    except Exception as exc:  # noqa: BLE001
        checks.append(("scapy", True, f"import error (ignored): {exc}"[:100]))
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        probe.close()
        checks.append(("loopback_udp", True, "can bind UDP on 127.0.0.1"))
    except OSError as exc:
        checks.append(("loopback_udp", False, str(exc)[:100]))
    ifaces = _detect_interfaces()
    checks.append(("interfaces", True, f"{len(ifaces)} non-loopback: " + ", ".join(i["name"] for i in ifaces) if ifaces else "none detected"))
    try:
        sessions = os.path.join(root, "sessions")
        os.makedirs(sessions, exist_ok=True)
        checks.append(("storage_writable", os.access(sessions, os.W_OK), sessions))
    except OSError as exc:
        checks.append(("storage_writable", False, str(exc)[:100]))
    import os as _os

    admin = False
    try:
        admin = _os.geteuid() == 0
    except AttributeError:
        try:
            import ctypes

            admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            admin = False
    checks.append(("privileges", True, "root/admin" if admin else "unprivileged (loopback lab only; ports 67/68 need privilege)"))
    healthy = all(ok for _, ok, _ in checks)
    if args.json:
        print(dump_json([{"check": name, "ok": ok, "detail": detail} for name, ok, detail in checks]))
        return 0 if healthy else 1
    for name, ok, detail in checks:
        print(f"{'PASS' if ok else 'FAIL'} {name} — {detail}")
    print("lab ready." if healthy else "lab has FAILURES (see above).")
    return 0 if healthy else 1


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    root = _project_root()
    try:
        if args.command == "start":
            return _cmd_start(args, root)
        if args.command == "status":
            return _cmd_status(args, root)
        if args.command == "stop":
            return _cmd_stop(args, root)
        if args.command == "sessions":
            return _cmd_sessions(args, root)
        if args.command == "report":
            return _cmd_report(args, root)
        if args.command == "lab-server":
            return _cmd_lab_server(args, root)
        if args.command == "interfaces":
            return _cmd_interfaces(args, root)
        if args.command == "doctor":
            return _cmd_doctor(args, root)
        parser.print_help(sys.stdout)
        return 0
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except SystemExit:
        raise
    except Exception as exc:
        print(f"error: unexpected failure: {exc}", file=sys.stderr)
        return 1
