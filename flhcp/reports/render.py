"""Report renderers: verbose terminal, JSON export, CSV export."""

from __future__ import annotations

import csv
import io
import json
from typing import Any


def render_terminal(session: dict[str, Any], results: list[dict], stats: dict) -> str:
    lines = [
        "",
        "FLHCP SESSION",
        "",
        f"Interface:\n{session.get('interface') or 'lo (isolated lab)'}",
        "",
        f"Generated Clients:\n{stats.get('clients', 0)}",
        "",
    ]
    for item in results:
        lines += [
            f"Client #{item['index']:03d}",
            "",
            f"MAC:\n{item['mac']}",
            "",
            f"Hostname:\n{item['hostname']}",
            "",
            "DHCP State:",
            "",
            f"DISCOVER  {'OK' if item['state'] in ('DISCOVER_SENT', 'OFFER_RECEIVED', 'REQUEST_SENT', 'ACK_RECEIVED') else 'FAIL'}",
            f"OFFER     {'OK' if item['state'] in ('OFFER_RECEIVED', 'REQUEST_SENT', 'ACK_RECEIVED') else 'FAIL'}",
            f"REQUEST   {'OK' if item['state'] in ('REQUEST_SENT', 'ACK_RECEIVED') else 'FAIL'}",
            f"ACK       {'OK' if item['state'] == 'ACK_RECEIVED' else 'FAIL'}",
            "",
            "Assigned IP:",
            item["assigned_ip"] or "-",
            "",
            "Lease:",
            f"{item['lease']} seconds" if item["lease"] else "-",
            "",
        ]
    granted_leases = sorted({item["lease"] for item in results if item["lease"]})
    lines += [
        "SESSION SUMMARY", "",
        f"Clients:\n{stats.get('clients', 0)}", "",
        f"Successful:\n{stats.get('successful', 0)}", "",
        f"Failed:\n{stats.get('failed', 0)}", "",
        f"Success:\n{stats.get('success_pct', 0)}%", "",
        f"DISCOVER sent:\n{stats.get('discovers_sent', 'unknown')}", "",
        f"REQUEST sent:\n{stats.get('requests_sent', 'unknown')}", "",
        f"Offers received:\n{stats.get('offers_received', 0)}", "",
        f"ACKs received:\n{stats.get('acks_received', 0)}", "",
        f"NAKs received:\n{stats.get('naks_received', 0)}", "",
        f"Packets sent:\n{stats.get('packets_sent', 0)}", "",
        f"Average response time:\n{stats.get('avg_rtt', 0)}s", "",
        f"RTT p50/p95/max:\n{stats.get('rtt_p50', 0)}s / {stats.get('rtt_p95', 0)}s / {stats.get('rtt_max', 0)}s", "",
    ]
    lease_req = session.get("lease_requested", 0)
    lines += [
        f"Lease requested:\n{lease_req or 'server default'} seconds", "",
        f"Leases granted:\n{', '.join(f'{g}s' for g in granted_leases) if granted_leases else 'none'}", "",
    ]
    starv = stats.get("starvation")
    if starv:
        lines += [
            "STARVATION TEST", "",
            f"Pool size:\n{starv.get('pool_size', 0)}", "",
            f"Clients tested:\n{starv.get('total_clients', 0)}", "",
            f"Leased after run:\n{starv.get('leased_after', 0)}", "",
            f"Free after run:\n{starv.get('free_after', 0)}", "",
            f"Pool exhausted:\n{'YES' if starv.get('pool_exhausted') else 'NO'}", "",
            f"Server-side evidence:\n{starv.get('server_evidence', {})}", "",
            f"NAK count:\n{starv.get('nak_count', 0)}", "",
            f"Timeout count:\n{starv.get('timeout_count', 0)}", "",
        ]
    return "\n".join(lines)


def render_json(session: dict[str, Any], results: list[dict], stats: dict) -> str:
    return json.dumps({"session": session, "clients": results, "stats": stats}, indent=2, sort_keys=True)


def render_csv(results: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["index", "mac", "hostname", "state",
                     "offered_ip", "assigned_ip", "lease", "server_id", "rtt",
                     "discovers", "requests", "naks", "error"])
    for item in results:
        writer.writerow([item.get("index"), item.get("mac"), item.get("hostname"),
                         item.get("state"), item.get("offered_ip"),
                         item.get("assigned_ip"), item.get("lease"), item.get("server_id"),
                         item.get("rtt"), item.get("discovers_sent", 0), item.get("requests_sent", 0),
                         item.get("naks", 0), item.get("error")])
    return buffer.getvalue()
