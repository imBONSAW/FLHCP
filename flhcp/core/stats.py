"""Live session statistics aggregation."""

from __future__ import annotations

from typing import Any


def _percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    rank = (len(sorted_values) - 1) * (pct / 100.0)
    low, high = int(rank), min(int(rank) + 1, len(sorted_values) - 1)
    frac = rank - low
    return round(sorted_values[low] * (1 - frac) + sorted_values[high] * frac, 4)


def summarize(results: list, elapsed: float) -> dict[str, Any]:
    total = len(results)
    ok = sum(1 for r in results if r.state == "ACK_RECEIVED")
    failed = total - ok
    offers = sum(1 for r in results if r.state in ("OFFER_RECEIVED", "REQUEST_SENT", "ACK_RECEIVED"))
    naks = sum(r.naks for r in results)
    rtts = sorted(r.rtt for r in results if r.state == "ACK_RECEIVED" and r.rtt > 0)
    sent = sum(r.packets_sent for r in results)
    return {
        "clients": total,
        "successful": ok,
        "failed": failed,
        "success_pct": round(100.0 * ok / total, 1) if total else 0.0,
        "offers_received": offers,
        "acks_received": ok,
        "naks_received": naks,
        "packets_sent": sent,
        "discovers_sent": sum(r.discovers_sent for r in results),
        "requests_sent": sum(r.requests_sent for r in results),
        "avg_rtt": round(sum(rtts) / len(rtts), 4) if rtts else 0.0,
        "rtt_p50": _percentile(rtts, 50),
        "rtt_p95": _percentile(rtts, 95),
        "rtt_max": round(rtts[-1], 4) if rtts else 0.0,
        "active_leases": ok,
        "elapsed": round(elapsed, 2),
    }
