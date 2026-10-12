"""DHCP starvation testing: exhaustive pool depletion analysis.

Runs N client identity machines against a DHCP server until either:
- all N clients complete the full DORA handshake, or
- the server's IP pool is exhausted and clients begin to fail/timeout

The engine captures server-side truth (pool_size, leased count, free count,
exhaustion status) and produces a structured StarvationResult for reporting.

A starvation test is authoritative ONLY when run against a server whose pool
size is explicitly known and recorded (lab server, --pool-size flag). External
servers are reported as "pool unknown" and starvation cannot be confirmed.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from flhcp.dhcp.engine import ACK_RECEIVED, Engine, SimClient


@dataclass
class StarvationResult:
    """Aggregate outcome of a pool-exhaustion test run."""

    total_clients: int
    pool_size: int
    leased_after: int
    free_after: int
    pool_exhausted: bool
    success_count: int
    fail_count: int
    failed_identity_count: int
    nak_count: int
    timeout_count: int
    release_count: int
    elapsed: float
    server_evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        return round(100.0 * self.success_count / self.total_clients, 1) if self.total_clients else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_clients": self.total_clients,
            "pool_size": self.pool_size,
            "leased_after": self.leased_after,
            "free_after": self.free_after,
            "pool_exhausted": self.pool_exhausted,
            "success_count": self.success_count,
            "fail_count": self.fail_count,
            "failed_identity_count": self.failed_identity_count,
            "nak_count": self.nak_count,
            "timeout_count": self.timeout_count,
            "release_count": self.release_count,
            "elapsed": self.elapsed,
            "success_rate": self.success_rate,
            "server_evidence": self.server_evidence,
        }


class StarvationEngine:
    """Orchestrate a full DORA handshake for N clients and detect pool exhaustion.

    The engine respects all safety constraints from the underlying Engine:
    loopback-only unless --interface + --confirm-live are explicitly provided.
    """

    def __init__(
        self,
        engine: Engine,
        pool_size: int,
        logger: logging.Logger | None = None,
    ) -> None:
        self.engine = engine
        self.pool_size = pool_size
        self.log = logger or logging.getLogger("flhcp.starvation")
        self._lock = threading.Lock()

    def run(
        self,
        clients: list[SimClient],
        *,
        seed: int | None = None,
        server_pool_status: Callable[[], dict] | None = None,
    ) -> StarvationResult:
        """Execute DORA for all clients; capture pool state before and after.

        `server_pool_status` is an optional callable returning the server's
        current pool_status() dict (used by the lab integration to record
        server-side truth).
        """
        if not clients:
            raise ValueError("starvation run needs at least one client")
        t0 = time.monotonic()
        results = self.engine.run(clients, seed=seed)
        elapsed = time.monotonic() - t0

        # Server-side truth (only available when a known pool was targeted).
        server_evidence: dict[str, Any] = {"pool_known": False}
        if server_pool_status is not None:
            try:
                server_evidence = dict(server_pool_status())
                server_evidence["pool_known"] = True
            except Exception as exc:
                self.log.warning("server pool status unavailable: %s", exc)
                server_evidence = {"pool_known": False, "error": str(exc)}

        leased = server_evidence.get("leased", sum(1 for r in results if r.state == ACK_RECEIVED))
        free = server_evidence.get("free", max(0, self.pool_size - leased))
        # Pool exhausted means: server-side pool shows zero free AND at least one
        # client failed (NAK or timeout) after exhausting every address.
        failed = sum(1 for r in results if r.state != ACK_RECEIVED)
        nak_count = sum(r.naks for r in results)
        timeout_count = sum(
            1 for r in results
            if r.state != ACK_RECEIVED and "timeout" in (r.error or "").lower()
        )
        pool_exhausted = bool(
            server_evidence.get("pool_known")
            and free == 0
            and failed > 0
        )

        return StarvationResult(
            total_clients=len(clients),
            pool_size=self.pool_size,
            leased_after=leased,
            free_after=free,
            pool_exhausted=pool_exhausted,
            success_count=sum(1 for r in results if r.state == ACK_RECEIVED),
            fail_count=failed,
            failed_identity_count=0,
            nak_count=nak_count,
            timeout_count=timeout_count,
            release_count=0,
            elapsed=round(elapsed, 2),
            server_evidence=server_evidence,
        )
