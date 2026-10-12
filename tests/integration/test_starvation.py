"""Integration: starvation (pool exhaustion) test against the lab server."""

import unittest

from flhcp.dhcp.engine import Engine, SimClient
from flhcp.mock.server import MockDhcpServer
from flhcp.starvation.engine import StarvationEngine
from tests.support import temp_root


class StarvationTests(unittest.TestCase):
    """Real DORA exchange against the mock lab server until pool exhaustion."""

    def _run_starvation(self, pool_size: int, client_count: int, port: int):
        server = MockDhcpServer(bind_address="127.0.0.1", port=port, pool_size=pool_size)
        server.start()
        self.addCleanup(server.stop)
        engine = Engine("127.0.0.1", port, client_port=port + 1, bind_address="127.0.0.1",
                        offer_timeout=1.0, ack_timeout=1.0, attempts=1, workers=8)
        clients = [
            SimClient(i + 1, f"02:00:00:00:{i:02X}:{(i * 7) % 256:02X}", f"starv-{i:03d}")
            for i in range(client_count)
        ]
        se = StarvationEngine(engine, pool_size=pool_size)
        result = se.run(clients, seed=42, server_pool_status=server.pool_status)
        return server, result

    def test_pool_exhaustion_with_evidence(self):
        """More clients than pool: pool must be exhausted with server evidence."""
        server, result = self._run_starvation(pool_size=5, client_count=12, port=16790)
        self.assertEqual(result.success_count, 5)
        self.assertEqual(result.fail_count, 7)
        self.assertTrue(result.pool_exhausted)
        self.assertEqual(result.free_after, 0)
        self.assertEqual(result.leased_after, 5)
        self.assertTrue(result.server_evidence.get("pool_known"))
        self.assertEqual(result.server_evidence.get("leased"), 5)
        # Timeouts dominate: exhausted pool = no OFFER = timeout
        self.assertGreater(result.timeout_count, 0)
        self.assertGreaterEqual(result.success_rate, 41.7)

    def test_no_exhaustion_when_pool_is_sufficient(self):
        """Fewer clients than pool: all succeed, pool NOT exhausted."""
        server, result = self._run_starvation(pool_size=50, client_count=10, port=16792)
        self.assertEqual(result.success_count, 10)
        self.assertEqual(result.fail_count, 0)
        self.assertFalse(result.pool_exhausted)
        self.assertEqual(result.free_after, 40)
        self.assertEqual(result.leased_after, 10)

    def test_lease_release_frees_pool_slots(self):
        """RELEASE must return slots to the free list (post-exhaustion reuse)."""
        server = MockDhcpServer(bind_address="127.0.0.1", port=16794, pool_size=3)
        server.start()
        self.addCleanup(server.stop)
        engine = Engine("127.0.0.1", 16794, client_port=16795, bind_address="127.0.0.1",
                        offer_timeout=1.0, ack_timeout=1.0, attempts=1, workers=3)
        clients = [SimClient(i + 1, f"02:00:00:00:00:{i:02X}", f"r{i}")
                   for i in range(3)]
        results = engine.run(clients, seed=1)
        self.assertTrue(all(r.state == "ACK_RECEIVED" for r in results))
        status = server.pool_status()
        self.assertEqual(status["free"], 0)
        released = engine.release_all(results)
        self.assertEqual(released, 3)
        status = server.pool_status()
        self.assertEqual(status["free"], 3)
        self.assertEqual(status["leased"], 0)

    def test_per_client_unique_source_ports(self):
        """Concurrent clients must each use a unique source port (no shared-socket
        races against real routers that get confused by one source port)."""
        server = MockDhcpServer(bind_address="127.0.0.1", port=16796, pool_size=10)
        server.start()
        self.addCleanup(server.stop)
        engine = Engine("127.0.0.1", 16796, client_port=16797, bind_address="127.0.0.1",
                        offer_timeout=1.0, ack_timeout=1.0, attempts=1, workers=10)
        clients = [SimClient(i + 1, f"02:00:00:00:01:{i:02X}", f"p{i}") for i in range(8)]
        results = engine.run(clients, seed=3)
        self.assertTrue(all(r.state == "ACK_RECEIVED" for r in results))
        # Every client completed on its own socket with a distinct source port.
        ports = [r.source_port for r in results]
        self.assertEqual(len(set(ports)), 8)

    def test_cli_starvation_end_to_end(self):
        """CLI: --starvation flag triggers StarvationEngine and records evidence."""
        import io
        import os
        import sys

        from flhcp.cli.app import main

        root = temp_root(self)
        argv = ["start", "--starvation", "--clients", "15", "--pool-size", "5",
                "--seed", "7", "--server-port", "16796", "--client-port", "16797",
                "--workers", "10", "--output", "json", "--attempts", "1", "--timeout", "1"]
        old_out, old_err = sys.stdout, sys.stderr
        out, err = io.StringIO(), io.StringIO()
        sys.stdout, sys.stderr = out, err
        old_home = os.environ.get("FLHCP_HOME")
        try:
            os.environ["FLHCP_HOME"] = str(root)
            code = main(argv)
        finally:
            sys.stdout, sys.stderr = old_out, old_err
            if old_home is None:
                os.environ.pop("FLHCP_HOME", None)
            else:
                os.environ["FLHCP_HOME"] = old_home
        import json

        payload = json.loads(out.getvalue())
        stats = payload["stats"]
        self.assertIn("starvation", stats)
        starv = stats["starvation"]
        self.assertEqual(starv["total_clients"], 15)
        self.assertEqual(starv["pool_size"], 5)
        self.assertEqual(starv["success_count"], 5)
        self.assertEqual(starv["fail_count"], 10)
        self.assertTrue(starv["pool_exhausted"])
        self.assertTrue(starv["server_evidence"]["pool_known"])

    def test_mock_server_honors_requested_lease(self):
        """Lab server must ACK with the client's requested lease (8-day test)."""
        server = MockDhcpServer(bind_address="127.0.0.1", port=16799, pool_size=4)
        server.start()
        self.addCleanup(server.stop)
        engine = Engine("127.0.0.1", 16799, client_port=16798, bind_address="127.0.0.1",
                        offer_timeout=1.0, ack_timeout=1.0, attempts=1, workers=2,
                        lease_request=691200)  # 8 days
        clients = [SimClient(1, "02:00:00:00:00:01", "lease8d")]
        results = engine.run(clients, seed=1)
        self.assertEqual(results[0].state, "ACK_RECEIVED")
        self.assertEqual(results[0].lease, 691200)


if __name__ == "__main__":
    unittest.main()
