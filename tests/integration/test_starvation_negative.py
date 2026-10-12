"""Negative / timeout / hygiene tests for starvation mode."""

import unittest

from flhcp.dhcp.engine import Engine, SimClient
from flhcp.mock.server import MockDhcpServer
from flhcp.starvation.engine import StarvationEngine
from tests.support import temp_root


class StarvationNegativeTests(unittest.TestCase):
    def test_no_server_all_clients_timeout(self):
        """Dead server: every client times out, no fabricated success."""
        engine = Engine("127.0.0.1", 16999, client_port=16998, bind_address="127.0.0.1",
                        offer_timeout=0.5, ack_timeout=0.5, attempts=1, workers=4)
        clients = [SimClient(1, "02:00:00:00:00:01", "dead")]
        se = StarvationEngine(engine, pool_size=0)
        result = se.run(clients, seed=1)
        self.assertEqual(result.success_count, 0)
        self.assertEqual(result.fail_count, 1)
        self.assertGreater(result.timeout_count, 0)
        self.assertFalse(result.pool_exhausted)
        self.assertFalse(result.server_evidence.get("pool_known"))

    def test_starvation_engine_requires_clients(self):
        engine = Engine("127.0.0.1", 1, client_port=2)
        se = StarvationEngine(engine, pool_size=1)
        with self.assertRaises(ValueError):
            se.run([], seed=1)

    def test_repeated_run_after_release_reuses_pool(self):
        """After releasing, a new run of the same size fully succeeds again."""
        server = MockDhcpServer(bind_address="127.0.0.1", port=16990, pool_size=4)
        server.start()
        self.addCleanup(server.stop)
        clients = [SimClient(i + 1, f"02:00:00:00:00:{i:02X}", f"c{i}")
                   for i in range(4)]
        engine = Engine("127.0.0.1", 16990, client_port=16991, bind_address="127.0.0.1",
                        offer_timeout=1.0, ack_timeout=1.0, attempts=1, workers=4)
        first = engine.run(clients, seed=1)
        self.assertTrue(all(r.state == "ACK_RECEIVED" for r in first))
        self.assertEqual(server.pool_status()["free"], 0)
        engine.release_all(first)
        self.assertEqual(server.pool_status()["free"], 4)
        # Same MACs again: pool was freed, so all succeed a second time
        second = engine.run(clients, seed=2)
        self.assertTrue(all(r.state == "ACK_RECEIVED" for r in second))


if __name__ == "__main__":
    unittest.main()
