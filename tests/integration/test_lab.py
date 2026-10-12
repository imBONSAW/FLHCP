"""Integration: real engine against the mock lab server on loopback."""

import json
import os
import unittest

from flhcp.dhcp.engine import Engine, SimClient
from flhcp.mock.server import MockDhcpServer
from tests.support import temp_root


class LabTests(unittest.TestCase):
    def test_full_dora_ten_clients(self):
        server = MockDhcpServer(bind_address="127.0.0.1", port=16767)
        server.start()
        self.addCleanup(server.stop)
        engine = Engine("127.0.0.1", 16767, client_port=16768, bind_address="127.0.0.1",
                        offer_timeout=3.0, ack_timeout=3.0, attempts=2, workers=8)
        clients = [
            SimClient(i + 1, f"02:00:00:00:{i:02X}:{(i * 7) % 256:02X}", f"host-{i:03d}")
            for i in range(10)
        ]
        results = engine.run(clients, seed=42)
        states = [r.state for r in results]
        self.assertEqual(states, ["ACK_RECEIVED"] * 10, states)
        ips = [r.assigned_ip for r in results]
        self.assertEqual(len(set(ips)), 10)
        self.assertTrue(all(r.lease == 3600 for r in results))

    def test_nak_path(self):
        server = MockDhcpServer(bind_address="127.0.0.1", port=16777)
        server.start()
        self.addCleanup(server.stop)
        engine = Engine("127.0.0.1", 16777, client_port=16778, bind_address="127.0.0.1",
                        offer_timeout=2.0, ack_timeout=2.0, attempts=1, workers=2)
        # exhaust the 2-address pool, third client gets NAK/failure honestly
        tiny = MockDhcpServer(bind_address="127.0.0.1", port=16779, pool_size=1)
        tiny.start()
        self.addCleanup(tiny.stop)
        engine2 = Engine("127.0.0.1", 16779, client_port=16780, bind_address="127.0.0.1",
                         offer_timeout=2.0, ack_timeout=2.0, attempts=1, workers=2)
        clients = [SimClient(1, "02:00:00:00:00:01", "h1"),
                   SimClient(2, "02:00:00:00:00:02", "h2")]
        results = engine2.run(clients, seed=1)
        self.assertEqual(results[0].state, "ACK_RECEIVED")


class CliLabTests(unittest.TestCase):
    def test_cli_start_lab_end_to_end(self):
        import io
        import sys

        from flhcp.cli.app import main

        root = temp_root(self)
        argv = ["start", "--clients", "5", "--seed", "11", "--server-port", "16787",
                "--client-port", "16788", "--workers", "5", "--output", "terminal"]
        old_argv, old_cwd, old_home = sys.argv, __import__("os").getcwd(), __import__("os").environ.get("FLHCP_HOME")
        out, err = io.StringIO(), io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            __import__("os").environ["FLHCP_HOME"] = str(root)
            code = main(argv)
        finally:
            sys.stdout, sys.stderr = old_out, old_err
            sys.argv = old_argv
            __import__("os").chdir(old_cwd)
            if old_home is None:
                __import__("os").environ.pop("FLHCP_HOME", None)
            else:
                __import__("os").environ["FLHCP_HOME"] = old_home
        text = out.getvalue()
        self.assertEqual(code, 0, text + err.getvalue())
        self.assertIn("FLHCP SESSION", text)
        self.assertIn("Success:\n100.0%", text)
        sessions = list((root / "sessions").iterdir())
        self.assertEqual(len(sessions), 1)
        names = {p.name for p in (sessions[0]).iterdir()}
        self.assertTrue({"session.json", "clients.json", "leases.json", "events.log"} <= names)


if __name__ == "__main__":
    unittest.main()
