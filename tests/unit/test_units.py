"""Unit tests: generators, config, stats, reports, storage."""

import unittest

from flhcp.clients.generator import (
    make_rng,
    normalize_mac,
    random_mac,
    render_hostname,
)
from flhcp.core.config import Config
from flhcp.core.docs import dump_json, load_document
from flhcp.core.stats import summarize
from flhcp.reports.render import render_csv, render_json, render_terminal
from flhcp.storage.store import Storage
from tests.support import temp_root


class GeneratorTests(unittest.TestCase):
    def test_normalize_mac(self):
        self.assertEqual(normalize_mac("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF")
        with self.assertRaises(ValueError):
            normalize_mac("zz:zz")

    def test_random_mac_laa(self):
        rng = make_rng(5)
        for _ in range(30):
            mac = random_mac(rng)
            first = int(mac.split(":")[0], 16)
            self.assertTrue(first & 0x02 and not first & 0x01)

    def test_unique_macs_no_collisions(self):
        from flhcp.clients.generator import unique_macs

        rng = make_rng(42)
        macs, skipped = unique_macs(200, rng)
        self.assertEqual(len(set(macs)), 200)
        self.assertGreaterEqual(skipped, 0)

    def test_unique_macs_honors_taken(self):
        from flhcp.clients.generator import unique_macs

        rng = make_rng(42)
        first, _ = unique_macs(10, rng)
        taken = set(first)
        second, skipped = unique_macs(10, rng, taken=taken)
        self.assertTrue(set(second).isdisjoint(set(first)))
        self.assertGreaterEqual(skipped, 0)

    def test_unique_macs_exhaustion_bounded(self):
        """unique_macs must raise (never loop forever) when the space is full."""
        from flhcp.clients.generator import unique_macs

        # Drive the generator with an RNG that always returns the same value:
        # after `cap` attempts it must raise instead of looping forever.
        class _FixedRng:
            def randrange(self, n):
                return 0

        taken = {"02:00:00:00:00:00"}
        with self.assertRaises(ValueError):
            unique_macs(2, _FixedRng(), taken=taken)

    def test_hostname(self):
        name = render_hostname(make_rng(2))
        self.assertTrue(name.startswith("host-") and len(name) == 9)

    def test_generate_clients_unique_and_seeded(self):
        """generate_clients: N unique (mac, hostname) identities, reproducible."""
        from flhcp.clients.generator import generate_clients

        clients, meta = generate_clients(100, make_rng(7))
        self.assertEqual(len(clients), 100)
        self.assertEqual(len({c["mac"] for c in clients}), 100)
        self.assertEqual([c["index"] for c in clients], list(range(1, 101)))
        for c in clients:
            self.assertTrue(c["hostname"].startswith("host-"))
            first = int(c["mac"].split(":")[0], 16)
            self.assertTrue(first & 0x02 and not first & 0x01)  # locally-administered, unicast
        self.assertEqual(meta["source"], "generated")
        # Reproducible: same seed → identical identities
        again, _ = generate_clients(100, make_rng(7))
        self.assertEqual([c["mac"] for c in clients], [c["mac"] for c in again])
        # Different seed → different identities
        other, _ = generate_clients(100, make_rng(8))
        self.assertNotEqual([c["mac"] for c in clients], [c["mac"] for c in other])

    def test_generate_clients_rejects_nonpositive(self):
        from flhcp.clients.generator import generate_clients

        with self.assertRaises(ValueError):
            generate_clients(0, make_rng(1))


class DocsConfigTests(unittest.TestCase):
    def test_json_roundtrip(self):
        import tempfile
        from pathlib import Path

        tmp = Path(tempfile.mkdtemp())
        path = tmp / "s.json"
        path.write_text('{"a": 1}', encoding="utf-8")
        self.assertEqual(load_document(path), {"a": 1})
        import shutil

        shutil.rmtree(tmp, ignore_errors=True)

    def test_yaml_when_available(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not installed")
        import tempfile
        from pathlib import Path

        tmp = Path(tempfile.mkdtemp())
        path = tmp / "s.yaml"
        path.write_text("a: 1\n", encoding="utf-8")
        self.assertEqual(load_document(path), {"a": 1})
        import shutil

        shutil.rmtree(tmp, ignore_errors=True)

    def test_config_defaults_and_merge(self):
        cfg = Config(None)
        cfg.load()
        self.assertEqual(cfg.get("server_port"), 6767)
        import tempfile
        from pathlib import Path

        tmp = Path(tempfile.mkdtemp())
        path = tmp / "c.json"
        path.write_text('{"workers": 4}', encoding="utf-8")
        cfg2 = Config(path)
        cfg2.load()
        self.assertEqual(cfg2.get("workers"), 4)
        self.assertEqual(cfg2.get("server_port"), 6767)
        import shutil

        shutil.rmtree(tmp, ignore_errors=True)


class StatsReportTests(unittest.TestCase):
    def _result(self, state, rtt=0.1, ip="10.0.0.1"):
        from flhcp.dhcp.engine import ClientResult, SimClient

        client = SimClient(1, "02:AA:BB:CC:DD:01", "host-AB12")
        return ClientResult(client=client, state=state, assigned_ip=ip if state == "ACK_RECEIVED" else "",
                            lease=3600 if state == "ACK_RECEIVED" else 0, rtt=rtt, packets_sent=2)

    def test_summarize(self):
        results = [self._result("ACK_RECEIVED", 0.2), self._result("ACK_RECEIVED", 0.4), self._result("FAILED", 0)]
        stats = summarize(results, 1.5)
        self.assertEqual((stats["clients"], stats["successful"], stats["failed"]), (3, 2, 1))
        self.assertEqual(stats["success_pct"], 66.7)
        self.assertEqual(stats["avg_rtt"], 0.3)
        self.assertEqual(stats["packets_sent"], 6)

    def test_reports(self):
        results = [self._result("ACK_RECEIVED").to_dict()]
        session = {"interface": "lo", "server": {}}
        stats = summarize([self._result("ACK_RECEIVED")], 0.5)
        terminal = render_terminal(session, results, stats)
        self.assertIn("FLHCP SESSION", terminal)
        self.assertIn("ACK       OK", terminal)
        data = __import__("json").loads(render_json(session, results, stats))
        self.assertEqual(data["stats"]["successful"], 1)
        csv_text = render_csv(results)
        self.assertIn("02:AA:BB:CC:DD:01", csv_text)


class StorageTests(unittest.TestCase):
    def test_session_lifecycle(self):
        root = temp_root(self)
        storage = Storage(root)
        session_dir = storage.new_session_dir("2026-01-01-00-00")
        self.assertTrue((session_dir / "events.log").is_file())
        storage.write_json(session_dir / "session.json", {"a": 1})
        self.assertEqual(storage.read_json(session_dir / "session.json"), {"a": 1})
        storage.append_event(session_dir, "hello")
        self.assertIn("hello", (session_dir / "events.log").read_text(encoding="utf-8"))
        self.assertEqual(storage.list_sessions(), ["2026-01-01-00-00"])


if __name__ == "__main__":
    unittest.main()
