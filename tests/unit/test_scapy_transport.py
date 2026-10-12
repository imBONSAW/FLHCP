"""Unit tests: scapy transport is used only when available, never required."""
import unittest
from unittest import mock
from flhcp.dhcp.engine import Engine


class ScapyTransportTests(unittest.TestCase):
    def test_engine_accepts_transport_option(self):
        engine = Engine("127.0.0.1", 6767, client_port=6768, bind_address="127.0.0.1",
                        transport="auto")
        self.assertEqual(engine.transport, "auto")

    def test_transport_auto_falls_back_to_socket_without_scapy(self):
        with mock.patch.dict("sys.modules", {"scapy": None, "scapy.all": None}):
            engine = Engine("127.0.0.1", 6767, client_port=6768, bind_address="127.0.0.1",
                            transport="auto")
            self.assertEqual(engine._resolve_transport(), "socket")

    def test_transport_socket_forces_socket_mode(self):
        engine = Engine("127.0.0.1", 6767, client_port=6768, bind_address="127.0.0.1",
                        transport="socket")
        self.assertEqual(engine._resolve_transport(), "socket")


if __name__ == "__main__":
    unittest.main()
