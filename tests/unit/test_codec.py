"""Unit tests: DHCP codec round-trips."""

import unittest

from flhcp.dhcp import codec


class CodecTests(unittest.TestCase):
    def test_magic_cookie_is_rfc2131(self):
        """RFC 2131 magic cookie must be 0x63 0x82 0x53 0x63 (99.130.83.99)."""
        self.assertEqual(codec.MAGIC_COOKIE, bytes([0x63, 0x82, 0x53, 0x63]))

    def test_discover_roundtrip(self):
        mac = bytes.fromhex("AABBCCDDEEFF")
        pkt = codec.build_discover(0x12345678, mac, hostname="Galaxy-X1")
        msg = codec.decode(pkt)
        self.assertIsNotNone(msg)
        self.assertEqual(msg["xid"], 0x12345678)
        self.assertEqual(msg["msgtype"], codec.DISCOVER)
        self.assertEqual(msg["chaddr"][:6], mac)
        self.assertEqual(msg["hostname"], "Galaxy-X1")
        self.assertTrue(msg["flags"] & codec.BROADCAST_FLAG)

    def test_request_roundtrip(self):
        mac = bytes.fromhex("020011223344")
        pkt = codec.build_request(99, mac, requested_ip="10.0.0.5", server_id="10.0.0.1")
        msg = codec.decode(pkt)
        self.assertEqual(msg["msgtype"], codec.REQUEST)
        self.assertEqual(msg["requested_ip"], "10.0.0.5")
        self.assertEqual(msg["server_id"], "10.0.0.1")

    def test_reply_roundtrip(self):
        mac = bytes.fromhex("020011223344")
        pkt = codec.build_reply(77, mac, "10.200.0.10", codec.ACK, lease_time=7200)
        msg = codec.decode(pkt)
        self.assertEqual(msg["op"], 2)
        self.assertEqual(msg["msgtype"], codec.ACK)
        self.assertEqual(msg["yiaddr"], "10.200.0.10")
        self.assertEqual(msg["lease"], 7200)

    def test_malformed(self):
        self.assertIsNone(codec.decode(b""))
        self.assertIsNone(codec.decode(b"junk" * 100))
        pkt = bytearray(codec.build_discover(1, b"\x02" * 6))
        pkt[236:240] = b"\x00\x00\x00\x00"
        self.assertIsNone(codec.decode(bytes(pkt)))

    def test_options_edge(self):
        self.assertEqual(codec.decode_options(b"\x00\xff"), {})
        self.assertEqual(codec.decode_options(b"\x35"), {})

    def test_discover_lease_time_request(self):
        """DISCOVER must carry option 51 (requested lease) when asked."""
        mac = bytes.fromhex("020011223344")
        pkt = codec.build_discover(0xABCD, mac, lease_time=691200)
        msg = codec.decode(pkt)
        self.assertEqual(msg["lease"], 691200)

    def test_request_lease_time_request(self):
        """REQUEST must carry option 51 (requested lease) when asked."""
        mac = bytes.fromhex("020011223344")
        pkt = codec.build_request(0xEF01, mac, requested_ip="10.0.0.5",
                                  server_id="10.0.0.1", lease_time=691200)
        msg = codec.decode(pkt)
        self.assertEqual(msg["lease"], 691200)

    def test_discover_without_lease_time_has_no_opt51(self):
        """Default (lease_time=0) must NOT add option 51 (backwards compat)."""
        mac = bytes.fromhex("020011223344")
        pkt = codec.build_discover(1, mac)
        msg = codec.decode(pkt)
        self.assertEqual(msg["lease"], 0)

    def test_request_without_lease_time_has_no_opt51(self):
        mac = bytes.fromhex("020011223344")
        pkt = codec.build_request(1, mac, requested_ip="10.0.0.5", server_id="10.0.0.1")
        msg = codec.decode(pkt)
        self.assertEqual(msg["lease"], 0)


if __name__ == "__main__":
    unittest.main()
