"""
Comprehensive automated tests for PacketStream Python client using standard unittest.
Zero external dependencies required.
"""

import asyncio
import base64
import socket
import struct
import unittest

from packetstream.auth import parse_auth_code, decode_jwt_unverified, AuthError
from packetstream.security import (
    validate_hostname,
    resolve_and_validate_destination,
    SecurityError
)
from packetstream.yamux import YamuxSession, YamuxStream
from packetstream.proxy import (
    TrafficStats,
    pipe_bidirectional,
    SOCKS5_REPLY_SUCCESS,
)


class TestPacketStreamAuth(unittest.TestCase):
    def test_auth_code_parsing(self):
        # Standard base64 with username:user_id (e.g. pranavkd:782600)
        uid, tok = parse_auth_code("cHJhbmF2a2Q6NzgyNjAw")
        self.assertEqual(uid, 782600)
        self.assertEqual(tok, "pranavkd")

        # Direct username:user_id raw credentials
        uid, tok = parse_auth_code("pranavkd:782600")
        self.assertEqual(uid, 782600)
        self.assertEqual(tok, "pranavkd")

        # Direct raw credentials user_id:token
        uid, tok = parse_auth_code("98765:my_token_value")
        self.assertEqual(uid, 98765)
        self.assertEqual(tok, "my_token_value")

        # URL-safe base64 without padding
        raw = "12345:token_secret_123"
        b64_url = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
        uid, tok = parse_auth_code(b64_url)
        self.assertEqual(uid, 12345)
        self.assertEqual(tok, "token_secret_123")

        # Invalid: non-numeric user_id
        bad_b64 = base64.b64encode(b"notanumber:token").decode()
        with self.assertRaises(AuthError):
            parse_auth_code(bad_b64)

        # Invalid: negative user_id
        bad_b64 = base64.b64encode(b"-5:token").decode()
        with self.assertRaises(AuthError):
            parse_auth_code(bad_b64)

        # Invalid: missing delimiter
        bad_b64 = base64.b64encode(b"12345").decode()
        with self.assertRaises(AuthError):
            parse_auth_code(bad_b64)

        # Invalid: token too short
        bad_b64 = base64.b64encode(b"12345:ab").decode()
        with self.assertRaises(AuthError):
            parse_auth_code(bad_b64)

    def test_jwt_claims_decoding(self):
        header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        payload = base64.urlsafe_b64encode(b'{"sub":12345,"ip":"1.2.3.4","exp":1800000000}').decode().rstrip("=")
        dummy_jwt = f"{header}.{payload}.dummysignature"

        claims = decode_jwt_unverified(dummy_jwt)
        self.assertEqual(claims.get("sub"), 12345)
        self.assertEqual(claims.get("ip"), "1.2.3.4")
        self.assertEqual(claims.get("exp"), 1800000000)


class TestPacketStreamSecurity(unittest.IsolatedAsyncioTestCase):
    async def test_security_blocking(self):
        # Blocked hostnames
        for bad in ["localhost", "local", "broadcasthost", "test.local", "nas.lan", "site.internal", "hidden.onion"]:
            with self.assertRaises(SecurityError):
                validate_hostname(bad)

        # Blocked IPs
        for bad_ip in [
            "127.0.0.1", "127.0.0.50", "::1",
            "10.0.0.1", "10.254.1.1",
            "192.168.1.1", "192.168.100.254",
            "172.16.0.1", "172.31.255.254",
            "169.254.1.1",
            "100.64.1.1",
            "0.0.0.0",
            "fc00::1",
            "fe80::1",
        ]:
            with self.assertRaises(SecurityError):
                await resolve_and_validate_destination(bad_ip, 80)

        # Safe IP
        addrs = await resolve_and_validate_destination("1.1.1.1", 443)
        self.assertGreater(len(addrs), 0)
        self.assertEqual(addrs[0][4], ("1.1.1.1", 443))


class TestPacketStreamYamuxAndProxy(unittest.IsolatedAsyncioTestCase):
    async def test_yamux_and_proxy_pipeline(self):
        # Start a dummy destination HTTP server
        async def echo_server_handler(reader, writer):
            req = await reader.readline()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(echo_server_handler, "127.0.0.1", 0)
        server_port = server.sockets[0].getsockname()[1]

        # Create connected Yamux sessions via socketpair
        s1, s2 = socket.socketpair()
        r1, w1 = await asyncio.open_connection(sock=s1)
        r2, w2 = await asyncio.open_connection(sock=s2)

        yamux_server = YamuxSession(r1, w1, is_server=True)
        yamux_client = YamuxSession(r2, w2, is_server=False)
        yamux_server.start()
        yamux_client.start()

        stats = TrafficStats()

        # 1. Test SOCKS5 proxy handler over Yamux
        async def serve_one_socks():
            st = await yamux_server.accept()
            target_reader, target_writer = await asyncio.open_connection("127.0.0.1", server_port)
            # Read SOCKS header
            hdr = await st.readexactly(4)
            ip = await st.readexactly(4)
            port = await st.readexactly(2)
            await st.write(SOCKS5_REPLY_SUCCESS)
            await pipe_bidirectional(st, target_reader, target_writer, stats=stats)

        server_task = asyncio.create_task(serve_one_socks())

        # Client opens stream and sends SOCKS5 request
        client_stream = await yamux_client.open()
        port_bytes = struct.pack(">H", server_port)
        await client_stream.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + port_bytes)
        resp = await client_stream.readexactly(10)
        self.assertEqual(resp, SOCKS5_REPLY_SUCCESS)

        # Send HTTP GET over the SOCKS tunnel
        await client_stream.write(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        data = await client_stream.read(1024)
        self.assertIn(b"HELLO", data)
        await client_stream.close()

        await server_task

        self.assertGreater(stats.bytes_downloaded, 0)
        self.assertGreater(stats.bytes_uploaded, 0)

        await yamux_client.close()
        await yamux_server.close()
        server.close()
        await server.wait_closed()


if __name__ == "__main__":
    unittest.main()
