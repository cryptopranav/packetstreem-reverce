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
from packetstream.yamux import (
    YamuxSession,
    YamuxStream,
    FLAG_SYN,
    FLAG_ACK,
    FLAG_FIN,
    STREAM_SYN_RECEIVED,
    STREAM_ESTABLISHED
)
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


class TestPacketStreamYamux(unittest.IsolatedAsyncioTestCase):
    async def test_yamux_ping_protocol(self):
        """Verifies HashiCorp Yamux ping/pong specification (SYN request, ACK response)."""
        s1, s2 = socket.socketpair()
        r1, w1 = await asyncio.open_connection(sock=s1)
        r2, w2 = await asyncio.open_connection(sock=s2)

        server = YamuxSession(r1, w1, is_server=True)
        client = YamuxSession(r2, w2, is_server=False)
        server.start()
        client.start()

        try:
            # Client pings server: verifies ping resolves with no timeout
            await client.ping(timeout=2.0)

            # Server pings client: verifies bi-directional ping support
            await server.ping(timeout=2.0)
        finally:
            await client.close()
            await server.close()

    async def test_yamux_stream_establishment_and_flags(self):
        """Verifies that incoming streams transition to established and send FLAG_ACK on first response."""
        s1, s2 = socket.socketpair()
        r1, w1 = await asyncio.open_connection(sock=s1)
        r2, w2 = await asyncio.open_connection(sock=s2)

        server = YamuxSession(r1, w1, is_server=True)
        client = YamuxSession(r2, w2, is_server=False)
        server.start()
        client.start()

        try:
            # Client opens a stream
            client_stream = await client.open()

            # Server accepts incoming stream
            server_stream = await server.accept()
            self.assertEqual(server_stream.stream_id, client_stream.stream_id)
            self.assertEqual(server_stream.state, STREAM_SYN_RECEIVED)

            # Server writes first response: triggers sendFlags() -> FLAG_ACK
            await server_stream.write(b"ACK_AND_DATA")
            self.assertEqual(server_stream.state, STREAM_ESTABLISHED)

            # Client reads response
            data = await client_stream.read(12)
            self.assertEqual(data, b"ACK_AND_DATA")
        finally:
            await client.close()
            await server.close()

    async def test_yamux_large_transfer_flow_control(self):
        """Verifies Yamux window replenishment under transfers exceeding initial 256KB stream window."""
        s1, s2 = socket.socketpair()
        r1, w1 = await asyncio.open_connection(sock=s1)
        r2, w2 = await asyncio.open_connection(sock=s2)

        server = YamuxSession(r1, w1, is_server=True)
        client = YamuxSession(r2, w2, is_server=False)
        server.start()
        client.start()

        # Transfer 600 KB (> 2x INITIAL_STREAM_WINDOW of 256 KB)
        payload = b"X" * (600 * 1024)

        async def server_worker():
            stream = await server.accept()
            # Send the large payload
            await stream.write(payload)
            await stream.close()

        server_task = asyncio.create_task(server_worker())

        try:
            client_stream = await client.open()
            received = bytearray()
            while True:
                chunk = await client_stream.read(65536)
                if not chunk:
                    break
                received.extend(chunk)

            await server_task
            self.assertEqual(len(received), len(payload))
            self.assertEqual(bytes(received), payload)
        finally:
            await client.close()
            await server.close()


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

    async def test_http_connect_proxy_pipeline(self):
        from unittest.mock import patch

        async def echo_server_handler(reader, writer):
            data = await reader.read(4)
            if data == b"PING":
                writer.write(b"PONG")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(echo_server_handler, "127.0.0.1", 0)
        server_port = server.sockets[0].getsockname()[1]

        s1, s2 = socket.socketpair()
        r1, w1 = await asyncio.open_connection(sock=s1)
        r2, w2 = await asyncio.open_connection(sock=s2)

        yamux_server = YamuxSession(r1, w1, is_server=True)
        yamux_client = YamuxSession(r2, w2, is_server=False)
        yamux_server.start()
        yamux_client.start()

        from packetstream.proxy import handle_http_request
        stats = TrafficStats()

        with patch("packetstream.proxy.resolve_and_validate_destination") as mock_resolve:
            mock_resolve.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", server_port))
            ]

            async def server_worker():
                st = await yamux_server.accept()
                await handle_http_request(st, stats=stats)

            srv_task = asyncio.create_task(server_worker())

            client_st = await yamux_client.open()
            await client_st.write(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")

            resp_line = await client_st.readline()
            self.assertIn(b"200 Connection Established", resp_line)
            # Read blank line
            blank = await client_st.readline()
            self.assertEqual(blank, b"\r\n")

            # Send payload through the tunnel
            await client_st.write(b"PING")
            echo = await client_st.read(4)
            self.assertEqual(echo, b"PONG")

            await client_st.close()
            await srv_task

        self.assertGreater(stats.bytes_uploaded, 0)
        self.assertGreater(stats.bytes_downloaded, 0)

        await yamux_client.close()
        await yamux_server.close()
        server.close()
        await server.wait_closed()


if __name__ == "__main__":
    unittest.main()
