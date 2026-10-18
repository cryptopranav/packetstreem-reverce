"""
Proxy request handlers for PacketStream exit node.
Replicates:
- core/http.handleReqWithDialerContext (HTTP CONNECT & HTTP proxy)
- core/socks.HandleReqContext (SOCKS5 CONNECT)
- lib/tunnel.Pipe (bi-directional zero-leak stream piping)
"""

import asyncio
import logging
import socket
import struct
import urllib.parse
from typing import Callable, Optional, Tuple

from .security import resolve_and_validate_destination, SecurityError
from .yamux import YamuxStream

logger = logging.getLogger("packetstream.proxy")

# SOCKS5 constants
SOCKS_VERSION = 0x05
SOCKS_CMD_CONNECT = 0x01
SOCKS_ATYP_IPV4 = 0x01
SOCKS_ATYP_DOMAIN = 0x03
SOCKS_ATYP_IPV6 = 0x04

SOCKS_REP_SUCCESS = 0x00
SOCKS_REP_GENERAL_FAILURE = 0x01

# Pre-formatted SOCKS replies (10 bytes: VER, REP, RSV, ATYP=1, BND.ADDR=0.0.0.0, BND.PORT=0)
SOCKS5_REPLY_SUCCESS = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
SOCKS5_REPLY_FAILURE = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"

HTTP_200_RESPONSE = b"HTTP/1.1 200 Connection Established\r\n\r\n"
HTTP_502_RESPONSE = b"HTTP/1.1 502 Bad Gateway\r\n\r\n"


class TrafficStats:
    """Thread-safe and async-safe traffic metrics collector."""
    def __init__(self):
        self.bytes_uploaded: int = 0
        self.bytes_downloaded: int = 0
        self.active_tunnels: int = 0
        self.total_tunnels_served: int = 0
        self._lock = asyncio.Lock()

    def record_upload(self, n: int) -> None:
        self.bytes_uploaded += n

    def record_download(self, n: int) -> None:
        self.bytes_downloaded += n

    def tunnel_opened(self) -> None:
        self.active_tunnels += 1
        self.total_tunnels_served += 1

    def tunnel_closed(self) -> None:
        if self.active_tunnels > 0:
            self.active_tunnels -= 1


async def pipe_bidirectional(
    stream: YamuxStream,
    target_reader: asyncio.StreamReader,
    target_writer: asyncio.StreamWriter,
    stats: Optional[TrafficStats] = None,
    buffer_size: int = 32768
) -> None:
    """
    Pipes bytes bi-directionally between the Yamux stream and the target destination TCP socket.
    Replicates github.com/packetstream/ecosystem/lib/tunnel.Pipe.
    """
    async def stream_to_target():
        try:
            while True:
                data = await stream.read(buffer_size)
                if not data:
                    break
                target_writer.write(data)
                await target_writer.drain()
                if stats:
                    stats.record_upload(len(data))
        except Exception as e:
            logger.debug(f"Stream -> Target pipe closed: {e}")
        finally:
            try:
                target_writer.close()
            except Exception:
                pass

    async def target_to_stream():
        try:
            while True:
                data = await target_reader.read(buffer_size)
                if not data:
                    break
                await stream.write(data)
                if stats:
                    stats.record_download(len(data))
        except Exception as e:
            logger.debug(f"Target -> Stream pipe closed: {e}")
        finally:
            try:
                await stream.close()
            except Exception:
                pass

    await asyncio.gather(stream_to_target(), target_to_stream(), return_exceptions=True)


async def handle_http_request(
    stream: YamuxStream,
    stats: Optional[TrafficStats] = None,
    connect_timeout: float = 15.0
) -> None:
    """
    Handles an incoming HTTP proxy request from Yamux stream.
    Replicates github.com/packetstream/ecosystem/exit-node/core/http.handleReqWithDialerContext.
    """
    if stats:
        stats.tunnel_opened()
    target_writer: Optional[asyncio.StreamWriter] = None

    try:
        req_line_bytes = await stream.readline()
        if not req_line_bytes:
            return

        req_line = req_line_bytes.decode("utf-8", errors="replace").strip()
        parts = req_line.split()
        if len(parts) < 2:
            await stream.write(HTTP_502_RESPONSE)
            await stream.close()
            return

        method = parts[0].upper()
        target_spec = parts[1]

        if method == "CONNECT":
            # CONNECT host:port HTTP/1.x
            if ":" in target_spec:
                host, port_str = target_spec.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    port = 443
            else:
                host = target_spec
                port = 443

            # Drain remaining HTTP headers until \r\n\r\n
            while True:
                header_line = await stream.readline()
                if not header_line or header_line in (b"\r\n", b"\n", b""):
                    break

            # Validate destination security (BlockLocalAccess)
            try:
                addrs = await resolve_and_validate_destination(host, port)
            except SecurityError as e:
                logger.warning(f"Blocked HTTP CONNECT to {host}:{port}: {e}")
                await stream.write(HTTP_502_RESPONSE)
                await stream.close()
                return

            # Dial destination
            target_ip, target_port = addrs[0][4][0], addrs[0][4][1]
            try:
                target_reader, target_writer = await asyncio.wait_for(
                    asyncio.open_connection(target_ip, target_port),
                    timeout=connect_timeout
                )
            except Exception as e:
                logger.debug(f"Failed to connect to destination {host}:{port} ({target_ip}:{target_port}): {e}")
                await stream.write(HTTP_502_RESPONSE)
                await stream.close()
                return

            # Connection established: send 200 Connection Established
            await stream.write(HTTP_200_RESPONSE)

            # Start bi-directional pipe
            await pipe_bidirectional(stream, target_reader, target_writer, stats=stats)

        else:
            # Plain HTTP proxy request (e.g., GET http://example.com/foo HTTP/1.1)
            parsed = urllib.parse.urlsplit(target_spec)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            if not host:
                await stream.write(HTTP_502_RESPONSE)
                await stream.close()
                return

            try:
                addrs = await resolve_and_validate_destination(host, port)
            except SecurityError as e:
                logger.warning(f"Blocked plain HTTP request to {host}:{port}: {e}")
                await stream.write(HTTP_502_RESPONSE)
                await stream.close()
                return

            target_ip, target_port = addrs[0][4][0], addrs[0][4][1]
            try:
                target_reader, target_writer = await asyncio.wait_for(
                    asyncio.open_connection(target_ip, target_port),
                    timeout=connect_timeout
                )
            except Exception as e:
                logger.debug(f"Failed to connect to {host}:{port}: {e}")
                await stream.write(HTTP_502_RESPONSE)
                await stream.close()
                return

            # Rewrite request line to relative path
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            rewritten_line = f"{method} {path} {parts[2] if len(parts) > 2 else 'HTTP/1.1'}\r\n".encode("utf-8")
            target_writer.write(rewritten_line)
            await target_writer.drain()

            await pipe_bidirectional(stream, target_reader, target_writer, stats=stats)

    except Exception as e:
        logger.debug(f"Error handling HTTP request on stream {stream.stream_id}: {e}")
    finally:
        if target_writer:
            try:
                target_writer.close()
            except Exception:
                pass
        try:
            await stream.close()
        except Exception:
            pass
        if stats:
            stats.tunnel_closed()


async def handle_socks_request(
    stream: YamuxStream,
    stats: Optional[TrafficStats] = None,
    connect_timeout: float = 15.0
) -> None:
    """
    Handles an incoming SOCKS5 CONNECT request from Yamux stream.
    Replicates github.com/packetstream/ecosystem/exit-node/core/socks.HandleReqContext.
    """
    if stats:
        stats.tunnel_opened()
    target_writer: Optional[asyncio.StreamWriter] = None

    try:
        # Read 4 bytes: VER, CMD, RSV, ATYP
        header = await stream.readexactly(4)
        ver, cmd, rsv, atyp = header[0], header[1], header[2], header[3]

        if ver != SOCKS_VERSION or cmd != SOCKS_CMD_CONNECT or rsv != 0:
            logger.debug(f"Invalid SOCKS header: ver={ver}, cmd={cmd}, rsv={rsv}")
            await stream.write(SOCKS5_REPLY_FAILURE)
            await stream.close()
            return

        # Read destination address based on ATYP
        dest_host = ""
        if atyp == SOCKS_ATYP_IPV4:
            ip_bytes = await stream.readexactly(4)
            dest_host = socket.inet_ntoa(ip_bytes)
        elif atyp == SOCKS_ATYP_DOMAIN:
            domain_len = (await stream.readexactly(1))[0]
            domain_bytes = await stream.readexactly(domain_len)
            dest_host = domain_bytes.decode("utf-8", errors="replace")
        elif atyp == SOCKS_ATYP_IPV6:
            ip6_bytes = await stream.readexactly(16)
            dest_host = socket.inet_ntop(socket.AF_INET6, ip6_bytes)
        else:
            logger.debug(f"Unsupported SOCKS ATYP: {atyp}")
            await stream.write(SOCKS5_REPLY_FAILURE)
            await stream.close()
            return

        # Read 2-byte big-endian port
        port_bytes = await stream.readexactly(2)
        dest_port = struct.unpack(">H", port_bytes)[0]

        # Security check: BlockLocalAccess
        try:
            addrs = await resolve_and_validate_destination(dest_host, dest_port)
        except SecurityError as e:
            logger.warning(f"Blocked SOCKS5 connection to {dest_host}:{dest_port}: {e}")
            await stream.write(SOCKS5_REPLY_FAILURE)
            await stream.close()
            return

        # Dial target host:port
        target_ip, target_port = addrs[0][4][0], addrs[0][4][1]
        try:
            target_reader, target_writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, target_port),
                timeout=connect_timeout
            )
        except Exception as e:
            logger.debug(f"SOCKS failed to connect to {dest_host}:{dest_port} ({target_ip}:{target_port}): {e}")
            await stream.write(SOCKS5_REPLY_FAILURE)
            await stream.close()
            return

        # Send SOCKS5 success reply
        await stream.write(SOCKS5_REPLY_SUCCESS)

        # Pipe bi-directionally
        await pipe_bidirectional(stream, target_reader, target_writer, stats=stats)

    except Exception as e:
        logger.debug(f"Error handling SOCKS5 request on stream {stream.stream_id}: {e}")
    finally:
        if target_writer:
            try:
                target_writer.close()
            except Exception:
                pass
        try:
            await stream.close()
        except Exception:
            pass
        if stats:
            stats.tunnel_closed()
