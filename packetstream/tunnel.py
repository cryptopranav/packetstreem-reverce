"""
TLS Handshake and Packetermux Tunnel Connection Module.
Replicates:
- core/packetermux.Handshake (TLS with ALPN packetstream-packeter-mux/1)
- core/packetermux.authenticate (Send token + \\n, read 0x00 ack)
- core/packetermux.sendRefresh (Open stream, write refreshed token + \\n, read 0x00 ack)
"""

import asyncio
import logging
import ssl
from typing import Optional

from .yamux import YamuxSession, YamuxStream

logger = logging.getLogger("packetstream.tunnel")

ALPN_PROTOCOL = "packetstream-packeter-mux/1"


class TunnelError(Exception):
    """Raised when tunnel handshake, TLS or authentication fails."""
    pass


async def connect_tunnel(
    host: str,
    port: int,
    session_token: str,
    connect_timeout: float = 15.0,
    keepalive_interval: float = 30.0
) -> YamuxSession:
    """
    Connects to a PacketStream gateway endpoint, performs TLS handshake with ALPN,
    authenticates with the admission session token, and establishes a Yamux Server session.

    Replicates Handshake + authenticate in Go mobilecore.
    """
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.set_alpn_protocols([ALPN_PROTOCOL])

    logger.debug(f"Connecting TLS to {host}:{port} with ALPN {ALPN_PROTOCOL}...")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=host,
                port=port,
                ssl=ssl_ctx,
                server_hostname=host
            ),
            timeout=connect_timeout
        )
    except Exception as e:
        raise TunnelError(f"TLS connection to {host}:{port} failed: {e}")

    # Check negotiated ALPN protocol
    ssl_obj = writer.get_extra_info("ssl_object")
    if ssl_obj:
        selected = ssl_obj.selected_alpn_protocol()
        if selected != ALPN_PROTOCOL:
            logger.warning(f"Unexpected ALPN protocol negotiated: '{selected}' (expected '{ALPN_PROTOCOL}')")

    # Perform Packetermux Authentication Frame Handshake:
    # 1. Client writes: token + "\n"
    # 2. Client reads: 1 byte ack (must be 0x00)
    logger.debug(f"Authenticating session token on {host}:{port}...")
    try:
        auth_payload = session_token.encode("utf-8") + b"\n"
        writer.write(auth_payload)
        await writer.drain()

        ack_byte = await asyncio.wait_for(reader.readexactly(1), timeout=connect_timeout)
        if ack_byte != b"\x00":
            writer.close()
            raise TunnelError(
                f"Unexpected Packeter mux authentication byte: 0x{ack_byte.hex()} (expected 0x00)"
            )
    except asyncio.TimeoutError:
        writer.close()
        raise TunnelError(f"Timed out waiting for authentication acknowledgement on {host}:{port}")
    except Exception as e:
        writer.close()
        raise TunnelError(f"Authentication on {host}:{port} failed: {e}")

    logger.info(f"Successfully authenticated tunnel to {host}:{port}! Initializing Yamux...")

    # Wrap TLS connection in Yamux Server session (exit node is the Yamux Server)
    session = YamuxSession(
        reader=reader,
        writer=writer,
        is_server=True,
        keepalive_interval=keepalive_interval
    )
    session.start()
    return session


async def send_token_refresh(
    session: YamuxSession,
    refreshed_token: str,
    timeout: float = 10.0
) -> None:
    """
    Sends refreshed admission token over an existing Yamux session.
    Replicates core/packetermux.sendRefresh:
    1. Opens a new Yamux stream on the session.
    2. Writes refreshed_token + "\n".
    3. Reads 1 byte acknowledgement (must be 0x00).
    4. Closes the stream.
    """
    logger.debug("Opening Yamux stream to publish token refresh...")
    stream: Optional[YamuxStream] = None
    try:
        stream = await asyncio.wait_for(session.open(), timeout=timeout)
        payload = refreshed_token.encode("utf-8") + b"\n"
        await stream.write(payload)

        ack = await asyncio.wait_for(stream.readexactly(1), timeout=timeout)
        if ack != b"\x00":
            raise TunnelError(f"Unexpected token refresh acknowledgement byte: 0x{ack.hex()}")

        logger.info("Token refresh successfully acknowledged by remote gateway!")
    except Exception as e:
        raise TunnelError(f"Failed to publish replacement token: {e}")
    finally:
        if stream:
            try:
                await stream.close()
            except Exception:
                pass
