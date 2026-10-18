"""
PacketStream Core Client Engine.
Orchestrates admission token fetching, multi-endpoint maintenance (HTTP + SOCKS5),
stream acceptance, proxy execution, and traffic metrics.
Replicates github.com/packetstream/ecosystem/exit-node/mobilecore.(*Client).
"""

import asyncio
import logging
import random
import time
import uuid
from typing import Callable, Dict, List, Optional, Tuple

from .auth import fetch_token, AuthError, decode_jwt_unverified
from .proxy import handle_http_request, handle_socks_request, TrafficStats
from .tunnel import connect_tunnel, send_token_refresh, TunnelError
from .yamux import YamuxSession

logger = logging.getLogger("packetstream.client")

# Default gateway endpoints from Go mobilecore defaultClientConfig:
# 1. client.packetstream.io:30944 (HTTP proxy, is_socks=False)
# 2. client.packetstream.io:30946 (SOCKS5 proxy, is_socks=True)
DEFAULT_ENDPOINTS: List[Tuple[str, int, bool]] = [
    ("client.packetstream.io", 30944, False),
    ("client.packetstream.io", 30946, True),
]


class PacketStreamClient:
    """
    Independent headless PacketStream exit node client.
    Replicates the exact functionality of the Android app's libgojni mobilecore client.
    """
    def __init__(
        self,
        user_id: int,
        secret_token: str,
        endpoints: Optional[List[Tuple[str, int, bool]]] = None,
        client_version: str = "v2.5.1",
        os_name: str = "android",
        arch: str = "amd64",
        installation_id: Optional[str] = None,
        status_callback: Optional[Callable[[str, Dict], None]] = None
    ):
        self.user_id = user_id
        self.secret_token = secret_token
        self.endpoints = endpoints or DEFAULT_ENDPOINTS
        self.client_version = client_version
        self.os_name = os_name
        self.arch = arch
        self.installation_id = installation_id or str(uuid.uuid4())
        self.status_callback = status_callback

        # State
        self.current_token: Optional[str] = None
        self.detected_ip: Optional[str] = None
        self.stats = TrafficStats()
        self.is_running = False

        self._token_ready_event = asyncio.Event()
        self._active_sessions: Dict[Tuple[str, int], YamuxSession] = {}
        self._background_tasks: List[asyncio.Task] = []
        self._last_status_message: str = "Initializing"

    def _emit_status(self, event_type: str, details: Optional[Dict] = None) -> None:
        """Notifies status callback if registered."""
        d = details or {}
        d.update({
            "user_id": self.user_id,
            "detected_ip": self.detected_ip,
            "active_tunnels": self.stats.active_tunnels,
            "bytes_uploaded": self.stats.bytes_uploaded,
            "bytes_downloaded": self.stats.bytes_downloaded,
            "total_tunnels": self.stats.total_tunnels_served,
        })
        if self.status_callback:
            try:
                self.status_callback(event_type, d)
            except Exception as e:
                logger.debug(f"Error in status callback: {e}")

    async def start(self) -> None:
        """Starts admission loop and endpoint maintainer workers."""
        if self.is_running:
            return
        self.is_running = True

        loop = asyncio.get_running_loop()

        # 1. Start Token Admission loop
        adm_task = loop.create_task(self._admission_loop())
        self._background_tasks.append(adm_task)

        # 2. Start Maintainer for each endpoint (HTTP on 30944, SOCKS5 on 30946)
        for host, port, is_socks in self.endpoints:
            worker_task = loop.create_task(self._maintain_endpoint_loop(host, port, is_socks))
            self._background_tasks.append(worker_task)

    async def stop(self) -> None:
        """Stops all workers and closes active Yamux sessions."""
        if not self.is_running:
            return
        self.is_running = False
        self._emit_status("stopping", {"message": "Stopping client..."})

        # Cancel tasks
        for task in self._background_tasks:
            if not task.done():
                task.cancel()
        self._background_tasks.clear()

        # Close all active sessions
        for ep, session in list(self._active_sessions.items()):
            try:
                await session.close()
            except Exception:
                pass
        self._active_sessions.clear()

        self._emit_status("stopped", {"message": "Client stopped."})

    async def _admission_loop(self) -> None:
        """
        Continuously maintains admission session token with PacketStream API.
        Replicates mobilecore.(*Client).run token loop:
        1. Calls fetchToken.
        2. If error, waits retry delay and retries.
        3. If IP changes, signals reconnect.
        4. If token renewed, publishes replacement to existing tunnels.
        """
        initial_fetch = True
        while self.is_running:
            try:
                logger.info(f"Contacting PacketStream admission service for user {self.user_id}...")
                self._emit_status("authenticating", {"message": "Requesting admission session token..."})

                token, delay, claims = fetch_token(
                    user_id=self.user_id,
                    secret_token=self.secret_token,
                    client_version=self.client_version,
                    os_name=self.os_name,
                    arch=self.arch,
                    installation_id=self.installation_id
                )

                new_ip = claims.get("ip") or claims.get("detected_ip")
                ip_changed = bool(self.detected_ip and new_ip and self.detected_ip != new_ip)

                self.current_token = token
                self.detected_ip = new_ip
                self._token_ready_event.set()

                logger.info(
                    f"Admission granted! Detected IP: {self.detected_ip or 'unknown'}, "
                    f"Token length: {len(token)} bytes"
                )
                self._emit_status("admitted", {
                    "message": f"Admission granted! IP: {self.detected_ip or 'unknown'}",
                    "claims": claims
                })

                if not initial_fetch:
                    if ip_changed:
                        logger.warning(f"Public IP changed to {new_ip}! Tearing down tunnels to re-admit...")
                        # Close existing sessions to trigger clean reconnect with new IP/token
                        for ep, session in list(self._active_sessions.items()):
                            await session.close()
                        self._active_sessions.clear()
                    else:
                        # Publish replacement token over existing sessions
                        for ep, session in list(self._active_sessions.items()):
                            try:
                                await send_token_refresh(session, token)
                            except Exception as e:
                                logger.warning(f"Failed to refresh token on {ep}: {e}")

                initial_fetch = False

                # Calculate next refresh interval (typically before JWT expiration or ~20-30 minutes)
                exp = claims.get("exp")
                refresh_interval = 1800.0  # default 30 minutes
                if isinstance(exp, (int, float)):
                    time_to_exp = float(exp) - time.time()
                    if time_to_exp > 60:
                        refresh_interval = max(60.0, time_to_exp - 300.0)  # Refresh 5 min before expiry

                logger.debug(f"Next admission refresh scheduled in {refresh_interval:.0f} seconds")
                await asyncio.sleep(refresh_interval)

            except AuthError as e:
                logger.warning(f"Admission error: {e}. Retrying in {e.retry_delay:.0f}s...")
                self._emit_status("admission_error", {
                    "message": str(e),
                    "retry_delay": e.retry_delay,
                    "status_code": e.status_code
                })
                await asyncio.sleep(e.retry_delay)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Unexpected admission loop error: {e}", exc_info=True)
                await asyncio.sleep(10.0)

    async def _maintain_endpoint_loop(self, host: str, port: int, is_socks: bool) -> None:
        """
        Maintains connection to a specific endpoint (HTTP or SOCKS5).
        Replicates packetermux.Client.Maintain + serveSession:
        1. Waits for admission token.
        2. Dials TLS and authenticates with token.
        3. Wraps in Yamux Server session.
        4. Accepts incoming proxy streams and serves them.
        5. Handles retries with jitter on disconnection.
        """
        proto_name = "SOCKS5" if is_socks else "HTTP"
        endpoint_key = (host, port)
        retry_delay = 2.0

        while self.is_running:
            # Wait until admission token is available
            await self._token_ready_event.wait()
            if not self.is_running:
                break

            session: Optional[YamuxSession] = None
            try:
                logger.info(f"Connecting {proto_name} tunnel to {host}:{port}...")
                self._emit_status("connecting_tunnel", {
                    "endpoint": f"{host}:{port}",
                    "type": proto_name
                })

                session = await connect_tunnel(
                    host=host,
                    port=port,
                    session_token=self.current_token,
                    connect_timeout=15.0,
                    keepalive_interval=30.0
                )
                self._active_sessions[endpoint_key] = session
                retry_delay = 2.0  # Reset backoff on successful connection

                self._emit_status("tunnel_connected", {
                    "endpoint": f"{host}:{port}",
                    "type": proto_name,
                    "active_endpoints": len(self._active_sessions)
                })

                # Stream acceptance loop (replicates acceptRequests)
                await self._accept_requests_loop(session, is_socks)

            except (TunnelError, ConnectionError, asyncio.TimeoutError) as e:
                logger.warning(f"{proto_name} tunnel ({host}:{port}) disconnected: {e}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Unexpected error in {proto_name} tunnel worker: {e}", exc_info=True)
            finally:
                self._active_sessions.pop(endpoint_key, None)
                if session:
                    try:
                        await session.close()
                    except Exception:
                        pass
                self._emit_status("tunnel_disconnected", {
                    "endpoint": f"{host}:{port}",
                    "type": proto_name
                })

            if not self.is_running:
                break

            # Exponential backoff with jitter (matches JitterRetry in Go)
            jitter = random.uniform(0.5, 1.5)
            wait_time = min(60.0, retry_delay * jitter)
            retry_delay = min(60.0, retry_delay * 1.5)
            logger.info(f"Reconnecting {proto_name} tunnel in {wait_time:.1f}s...")
            await asyncio.sleep(wait_time)

    async def _accept_requests_loop(self, session: YamuxSession, is_socks: bool) -> None:
        """Accepts streams from Yamux session and dispatches each to proxy handlers."""
        handler_fn = handle_socks_request if is_socks else handle_http_request
        proto_name = "SOCKS5" if is_socks else "HTTP"

        loop = asyncio.get_running_loop()
        while self.is_running and not session._closed:
            try:
                stream = await session.accept()
                logger.debug(f"Accepted new {proto_name} stream ID {stream.stream_id}")
                loop.create_task(handler_fn(stream, stats=self.stats))
            except Exception as e:
                if not session._closed:
                    logger.debug(f"Stream accept error: {e}")
                break
