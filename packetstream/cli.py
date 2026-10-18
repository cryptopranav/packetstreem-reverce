"""
Terminal CLI and Live Dashboard for PacketStream Python Client.
Provides real-time bandwidth sharing statistics, tunnel status, and clean TTY UI.
"""

import argparse
import asyncio
import logging
import os
import signal
import sys
import time
from typing import Dict, Optional

from .auth import parse_auth_code, AuthError
from .client import PacketStreamClient, DEFAULT_ENDPOINTS

logger = logging.getLogger("packetstream.cli")

BANNER = r"""
  ____            _        _   ____  _                              
 |  _ \ __ _  ___| | _____| |_/ ___|| |_ _ __ ___  __ _ _ __ ___  
 | |_) / _` |/ __| |/ / _ \ __\___ \| __| '__/ _ \/ _` | '_ ` _ \ 
 |  __/ (_| | (__|   <  __/ |_ ___) | |_| | |  __/ (_| | | | | | |
 |_|   \__,_|\___|_|\_\___|\__|____/ \__|_|  \___|\__,_|_| |_| |_|
            Autonomous Python Exit Node - Client v2.5.1
"""

def format_bytes(n: int) -> str:
    """Formats bytes into human readable KB, MB, GB."""
    if n < 1024:
        return f"{n} B"
    elif n < 1024 * 1024:
        return f"{n / 1024:.2f} KB"
    elif n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.2f} MB"
    else:
        return f"{n / (1024 * 1024 * 1024):.3f} GB"


def format_duration(seconds: float) -> str:
    """Formats seconds into HH:MM:SS."""
    secs = int(seconds)
    hours = secs // 3600
    minutes = (secs % 3600) // 60
    rem_secs = secs % 60
    return f"{hours:02d}:{minutes:02d}:{rem_secs:02d}"


class TerminalDashboard:
    """Renders a clean live terminal dashboard showing real-time sharing metrics."""
    def __init__(self, user_id: int, is_tty: bool = True):
        self.user_id = user_id
        self.is_tty = is_tty
        self.status_msg = "Connecting..."
        self.detected_ip: Optional[str] = None
        self.active_endpoints = 0
        self.start_time = time.time()
        self.last_update_time = time.time()
        self.last_up_bytes = 0
        self.last_down_bytes = 0
        self.up_speed = 0.0
        self.down_speed = 0.0

    def update_status(self, event_type: str, details: Dict) -> None:
        if event_type == "authenticating":
            self.status_msg = "Authenticating with PacketStream API..."
        elif event_type == "admitted":
            self.detected_ip = details.get("detected_ip")
            self.status_msg = "Admission granted! Connecting tunnels..."
        elif event_type == "admission_error":
            msg = details.get("message", "Admission rejected")
            delay = details.get("retry_delay", 5)
            self.status_msg = f"Admission waiting ({delay:.0f}s): {msg}"
        elif event_type == "tunnel_connected":
            self.active_endpoints = details.get("active_endpoints", 1)
            self.status_msg = "Online & Sharing Bandwidth"
        elif event_type == "tunnel_disconnected":
            self.active_endpoints = max(0, self.active_endpoints - 1)
            if self.active_endpoints == 0:
                self.status_msg = "Tunnels disconnected. Reconnecting..."
        elif event_type == "stopping":
            self.status_msg = "Shutting down..."
        elif event_type == "stopped":
            self.status_msg = "Stopped."

        if details.get("detected_ip"):
            self.detected_ip = details["detected_ip"]

    def render(self, client: PacketStreamClient) -> None:
        now = time.time()
        dt = max(0.001, now - self.last_update_time)

        current_up = client.stats.bytes_uploaded
        current_down = client.stats.bytes_downloaded

        if dt >= 0.5:
            self.up_speed = max(0.0, (current_up - self.last_up_bytes) / dt)
            self.down_speed = max(0.0, (current_down - self.last_down_bytes) / dt)
            self.last_up_bytes = current_up
            self.last_down_bytes = current_down
            self.last_update_time = now

        uptime_str = format_duration(now - self.start_time)
        up_str = format_bytes(current_up)
        down_str = format_bytes(current_down)
        up_speed_str = f"{format_bytes(int(self.up_speed))}/s"
        down_speed_str = f"{format_bytes(int(self.down_speed))}/s"

        ip_display = self.detected_ip or "Detecting..."

        if self.is_tty:
            # Clear screen and draw dashboard
            output = [
                "\033[H\033[J",  # Clear ANSI
                "\033[1;36m" + BANNER + "\033[0m",
                "\033[1;37m" + "=" * 65 + "\033[0m",
                f"  \033[1;33mUser ID:\033[0m            {self.user_id}",
                f"  \033[1;33mDetected IP:\033[0m        {ip_display}",
                f"  \033[1;33mStatus:\033[0m             \033[1;32m{self.status_msg}\033[0m",
                f"  \033[1;33mActive Tunnels:\033[0m     {len(client._active_sessions)} / {len(client.endpoints)}",
                f"  \033[1;33mActive Streams:\033[0m     {client.stats.active_tunnels}",
                f"  \033[1;33mTotal Served:\033[0m       {client.stats.total_tunnels_served} connections",
                "\033[1;37m" + "-" * 65 + "\033[0m",
                f"  \033[1;34mData Uploaded:\033[0m      {up_str:<18} \033[1;34mRate:\033[0m ↑ {up_speed_str}",
                f"  \033[1;34mData Downloaded:\033[0m    {down_str:<18} \033[1;34mRate:\033[0m ↓ {down_speed_str}",
                f"  \033[1;34mSession Uptime:\033[0m     {uptime_str}",
                "\033[1;37m" + "=" * 65 + "\033[0m",
                "  \033[90m[Press Ctrl+C to Stop]\033[0m\n"
            ]
            sys.stdout.write("\n".join(output))
            sys.stdout.flush()
        else:
            logger.info(
                f"[Stats] IP: {ip_display} | Status: {self.status_msg} | "
                f"Tunnels: {len(client._active_sessions)} | "
                f"Active Streams: {client.stats.active_tunnels} | "
                f"Up: {up_str} ({up_speed_str}) | Down: {down_str} ({down_speed_str}) | "
                f"Uptime: {uptime_str}"
            )


async def async_main() -> None:
    parser = argparse.ArgumentParser(
        description="PacketStream Autonomous Python CLI Exit Node Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Using auth code directly
  python3 packetstream-cli.py -a "MTIzNDU6YWJjZGVmZ2hpams="

  # Using plain user_id:token credentials
  python3 packetstream-cli.py -a "12345:my_secret_token"

  # Or set via environment variable:
  export PACKETSTREAM_AUTH_CODE="MTIzNDU6YWJjZGVmZ2hpams="
  python3 packetstream-cli.py
        """
    )
    parser.add_argument(
        "-a", "--auth-code",
        default=os.environ.get("PACKETSTREAM_AUTH_CODE", ""),
        help="Base64-encoded login code from PacketStream dashboard"
    )
    parser.add_argument(
        "--socks-only",
        action="store_true",
        help="Run only SOCKS5 tunnel (:30946)"
    )
    parser.add_argument(
        "--http-only",
        action="store_true",
        help="Run only HTTP tunnel (:30944)"
    )
    parser.add_argument(
        "--client-version",
        default="v2.5.1",
        help="Client version reported to PacketStream (default: v2.5.1)"
    )
    parser.add_argument(
        "--os",
        default="android",
        help="OS reported to PacketStream (default: android)"
    )
    parser.add_argument(
        "--arch",
        default="amd64",
        help="Architecture reported to PacketStream (default: amd64)"
    )
    parser.add_argument(
        "--status-interval",
        type=float,
        default=1.0,
        help="Dashboard refresh interval in seconds (default: 1.0)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging"
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Disable interactive ANSI dashboard (standard log mode)"
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else (logging.WARNING if not args.no_dashboard and sys.stdout.isatty() else logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S"
    )

    auth_code = args.auth_code.strip()
    if not auth_code:
        print(BANNER)
        print("Obtain your Login Code from: https://app.packetstream.io/dashboard/client_auth\n")
        try:
            auth_code = input("Enter PacketStream Login Code: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(0)

    try:
        user_id, secret_token = parse_auth_code(auth_code)
    except AuthError as e:
        print(f"\033[1;31mError:\033[0m {e}")
        sys.exit(1)

    # Determine endpoints
    endpoints = []
    if args.socks_only:
        endpoints = [("client.packetstream.io", 30946, True)]
    elif args.http_only:
        endpoints = [("client.packetstream.io", 30944, False)]
    else:
        endpoints = list(DEFAULT_ENDPOINTS)

    is_tty = sys.stdout.isatty() and not args.no_dashboard and not args.verbose
    dashboard = TerminalDashboard(user_id=user_id, is_tty=is_tty)

    client = PacketStreamClient(
        user_id=user_id,
        secret_token=secret_token,
        endpoints=endpoints,
        client_version=args.client_version,
        os_name=args.os,
        arch=args.arch,
        status_callback=dashboard.update_status
    )

    stop_event = asyncio.Event()

    def sig_handler():
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, sig_handler)
        except NotImplementedError:
            pass

    print(f"\033[1;32mStarting PacketStream client for User ID: {user_id}...\033[0m")
    await client.start()

    try:
        while not stop_event.is_set():
            dashboard.render(client)
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=args.status_interval)
            except asyncio.TimeoutError:
                pass
    finally:
        if is_tty:
            print("\n\033[1;33mShutting down PacketStream client...\033[0m")
        await client.stop()
        print("\033[1;32mPacketStream client stopped cleanly. Goodbye!\033[0m")


def main():
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\nExited.")


if __name__ == "__main__":
    main()
