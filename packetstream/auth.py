"""
PacketStream Authentication and Admission Module.
Replicates the Go mobilecore logic:
- parseAuthCode: base64-encoded "<user_id>:<secret_token>"
- fetchToken: GET https://api.packetstream.io/exitnode/ipinfo/<user_id>
"""

import base64
import json
import logging
import time
import urllib.parse
import urllib.request
from typing import Optional, Tuple, Dict, Any

logger = logging.getLogger("packetstream.auth")

DEFAULT_API_BASE = "https://api.packetstream.io/exitnode/ipinfo"
DEFAULT_CLIENT_VERSION = "v2.5.1"
DEFAULT_OS = "android"
DEFAULT_ARCH = "amd64"
DEFAULT_UPDATE_MODE = "android_sideload"


class AuthError(Exception):
    """Raised when authentication parsing or API admission fails."""
    def __init__(self, message: str, retry_delay: float = 5.0, status_code: Optional[int] = None):
        super().__init__(message)
        self.retry_delay = retry_delay
        self.status_code = status_code


def parse_auth_code(raw_code: str) -> Tuple[int, str]:
    """
    Parses the PacketStream login code.
    Matches Go implementation `parseAuthCode` in mobilecore:
    1. Base64 decodes the input string.
    2. Splits string by ':' into [user_id_str, secret_token].
    3. Validates user_id > 0 and len(secret_token) >= 3.
    """
    cleaned = raw_code.strip()
    if not cleaned:
        raise AuthError("Authentication code cannot be empty")

    decoded_str = ""
    # Support direct "username:user_id" if user pasted raw credentials (colon is never in base64)
    if ":" in cleaned:
        decoded_str = cleaned

    if not decoded_str:
        # Try standard and urlsafe base64
        padded = cleaned + "=" * ((4 - len(cleaned) % 4) % 4)
        try:
            decoded_bytes = base64.b64decode(padded, validate=False)
            decoded_str = decoded_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            raise AuthError(f"invalid PacketStream authentication code: base64 decode failed: {e}")

    if ":" not in decoded_str:
        raise AuthError("invalid PacketStream authentication code: missing ':' delimiter")

    parts = decoded_str.split(":", 1)
    if len(parts) != 2:
        raise AuthError("invalid PacketStream authentication code: expected <username>:<user_id>")

    p0, p1 = parts[0].strip(), parts[1].strip()

    # In PacketStream, the standard format is "<username>:<user_id>" (e.g. pranavkd:782600)
    # where p0 is username (len >= 3) and p1 is user_id (positive integer).
    # We also support "<user_id>:<token>" if p0 is the integer.
    user_id = None
    token = None

    if p1.isdigit() and int(p1) > 0 and len(p0) >= 3:
        user_id = int(p1)
        token = p0
    elif p0.isdigit() and int(p0) > 0 and len(p1) >= 3:
        user_id = int(p0)
        token = p1
    else:
        raise AuthError(
            f"invalid PacketStream authentication code: could not find valid positive user_id in '{decoded_str}'"
        )

    return user_id, token


def decode_jwt_unverified(jwt_token: str) -> Dict[str, Any]:
    """
    Decodes the unverified payload claims of a JWT token string.
    Extracts claims such as 'exp' (expiration), 'ip' (detected public IP), 'sub', etc.
    """
    try:
        parts = jwt_token.strip().split(".")
        if len(parts) < 2:
            return {}
        payload_b64 = parts[1]
        payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        logger.debug(f"Could not parse JWT claims: {e}")
        return {}


def fetch_token(
    user_id: int,
    secret_token: str,
    client_version: str = DEFAULT_CLIENT_VERSION,
    os_name: str = DEFAULT_OS,
    arch: str = DEFAULT_ARCH,
    update_mode: str = DEFAULT_UPDATE_MODE,
    installation_id: Optional[str] = None,
    api_base: str = DEFAULT_API_BASE,
    timeout: float = 15.0
) -> Tuple[str, float, Dict[str, Any]]:
    """
    Fetches the admission session token (JWT) from PacketStream API.
    Replicates mobilecore.fetchToken:
    GET https://api.packetstream.io/exitnode/ipinfo/<user_id>?client_version=v2.5.1&os=android&arch=amd64&update_mode=android_sideload

    Returns:
        (jwt_token, retry_delay_seconds, claims_dict)
    """
    params = {
        "client_version": client_version,
        "os": os_name,
        "arch": arch,
        "update_mode": update_mode,
    }
    query_str = urllib.parse.urlencode(params)
    url = f"{api_base.rstrip('/')}/{user_id}?{query_str}"

    headers = {
        "User-Agent": "Go-http-client/1.1",
        "Accept": "application/json",
    }
    if installation_id:
        headers["X-PacketStream-Installation-ID"] = installation_id

    req = urllib.request.Request(url, headers=headers, method="GET")

    status_code = None
    response_bytes = b""
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.status
            response_bytes = resp.read()
    except urllib.error.HTTPError as e:
        status_code = e.code
        response_bytes = e.read()
    except urllib.error.URLError as e:
        raise AuthError(f"Network error contacting admission service: {e.reason}", retry_delay=5.0)
    except Exception as e:
        raise AuthError(f"Unexpected error contacting admission service: {e}", retry_delay=5.0)

    try:
        body = json.loads(response_bytes.decode("utf-8"))
    except Exception as e:
        raise AuthError(
            f"Failed to parse admission response (HTTP {status_code}): {e}",
            retry_delay=5.0,
            status_code=status_code
        )

    api_status = body.get("status", status_code)
    api_message = body.get("message", "No message provided")
    api_data = body.get("data")

    # Parse response delay if provided (in nanoseconds or seconds)
    retry_delay = 5.0
    if isinstance(api_data, (int, float)):
        # In Go mobilecore: responseDelay parses delay, often sent in nanoseconds (e.g. 300000000000 ns = 300s)
        if api_data > 1_000_000:
            retry_delay = max(1.0, float(api_data) / 1_000_000_000.0)
        else:
            retry_delay = max(1.0, float(api_data))

    if api_status != 200 or status_code != 200:
        raise AuthError(
            f"PacketStream admission rejected (HTTP {status_code}, status {api_status}): {api_message}",
            retry_delay=retry_delay,
            status_code=status_code
        )

    if not isinstance(api_data, str) or not api_data:
        raise AuthError(
            f"Invalid admission response: 'data' did not contain a session token string",
            retry_delay=retry_delay,
            status_code=status_code
        )

    jwt_token = api_data.strip()
    if len(jwt_token.encode("utf-8")) > 512:
        raise AuthError(
            f"packeter JWT is {len(jwt_token)} bytes, maximum is 512",
            retry_delay=5.0
        )

    claims = decode_jwt_unverified(jwt_token)
    return jwt_token, retry_delay, claims
