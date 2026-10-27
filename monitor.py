import hashlib
import time
from urllib.parse import urlparse

import requests

MAX_BODY_BYTES = 1_000_000
USER_AGENT = "DarkWatch-Research-Monitor/1.0"


def validate_onion_url(raw_url):
    """Accept a valid-looking v3 onion URL, not arbitrary websites."""
    raw_url = raw_url.strip()

    if not raw_url:
        raise ValueError("Enter a public onion URL.")

    if "://" not in raw_url:
        raw_url = "http://" + raw_url

    parsed = urlparse(raw_url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS are allowed.")

    if not parsed.hostname:
        raise ValueError("The URL has no hostname.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed.")

    host = parsed.hostname.lower()

    if not host.endswith(".onion"):
        raise ValueError("The hostname must end in .onion.")

    # Validate the format of a modern v3 onion hostname.
    label = host[:-len(".onion")]
    allowed = "abcdefghijklmnopqrstuvwxyz234567"

    if len(label) != 56 or any(c not in allowed for c in label):
        raise ValueError(
            "Enter a v3 onion hostname with "
            "56 base32 characters before .onion."
        )

    try:
        port = parsed.port
    except ValueError:
        raise ValueError("The URL contains an invalid port.")

    if port not in (None, 80, 443):
        raise ValueError("Custom ports are disabled in this version.")

    if parsed.query or parsed.fragment:
        raise ValueError(
            "Remove query parameters and fragments."
        )

    return (
        f"{parsed.scheme}://{host}{parsed.path or '/'}"
    )


def check_onion_site(url, proxy_port):
    """Make one bounded HTTP check through the local Tor proxy."""
    proxies = {
        "http": f"socks5h://127.0.0.1:{proxy_port}",
        "https": f"socks5h://127.0.0.1:{proxy_port}",
    }

    start = time.perf_counter()

    result = {
        "reachable": False,
        "http_status": None,
        "response_ms": None,
        "content_hash": None,
        "body_truncated": False,
        "error": None,
    }

    try:
        with requests.get(
            url,
            proxies=proxies,
            timeout=(10, 30),
            allow_redirects=False,
            stream=True,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml",
            },
        ) as response:

            result["reachable"] = True
            result["http_status"] = response.status_code
            result["response_ms"] = round(
                (time.perf_counter() - start) * 1000, 2
            )

            content_type = response.headers.get(
                "Content-Type", ""
            ).lower()

            # Fingerprint HTML only; do not save the page itself.
            if (
                "text/html" in content_type
                or "application/xhtml+xml" in content_type
            ):
                digest = hashlib.sha256()
                total = 0

                for chunk in response.iter_content(
                    chunk_size=16384
                ):
                    if not chunk:
                        continue

                    remaining = MAX_BODY_BYTES - total

                    if remaining <= 0:
                        result["body_truncated"] = True
                        break

                    portion = chunk[:remaining]
                    digest.update(portion)
                    total += len(portion)

                    if len(chunk) > remaining:
                        result["body_truncated"] = True
                        break

                result["content_hash"] = digest.hexdigest()

    except requests.exceptions.RequestException as exc:
        # Do not mistake a failed connection for a confirmed
        # website outage: the local Tor connection may have failed.
        result["error"] = type(exc).__name__

    result["response_ms"] = round(
        (time.perf_counter() - start) * 1000, 2
    )

    return result