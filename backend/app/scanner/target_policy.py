import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


class TargetRejected(ValueError):
    pass


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    host: str


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return ip.is_global and not any((ip.is_private, ip.is_loopback, ip.is_link_local,
                                     ip.is_multicast, ip.is_reserved, ip.is_unspecified))


async def validate_target(raw_url: str) -> ValidatedTarget:
    parsed = urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TargetRejected("Only absolute HTTP and HTTPS URLs are allowed")
    if parsed.username or parsed.password:
        raise TargetRejected("Credentials in target URLs are not allowed")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in {80, 443}:
        raise TargetRejected("Only ports 80 and 443 are allowed")
    host = parsed.hostname.rstrip(".").lower()
    if host in {"localhost", "metadata.google.internal"} or host.endswith((".local", ".internal")):
        raise TargetRejected("Private and internal targets are not allowed")
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetRejected("Target hostname could not be resolved") from exc
    addresses = {item[4][0].split("%", 1)[0] for item in infos}
    if not addresses or any(not _is_public(value) for value in addresses):
        raise TargetRejected("Target resolves to a non-public address")
    normalized = urlunsplit((parsed.scheme, parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))
    return ValidatedTarget(normalized, host)
