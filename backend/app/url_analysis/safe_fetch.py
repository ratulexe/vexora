"""Outbound requests to user-submitted sites, with protection against SSRF.

Every hop of a redirect chain is checked before we connect: only http and https
on ports 80 and 443, and only hosts that resolve to public IP addresses. We then
connect to the IP we checked (not a fresh DNS lookup), so a domain cannot switch
to an internal address between the check and the request. We never read the page
body, run scripts or download files.
"""

import ipaddress
import socket
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

ALLOWED_PORTS = {80, 443}
MAX_REDIRECTS = 5
TOTAL_BUDGET_SECONDS = 15
TIMEOUT = httpx.Timeout(5.0)
# How long to wait for each address before trying the next one.
CONNECT_PROBE_SECONDS = 3.0
USER_AGENT = "Mozilla/5.0 (compatible; VexoraScanner/0.1; +https://github.com/ratulexe/vexora)"
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")
# Response headers kept for the website security assessment. Page content is never read.
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "server",
    "x-powered-by",
    "x-aspnet-version",
)


class BlockedDestination(Exception):
    """The destination is not allowed, for example an internal address."""


class DnsFailure(Exception):
    """The host name does not resolve."""


def is_public_address(ip: str) -> bool:
    address = ipaddress.ip_address(ip.split("%")[0])
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped:
            address = address.ipv4_mapped
        elif address in NAT64_PREFIX:
            # NAT64 networks (common on mobile data) wrap IPv4 addresses in IPv6.
            # Judge the wrapped IPv4 address, so internal targets stay blocked.
            address = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    return address.is_global and not (
        address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_private
    )


def resolve_public_ips(host: str) -> list[str]:
    """Resolve a host and refuse it if ANY of its addresses is not public."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as error:
        raise DnsFailure(f"{host} does not resolve") from error

    # IPv4 first: many hosts (Render included) cannot make IPv6 connections, and sites such as
    # facebook.com publish both. Sorting the addresses as text put IPv6 first for some of them.
    ips = sorted({info[4][0] for info in infos}, key=lambda ip: (ipaddress.ip_address(ip).version, ip))
    blocked = [ip for ip in ips if not is_public_address(ip)]
    if blocked:
        raise BlockedDestination(f"{host} resolves to a non-public address ({', '.join(blocked)})")
    return ips


def first_reachable(ips: list[str], port: int) -> str:
    """The first address that accepts a connection on the port, trying each in order.

    Every address has already passed the public-address check, so falling back to another
    one is safe. If none answer, the first is returned and the real request reports the error.
    """
    if len(ips) == 1:
        return ips[0]
    for ip in ips:
        try:
            with socket.create_connection((ip, port), timeout=CONNECT_PROBE_SECONDS):
                return ip
        except OSError:
            continue
    return ips[0]


@dataclass
class Hop:
    url: str
    status: int | None
    ip: str
    location: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)


@dataclass
class FetchResult:
    hops: list[Hop] = field(default_factory=list)
    final_url: str | None = None
    final_status: int | None = None
    error: str | None = None
    blocked: str | None = None
    dns_failed: bool = False


def check_destination(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise BlockedDestination(f"Redirect to unsupported scheme '{scheme}'")
    host = parts.hostname
    if not host:
        raise BlockedDestination("Redirect to a URL without a host")
    port = parts.port or (443 if scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise BlockedDestination(f"Port {port} is not allowed (only 80 and 443)")
    return scheme, host, port


def fetch_redirect_chain(url: str) -> FetchResult:
    result = FetchResult()
    current = url
    deadline = time.monotonic() + TOTAL_BUDGET_SECONDS
    with httpx.Client(
        # Certificates are judged separately by the TLS check, so a bad certificate
        # must not stop us from seeing where the site redirects.
        verify=False,
        timeout=TIMEOUT,
        follow_redirects=False,
        trust_env=False,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"},
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            if time.monotonic() > deadline:
                result.error = f"Gave up after {TOTAL_BUDGET_SECONDS} seconds"
                return result
            try:
                scheme, host, port = check_destination(current)
                ip = first_reachable(resolve_public_ips(host), port)
            except BlockedDestination as error:
                result.blocked = str(error)
                return result
            except DnsFailure as error:
                result.dns_failed = True
                result.error = str(error)
                return result

            try:
                try:
                    status, location, headers, cookies = _request_pinned(client, current, scheme, host, port, ip)
                except (httpx.ConnectError, httpx.ReadError):
                    # One retry: flaky networks sometimes drop the first connection.
                    status, location, headers, cookies = _request_pinned(client, current, scheme, host, port, ip)
            except httpx.TimeoutException:
                result.error = f"Timed out connecting to {host}"
                return result
            except httpx.HTTPError as error:
                result.error = f"Could not connect to {host} ({type(error).__name__})"
                return result

            result.hops.append(
                Hop(url=current, status=status, ip=ip, location=location, headers=headers, cookies=cookies)
            )
            if status in REDIRECT_STATUSES and location:
                current = urljoin(current, location)
                continue

            result.final_url = current
            result.final_status = status
            return result

    result.error = f"Stopped after {MAX_REDIRECTS} redirects"
    return result


def _request_pinned(
    client: httpx.Client, url: str, scheme: str, host: str, port: int, ip: str
) -> tuple[int, str | None, dict[str, str], list[str]]:
    parts = urlsplit(url)
    ip_netloc = f"[{ip}]" if ":" in ip else ip
    default_port = 443 if scheme == "https" else 80
    if port != default_port:
        ip_netloc += f":{port}"
    pinned_url = urlunsplit((scheme, ip_netloc, parts.path or "/", parts.query, ""))
    host_header = host if port == default_port else f"{host}:{port}"

    request = client.build_request(
        "GET",
        pinned_url,
        headers={"Host": host_header},
        extensions={"sni_hostname": host},
    )
    response = client.send(request, stream=True)
    try:
        headers = {name: response.headers[name] for name in SECURITY_HEADERS if name in response.headers}
        cookies = response.headers.get_list("set-cookie")
        return response.status_code, response.headers.get("location"), headers, cookies
    finally:
        response.close()
