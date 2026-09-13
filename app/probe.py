"""Deciding whether a URL is up, without becoming a tool for reaching things.

Split out from `main.py` because this is the only part with real logic in it.
`main.py` is routing; this is what actually gets tested.
"""

import asyncio
import ipaddress
import socket
import time
from urllib.parse import urlsplit

import httpx2
from pydantic import BaseModel

# A probe is not a page load. If something has not answered in this long it is
# not usable as a bookmark, and waiting longer only makes /status slower.
PROBE_TIMEOUT = 3.0

# How many probes run at once. Not unlimited: a catalogue of 200 links would
# otherwise open 200 sockets at the same instant, which looks like a burst of
# outbound scanning from the cluster and exhausts the connection pool.
MAX_CONCURRENCY = 10


class ProbeResult(BaseModel):
    # "up" and "down" are self-explanatory. "blocked" is deliberately NOT
    # folded into "down": down means we asked and got nothing, blocked means
    # we refused to ask. Collapsing them would hide the refusal, and a security
    # control nobody can see is one nobody maintains.
    status: str
    http_status: int | None = None
    latency_ms: int | None = None
    detail: str | None = None


# ---------------------------------------------------------------- SSRF guard --
#
# This service fetches URLs that ANYONE who can POST to links-service chose,
# from inside the cluster, where it can reach things the author never could.
# That is the textbook shape of SSRF -- the value of the attack is precisely
# the network position, which is exactly what this service has.
#
# The obvious mitigation -- block private address space -- is WRONG here, and
# it is worth being clear about why. app-hub exists to catalogue self-hosted
# apps: Grafana on 10.x, n8n on localhost, a NAS on 192.168.x. Blocking
# RFC1918 would block the actual product.
#
# So the guard is narrow and specific: LINK-LOCAL only.
#
# 169.254.169.254 is the cloud instance metadata endpoint. On EC2 it is the
# classic route from "can fetch a URL" to "has IAM credentials". IMDSv2 needs
# a PUT to get a token, so a plain GET is already weak -- but C-05 is about to
# attach a real IAM role to this namespace, and "weak" is not a thing to build
# on top of.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),  # IPv4 link-local, incl. IMDS
    ipaddress.ip_network("fe80::/10"),       # IPv6 link-local
]

# Some clouds expose metadata under a name as well as an address. Cheap to
# refuse by name too, so that a resolver that lies still gets caught by the
# address check below and vice versa.
_BLOCKED_HOSTS = {"metadata.google.internal", "metadata.goog"}


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_blocked_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in _BLOCKED_NETWORKS)


async def resolve_and_check(url: str) -> str | None:
    """Return a reason to refuse this URL, or None to allow it.

    Hostnames are resolved before the check rather than pattern-matched,
    because `http://metadata.my-domain.com/` can resolve to 169.254.169.254
    just as easily as the literal address can be typed in.

    **This is not airtight, and pretending otherwise would be worse than the
    gap.** DNS can return a different answer between this lookup and httpx's
    own, so a determined attacker with control of a domain can still slip
    through (a "DNS rebinding" attack). Closing that properly means resolving
    once and connecting to the pinned address, which is a custom transport.
    Worth doing if this service ever probes URLs from an untrusted source;
    today the only writer is the owner.
    """
    parts = urlsplit(url)

    if parts.scheme not in ("http", "https"):
        return f"refusing scheme {parts.scheme!r}"

    host = parts.hostname
    if not host:
        return "no host in URL"

    if host.lower() in _BLOCKED_HOSTS:
        return "refusing cloud metadata hostname"

    if _is_blocked_ip(host):
        return "refusing link-local address"

    # An IP literal has already been checked above, so resolving it is a
    # pointless trip to the resolver. Skipping it also keeps the guard's cost
    # at zero for the `http://10.0.1.5:9090/` style entries that a self-hosted
    # catalogue is mostly made of.
    if _is_ip_literal(host):
        return None

    # getaddrinfo blocks, so it goes through the event loop's own resolver
    # rather than being called directly -- a blocking DNS lookup inside an
    # async handler stalls EVERY other probe running concurrently, which is
    # the kind of bug that only shows up under load.
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        # Not a refusal -- it simply does not resolve. Let the probe run and
        # report that as "down", which is the more useful answer.
        return None

    for info in infos:
        if _is_blocked_ip(info[4][0]):
            return "refusing host that resolves to a link-local address"

    return None


# -------------------------------------------------------------------- probing --

async def probe_one(client: httpx2.AsyncClient, url: str) -> ProbeResult:
    """Is this one URL usable? Never raises."""
    blocked = await resolve_and_check(url)
    if blocked:
        return ProbeResult(status="blocked", detail=blocked)

    started = time.monotonic()
    try:
        # HEAD first: it should return the same status with no body, which
        # makes probing a 2 GB download page cheap. Plenty of servers answer
        # HEAD with 405 or 501 though, so that is not a failure -- it is a
        # signal to ask properly.
        response = await client.head(url, timeout=PROBE_TIMEOUT,
                                     follow_redirects=True)
        if response.status_code in (403, 405, 501):
            response = await client.get(url, timeout=PROBE_TIMEOUT,
                                        follow_redirects=True)
    except httpx2.TimeoutException:
        return ProbeResult(status="down", detail=f"no answer in {PROBE_TIMEOUT:g}s",
                           latency_ms=int((time.monotonic() - started) * 1000))
    except httpx2.RequestError as e:
        # The exception TYPE is useful and the message is noise (it repeats the
        # URL, which the caller already has). Same reasoning as gateway's
        # fixed detail strings, for a different reason: here the URL is not a
        # secret, it is just not information.
        return ProbeResult(status="down", detail=type(e).__name__,
                           latency_ms=int((time.monotonic() - started) * 1000))

    latency_ms = int((time.monotonic() - started) * 1000)

    # Anything the server answered at all means the service is running, which
    # is the question being asked. A 401 on a Grafana behind auth is "up" --
    # reporting it as down would make the dashboard cry wolf about every
    # protected app on it.
    up = response.status_code < 500
    return ProbeResult(
        status="up" if up else "down",
        http_status=response.status_code,
        latency_ms=latency_ms,
        detail=None if up else f"HTTP {response.status_code}",
    )


async def probe_many(client: httpx2.AsyncClient, urls: list[str],
                     concurrency: int = MAX_CONCURRENCY) -> list[ProbeResult]:
    """Probe every URL concurrently, preserving input order.

    Concurrency is the whole reason this service is worth having. Twenty links
    probed one after another at a 3s timeout is a worst case of a minute, which
    is not a dashboard. Probed together it is 3 seconds regardless of how many
    there are, because the time is spent waiting, not computing.

    `gather` preserves order, so results line up with `urls` positionally and
    the caller does not have to match them back up by URL -- which would be
    wrong anyway, since two links may share one.
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def guarded(url: str) -> ProbeResult:
        async with semaphore:
            return await probe_one(client, url)

    return list(await asyncio.gather(*(guarded(u) for u in urls)))
