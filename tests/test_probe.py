"""The SSRF guard and the probing logic.

These call `probe.py` directly rather than through HTTP. The two things most
worth pinning down here -- what gets refused, and that probes really do run
concurrently -- are both invisible from the outside of a request.
"""

import asyncio
import time

import httpx2
import pytest

from app.probe import ProbeResult, probe_many, probe_one, resolve_and_check


def responder(handler):
    return httpx2.AsyncClient(transport=httpx2.MockTransport(handler))


# ----------------------------------------------------------------- the guard --

@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/",
    "https://169.254.1.1/",
    "http://[fe80::1]/",
])
async def test_link_local_is_refused(url):
    """169.254.169.254 is the cloud instance metadata endpoint.

    On EC2 it is the classic path from "this service will fetch a URL you
    chose" to "this service handed you its IAM credentials". C-05 is about to
    attach a real role to this namespace, which is exactly why the refusal
    exists before the role does rather than after.
    """
    assert await resolve_and_check(url) is not None


@pytest.mark.parametrize("url", [
    "http://localhost:3000/",
    "http://127.0.0.1:8000/",
    "http://10.0.1.5:9090/",
    "http://192.168.1.50/",
    "https://grafana.example.com/",
])
async def test_private_and_public_addresses_are_allowed(url):
    """Blocking RFC1918 would block the actual product.

    The obvious SSRF mitigation is "refuse private address space". Here that
    is wrong: app-hub exists to catalogue self-hosted apps, which live on
    10.x, 192.168.x and localhost. A guard that broke those would be removed
    within a day, which makes it worth less than a narrow guard that stays.
    """
    assert await resolve_and_check(url) is None


@pytest.mark.parametrize("url,reason", [
    ("file:///etc/passwd", "scheme"),
    ("gopher://example.com/", "scheme"),
    ("ftp://example.com/", "scheme"),
])
async def test_non_http_schemes_are_refused(url, reason):
    got = await resolve_and_check(url)
    assert got is not None and reason in got


async def test_metadata_hostname_is_refused():
    assert await resolve_and_check("http://metadata.google.internal/") is not None


async def test_a_name_that_does_not_resolve_is_not_a_refusal():
    """Unresolvable is "down", not "blocked", and the difference matters.

    Reporting a dead DNS name as blocked would tell the owner their own
    security control ate a link, sending them to read the guard rather than
    fix the bookmark.
    """
    assert await resolve_and_check("http://no-such-host.invalid./") is None


# ---------------------------------------------------------------- probe_one --

async def test_a_200_is_up():
    client = responder(lambda r: httpx2.Response(200))
    result = await probe_one(client, "https://example.com/")
    assert result.status == "up"
    assert result.http_status == 200
    assert result.latency_ms is not None


@pytest.mark.parametrize("code", [200, 204, 301, 401, 403, 404])
async def test_anything_under_500_counts_as_up(code):
    """A 401 from a Grafana behind auth means Grafana is running.

    The question this service answers is "is the app up?", not "may I in?".
    Marking every protected app as down would make the dashboard cry wolf
    about most of the catalogue, and a dashboard that cries wolf gets ignored
    -- at which point it is worse than not having one.
    """
    # 403/405/501 fall through to GET, so answer both verbs the same way.
    client = responder(lambda r: httpx2.Response(code))
    result = await probe_one(client, "https://example.com/")
    assert result.status == "up"


@pytest.mark.parametrize("code", [500, 502, 503])
async def test_5xx_is_down(code):
    client = responder(lambda r: httpx2.Response(code))
    result = await probe_one(client, "https://example.com/")
    assert result.status == "down"
    assert result.detail == f"HTTP {code}"


async def test_head_rejected_falls_back_to_get():
    """Plenty of servers answer HEAD with 405 and serve GET perfectly well.

    Treating that as down would mark a working app broken, which is the most
    expensive kind of wrong answer a status page can give.
    """
    seen = []

    def handler(request):
        seen.append(request.method)
        if request.method == "HEAD":
            return httpx2.Response(405)
        return httpx2.Response(200)

    result = await probe_one(responder(handler), "https://example.com/")
    assert seen == ["HEAD", "GET"]
    assert result.status == "up"
    assert result.http_status == 200


async def test_connection_error_is_down_not_an_exception():
    """A probe must NEVER raise. One dead link would take out the whole report."""
    def handler(request):
        raise httpx2.ConnectError("refused")

    result = await probe_one(responder(handler), "https://example.com/")
    assert result.status == "down"
    assert result.detail == "ConnectError"


async def test_timeout_is_down():
    def handler(request):
        raise httpx2.ReadTimeout("too slow")

    result = await probe_one(responder(handler), "https://example.com/")
    assert result.status == "down"
    assert "no answer" in result.detail


async def test_blocked_url_is_never_fetched():
    """The guard has to run BEFORE the request, not alongside it.

    If the transport is reached at all, the packet left -- and for
    169.254.169.254 the request itself is the whole attack.
    """
    def handler(request):
        raise AssertionError("blocked URL was fetched: %s" % request.url)

    result = await probe_one(responder(handler), "http://169.254.169.254/")
    assert result.status == "blocked"
    assert result.http_status is None


# --------------------------------------------------------------- probe_many --

async def test_results_line_up_with_the_urls_given():
    """Order is the contract, because two links may share a URL.

    Matching results back by URL would silently mis-assign them; `gather`
    preserves order, and this is what stops someone "improving" it into
    `as_completed` without noticing.
    """
    def handler(request):
        return httpx2.Response(500 if "bad" in str(request.url) else 200)

    urls = ["https://good1.example/", "https://bad.example/", "https://good2.example/"]
    results = await probe_many(responder(handler), urls)
    assert [r.status for r in results] == ["up", "down", "up"]


async def test_probes_run_concurrently_not_one_after_another():
    """The entire reason this is a service and not a loop in the dashboard.

    Twenty links at a 3s timeout is a worst case of a minute serially and
    3 seconds concurrently, because the time is spent waiting rather than
    computing. This asserts the wall-clock difference rather than trusting
    that `gather` was used.

    **IP literals, not hostnames, and that is not cosmetic.** The SSRF guard
    resolves hostnames for real before any request is made, so with fake
    `.example` names this test spent 5.2s waiting on NXDOMAIN and reported
    the probes as serial. It was measuring DNS, not concurrency. An IP
    literal is checked directly and never reaches the resolver -- which is
    also why `_is_ip_literal` short-circuits in `resolve_and_check`.
    """
    async def handler(request):
        await asyncio.sleep(0.2)
        return httpx2.Response(200)

    urls = [f"https://203.0.113.{i}/" for i in range(1, 11)]
    started = time.monotonic()
    results = await probe_many(responder(handler), urls, concurrency=10)
    elapsed = time.monotonic() - started

    assert all(r.status == "up" for r in results)
    # Serial would be >= 2.0s. Allow generous headroom for a slow machine and
    # still fail loudly if the concurrency is ever lost.
    assert elapsed < 1.0, f"took {elapsed:.2f}s -- probes appear to be serial"


async def test_concurrency_limit_is_respected():
    """Unbounded gather on a 200-link catalogue opens 200 sockets at once.

    From outside, that is indistinguishable from the cluster port-scanning.

    IP literals again, so the timing reflects probes rather than DNS.
    """
    in_flight = 0
    peak = 0

    async def handler(request):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.05)
        in_flight -= 1
        return httpx2.Response(200)

    urls = [f"https://198.51.100.{i}/" for i in range(1, 21)]
    await probe_many(responder(handler), urls, concurrency=3)
    assert peak <= 3, f"peak concurrency was {peak}, limit was 3"


async def test_an_empty_catalogue_is_not_an_error():
    assert await probe_many(responder(lambda r: httpx2.Response(200)), []) == []


def test_probe_result_defaults():
    r = ProbeResult(status="blocked", detail="nope")
    assert (r.http_status, r.latency_ms) == (None, None)
