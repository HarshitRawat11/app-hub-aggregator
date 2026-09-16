"""aggregator — is everything in the catalogue actually up?

Service #3. It reads the link catalogue from links-service and probes every
URL, so the dashboard can show which self-hosted apps are reachable rather
than just listing them.

Why it is a separate service rather than a route on gateway:

  - **It proves the thing gateway cannot.** gateway is the external entry
    point, so a call from gateway to links-service is "outside talking in".
    aggregator is never publicly reachable, so gateway -> aggregator ->
    links-service is pod-to-pod discovery with neither end being the front
    door. That is the claim the whole architecture rests on.
  - Its workload genuinely differs. A CRUD API answers in microseconds from
    memory; this one sits waiting on dozens of slow third parties. Those want
    different timeouts, different concurrency and eventually different replica
    counts -- which is the honest test of whether something deserves to be its
    own service.
"""

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx2
from fastapi import FastAPI, HTTPException
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import BaseModel

from app.probe import ProbeResult, probe_many

logger = logging.getLogger(__name__)

# Same variable, same default, same rstrip as gateway -- deliberately. Two
# services reading one concept under two names is how a deploy goes wrong at
# 2am. See gateway/app/main.py for why the port differs between laptop and
# cluster (8000 is the container's, 80 is the Service's).
LINKS_SERVICE_URL = os.getenv("LINKS_SERVICE_URL", "http://localhost:8000").rstrip("/")

# Probing every target on every request would turn a page refresh into a burst
# of outbound traffic to other people's servers. 30s is short enough that the
# dashboard feels live and long enough that a human mashing reload costs one
# round of probes, not twenty.
CACHE_TTL = float(os.getenv("STATUS_CACHE_TTL", "30"))


class LinkStatus(BaseModel):
    id: str
    name: str
    url: str
    category: str
    icon: str | None = None
    probe: ProbeResult


class StatusReport(BaseModel):
    # An ISO-8601 UTC timestamp, and it is a STRING rather than the float it
    # was until 2026-09-16.
    #
    # It used to carry `time.monotonic()` straight out of the cache entry,
    # which produced responses like `"checked_at": 120573.88`. Monotonic time
    # counts from an arbitrary epoch -- in practice boot -- so that number is
    # meaningless outside the process that produced it. Three ways it was
    # actively wrong, not merely ugly:
    #
    #   - A field named `checked_at` reads as a timestamp, so any client
    #     renders it and gets a date in 1970.
    #   - It is not comparable ACROSS PODS. Two replicas answering the same
    #     question return wildly different values for the same instant.
    #   - It goes BACKWARDS on restart, because the epoch resets.
    #
    # Monotonic is still exactly right for the cache TTL below -- that is what
    # it is for, since it cannot jump when the system clock is adjusted. The
    # bug was never using it; it was publishing it.
    checked_at: str
    age_seconds: float
    cached: bool
    summary: dict[str, int]
    links: list[LinkStatus]


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Two clients, not one, and this is the only structural decision in the
    # file. The call to links-service is to a known, trusted, fast neighbour.
    # The probes go to arbitrary third-party URLs. Sharing one client would
    # mean a catalogue full of slow hosts could exhaust the connection pool
    # that the links-service call also depends on -- so a few dead bookmarks
    # would take out the endpoint entirely.
    app.state.upstream = httpx2.AsyncClient(timeout=3.0)
    app.state.prober = httpx2.AsyncClient(
        timeout=3.0,
        limits=httpx2.Limits(max_connections=20, max_keepalive_connections=5),
        # Probing is not browsing. Identify honestly so anyone reading their
        # own access logs can see what this is.
        headers={"User-Agent": "app-hub-aggregator/0.1 (liveness probe)"},
    )
    app.state.cache = None
    app.state.cache_lock = asyncio.Lock()
    yield
    await app.state.upstream.aclose()
    await app.state.prober.aclose()


app = FastAPI(lifespan=lifespan, title="aggregator")


@app.get("/health")
def health():
    # Does not check links-service and does not probe anything. Same reasoning
    # as the other two services: this backs the liveness probe, so depending on
    # a neighbour here turns one outage into two. It is doubly wrong in this
    # service, whose whole job is that other things are allowed to be down.
    return {"status": "ok"}


async def fetch_links() -> list[dict]:
    url = f"{LINKS_SERVICE_URL}/links"
    try:
        response = await app.state.upstream.get(url)
    except httpx2.TimeoutException:
        logger.warning("timeout calling %s", url)
        raise HTTPException(status_code=504, detail="links-service timed out")
    except httpx2.RequestError as e:
        logger.warning("cannot reach %s: %s", url, e)
        raise HTTPException(status_code=503, detail="links-service unavailable")
    if response.status_code >= 400:
        logger.warning("%s returned HTTP %s", url, response.status_code)
        raise HTTPException(status_code=502, detail="links-service returned an error")
    return response.json()


@app.get("/status", response_model=StatusReport)
async def status(refresh: bool = False):
    """Every link, with whether it answered.

    A link being down is DATA, not an error: this returns 200 with that link
    marked down. The only 5xx here means links-service itself is unreachable --
    that is, the failure is in app-hub rather than in the things it points at.
    Blurring the two would make the dashboard unable to distinguish "your NAS
    is off" from "the hub is broken".
    """
    now = time.monotonic()

    cached = app.state.cache
    if not refresh and cached and (now - cached["monotonic"]) < CACHE_TTL:
        return _report(cached, now, from_cache=True)

    # One probe run at a time. Without this, ten simultaneous requests on a
    # cold cache each start their own full sweep -- ten times the outbound
    # traffic for one answer, and the exact moment it happens is a page that
    # several people opened at once.
    async with app.state.cache_lock:
        cached = app.state.cache
        if not refresh and cached and (time.monotonic() - cached["monotonic"]) < CACHE_TTL:
            # Someone else refreshed it while we waited for the lock.
            return _report(cached, time.monotonic(), from_cache=True)

        links = await fetch_links()
        results = await probe_many(app.state.prober, [link["url"] for link in links])
        app.state.cache = {
            # TWO clocks, deliberately, because they answer different
            # questions and neither can do the other's job.
            #
            # `monotonic` drives the TTL comparison above. It never jumps when
            # NTP corrects the system clock, so a cache entry cannot suddenly
            # look an hour old (or an hour in the future) because of a clock
            # adjustment.
            #
            # `wall` is the one that goes in the response. It is the only one
            # a caller can interpret, compare between pods, or print.
            "monotonic": time.monotonic(),
            "wall": datetime.now(timezone.utc),
            "links": [
                LinkStatus(**link, probe=probe) for link, probe in zip(links, results)
            ],
        }

    return _report(app.state.cache, time.monotonic(), from_cache=False)


def _report(entry: dict, now: float, from_cache: bool) -> StatusReport:
    summary = {"total": len(entry["links"]), "up": 0, "down": 0, "blocked": 0}
    for item in entry["links"]:
        summary[item.probe.status] = summary.get(item.probe.status, 0) + 1
    return StatusReport(
        # Wall clock out, monotonic for the arithmetic. `age_seconds` stays
        # derived from monotonic on purpose: subtracting two wall-clock
        # readings would report a negative age if NTP stepped the clock back
        # between the probe run and this response.
        checked_at=entry["wall"].isoformat(),
        age_seconds=round(now - entry["monotonic"], 1),
        cached=from_cache,
        summary=summary,
        links=entry["links"],
    )

# ---------------------------------------------------------------------------
# /metrics for Prometheus (R-05).
#
# `instrument(app)` adds middleware that times every request; `expose(app)`
# adds the /metrics endpoint Prometheus scrapes. Both at module scope, because
# middleware has to be registered before the app starts serving.
#
# WHY A LIBRARY AND NOT A HAND-ROLLED COUNTER: the hard part of this is not
# counting requests, it is LABEL CARDINALITY. A naive implementation labels by
# the request path, so `/links/<uuid>` creates a brand new time series per id
# -- and with server-generated UUIDs that is unbounded. Prometheus holds
# series in memory; unbounded cardinality is the classic way to OOM it. This
# library groups by the ROUTE TEMPLATE (`/links/{link_id}`) instead, so the
# series count is bounded by the number of routes.
#
# Deliberately exposed on the same port as the app, not a second one. A
# separate metrics port would need another containerPort, another Service
# port and another ServiceMonitor endpoint, to hide something that is not
# secret -- request counts and latencies, on a ClusterIP service.
Instrumentator().instrument(app).expose(app)
