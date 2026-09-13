"""The HTTP surface: /health, /status, the cache, and upstream failure.

`test_probe.py` covers the probing itself. This file is about what the service
does with it -- and specifically about the one distinction that makes the
endpoint useful: a link being down is DATA, while links-service being down is
an ERROR.
"""

import contextlib

import httpx2
import pytest
from fastapi.testclient import TestClient

from app import main

CATALOGUE = [
    {"id": "a1", "name": "Grafana", "url": "https://grafana.example/",
     "category": "observability", "icon": "chart"},
    {"id": "b2", "name": "Broken", "url": "https://broken.example/",
     "category": "tools", "icon": None},
    {"id": "c3", "name": "Metadata", "url": "http://169.254.169.254/",
     "category": "tools", "icon": None},
]


@contextlib.contextmanager
def client(catalogue=CATALOGUE, upstream_status=200, upstream_raises=None,
           probe_handler=None):
    """A running aggregator with both of its clients faked.

    A `@contextmanager` wrapping ONE `with TestClient(...)`, not a TestClient
    returned for the caller to enter. Entering a TestClient runs `lifespan`,
    and the first version of this helper entered it itself and then handed it
    back to `with` -- which entered it a second time, re-ran `lifespan`, and
    silently replaced both mocks with the real clients. Eleven tests failed
    against `localhost:8000`.

    `main.app` is resolved per call rather than imported at module scope, for
    the reason spelled out in gateway's helper: a module reload rebinds it
    under any name already imported from it.
    """
    def links_handler(request):
        if upstream_raises:
            raise upstream_raises
        return httpx2.Response(upstream_status, json=catalogue)

    def default_probe(request):
        return httpx2.Response(500 if "broken" in str(request.url) else 200)

    with TestClient(main.app) as c:
        app = main.app
        app.state.upstream = httpx2.AsyncClient(
            transport=httpx2.MockTransport(links_handler))
        app.state.prober = httpx2.AsyncClient(
            transport=httpx2.MockTransport(probe_handler or default_probe))
        app.state.cache = None
        yield c


# ------------------------------------------------------------------ health --

def test_health_does_not_touch_anything():
    """Doubly important in THIS service.

    /health backs the liveness probe. aggregator's entire job is that other
    things are allowed to be down -- so a health check that went red when a
    catalogued app went down would have Kubernetes restart the one service
    whose purpose is to report that calmly.
    """
    with client(upstream_raises=httpx2.ConnectError("gone")) as c:
        r = c.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


# ------------------------------------------------------------------ status --

def test_status_reports_each_link():
    with client() as c:
        r = c.get("/status")
    assert r.status_code == 200
    body = r.json()
    by_name = {x["name"]: x for x in body["links"]}
    assert by_name["Grafana"]["probe"]["status"] == "up"
    assert by_name["Broken"]["probe"]["status"] == "down"
    assert by_name["Metadata"]["probe"]["status"] == "blocked"


def test_a_down_link_is_data_not_an_error():
    """The central distinction in this service.

    Every reachable link in the catalogue is dead, and /status is still 200.
    If this returned 5xx the dashboard could not tell "your NAS is switched
    off" from "the hub is broken" -- and those need completely different
    reactions.

    Note the count: two down, not three. The third entry is the metadata
    address, which is `blocked` -- the guard refuses it before the transport
    is reached, so it never had the chance to be down. The first version of
    this test asserted three and was wrong in exactly the way the two statuses
    exist to prevent.
    """
    def all_dead(request):
        raise httpx2.ConnectError("refused")

    with client(probe_handler=all_dead) as c:
        r = c.get("/status")
    assert r.status_code == 200
    assert r.json()["summary"] == {"total": 3, "up": 0, "down": 2, "blocked": 1}


def test_summary_counts_match_the_links():
    with client() as c:
        body = c.get("/status").json()
    s = body["summary"]
    assert s == {"total": 3, "up": 1, "down": 1, "blocked": 1}
    assert s["total"] == len(body["links"])


def test_link_fields_are_carried_through_untouched():
    """aggregator adds a field; it does not restate links-service's schema.

    Same rule as gateway's opaque POST body. If this service ever starts
    rebuilding link records field by field, a new field added upstream goes
    missing here and looks like a bug in links-service.
    """
    with client() as c:
        body = c.get("/status").json()
    grafana = next(x for x in body["links"] if x["name"] == "Grafana")
    for key, value in CATALOGUE[0].items():
        assert grafana[key] == value


def test_empty_catalogue_is_fine():
    with client(catalogue=[]) as c:
        body = c.get("/status").json()
    assert body["summary"]["total"] == 0
    assert body["links"] == []


# -------------------------------------------------- upstream failure mapping --

@pytest.mark.parametrize("raises,expected", [
    (httpx2.ConnectError("refused"), 503),
    (httpx2.ReadTimeout("slow"), 504),
])
def test_unreachable_links_service_is_an_error(raises, expected):
    """THIS is the failure that is genuinely aggregator's problem to report."""
    with client(upstream_raises=raises) as c:
        r = c.get("/status")
    assert r.status_code == expected


def test_links_service_error_status_maps_to_502():
    with client(upstream_status=500) as c:
        r = c.get("/status")
    assert r.status_code == 502


# ------------------------------------------------------------------- cache --

def test_second_call_is_served_from_cache():
    """Probing every target on every page refresh is abusive to other people.

    Counting requests rather than trusting the flag, because a cache that
    reports `cached: true` while still making the calls is the failure worth
    catching.
    """
    calls = []

    def counting(request):
        calls.append(str(request.url))
        return httpx2.Response(200)

    with client(probe_handler=counting) as c:
        first = c.get("/status").json()
        after_first = len(calls)
        second = c.get("/status").json()

    assert first["cached"] is False
    assert second["cached"] is True
    assert len(calls) == after_first, "cached response still probed"


def test_refresh_bypasses_the_cache():
    calls = []

    def counting(request):
        calls.append(str(request.url))
        return httpx2.Response(200)

    with client(probe_handler=counting) as c:
        c.get("/status")
        after_first = len(calls)
        body = c.get("/status?refresh=true").json()

    assert body["cached"] is False
    assert len(calls) > after_first


def test_expired_cache_is_refetched(monkeypatch):
    monkeypatch.setattr(main, "CACHE_TTL", 0.0)
    calls = []

    def counting(request):
        calls.append(str(request.url))
        return httpx2.Response(200)

    with client(probe_handler=counting) as c:
        c.get("/status")
        after_first = len(calls)
        c.get("/status")

    assert len(calls) > after_first


def test_age_seconds_is_reported():
    with client() as c:
        body = c.get("/status").json()
    assert body["age_seconds"] >= 0


# ------------------------------------------------------------------ config --

def test_links_service_url_default_and_trailing_slash(monkeypatch):
    import importlib

    monkeypatch.delenv("LINKS_SERVICE_URL", raising=False)
    reloaded = importlib.reload(main)
    try:
        assert reloaded.LINKS_SERVICE_URL == "http://localhost:8000"
        monkeypatch.setenv("LINKS_SERVICE_URL", "http://links-service:80/")
        reloaded = importlib.reload(main)
        assert reloaded.LINKS_SERVICE_URL == "http://links-service:80"
    finally:
        monkeypatch.undo()
        importlib.reload(main)
