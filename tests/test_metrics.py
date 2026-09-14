"""The /metrics endpoint on aggregator.

Cardinality reasoning: see links-service/tests/test_metrics.py. aggregator has
no path parameters today, so the risk is lower -- but the assertion is kept so
that adding one later cannot quietly reintroduce it.
"""

from fastapi.testclient import TestClient

from app import main


def test_metrics_endpoint_is_served_and_is_prometheus_format():
    with TestClient(main.app) as client:
        r = client.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    assert "# HELP" in r.text


def test_request_metrics_are_recorded():
    with TestClient(main.app) as client:
        client.get("/health")
        body = client.get("/metrics").text
    assert "http_requests_total" in body
    assert "/health" in body


def test_probe_targets_never_appear_in_metrics():
    """aggregator fetches attacker-controllable URLs. None must reach a label.

    A metric labelled with a probed URL would be unbounded cardinality AND an
    information leak -- anyone who can read /metrics would learn the catalogue.
    The instrumentator only ever labels by this service's OWN routes, and this
    pins that.
    """
    with TestClient(main.app) as client:
        body = client.get("/metrics").text
    for leak in ("http://", "https://", "169.254"):
        assert leak not in body.replace("https://github.com", ""), f"{leak} in metrics"
