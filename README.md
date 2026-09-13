# aggregator

Service #3 of [app-hub](https://github.com/HarshitRawat11). It reads the link catalogue from `links-service` and **probes every URL**, so the dashboard can show which self-hosted apps are actually reachable rather than just listing them.

Runs on port **8002**. `links-service` owns 8000 and `gateway` owns 8001.

## Why it is its own service

**It proves what `gateway` cannot.** `gateway` is the external entry point, so `gateway → links-service` is "outside talking in". `aggregator` is never publicly reachable, so `gateway → aggregator → links-service` is **pod-to-pod discovery with neither end being the front door** — the claim the whole architecture rests on, and the reason Eureka was dropped.

**Its workload genuinely differs**, which is the honest test of whether something deserves to be a separate service. A CRUD API answers in microseconds from memory. This one sits waiting on dozens of slow third parties, so it wants different timeouts, different concurrency, and eventually a different replica count.

## API

| Method | Path | Returns |
|---|---|---|
| `GET` | `/health` | `{"status": "ok"}`. Checks nothing else — see below |
| `GET` | `/status` | Every link, plus whether it answered |
| `GET` | `/status?refresh=true` | Same, bypassing the cache |

### A down link is data; a down `links-service` is an error

This is the distinction the endpoint exists for.

| Situation | Code |
|---|---|
| A catalogued app is unreachable | **`200`**, with that link marked `down` |
| `links-service` unreachable | `503` |
| `links-service` too slow | `504` |
| `links-service` returned 4xx/5xx | `502` |

Blurring those would leave the dashboard unable to tell *"your NAS is switched off"* from *"the hub is broken"* — and those need completely different reactions.

### Probe statuses

| Status | Means |
|---|---|
| `up` | Answered with anything below 500 |
| `down` | Refused, timed out, or answered 5xx |
| `blocked` | **We refused to fetch it.** See the SSRF section |

**Anything under 500 counts as `up`, including 401 and 403.** The question is *"is the app running?"*, not *"may I in?"*. Marking every auth-protected app as down would make the dashboard cry wolf about most of the catalogue — and a status page that cries wolf gets ignored, at which point it is worse than not having one.

## The SSRF guard, and why it is deliberately narrow

This service fetches URLs that **anyone who can `POST` to `links-service` chose**, from inside the cluster, where it can reach things the author could not. That is textbook SSRF — the value of the attack is precisely the network position this service has.

The obvious mitigation is "block private address space", and **here that is wrong**: app-hub exists to catalogue self-hosted apps on `10.x`, `192.168.x` and `localhost`. Blocking RFC1918 would block the product. A guard that breaks the use case gets deleted within a day, which makes it worth less than a narrow one that stays.

So the guard refuses exactly three things:

- **Link-local addresses** (`169.254.0.0/16`, `fe80::/10`) — `169.254.169.254` is the cloud instance metadata endpoint, the classic route from "will fetch a URL" to "hands over IAM credentials". `C-05` is about to attach a real role to this namespace, which is why this exists *before* the role rather than after.
- **Cloud metadata hostnames**
- **Non-HTTP schemes** — `file://`, `gopher://` and friends

Hostnames are **resolved before checking**, because `http://metadata.example.com/` can point at `169.254.169.254` just as easily as the literal address can be typed.

**It is not airtight, and the gap is documented rather than hidden:** DNS can return a different answer between our lookup and the client's, so a domain owner can still slip through (DNS rebinding). Closing that means resolving once and connecting to the pinned address via a custom transport. Worth doing if this ever probes URLs from an untrusted source; today the only writer is the owner.

## Caching

`/status` caches for **30 seconds** (`STATUS_CACHE_TTL`). Probing every target on every page refresh would turn a browser reload into a burst of outbound traffic to other people's servers.

A lock guards the refresh, so ten simultaneous requests on a cold cache produce **one** probe sweep rather than ten.

## `/health` deliberately checks nothing

It backs the Kubernetes **liveness** probe, and this service's whole job is that other things are allowed to be down. A health check that went red when a catalogued app went down would have Kubernetes restart the one service whose purpose is to report that calmly.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `LINKS_SERVICE_URL` | `http://localhost:8000` | Same name, default and `rstrip` as `gateway` — deliberately. Two services reading one concept under two names is how a deploy goes wrong at 2am. |
| `STATUS_CACHE_TTL` | `30` | Seconds |

In-cluster the Deployment supplies `http://links-service:80` — **the Service's port, not the container's 8000**.

## Running locally

From WSL, with `links-service` already up on 8000:

```bash
uv sync && uv run uvicorn app.main:app --reload --port 8002
```

```bash
curl -s localhost:8002/status | python3 -m json.tool
```

## Tests

```bash
uv run pytest
```

`tests/test_probe.py` covers the guard and the probing; `tests/test_aggregator.py` covers the HTTP surface, the failure mapping and the cache. Nothing touches a socket — every upstream and every probe target is faked with `httpx2.MockTransport`.

Two are worth knowing about: one asserts probes really run **concurrently** by measuring wall-clock time (serial would be 2s, concurrent is under 1s), and one asserts the **concurrency limit** is respected, because an unbounded `gather` over a 200-link catalogue opens 200 sockets at once — indistinguishable from the outside from the cluster port-scanning.

## Background

`learn/28` covers the design decisions. `learn/21` covers the service-to-service call pattern this reuses.
