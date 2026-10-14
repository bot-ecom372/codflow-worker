"""
Asynchronous demo visit jobs (2026-10-14).

CodFlow sends a batch ("job") of N demo visits with its OWN job id; the worker answers at once
(202) and runs the visits in the background. Guarantees:
  - idempotent: the same job id is never run twice (a resend after a timeout returns the status);
  - bounded: at most MAX_BROWSERS browsers at the same time across all jobs, and at most
    MAX_QUEUED visits waiting — beyond that new jobs are refused (backpressure, 429);
  - stoppable: cancel one job or all jobs; visits not yet started are dropped, a running one
    finishes its current page (never left half-open);
  - each visit = demo_geo._one_session: strict geo, browser-level proxy, utm_source=codflow_demo.
Registry is in memory: a worker restart loses running jobs; CodFlow then marks them "lost"
after a timeout and NEVER resends them (no duplicates).
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Callable, Optional

from demo_geo import ProxyConfig, SessionResult, _one_session

MAX_BROWSERS = max(1, min(4, int(os.getenv("DEMO_GEO_MAX_BROWSERS", "2") or 2)))
MAX_QUEUED = int(os.getenv("DEMO_GEO_MAX_QUEUED", "60") or 60)
VISIT_TIMEOUT_S = 90.0
KEEP_S = 6 * 3600

JOBS: dict[str, dict[str, Any]] = {}
_sem: Optional[asyncio.Semaphore] = None


def _semaphore() -> asyncio.Semaphore:
    global _sem
    if _sem is None:
        _sem = asyncio.Semaphore(MAX_BROWSERS)
    return _sem


def queued_visits() -> int:
    return sum(j["requested"] - j["done"] - j["failed"] - j["rejected"] - j["cancelled"]
               for j in JOBS.values() if j["status"] in ("queued", "running"))


def public(job: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in job.items() if k not in ("_task", "_cancel")}


def _gc() -> None:
    now = time.time()
    for jid in [k for k, j in JOBS.items() if j.get("finished_at") and now - j["finished_at"] > KEEP_S]:
        JOBS.pop(jid, None)


def start_job(job_id: str, cfg: ProxyConfig, store_url: str, cities: list[str], dwell_ms: int,
              launch: Callable) -> tuple[dict[str, Any], bool]:
    """Returns (job, created). Existing id → (job, False): never runs twice."""
    _gc()
    if job_id in JOBS:
        return JOBS[job_id], False
    if queued_visits() + len(cities) > MAX_QUEUED:
        raise OverflowError("coda piena")
    job: dict[str, Any] = {
        "job_id": job_id, "status": "queued", "store_url": store_url, "requested": len(cities),
        "done": 0, "failed": 0, "rejected": 0, "cancelled": 0, "bytes": 0,
        "visits": [], "created_at": time.time(), "started_at": None, "finished_at": None,
        "max_browsers": MAX_BROWSERS, "_cancel": False,
    }
    JOBS[job_id] = job
    job["_task"] = asyncio.create_task(_run(job, cfg, store_url, cities, dwell_ms, launch))
    return job, True


def cancel(job_id: Optional[str] = None) -> int:
    n = 0
    for jid, j in JOBS.items():
        if (job_id is None or jid == job_id) and j["status"] in ("queued", "running"):
            j["_cancel"] = True
            n += 1
    return n


async def _visit(job: dict[str, Any], cfg: ProxyConfig, store_url: str, city: str, dwell_ms: int, launch: Callable) -> None:
    async with _semaphore():
        if job["_cancel"]:
            job["cancelled"] += 1
            return
        job["status"] = "running"
        job["started_at"] = job["started_at"] or time.time()
        res = SessionResult(city=city, session_id="")
        try:
            await asyncio.wait_for(_one_session(launch, store_url, city, cfg, res, dwell_ms), timeout=VISIT_TIMEOUT_S)
        except asyncio.TimeoutError:
            res.status, res.error_code = "error", "timeout"
        except Exception as exc:  # noqa: BLE001 — recorded
            res.status, res.error_code = "error", getattr(exc, "code", "unexpected")
        job["bytes"] += int(res.bytes_received or 0)
        if res.status == "ok" and res.navigation_completed:
            job["done"] += 1
        elif not res.navigation_completed and res.error_code in ("geo_mismatch", "proxy_unreachable", "geo_check_failed", "geo_check_unreadable"):
            job["rejected"] += 1  # strict geo: the store was never visited
        else:
            job["failed"] += 1
        if len(job["visits"]) < 50:
            job["visits"].append({"city": city, "status": res.status, "error_code": res.error_code,
                                  "detected": (res.egress or {}).get("city"), "analytics": res.analytics_request_observed,
                                  "kb": round((res.bytes_received or 0) / 1024)})


async def _run(job: dict[str, Any], cfg: ProxyConfig, store_url: str, cities: list[str], dwell_ms: int, launch: Callable) -> None:
    try:
        await asyncio.gather(*(_visit(job, cfg, store_url, c, dwell_ms, launch) for c in cities))
        job["status"] = "cancelled" if job["_cancel"] and job["cancelled"] else "done"
    except Exception as exc:  # noqa: BLE001
        job["status"], job["error"] = "failed", str(exc)[:200]
    finally:
        job["finished_at"] = time.time()
