import asyncio
import pytest

import demo_jobs
from demo_geo import ProxyConfig

CFG = ProxyConfig.from_dict({"server": "http://gw.example:8000", "username_template": "{user}-c-{geo}-s-{session}",
                             "user": "u", "password": "p", "geo_map": {"lima": "lima", "arequipa": "arequipa", "trujillo": "trujillo"}})
GEO = {"lima": {"country": "PE", "city": "Lima", "region": "Lima"}, "arequipa": {"country": "PE", "city": "Arequipa", "region": "Arequipa"},
       "trujillo": {"country": "PE", "city": "Trujillo", "region": "La Libertad"}}


class Resp:
    def __init__(self, status=200, url="", headers=None): self.status, self.url, self.headers = status, url, headers or {}
    @property
    def ok(self): return 200 <= self.status < 300


class Page:
    def __init__(self, city, stats, delay):
        self.city, self.stats, self.delay, self.body = city, stats, delay, "{}"
    def on(self, *a): pass
    async def route(self, *a): pass
    async def goto(self, url, **kw):
        import json
        if "ipinfo" in url or "geojs" in url or "ipwho" in url:
            self.body = json.dumps(GEO[self.city]); return Resp(200)
        self.stats["store_visits"] += 1
        return Resp(200)
    async def inner_text(self, s): return self.body
    async def wait_for_timeout(self, ms): await asyncio.sleep(self.delay)


class Browser:
    def __init__(self, city, stats, delay): self.city, self.stats, self.delay = city, stats, delay
    async def new_context(self, **kw):
        b = self
        class Ctx:
            async def new_page(_): return Page(b.city, b.stats, b.delay)
            async def close(_): pass
        return Ctx()
    async def close(self):
        self.stats["open"] -= 1


def make_launch(stats, delay=0.02):
    async def launch(proxy):
        city = next(c for c in GEO if f"-{c}-" in proxy["username"])
        stats["open"] += 1
        stats["peak"] = max(stats["peak"], stats["open"])
        return Browser(city, stats, delay)
    return launch


def fresh():
    demo_jobs.JOBS.clear()
    demo_jobs._sem = None
    return {"open": 0, "peak": 0, "store_visits": 0}


async def wait_done(jid):
    for _ in range(500):
        if demo_jobs.JOBS[jid]["status"] in ("done", "cancelled", "failed"): return
        await asyncio.sleep(0.01)


def test_job_runs_all_visits_with_browser_limit_and_counts():
    async def go():
        st = fresh()
        job, created = demo_jobs.start_job("11111111-1111-1111-1111-111111111111", CFG, "https://d.myshopify.com", ["lima", "arequipa", "trujillo"] * 3, 0, make_launch(st))
        assert created
        await wait_done(job["job_id"])
        j = demo_jobs.JOBS[job["job_id"]]
        assert j["status"] == "done" and j["done"] == 9 and j["failed"] == 0
        assert st["store_visits"] == 9 and st["peak"] <= demo_jobs.MAX_BROWSERS
    asyncio.run(go())


def test_same_job_id_never_runs_twice():
    async def go():
        st = fresh()
        jid = "22222222-2222-2222-2222-222222222222"
        demo_jobs.start_job(jid, CFG, "https://d.myshopify.com", ["lima"] * 2, 0, make_launch(st))
        _, created = demo_jobs.start_job(jid, CFG, "https://d.myshopify.com", ["lima"] * 2, 0, make_launch(st))
        assert not created
        await wait_done(jid)
        assert st["store_visits"] == 2
    asyncio.run(go())


def test_cancel_stops_visits_not_started():
    async def go():
        st = fresh()
        jid = "33333333-3333-3333-3333-333333333333"
        demo_jobs.start_job(jid, CFG, "https://d.myshopify.com", ["lima"] * 10, 0, make_launch(st, delay=0.05))
        await asyncio.sleep(0.01)
        assert demo_jobs.cancel() == 1
        await wait_done(jid)
        j = demo_jobs.JOBS[jid]
        assert j["status"] == "cancelled" and j["cancelled"] >= 7 and j["done"] + j["cancelled"] == 10
        assert st["store_visits"] == j["done"]
    asyncio.run(go())


def test_queue_full_is_refused():
    async def go():
        fresh()
        with pytest.raises(OverflowError):
            demo_jobs.start_job("44444444-4444-4444-4444-444444444444", CFG, "https://d.myshopify.com", ["lima"] * (demo_jobs.MAX_QUEUED + 1), 0, make_launch(fresh()))
    asyncio.run(go())
