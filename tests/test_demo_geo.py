import asyncio
import json
import pytest

import demo_geo
from demo_geo import ProxyConfig, GeoTestError, location_matches, run_geo_test, new_session_id

ENV = {
    "DEMO_PROXY_ENABLED": "1", "DEMO_PROXY_PROVIDER": "test", "DEMO_PROXY_SERVER": "http://gw.example:8000",
    "DEMO_PROXY_USERNAME_TEMPLATE": "{user}-geo-{geo}-s-{session}", "DEMO_PROXY_USERNAME": "u1", "DEMO_PROXY_PASSWORD": "pw",
    "DEMO_PROXY_GEO_MAP": json.dumps({"lima": "pe_lima", "arequipa": "pe_arequipa", "trujillo": "pe_trujillo"}),
}


def test_missing_lists_names_only_and_disabled_by_default():
    cfg = ProxyConfig.from_env({})
    m = cfg.missing()
    assert "DEMO_PROXY_ENABLED" in m and "DEMO_PROXY_SERVER" in m
    assert all("pw" not in x for x in m)
    assert ProxyConfig.from_env(ENV).missing() == []


def test_sticky_session_distinct_per_context_and_strict_city():
    cfg = ProxyConfig.from_env(ENV)
    a, b = new_session_id(), new_session_id()
    assert a != b
    p = cfg.for_city("lima", a)
    assert p == {"server": "http://gw.example:8000", "username": f"u1-geo-pe_lima-s-{a}", "password": "pw"}
    with pytest.raises(GeoTestError) as e:
        cfg.for_city("cusco", a)
    assert e.value.code == "unknown_city"
    cfg2 = ProxyConfig.from_env({**ENV, "DEMO_PROXY_GEO_MAP": json.dumps({"lima": "x"})})
    with pytest.raises(GeoTestError) as e:
        cfg2.for_city("arequipa", a)
    assert e.value.code == "city_not_configured"


def test_location_match():
    assert location_matches("lima", {"country": "PE", "city": "Lima", "region": "Lima"})[0]
    ok, issues = location_matches("arequipa", {"country": "PE", "city": "Lima", "region": "Lima"})
    assert not ok and issues
    ok, issues = location_matches("lima", {"country": "CL", "city": "Santiago"})
    assert not ok and len(issues) == 2


class FakeResp:
    def __init__(self, status=200, url=""): self.status, self.url = status, url
    @property
    def ok(self): return 200 <= self.status < 300


class FakePage:
    def __init__(self, geo, store_status=200, analytics=True, fail_geo=False):
        self.geo, self.store_status, self.analytics, self.fail_geo = geo, store_status, analytics, fail_geo
        self.handlers, self.visited = [], []
    def on(self, ev, fn): self.handlers.append(fn)
    async def goto(self, url, **kw):
        self.visited.append(url)
        if "ipinfo" in url:
            if self.fail_geo: raise RuntimeError("ERR_PROXY_CONNECTION_FAILED")
            return FakeResp(200)
        if self.analytics:
            for h in self.handlers: h(FakeResp(200, "https://monorail-edge.shopifysvc.com/v1/produce?x=1"))
        return FakeResp(self.store_status)
    async def inner_text(self, sel): return json.dumps(self.geo)
    async def wait_for_timeout(self, ms): return None


class FakeContext:
    def __init__(self, page): self.page, self.closed = page, False
    async def new_page(self): return self.page
    async def close(self): self.closed = True


class FakeBrowser:
    def __init__(self, geos, **kw):
        self.geos, self.kw, self.contexts = geos, kw, []
    async def new_context(self, **kw):
        user = kw["proxy"]["username"]
        city = next(c for c in self.geos if c in user)
        ctx = FakeContext(FakePage(self.geos[city], **self.kw)); ctx.proxy = kw["proxy"]
        self.contexts.append(ctx); return ctx


def run(coro): return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


def test_three_cities_ok_distinct_sessions_and_observations():
    geos = {"lima": {"ip": "1.1.1.1", "country": "PE", "city": "Lima", "region": "Lima"},
            "arequipa": {"ip": "2.2.2.2", "country": "PE", "city": "Arequipa", "region": "Arequipa"},
            "trujillo": {"ip": "3.3.3.3", "country": "PE", "city": "Trujillo", "region": "La Libertad"}}
    br = FakeBrowser(geos)
    res = run(run_geo_test(br, "https://demo.myshopify.com", ["lima", "arequipa", "trujillo"], ProxyConfig.from_env(ENV), dwell_ms=0))
    assert [r.status for r in res] == ["ok", "ok", "ok"]
    assert len({r.session_id for r in res}) == 3
    assert all(r.navigation_completed and r.analytics_request_observed for r in res)
    assert all(r.shopify_session_counted == "non verificabile dal worker" for r in res)
    assert all(c.closed for c in br.contexts)


def test_geo_mismatch_never_visits_store():
    geos = {"lima": {"country": "PE", "city": "Arequipa", "region": "Arequipa"}}
    br = FakeBrowser(geos)
    [r] = run(run_geo_test(br, "https://demo.myshopify.com", ["lima"], ProxyConfig.from_env(ENV), dwell_ms=0))
    assert r.status == "error" and r.error_code == "geo_mismatch"
    assert br.contexts[0].page.visited == ["https://ipinfo.io/json"]
    assert br.contexts[0].closed


def test_proxy_unreachable_is_explicit_and_no_direct_fallback():
    geos = {"lima": {}}
    br = FakeBrowser(geos, fail_geo=True)
    [r] = run(run_geo_test(br, "https://demo.myshopify.com", ["lima"], ProxyConfig.from_env(ENV), dwell_ms=0))
    assert r.error_code == "proxy_unreachable" and not r.navigation_completed
    assert len(br.contexts) == 1  # no second (direct) attempt


def test_not_configured_raises_before_any_browser_use():
    br = FakeBrowser({})
    with pytest.raises(GeoTestError) as e:
        run(run_geo_test(br, "https://demo.myshopify.com", ["lima"], ProxyConfig.from_env({})))
    assert e.value.code == "proxy_not_configured" and br.contexts == []
