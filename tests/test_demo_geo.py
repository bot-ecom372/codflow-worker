import asyncio
import json
import pytest

import demo_geo
from demo_geo import ProxyConfig, GeoTestError, location_matches, run_geo_test, new_session_id

ENV = {
    "provider": "test", "server": "http://gw.example:8000",
    "username_template": "{user}-geo-{geo}-s-{session}", "user": "u1", "password": "pw",
    "geo_map": {"lima": "pe_lima", "arequipa": "pe_arequipa", "trujillo": "pe_trujillo"},
}


def test_missing_lists_names_only():
    cfg = ProxyConfig.from_dict({})
    m = cfg.missing()
    assert "server" in m and "username_template" in m
    assert all("pw" not in x for x in m)
    assert ProxyConfig.from_dict(ENV).missing() == []


def test_sticky_session_distinct_per_context_and_strict_city():
    cfg = ProxyConfig.from_dict(ENV)
    a, b = new_session_id(), new_session_id()
    assert a != b
    p = cfg.for_city("lima", a)
    assert p == {"server": "http://gw.example:8000", "username": f"u1-geo-pe_lima-s-{a}", "password": "pw"}
    with pytest.raises(GeoTestError) as e:
        cfg.for_city("cusco", a)
    assert e.value.code == "unknown_city"
    cfg2 = ProxyConfig.from_dict({**ENV, "geo_map": {"lima": "x"}})
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


GEO_HOSTS = ("ipinfo", "geojs", "ipwho")


class FakePage:
    """script: per-attempt behaviour for this context — dict with keys
       geo (dict) | fail (str error raised on geo goto) | primary_status (int, e.g. 429)."""
    def __init__(self, script, store_status=200, analytics=True):
        self.script, self.store_status, self.analytics = script, store_status, analytics
        self.handlers, self.visited, self._body = [], [], "{}"
    def on(self, ev, fn): self.handlers.append(fn)
    async def goto(self, url, **kw):
        self.visited.append(url)
        if any(h in url for h in GEO_HOSTS):
            if self.script.get("fail"): raise RuntimeError(self.script["fail"])
            if "ipinfo" in url and self.script.get("primary_status"): return FakeResp(self.script["primary_status"])
            self._body = json.dumps(self.script["geo"]); return FakeResp(200)
        if self.analytics:
            for h in self.handlers: h(FakeResp(200, "https://monorail-edge.shopifysvc.com/v1/produce?x=1"))
        return FakeResp(self.store_status)
    async def inner_text(self, sel): return self._body
    async def wait_for_timeout(self, ms): return None


class FakeContext:
    def __init__(self, page): self.page, self.closed = page, False
    async def new_page(self): return self.page
    async def close(self): self.closed = True


class FakeBrowser:
    """plans: city -> list of per-attempt scripts (last one repeats)."""
    def __init__(self, plans, **kw):
        self.plans, self.kw, self.contexts, self.count, self.closed_browsers = plans, kw, [], {}, 0
    async def launch(self, proxy):
        # browser-level proxy: every context of this browser uses it
        b = self
        class _B:
            async def new_context(_s, **kw):
                assert "proxy" not in kw  # no per-context proxy any more
                return await b._ctx(proxy)
            async def close(_s): b.closed_browsers += 1
        return _B()
    async def _ctx(self, proxy):
        kw = {"proxy": proxy}
        user = kw["proxy"]["username"]
        city = next(c for c in self.plans if f"pe_{c}-" in user)
        i = self.count.get(city, 0); self.count[city] = i + 1
        plan = self.plans[city]
        ctx = FakeContext(FakePage(plan[min(i, len(plan) - 1)], **self.kw)); ctx.proxy = kw["proxy"]
        self.contexts.append(ctx); return ctx


def store_visits(br): return sum(1 for c in br.contexts for u in c.page.visited if "myshopify" in u)


def run(coro): return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


G = {"lima": {"ip": "1.1.1.1", "country": "PE", "city": "Lima", "region": "Lima"},
     "arequipa": {"ip": "2.2.2.2", "country": "PE", "city": "Arequipa", "region": "Arequipa"},
     "trujillo": {"ip": "3.3.3.3", "country": "PE", "city": "Trujillo", "region": "La Libertad"},
     "piura": {"ip": "4.4.4.4", "country": "PE", "city": "Piura", "region": "Piura"}}
CFG = lambda: ProxyConfig.from_dict(ENV)


def test_three_cities_ok_distinct_sessions_and_observations():
    br = FakeBrowser({c: [{"geo": G[c]}] for c in ("lima", "arequipa", "trujillo")})
    res = run(run_geo_test(br.launch, "https://demo.myshopify.com", ["lima", "arequipa", "trujillo"], CFG(), dwell_ms=0))
    assert [r.status for r in res] == ["ok", "ok", "ok"]
    assert len({r.session_id for r in res}) == 3
    assert all(r.navigation_completed and r.analytics_request_observed for r in res)
    assert all(r.shopify_session_counted == "non verificabile dal worker" for r in res)
    assert all(c.closed for c in br.contexts) and store_visits(br) == 3
    assert br.closed_browsers == 3  # one browser per session, each closed


def test_mismatch_every_attempt_never_visits_store():
    br = FakeBrowser({"trujillo": [{"geo": G["piura"]}]})
    [r] = run(run_geo_test(br.launch, "https://demo.myshopify.com", ["trujillo"], CFG(), dwell_ms=0))
    assert r.status == "error" and r.error_code == "geo_mismatch"
    assert len(br.contexts) == 3 and store_visits(br) == 0
    assert len({c.proxy["username"] for c in br.contexts}) == 3  # a NEW sticky session each attempt
    assert [a["result"] for a in r.attempts] == ["geo_mismatch"] * 3
    assert all(c.closed for c in br.contexts)


def test_mismatch_then_match_visits_once_from_verified_session():
    br = FakeBrowser({"trujillo": [{"geo": G["piura"]}, {"geo": G["trujillo"]}]})
    [r] = run(run_geo_test(br.launch, "https://demo.myshopify.com", ["trujillo"], CFG(), dwell_ms=0))
    assert r.status == "ok" and r.geo_match and store_visits(br) == 1
    assert [a["result"] for a in r.attempts] == ["geo_mismatch", "geo_ok"]
    assert r.session_id in br.contexts[1].proxy["username"]  # the visit used the verified session
    assert not any("myshopify" in u for u in br.contexts[0].page.visited)


def test_primary_429_uses_fallback_service_same_session():
    br = FakeBrowser({"lima": [{"geo": G["lima"], "primary_status": 429}]})
    [r] = run(run_geo_test(br.launch, None, ["lima"], CFG(), dwell_ms=0))
    assert r.status == "ok" and r.geo_source == "get.geojs.io" and len(br.contexts) == 1


def test_proxy_tunnel_failure_retries_then_explicit_error_no_direct_fallback():
    br = FakeBrowser({"lima": [{"fail": "net::ERR_TUNNEL_CONNECTION_FAILED"}]})
    [r] = run(run_geo_test(br.launch, "https://demo.myshopify.com", ["lima"], CFG(), dwell_ms=0))
    assert r.error_code == "proxy_unreachable" and not r.navigation_completed
    assert len(br.contexts) == 3 and all("proxy" in vars(c) for c in br.contexts) and store_visits(br) == 0


def test_not_configured_raises_before_any_browser_use():
    br = FakeBrowser({})
    with pytest.raises(GeoTestError) as e:
        run(run_geo_test(br.launch, "https://demo.myshopify.com", ["lima"], ProxyConfig.from_dict({})))
    assert e.value.code == "proxy_not_configured" and br.contexts == []


def test_connection_test_mode_never_visits_store():
    br = FakeBrowser({"lima": [{"geo": G["lima"]}]})
    [r] = run(run_geo_test(br.launch, None, ["lima"], CFG(), dwell_ms=0))
    assert r.status == "ok" and r.geo_match and not r.navigation_completed and store_visits(br) == 0


def test_visits_carry_demo_utm_and_repeated_cities_get_distinct_sessions():
    br = FakeBrowser({"lima": [{"geo": G["lima"]}]})
    res = run(run_geo_test(br.launch, "https://demo.myshopify.com", ["lima", "lima"], CFG(), dwell_ms=0))
    assert len({r.session_id for r in res}) == 2
    assert all("utm_source=codflow_demo" in r.visit_url and "utm_medium=simulated" in r.visit_url for r in res)


def test_fallback_service_country_name_is_not_a_mismatch():
    # geojs / ipwho.is shape: country = full name, country_code = ISO
    assert location_matches("lima", {"country": "Peru", "country_code": "PE", "city": "Lima", "region": "Lima"})[0]
    ok, issues = location_matches("lima", {"country": "Chile", "country_code": "CL", "city": "Santiago"})
    assert not ok
    br = FakeBrowser({"lima": [{"geo": {"ip": "5.5.5.5", "country": "Peru", "country_code": "PE", "city": "Lima", "region": "Lima"}, "primary_status": 429}]})
    [r] = run(run_geo_test(br.launch, None, ["lima"], CFG(), dwell_ms=0))
    assert r.status == "ok" and r.geo_source == "get.geojs.io" and [a["result"] for a in r.attempts] == ["geo_ok"]
