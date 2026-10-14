"""
Demo geo-test sessions (2026-10-12) — CodFlow demo stores only.

One browser context per city, each through its OWN sticky proxy session, then:
  1. egress check THROUGH THAT SAME CONTEXT (geo lookup page) → detected ip/city/region/country;
  2. strict geo: requested city not configured / proxy unreachable / detected location ≠
     requested → explicit error, the store is NOT visited (no direct fallback, no other city);
  3. store visit, recording what we can actually observe:
       navigation_completed       — page loaded (HTTP status)
       analytics_request_observed — a Shopify analytics request left the page (+ status)
     and what we CANNOT observe from here (always reported as not verified):
       shopify_session_counted, live_view_location.

No credentials in code: the proxy config arrives per request from CodFlow. Provider-agnostic:
the provider's geo + sticky-session parameters are expressed through templates (see ProxyConfig).
Nothing here adds browser fingerprint masking; visits carry utm_source=codflow_demo.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Optional

# Cities supported by this first version. Keys are what CodFlow sends.
CITIES: dict[str, dict[str, str]] = {
    "lima": {"label": "Lima", "country": "PE", "match": "lima"},
    "arequipa": {"label": "Arequipa", "country": "PE", "match": "arequipa"},
    "trujillo": {"label": "Trujillo", "country": "PE", "match": "trujillo"},
}

# Requests that carry Shopify storefront analytics (observed, not a proof of counting).
_ANALYTICS_RE = re.compile(r"(monorail-edge\.shopifysvc\.com|/\.well-known/shopify/monorail|/api/collect|/v1/produce|trekkie)", re.I)


class GeoTestError(Exception):
    """Configuration / strict-geo failure with a stable code."""
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class ProxyConfig:
    """
    Generic sticky-geo proxy configuration, sent by CodFlow per request (stored there with the
    credentials encrypted; managed from the DemoSales admin page):

      server             scheme://host:port of the provider gateway
      username_template  must contain {geo} and {session}; may use {user}
      password_template  optional, default "{password}"
      user, password     provider credentials
      geo_map            {"lima": "<provider value>", "arequipa": ..., "trujillo": ...}
      geo_check_url      JSON geo lookup (ip/city/region/country), default https://ipinfo.io/json

    {geo} = provider-specific value for the city (ONLY from geo_map), {session} = fresh random id
    per browser context (sticky session). The exact syntax must come from the chosen provider's
    official documentation — nothing provider-specific is hard-coded here.
    """
    enabled: bool
    provider: str
    server: str
    username_template: str
    password_template: str
    user: str
    password: str
    geo_map: dict[str, str]
    geo_check_url: str
    max_concurrency: int

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ProxyConfig":
        """Config sent by CodFlow for one request (credentials are stored encrypted in CodFlow
        and decrypted server-side; they are never logged or echoed back here)."""
        gm = d.get("geo_map") or {}
        if not isinstance(gm, dict):
            raise GeoTestError("bad_geo_map", "geo_map deve essere un oggetto")
        return cls(
            enabled=True,
            provider=str(d.get("provider") or ""),
            server=str(d.get("server") or ""),
            username_template=str(d.get("username_template") or ""),
            password_template=str(d.get("password_template") or "") or "{password}",
            user=str(d.get("user") or ""),
            password=str(d.get("password") or ""),
            geo_map={str(k).lower(): str(v) for k, v in gm.items()},
            geo_check_url=str(d.get("geo_check_url") or "") or "https://ipinfo.io/json",
            max_concurrency=max(1, min(3, int(d.get("max_concurrency") or 1))),
        )

    def missing(self, cities: Optional[list[str]] = None) -> list[str]:
        """Env vars still missing for the feature to work (names only, never values)."""
        out = []
        if not self.enabled:
            out.append("enabled")
        if not self.server:
            out.append("server")
        if not self.username_template:
            out.append("username_template")
        if "{session}" not in (self.username_template + self.password_template):
            out.append("username_template ({session} mancante: niente sessione sticky)")
        if "{geo}" not in (self.username_template + self.password_template):
            out.append("username_template ({geo} mancante: niente selezione città)")
        if not self.password and "{password}" in self.password_template:
            out.append("password")
        if "{user}" in self.username_template and not self.user:
            out.append("user")
        for c in (cities or list(CITIES)):
            if c not in self.geo_map:
                out.append(f"geo_map[{c}]")
        return out

    def for_city(self, city: str, session_id: str) -> dict[str, str]:
        """Playwright proxy dict for ONE context. Strict: unknown/unmapped city → error."""
        if city not in CITIES:
            raise GeoTestError("unknown_city", f"Città non supportata: {city}")
        if city not in self.geo_map or not self.geo_map[city]:
            raise GeoTestError("city_not_configured", f"Nessun valore geo configurato per {city}")
        values = {"geo": self.geo_map[city], "session": session_id, "user": self.user, "password": self.password}
        try:
            username = self.username_template.format(**values)
            password = self.password_template.format(**values)
        except (KeyError, IndexError, ValueError) as exc:
            raise GeoTestError("bad_template", f"Template proxy non valido: {exc}")
        return {"server": self.server, "username": username, "password": password}


def new_session_id() -> str:
    # Provider-safe charset (letters+digits), distinct per context.
    return "cf" + secrets.token_hex(6)


def location_matches(city: str, detected: dict[str, Any]) -> tuple[bool, list[str]]:
    """Compare requested city with the geo lookup. Returns (ok, discrepancies)."""
    want = CITIES[city]
    issues = []
    # ISO code first: ipinfo puts "PE" in `country`, geojs/ipwho put "Peru" there and the code in
    # `country_code` (2026-10-13 bug: a fallback answer "Peru" was taken for a different country).
    cc = str(detected.get("country_code") or "").strip()
    c2 = str(detected.get("country") or "").strip()
    country = (cc if len(cc) == 2 else c2 if len(c2) == 2 else "").upper()
    if country != want["country"]:
        issues.append(f"paese rilevato {country or '?'} ≠ {want['country']}")
    hay = " ".join(str(detected.get(k) or "") for k in ("city", "region", "regionName")).lower()
    if want["match"] not in hay:
        issues.append(f"località rilevata '{(detected.get('city') or '?')}, {(detected.get('region') or detected.get('regionName') or '?')}' ≠ {want['label']}")
    return (not issues, issues)


# Simulated sessions stay distinguishable in the store's own analytics (UTM attribution).
DEMO_UTM = {"utm_source": "codflow_demo", "utm_medium": "simulated"}


def demo_url(store_url: str, city: str) -> str:
    from urllib.parse import urlencode
    return f"{store_url.rstrip('/')}/?{urlencode({**DEMO_UTM, 'utm_campaign': 'geo_' + city})}"


@dataclass
class SessionResult:
    city: str
    session_id: str
    label: str = "sessione di test demo (non è un cliente reale)"
    visit_url: Optional[str] = None
    status: str = "pending"                     # ok | error
    error_code: Optional[str] = None
    error: Optional[str] = None
    egress: Optional[dict[str, Any]] = None     # ip, city, region, country as seen by the geo check
    geo_match: Optional[bool] = None
    discrepancies: list[str] = field(default_factory=list)
    navigation_completed: bool = False
    navigation_status: Optional[int] = None
    analytics_request_observed: bool = False
    analytics_requests: list[dict[str, Any]] = field(default_factory=list)
    geo_source: Optional[str] = None              # which geo lookup service answered
    bytes_received: int = 0                       # approx. proxy traffic of the store visit (content-length sum)
    attempts: list[dict[str, Any]] = field(default_factory=list)  # one entry per proxy session tried
    shopify_session_counted: str = "non verificabile dal worker"
    live_view_location: str = "non verificata"
    started_at: float = field(default_factory=time.time)
    duration_ms: Optional[int] = None


_run_lock = asyncio.Lock()

# Robustness (2026-10-13), strictness unchanged:
#  - up to MAX_ATTEMPTS proxy sessions per city (a NEW sticky session each time) when the
#    egress check fails or lands in the wrong place — the store is visited at most once, and
#    only from a session verified in the requested city;
#  - fallback geo lookup services, used ONLY when the primary one is unavailable (429/5xx/
#    unreadable) — never to "shop around" for a different answer when it disagrees.
MAX_ATTEMPTS = 3
RETRYABLE = {"proxy_unreachable", "geo_check_failed", "geo_check_unreadable", "geo_mismatch"}
GEO_FALLBACKS = ["https://get.geojs.io/v1/ip/geo.json", "https://ipwho.is/"]


async def _geo_lookup(page, primary: str, city: str) -> tuple[dict[str, Any], str]:
    """Egress location as seen THROUGH this page's proxy. Raises GeoTestError."""
    last_status = None
    for url in [primary] + [u for u in GEO_FALLBACKS if u != primary]:
        try:
            r = await page.goto(url, wait_until="domcontentloaded", timeout=10000)
        except Exception as exc:
            msg = str(exc)
            # The proxy itself refused/failed the tunnel → no point asking another service.
            if "ERR_TUNNEL" in msg or "ERR_PROXY" in msg or "ERR_NO_SUPPORTED_PROXIES" in msg:
                raise GeoTestError("proxy_unreachable", f"Proxy non raggiungibile per {city}: {msg[:200]}")
            last_status = "timeout"
            continue
        if not r or not r.ok:
            last_status = r.status if r else "?"
            continue
        try:
            data = json.loads(await page.inner_text("body"))
        except Exception:
            last_status = "illeggibile"
            continue
        if isinstance(data, dict) and data.get("success") is False:  # ipwho.is error shape
            last_status = "rifiutata"
            continue
        return data, url.split("/")[2]
    raise GeoTestError("geo_check_failed", f"Verifica IP non disponibile (ultimo esito: {last_status})")


async def run_geo_test(launch, store_url: Optional[str], cities: list[str], cfg: ProxyConfig, *, dwell_ms: int = 8000, timeout_s: float = 90.0) -> list[SessionResult]:
    """`launch(proxy)` must return a NEW browser whose WHOLE traffic goes through `proxy`
    (browser-level proxy): a per-context proxy does not cover Shopify's background analytics
    (workers), which then left directly from the server — seen 2026-10-13 as sessions from
    Council Bluffs (US) instead of Peru. One browser per session, closed afterwards.
    One session per entry of `cities` (repeats allowed). store_url None = connection test only
    (egress/geo check, no store visit). Raises GeoTestError for config problems (nothing run)."""
    miss = cfg.missing(sorted(set(cities)))
    if miss:
        raise GeoTestError("proxy_not_configured", "Proxy non configurato: " + ", ".join(miss))
    for c in cities:
        if c not in CITIES:
            raise GeoTestError("unknown_city", f"Città non supportata: {c}")
    if _run_lock.locked():
        raise GeoTestError("busy", "Un'altra prova geografica è in corso")
    async with _run_lock:
        sem = asyncio.Semaphore(cfg.max_concurrency)

        async def one(city: str) -> SessionResult:
            async with sem:
                res = SessionResult(city=city, session_id="")
                try:
                    await asyncio.wait_for(_one_session(launch, store_url, city, cfg, res, dwell_ms), timeout=timeout_s)
                except asyncio.TimeoutError:
                    res.status, res.error_code, res.error = "error", "timeout", f"Sessione oltre {int(timeout_s)}s"
                except GeoTestError as ge:
                    res.status, res.error_code, res.error = "error", ge.code, str(ge)
                except Exception as exc:  # noqa: BLE001 — reported, never swallowed silently
                    res.status, res.error_code, res.error = "error", "unexpected", str(exc)[:300]
                res.duration_ms = int((time.time() - res.started_at) * 1000)
                return res

        return list(await asyncio.gather(*(one(c) for c in cities)))


async def _one_session(launch, store_url: Optional[str], city: str, cfg: ProxyConfig, res: SessionResult, dwell_ms: int) -> None:
    for n in range(1, MAX_ATTEMPTS + 1):
        sid = new_session_id()
        res.session_id = sid
        browser = await launch(cfg.for_city(city, sid))
        context = None
        try:
            context = await browser.new_context(locale="es-PE", timezone_id="America/Lima")
            page = await context.new_page()
            try:
                # 1) Egress check through THIS context (same proxy session as the visit).
                detected, source = await _geo_lookup(page, cfg.geo_check_url, city)
                res.geo_source = source
                res.egress = {k: detected.get(k) for k in ("ip", "city", "region", "regionName", "country", "country_code", "org") if detected.get(k) is not None}
                ok, issues = location_matches(city, detected)
                res.geo_match, res.discrepancies = ok, issues
                if not ok:
                    # Strict: never visit from a different location.
                    raise GeoTestError("geo_mismatch", "Località del proxy diversa da quella richiesta: " + "; ".join(issues))
            except GeoTestError as ge:
                res.attempts.append({"attempt": n, "session_id": sid, "result": ge.code, "detected": (res.egress or {}).get("city") if ge.code == "geo_mismatch" else None})
                if ge.code in RETRYABLE and n < MAX_ATTEMPTS:
                    res.egress = None if ge.code != "geo_mismatch" else res.egress
                    continue
                raise
            res.attempts.append({"attempt": n, "session_id": sid, "result": "geo_ok", "detected": (res.egress or {}).get("city")})

            if store_url is None:  # connection test only
                res.status = "ok"
                return

            # 2) Store visit (once), recording observable analytics traffic.
            # Bandwidth: images, media and fonts are not downloaded (proxy plans are metered);
            # documents, scripts, stylesheets and XHR/beacons — incl. Shopify analytics — load normally.
            async def _skip_heavy(route):
                try:
                    if route.request.resource_type in ("image", "media", "font"):
                        await route.abort()
                    else:
                        await route.continue_()
                except Exception:
                    pass
            await page.route("**/*", _skip_heavy)

            def on_response(resp):
                try:
                    res.bytes_received += int(resp.headers.get("content-length") or 0)
                except Exception:
                    pass
                if _ANALYTICS_RE.search(resp.url):
                    res.analytics_requests.append({"url": resp.url.split("?")[0][:160], "status": resp.status})

            page.on("response", on_response)
            res.visit_url = demo_url(store_url, city)
            nav = await page.goto(res.visit_url, wait_until="domcontentloaded", timeout=25000)
            res.navigation_status = nav.status if nav else None
            res.navigation_completed = bool(nav and nav.ok)
            await page.wait_for_timeout(dwell_ms)
            res.analytics_request_observed = any(200 <= a["status"] < 300 for a in res.analytics_requests)
            res.status = "ok" if res.navigation_completed else "error"
            if not res.navigation_completed:
                res.error_code, res.error = "navigation_failed", f"Store HTTP {res.navigation_status}"
            return
        finally:
            for closer in (context, browser):
                try:
                    if closer is not None:
                        await closer.close()
                except Exception:
                    pass


# ═══════════════════════════════════════════
# DIAGNOSTIC VISIT (2026-10-14): ONE visit, all resources loaded, NOTHING changed in the browser
# (no UA override, no scripts, no consent clicks). Records what is needed to tell "HTTP 200" apart
# from "a valid analytics event": final URL + redirects, JS errors, Shopify consent API state,
# tracking cookies, and the event names/consent fields inside the analytics payloads.
# ═══════════════════════════════════════════
_CONSENT_JS = """() => {
  const out = { has_customer_privacy: false };
  try {
    const cp = window.Shopify && window.Shopify.customerPrivacy;
    if (cp) {
      out.has_customer_privacy = true;
      const call = (f) => { try { return typeof cp[f] === 'function' ? cp[f]() : null; } catch (e) { return 'err:' + e.message; } };
      out.analyticsProcessingAllowed = call('analyticsProcessingAllowed');
      out.marketingAllowed = call('marketingAllowed');
      out.userCanBeTracked = call('userCanBeTracked');
      out.shouldShowBanner = call('shouldShowBanner');
      out.saleOfDataRegion = call('saleOfDataRegion');
      out.currentVisitorConsent = call('currentVisitorConsent');
    }
  } catch (e) { out.error = String(e); }
  const banner = document.querySelector('#shopify-pc__banner, .shopify-pc__banner__dialog, [id*="cookie" i][role="dialog"]');
  out.banner_visible = !!(banner && banner.offsetParent !== null);
  out.user_agent = navigator.userAgent;
  out.webdriver = navigator.webdriver === true;
  out.document_url = location.href;
  return out;
}"""


def _event_names(post: str) -> list[str]:
    names: list[str] = []
    try:
        data = json.loads(post)
    except Exception:
        return re.findall(r'"(?:event_name|name|schema_id)"\s*:\s*"([^"]{1,80})"', post or "")[:20]
    def walk(v, depth=0):
        if depth > 6 or len(names) >= 30:
            return
        if isinstance(v, dict):
            for k in ("event_name", "schema_id", "name"):
                if isinstance(v.get(k), str) and len(v[k]) < 80:
                    names.append(f"{k}={v[k]}")
            for x in v.values():
                walk(x, depth + 1)
        elif isinstance(v, list):
            for x in v:
                walk(x, depth + 1)
    walk(data)
    return names


async def run_diagnostic_visit(launch, store_url: str, city: str, cfg: ProxyConfig, marker: str, dwell_ms: int = 15000) -> dict[str, Any]:
    from urllib.parse import urlencode
    if cfg.missing([city]):
        raise GeoTestError("proxy_not_configured", "Proxy non configurato")
    if _run_lock.locked():
        raise GeoTestError("busy", "Un'altra prova è in corso")
    async with _run_lock:
        out: dict[str, Any] = {"city": city, "marker": marker, "started_at": time.time()}
        sid = new_session_id()
        browser = await launch(cfg.for_city(city, sid))
        context = None
        try:
            context = await browser.new_context(locale="es-PE", timezone_id="America/Lima")
            page = await context.new_page()
            detected, source = await _geo_lookup(page, cfg.geo_check_url, city)
            ok, issues = location_matches(city, detected)
            out["egress"] = {k: detected.get(k) for k in ("ip", "city", "region", "country", "country_code") if detected.get(k) is not None}
            out["geo_match"], out["discrepancies"] = ok, issues
            if not ok:
                out["status"] = "geo_mismatch"
                return out
            js_errors: list[str] = []
            console_errors: list[str] = []
            analytics: list[dict[str, Any]] = []
            failed: list[str] = []
            page.on("pageerror", lambda e: js_errors.append(str(e)[:200]))
            page.on("console", lambda m: console_errors.append(m.text[:200]) if m.type == "error" else None)
            page.on("requestfailed", lambda r: failed.append(f"{r.url.split('?')[0][:120]} {r.failure}"))

            async def on_response(resp):
                if not _ANALYTICS_RE.search(resp.url):
                    return
                req = resp.request
                post = ""
                try:
                    post = req.post_data or ""
                except Exception:
                    pass
                analytics.append({"url": resp.url.split("?")[0][:140], "method": req.method, "status": resp.status,
                                  "events": _event_names(post),
                                  "consent_fields": sorted(set(re.findall(r'"((?:analytics|marketing|preferences|sale_of_data|consent)[a-zA-Z_]*)"\s*:\s*("?[a-zA-Z0-9_]+"?)', post)))[:12]})
            page.on("response", on_response)

            url = f"{store_url.rstrip('/')}/?{urlencode({'utm_source': 'codflow_demo', 'utm_medium': 'simulated', 'utm_campaign': 'diag_' + marker})}"
            out["visit_url"] = url
            nav = await page.goto(url, wait_until="load", timeout=45000)
            chain = []
            r = nav.request if nav else None
            while r is not None:
                chain.append(r.url.split("?")[0][:140])
                r = r.redirected_from
            out["redirect_chain"] = list(reversed(chain))
            out["navigation_status"] = nav.status if nav else None
            await page.wait_for_timeout(dwell_ms)
            out["final_url"] = page.url[:200]
            out["consent"] = await page.evaluate(_CONSENT_JS)
            cookies = await context.cookies()
            out["cookies"] = sorted({c["name"] for c in cookies if c["name"].startswith(("_shopify", "_tracking", "_landing", "_orig", "_y", "_s", "cart"))})
            out["js_errors"] = js_errors[:10]
            out["console_errors"] = console_errors[:10]
            out["failed_requests"] = failed[:10]
            out["analytics"] = analytics[:25]
            out["status"] = "done"
            return out
        finally:
            for closer in (context, browser):
                try:
                    if closer is not None:
                        await closer.close()
                except Exception:
                    pass
            out["duration_ms"] = int((time.time() - out["started_at"]) * 1000)
