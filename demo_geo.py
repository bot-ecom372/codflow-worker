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

No credentials in code: everything comes from environment variables. Provider-agnostic: the
provider's geo + sticky-session parameters are expressed through templates (see README in
docstring of ProxyConfig). Nothing here adds browser fingerprint masking.
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
    Generic sticky-geo proxy configuration, from env (never from the request):

      DEMO_PROXY_ENABLED=1
      DEMO_PROXY_PROVIDER=<free label, e.g. the provider name — informational>
      DEMO_PROXY_SERVER=http://host:port          (scheme://host:port of the provider gateway)
      DEMO_PROXY_USERNAME_TEMPLATE=...{geo}...{session}...
      DEMO_PROXY_PASSWORD_TEMPLATE=...            (optional placeholders too; default: no template)
      DEMO_PROXY_PASSWORD=...                     (secret; substituted as {password})
      DEMO_PROXY_USERNAME=...                     (secret base user; substituted as {user})
      DEMO_PROXY_GEO_MAP={"lima":"<provider geo value>", "arequipa":"...", "trujillo":"..."}
      DEMO_GEO_CHECK_URL=https://ipinfo.io/json   (JSON with ip/city/region/country)
      DEMO_GEO_MAX_CONCURRENCY=1

    {geo} = the provider-specific value for the city (taken ONLY from DEMO_PROXY_GEO_MAP),
    {session} = a fresh random id per browser context (sticky session), {user} / {password}.
    The exact syntax (e.g. which username suffix selects city and sticky session) MUST come from
    the chosen provider's official documentation — it is not hard-coded here.
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
    def from_env(cls, env: Optional[dict[str, str]] = None) -> "ProxyConfig":
        e = env if env is not None else os.environ
        try:
            geo_map = json.loads(e.get("DEMO_PROXY_GEO_MAP", "") or "{}")
            if not isinstance(geo_map, dict):
                raise ValueError
        except ValueError:
            raise GeoTestError("bad_geo_map", "DEMO_PROXY_GEO_MAP non è un JSON oggetto valido")
        return cls(
            enabled=e.get("DEMO_PROXY_ENABLED", "") == "1",
            provider=e.get("DEMO_PROXY_PROVIDER", ""),
            server=e.get("DEMO_PROXY_SERVER", ""),
            username_template=e.get("DEMO_PROXY_USERNAME_TEMPLATE", ""),
            password_template=e.get("DEMO_PROXY_PASSWORD_TEMPLATE", "") or "{password}",
            user=e.get("DEMO_PROXY_USERNAME", ""),
            password=e.get("DEMO_PROXY_PASSWORD", ""),
            geo_map={str(k).lower(): str(v) for k, v in geo_map.items()},
            geo_check_url=e.get("DEMO_GEO_CHECK_URL", "") or "https://ipinfo.io/json",
            max_concurrency=max(1, min(3, int(e.get("DEMO_GEO_MAX_CONCURRENCY", "1") or 1))),
        )

    def missing(self) -> list[str]:
        """Env vars still missing for the feature to work (names only, never values)."""
        out = []
        if not self.enabled:
            out.append("DEMO_PROXY_ENABLED")
        if not self.server:
            out.append("DEMO_PROXY_SERVER")
        if not self.username_template:
            out.append("DEMO_PROXY_USERNAME_TEMPLATE")
        if "{session}" not in (self.username_template + self.password_template):
            out.append("DEMO_PROXY_USERNAME_TEMPLATE ({session} mancante: niente sessione sticky)")
        if "{geo}" not in (self.username_template + self.password_template):
            out.append("DEMO_PROXY_USERNAME_TEMPLATE ({geo} mancante: niente selezione città)")
        if not self.password and "{password}" in self.password_template:
            out.append("DEMO_PROXY_PASSWORD")
        if "{user}" in self.username_template and not self.user:
            out.append("DEMO_PROXY_USERNAME")
        for c in CITIES:
            if c not in self.geo_map:
                out.append(f"DEMO_PROXY_GEO_MAP[{c}]")
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
    country = str(detected.get("country") or detected.get("country_code") or "").upper()
    if country != want["country"]:
        issues.append(f"paese rilevato {country or '?'} ≠ {want['country']}")
    hay = " ".join(str(detected.get(k) or "") for k in ("city", "region", "regionName")).lower()
    if want["match"] not in hay:
        issues.append(f"località rilevata '{(detected.get('city') or '?')}, {(detected.get('region') or detected.get('regionName') or '?')}' ≠ {want['label']}")
    return (not issues, issues)


@dataclass
class SessionResult:
    city: str
    session_id: str
    label: str = "sessione di test demo (non è un cliente reale)"
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
    shopify_session_counted: str = "non verificabile dal worker"
    live_view_location: str = "non verificata"
    started_at: float = field(default_factory=time.time)
    duration_ms: Optional[int] = None


_run_lock = asyncio.Lock()


async def run_geo_test(browser, store_url: str, cities: list[str], cfg: ProxyConfig, *, dwell_ms: int = 8000, timeout_s: float = 45.0) -> list[SessionResult]:
    """One session per city. Raises GeoTestError for config problems (nothing visited)."""
    miss = cfg.missing()
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
                res = SessionResult(city=city, session_id=new_session_id())
                try:
                    await asyncio.wait_for(_one_session(browser, store_url, city, cfg, res, dwell_ms), timeout=timeout_s)
                except asyncio.TimeoutError:
                    res.status, res.error_code, res.error = "error", "timeout", f"Sessione oltre {int(timeout_s)}s"
                except GeoTestError as ge:
                    res.status, res.error_code, res.error = "error", ge.code, str(ge)
                except Exception as exc:  # noqa: BLE001 — reported, never swallowed silently
                    res.status, res.error_code, res.error = "error", "unexpected", str(exc)[:300]
                res.duration_ms = int((time.time() - res.started_at) * 1000)
                return res

        return list(await asyncio.gather(*(one(c) for c in cities)))


async def _one_session(browser, store_url: str, city: str, cfg: ProxyConfig, res: SessionResult, dwell_ms: int) -> None:
    proxy = cfg.for_city(city, res.session_id)
    context = await browser.new_context(proxy=proxy, locale="es-PE", timezone_id="America/Lima")
    try:
        page = await context.new_page()
        # 1) Egress check through THIS context (same proxy session as the visit).
        try:
            r = await page.goto(cfg.geo_check_url, wait_until="domcontentloaded", timeout=20000)
        except Exception as exc:
            raise GeoTestError("proxy_unreachable", f"Proxy non raggiungibile per {city}: {str(exc)[:200]}")
        if not r or not r.ok:
            raise GeoTestError("geo_check_failed", f"Verifica IP fallita (HTTP {r.status if r else '?'})")
        try:
            detected = json.loads(await page.inner_text("body"))
        except Exception:
            raise GeoTestError("geo_check_unreadable", "Risposta della verifica IP non leggibile")
        res.egress = {k: detected.get(k) for k in ("ip", "city", "region", "regionName", "country", "country_code", "org") if detected.get(k) is not None}
        ok, issues = location_matches(city, detected)
        res.geo_match, res.discrepancies = ok, issues
        if not ok:
            # Strict: never visit from a different location.
            raise GeoTestError("geo_mismatch", "Località del proxy diversa da quella richiesta: " + "; ".join(issues))

        # 2) Store visit, recording observable analytics traffic.
        def on_response(resp):
            if _ANALYTICS_RE.search(resp.url):
                res.analytics_requests.append({"url": resp.url.split("?")[0][:160], "status": resp.status})

        page.on("response", on_response)
        nav = await page.goto(store_url, wait_until="domcontentloaded", timeout=25000)
        res.navigation_status = nav.status if nav else None
        res.navigation_completed = bool(nav and nav.ok)
        await page.wait_for_timeout(dwell_ms)
        res.analytics_request_observed = any(200 <= a["status"] < 300 for a in res.analytics_requests)
        res.status = "ok" if res.navigation_completed else "error"
        if not res.navigation_completed:
            res.error_code, res.error = "navigation_failed", f"Store HTTP {res.navigation_status}"
    finally:
        try:
            await context.close()
        except Exception:
            pass
