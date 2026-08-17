"""
CodFlow Worker — Aliclik integration (Peru COD / dropshipping platform)

WHY A BROWSER, NOT PLAIN HTTP
─────────────────────────────
Aliclik's API has an aggressive fingerprint anti-bot: any request coming from
*outside* an authenticated browser page (plain requests/httpx, even with every
header spoofed) is rejected with 403 "Access denied". The ONLY reliable path
(proven on real traffic) is to run every API call via `page.evaluate(fetch)`
*inside* a logged-in Playwright page context → 200. So this module keeps ONE
warm authenticated page alive and bridges every API call through it. We never
need to navigate the heavy SPA UI (that route-guard is what gets killed in
headless) — we stay on a light page and only fire fetch() from its context.

API CONTRACT (reverse-engineered from the admin SPA bundle, verified live)
──────────────────────────────────────────────────────────────────────────
  Auth      JWT in localStorage["ALP_AuthToken"] -> {token}. Bearer.
            Headers: x-platform:web, x-aliclik-origin:aliclik-web, x-device:*
  Base      https://aliclik-api-release-f6985904c9e2.herokuapp.com
  whoami    decode JWT payload -> {id, company:{id,countryCode}, role}
  Geo       GET  /ubigeo?countryCode=PER&nivel=1|2|3&parentId=<id>
              nivel1 = departamento, 2 = provincia (parentId=depId),
              3 = distrito (parentId=provId). In Peru the district code
              alone determines province+department.
  Orders    GET  /order/call/all?companyId=..&countryCode=PER&parentId=1
                 &filterDate=creation&startDate=..&endDate=..&page=N
              -> { count, page, limit, result:[...] }
  Deliveries GET /order/order-delivery/list/{orderId}
  Fix addr  PATCH /order/recycle/customer-address
              { orderId, name, lastName, address1, address2, reference,
                districtCode, districtName, phone, lat, lng }
  Note      PATCH /order/masive-note            { orderIds, note }
  Dispatch  PATCH /order/update/massive/dispatch-status
              { orderIds, countryCode, createdBy }   (= "evadir/despachar")
  Shalom    GET  /ubigeo/agency/shalom            (pickup points, sin cobertura)

Every write endpoint defaults to dry_run=True: it resolves + builds the exact
payload and returns it WITHOUT sending, so the caller can preview ("ready to
save") before committing — mirroring how we verify an order before evasion.
"""

import os
import json
import asyncio
import unicodedata
from datetime import datetime, timedelta
from typing import Optional

import httpx

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

ALICLIK_API = "https://aliclik-api-release-f6985904c9e2.herokuapp.com"
ADMIN = "https://admin.aliclik.app"
WORKER_SECRET = os.getenv("WORKER_SECRET", "codflow-worker-2026")
UDATA_DIR = os.getenv("ALICLIK_UDATA", "/tmp/aliclik-udata")
# aliclik's own Google Maps key (referrer-locked to their domain → only usable
# from inside an aliclik.app page). Overridable with a server-side key via env.
_GMAPS_KEY = os.getenv("GMAPS_KEY", "AIzaSyDfqPYsPuygRlXodTtPpNxn_h6N3-IvVTw")

router = APIRouter(prefix="/aliclik", tags=["aliclik"])


def _verify_secret(secret: str):
    if secret != WORKER_SECRET:
        raise HTTPException(status_code=401, detail="Invalid worker secret")


def _norm(s) -> str:
    """Uppercase + strip accents, for tolerant ubigeo name matching."""
    if not s:
        return ""
    s = unicodedata.normalize("NFKD", str(s)).encode("ascii", "ignore").decode()
    return " ".join(s.strip().upper().split())


# ── the fetch bridge, executed INSIDE the authenticated page context ─────────
_API_JS = """async (a) => {
  const raw = localStorage.getItem('ALP_AuthToken');
  if (!raw) return { status: 0, body: 'no-token' };
  const jwt = JSON.parse(raw).token;
  let u = a.base + a.path;
  if (a.params) {
    const q = new URLSearchParams(a.params).toString();
    u += (u.includes('?') ? '&' : '?') + q;
  }
  const opts = { method: a.method, headers: {
    'Authorization': 'Bearer ' + jwt,
    'x-platform': 'web',
    'x-aliclik-origin': 'aliclik-web',
    'x-device': 'Chrome/worker',
    'Content-Type': 'application/json',
  }};
  if (a.data) opts.body = JSON.stringify(a.data);
  const r = await fetch(u, opts);
  const t = await r.text();
  return { status: r.status, body: t };
}"""

_WHOAMI_JS = """() => {
  const raw = localStorage.getItem('ALP_AuthToken');
  if (!raw) return null;
  const jwt = JSON.parse(raw).token;
  const pl = JSON.parse(atob(jwt.split('.')[1]));
  const company = pl.company || {};
  return {
    userId: pl.id || pl.userId || pl.sub,
    companyId: company.id || pl.companyId,
    countryCode: company.countryCode || pl.countryCode || 'PER',
    role: (pl.role && pl.role.name) || null,
  };
}"""


class AliclikSession:
    """One warm authenticated Playwright page, reused across calls."""

    def __init__(self):
        self._pw = None
        self._ctx = None
        self._page = None
        self._email: Optional[str] = None
        self._lock = asyncio.Lock()

    async def _ensure(self, email: str, password: str):
        from playwright.async_api import async_playwright

        # Fast path: page alive, same account, token present.
        if self._page and self._email == email:
            try:
                tok = await self._page.evaluate("() => localStorage.getItem('ALP_AuthToken')")
                if tok and "/login" not in self._page.url:
                    return
            except Exception:
                self._page = None  # page died, rebuild below

        if self._pw is None:
            self._pw = await async_playwright().start()
        if self._ctx is None:
            self._ctx = await self._pw.chromium.launch_persistent_context(
                UDATA_DIR,
                headless=True,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    # Memory-lean flags for the 512MB instance.
                    "--disable-gpu",
                    "--disable-extensions",
                    "--disable-background-networking",
                    "--disable-background-timer-throttling",
                    "--disable-renderer-backgrounding",
                    "--mute-audio",
                ],
                viewport={"width": 1024, "height": 768},
            )
        self._page = self._ctx.pages[0] if self._ctx.pages else await self._ctx.new_page()
        p = self._page

        print("[aliclik] login: loading app…", flush=True)
        await p.goto(ADMIN + "/", wait_until="domcontentloaded", timeout=45000)
        await p.wait_for_timeout(2500)
        tok = await self._read_token(p, wait_for_token=False)
        if not tok or "/login" in p.url:
            for _ in range(6):
                # Avoid a redundant re-navigation when goto('/') already
                # bounced us to /login (double nav is what times out fill).
                if "/login" not in p.url:
                    await p.goto(ADMIN + "/login", wait_until="domcontentloaded",
                                 timeout=45000)
                # Wait for the SPA login form to render + settle before filling
                # (React hydration finishes after networkidle on slow instances).
                try:
                    await p.wait_for_selector("#basic_email", state="visible",
                                              timeout=20000)
                    await p.wait_for_selector("#basic_password", state="visible",
                                              timeout=20000)
                except Exception as e:
                    print(f"[aliclik] form not visible (url={p.url}): {e}", flush=True)
                    await p.wait_for_timeout(2000)
                    continue
                await p.wait_for_timeout(1200)
                try:
                    await p.fill("#basic_email", email, timeout=15000)
                    await p.fill("#basic_password", password, timeout=15000)
                    await p.click('button:has-text("Iniciar sesión")', timeout=15000)
                    print("[aliclik] submitted credentials", flush=True)
                except Exception as e:
                    print(f"[aliclik] fill/submit failed: {e}", flush=True)
                    await p.wait_for_timeout(1500)
                    continue
                try:
                    await p.wait_for_url(lambda u: "/login" not in u, timeout=15000)
                    print(f"[aliclik] redirected to {p.url}", flush=True)
                    break
                except Exception:
                    print(f"[aliclik] no redirect after submit (still {p.url})", flush=True)
                    continue
            # Let the post-login SPA navigation settle so later evaluate() calls
            # don't hit a destroyed execution context.
            try:
                await p.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
                pass
            await p.wait_for_timeout(1500)
        tok = await self._read_token(p, wait_for_token=True)
        if not tok:
            print("[aliclik] login FAILED: no token after login", flush=True)
            raise HTTPException(status_code=502, detail="Aliclik login failed (no token)")
        print("[aliclik] login OK (token acquired)", flush=True)
        self._email = email

    async def _read_token(self, p, wait_for_token=False):
        """Read the JWT from localStorage, tolerating the post-login redirect
        chain that repeatedly tears down the execution context. When
        wait_for_token is True we poll until it appears (we just logged in);
        otherwise we do a quick tolerant probe (may legitimately be None)."""
        attempts = 12 if wait_for_token else 2
        for _ in range(attempts):
            try:
                tok = await p.evaluate("() => localStorage.getItem('ALP_AuthToken')")
                if tok:
                    return tok
                if not wait_for_token:
                    return None
            except Exception:
                pass
            await p.wait_for_timeout(1300)
        return None

    _RETRYABLE = ("context was destroyed", "Execution context",
                  "Failed to fetch", "NetworkError", "net::", "ERR_",
                  "Target closed", "detached")

    async def _eval(self, js, arg="__none__"):
        """page.evaluate with a retry on transient navigation/network errors."""
        for attempt in range(4):
            try:
                if arg == "__none__":
                    return await self._page.evaluate(js)
                return await self._page.evaluate(js, arg)
            except Exception as e:
                msg = str(e)
                if any(k in msg for k in self._RETRYABLE):
                    try:
                        await self._page.wait_for_load_state("networkidle", timeout=10000)
                    except Exception:
                        pass
                    await self._page.wait_for_timeout(1500)
                    continue
                raise
        # last try, let it raise if still broken
        if arg == "__none__":
            return await self._page.evaluate(js)
        return await self._page.evaluate(js, arg)

    async def api(self, email, password, path, method="GET", params=None, data=None):
        async with self._lock:
            await self._ensure(email, password)
            # stringify param values (URLSearchParams wants strings)
            if params:
                params = {k: ("" if v is None else str(v)) for k, v in params.items()}
            res = await self._eval(
                _API_JS,
                {"base": ALICLIK_API, "path": path, "method": method,
                 "params": params, "data": data},
            )
            return res

    async def api_json(self, *a, **k):
        res = await self.api(*a, **k)
        try:
            body = json.loads(res["body"])
        except Exception:
            body = res["body"]
        return res["status"], body

    async def whoami(self, email, password):
        async with self._lock:
            await self._ensure(email, password)
            return await self._eval(_WHOAMI_JS)

    async def _geocode(self, email, password, query):
        """Address -> 'lat,lng'. Uses Google Maps loaded INSIDE the aliclik page
        (their key is referrer-locked to aliclik.app, so it only works in-browser
        — exactly what the operator's 'Confirmar ubicación' does). Falls back to
        Photon (datacenter-friendly OSM geocoder). Returns None on failure."""
        async with self._lock:
            await self._ensure(email, password)
            try:
                res = await self._page.evaluate(
                    """async ({query, key}) => {
                        if (!(window.google && window.google.maps)) {
                            await new Promise((ok, no) => {
                                const s = document.createElement('script');
                                s.src = 'https://maps.googleapis.com/maps/api/js?key=' + key;
                                s.onload = ok; s.onerror = no;
                                document.head.appendChild(s);
                            }).catch(() => {});
                            for (let i=0;i<80 && !(window.google&&window.google.maps);i++)
                                await new Promise(r=>setTimeout(r,100));
                        }
                        if (!(window.google && window.google.maps)) return null;
                        return await new Promise(res => {
                            new google.maps.Geocoder().geocode({address: query},
                              (r, st) => {
                                if (st==='OK' && r && r[0]) {
                                    const l=r[0].geometry.location;
                                    res(l.lat()+','+l.lng());
                                } else res(null);
                              });
                        });
                    }""",
                    {"query": query, "key": _GMAPS_KEY})
                if res:
                    return res
            except Exception:
                pass
        # fallback: Photon (allows datacenter IPs, unlike Nominatim)
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get("https://photon.komoot.io/api/",
                                params={"q": query, "limit": 1})
                feats = (r.json() or {}).get("features") or []
                if feats:
                    lon, lat = feats[0]["geometry"]["coordinates"]
                    return f"{lat},{lon}"
        except Exception:
            pass
        return None

    async def screenshot(self, email, password, path="/order/orders", query=None):
        """Navigate the aliclik admin UI and capture PNG screenshots (base64).
        Debug/demo helper — shows the real order on aliclik. Does NOT save."""
        import base64
        async with self._lock:
            await self._ensure(email, password)
            p = self._page
            out = {}
            try:
                await p.goto(ADMIN + path, wait_until="domcontentloaded", timeout=30000)
                await p.wait_for_timeout(7000)
            except Exception as e:
                out["nav_error"] = str(e)[:200]
            out["url"] = p.url
            try:
                out["page_b64"] = base64.b64encode(await p.screenshot(full_page=True)).decode()
            except Exception as e:
                out["shot_error"] = str(e)[:200]
            if query and "/login" not in p.url:
                try:
                    si = await p.query_selector(
                        "input[placeholder*='Buscar'], input[placeholder*='buscar'], .ant-input")
                    if si:
                        await si.fill(query)
                        await si.press("Enter")
                        await p.wait_for_timeout(4500)
                    await p.evaluate(
                        "() => { const r=document.querySelector('tbody tr');"
                        " if(r){ (r.querySelector('a,button')||r).click(); } }")
                    await p.wait_for_timeout(4000)
                    out["detail_b64"] = base64.b64encode(
                        await p.screenshot(full_page=True)).decode()
                    out["detail_info"] = await p.evaluate(
                        "() => ({ drawer: !!document.querySelector('.ant-drawer,.ant-modal'),"
                        " selects: document.querySelectorAll('.ant-select').length,"
                        " labels: [...document.querySelectorAll('.ant-form-item-label label,label')]"
                        ".map(l=>l.textContent.trim()).filter(Boolean).slice(0,30) })")
                except Exception as e:
                    out["detail_error"] = str(e)[:200]
            return out

    # ── geo ──────────────────────────────────────────────────────────────
    async def _ubigeo(self, email, password, country, nivel, parent_id):
        st, body = await self.api_json(
            email, password, "/ubigeo",
            params={"countryCode": country, "nivel": nivel, "parentId": parent_id or ""},
        )
        return body if isinstance(body, list) else []

    @staticmethod
    def _pick(items, target):
        """Exact-normalized match first, then contains, on name/label/description."""
        t = _norm(target)
        if not t:
            return None
        cand = [(i, _norm(i.get("name") or i.get("label") or i.get("description"))) for i in items]
        for i, nm in cand:
            if nm == t:
                return i
        for i, nm in cand:
            if t in nm or nm in t:
                return i
        return None

    async def resolve_geo(self, email, password, district, province=None,
                          department=None, country="PER"):
        """Messy names -> aliclik ubigeo codes. District is the key output."""
        deps = await self._ubigeo(email, password, country, 1, "")
        dep = self._pick(deps, department) if department else None
        # If department unknown, we must still narrow provinces: try every dep
        # whose provinces contain the target district. Cheapest correct path is
        # to require province OR department; callers (CodFlow AI) supply them.
        dep_ids = [dep["id"]] if dep else [d["id"] for d in deps]
        for did in dep_ids:
            provs = await self._ubigeo(email, password, country, 2, did)
            prov = self._pick(provs, province) if province else None
            prov_ids = [prov["id"]] if prov else [pr["id"] for pr in provs]
            for pid in prov_ids:
                dists = await self._ubigeo(email, password, country, 3, pid)
                dist = self._pick(dists, district)
                if dist:
                    dep_obj = next((d for d in deps if d["id"] == did), None)
                    prov_obj = next((pr for pr in provs if pr["id"] == pid), None)
                    return {
                        "departmentCode": did,
                        "departmentName": (dep_obj or {}).get("name"),
                        "provinceCode": pid,
                        "provinceName": (prov_obj or {}).get("name"),
                        "districtCode": dist["id"],
                        "districtName": dist.get("name"),
                    }
                if not province:
                    # avoid O(prov*dist) blow-up when scanning blindly
                    break
        return None

    # ── orders ───────────────────────────────────────────────────────────
    async def find_order(self, email, password, query, start=None, end=None,
                         max_pages=12, page_size=50):
        """Match a CodFlow order on aliclik by orderNumber, note ("<num> - .."),
        or delivery address. Scans creation-date pages (newest first)."""
        who = await self.whoami(email, password)
        company_id = who["companyId"]
        country = who["countryCode"]
        if not end:
            end = datetime.utcnow().strftime("%Y-%m-%d")
        if not start:
            start = (datetime.utcnow() - timedelta(days=400)).strftime("%Y-%m-%d")
        q = _norm(query)
        base = {
            "companyId": company_id, "countryCode": country, "parentId": 1,
            "filterDate": "creation", "startDate": start, "endDate": end,
            "limit": page_size,
            # server-side search finds ANY order (not just the recent pages)
            "search": query,
        }
        for pg in range(1, max_pages + 1):
            st, body = await self.api_json(
                email, password, "/order/call/all",
                params={**base, "page": pg},
            )
            result = (body or {}).get("result", []) if isinstance(body, dict) else []
            if not result:
                break
            for o in result:
                delivery = (o.get("orderDeliveries") or [{}])[0] or {}
                ship = o.get("shipping") or {}
                num = _norm(o.get("orderNumber"))
                note = _norm(o.get("note"))
                addr = _norm(delivery.get("address") or ship.get("address1"))
                # aliclik orderNumber is "<prefix><orderNumber>" (e.g. BESH15X2561);
                # match the CodFlow number as a suffix too.
                if (num == q or num.endswith(q) or note == q
                        or note.startswith(q + " ") or note.startswith(q + " -")
                        or (q and q in note) or (q and q in addr)):
                    return o
        return None

    async def deliveries(self, email, password, order_id):
        st, body = await self.api_json(
            email, password, f"/order/order-delivery/list/{order_id}")
        return body if isinstance(body, list) else body

    # ── writes (dry_run builds the payload without sending) ───────────────
    async def fix_address(self, email, password, *, order_id, name, last_name,
                          address, district_code, district_name, phone,
                          address2="", reference="", gps="0,0",
                          schedule_date=None, dry_run=True):
        lat, _, lng = (gps or "0,0").partition(",")
        payload = {
            "orderId": order_id,
            "name": name or "",
            "lastName": last_name or "",
            "address1": address or "",
            "address2": address2 or "",
            "reference": reference or "",
            "scheduleDate": schedule_date,
            "districtCode": str(district_code),
            "districtName": district_name or "",
            "phone": str(phone or ""),
            "lat": lat.strip() or "0",
            "lng": (lng.strip() or "0"),
        }
        if dry_run:
            return {"dry_run": True, "method": "PATCH",
                    "url": "/order/recycle/customer-address", "payload": payload}
        st, body = await self.api_json(
            email, password, "/order/recycle/customer-address",
            method="PATCH", data=payload)
        return {"dry_run": False, "status": st, "response": body, "payload": payload}

    async def dispatch(self, email, password, order_ids, dry_run=True):
        who = await self.whoami(email, password)
        payload = {"orderIds": order_ids, "countryCode": who["countryCode"],
                   "createdBy": who["userId"]}
        if dry_run:
            return {"dry_run": True, "method": "PATCH",
                    "url": "/order/update/massive/dispatch-status", "payload": payload}
        st, body = await self.api_json(
            email, password, "/order/update/massive/dispatch-status",
            method="PATCH", data=payload)
        return {"dry_run": False, "status": st, "response": body, "payload": payload}

    async def note(self, email, password, order_ids, text, dry_run=True):
        payload = {"orderIds": order_ids, "note": text}
        if dry_run:
            return {"dry_run": True, "method": "PATCH",
                    "url": "/order/masive-note", "payload": payload}
        st, body = await self.api_json(
            email, password, "/order/masive-note", method="PATCH", data=payload)
        return {"dry_run": False, "status": st, "response": body, "payload": payload}

    async def shalom_agencies(self, email, password, contains=None):
        st, body = await self.api_json(
            email, password, "/ubigeo/agency/shalom")
        items = body if isinstance(body, list) else []
        if contains:
            c = _norm(contains)
            items = [x for x in items if c in _norm(x.get("name"))]
        return items

    async def confirm_order(self, email, password, *, order_query,
                            customer_name, customer_phone, address,
                            department, province, district, product_name,
                            quantity, amount, reference="", gps=None,
                            transport_id=1, dispatch_date=None, dry_run=True):
        """Replicate the operator's full 'Guardar' → POST /order that turns an
        IMPORTED pre-order into a CONFIRMED order ready for dispatch. Builds the
        whole payload from the existing order + the given (CodFlow) data + rules
        (courier=ALIDRIVER id 1, dispatch date=today). dry_run returns the
        payload WITHOUT posting so it can be reviewed first."""
        o = await self.find_order(email, password, order_query)
        if not o:
            raise HTTPException(status_code=404, detail="order not found on aliclik")
        who = await self.whoami(email, password)
        geo = await self.resolve_geo(email, password, district=district,
                                     province=province, department=department)
        if not geo:
            raise HTTPException(status_code=404, detail="could not resolve geo")
        sh = o.get("shipping") or {}
        details = o.get("orderDetails") or []
        if not details:
            raise HTTPException(status_code=400,
                                detail="order has no product details (skuId) to confirm")
        # GPS: ALIDRIVER requires it. Use provided → existing order gps →
        # geocode the address (like the operator's "Confirmar ubicación").
        gps = gps or sh.get("gps")
        if not gps or gps in ("0,0", "0", ",", "0.0,0.0"):
            gps = await self._geocode(email, password,
                                      f"{address}, {district}, {province}, Peru") \
                or await self._geocode(email, password,
                                       f"{district}, {province}, Lima, Peru") or "0,0"
        lat, _, lng = gps.partition(",")
        parts = (customer_name or "").split()
        first = parts[0] if parts else ""
        last = " ".join(parts[1:]) if len(parts) > 1 else ""
        phone = str(customer_phone or sh.get("senderPhone") or "")
        if dispatch_date:
            disp = dispatch_date
        else:
            disp = datetime.utcnow().strftime("%Y-%m-%dT00:00:00.000Z")
        # Preserve the real product line (skuId/price/subtotal from the Shopify
        # import) — only the display name (productDetail) and the COD total are
        # set from the given data.
        line_qty = details[0].get("quantity") or int(quantity or 1)
        amt = float(amount) if amount is not None else (o.get("total") or 0)
        cur = o.get("currency")
        cur = cur.get("code") if isinstance(cur, dict) else (cur or "PEN")
        od = []
        for d in details:
            od.append({
                "price": d.get("price"),
                "quantity": d.get("quantity"),
                "subtotal": d.get("subtotal"),
                "skuId": d.get("skuId"),
                "warehouseId": d.get("warehouseId"),
                "companyId": d.get("companyId"),
                "dropPrice": d.get("dropPrice"),
                "storeCentralProductId": d.get("storeCentralProductId"),
            })
        warehouse_id = o.get("warehouseId") or details[0].get("warehouseId") or -1
        payload = {
            "orderNumber": o.get("orderNumber"),
            "agencyUbigeoId": None,
            "userId": who["userId"],
            "total": amt,
            "prefixPhone": o.get("prefixPhone") or "+51",
            "forceCreateIfTwin": None,
            "confirmationGps": gps,
            "note": "",
            "channel": o.get("channel") or "Shopify",
            "status": o.get("status"),
            "commissionCod": o.get("commissionCod"),
            "reason": "",
            "callStatus": "CONFIRMED",
            "subStatus": o.get("subStatus"),
            "flagDeliveryExpress": o.get("flagDeliveryExpress"),
            "additionalCostExpress": 0,
            "currency": cur,
            "isOrderAgency": False,
            "trackingStatus": o.get("trackingStatus"),
            "paymentType": o.get("paymentType"),
            "shippingCost": sh.get("shippingCost") or 0,
            "managementType": o.get("managementType"),
            "productDetail": f"{line_qty} {product_name}",
            "warehouseName": o.get("warehouseName"),
            "warehouseId": warehouse_id,
            "createdAtShopify": o.get("createdAtShopify"),
            "transportId": transport_id,
            "customer": {"companyId": who["companyId"], "name": customer_name,
                         "lastName": "", "phone": phone},
            "orderDetails": od,
            "preOrderHistory": {},
            "shipping": {
                "id": sh.get("id"),
                "operationCode": sh.get("operationCode"),
                "address1": address, "address2": "", "reference": reference,
                "lat": lat.strip() or "0", "lng": lng.strip() or "0",
                "firstName": first, "firstLastName": last, "secondLastName": "",
                "countryCode": "PER",
                "departmentName": geo["departmentName"],
                "departmentCode": str(geo["departmentCode"]),
                "provinceName": geo["provinceName"],
                "provinceCode": str(geo["provinceCode"]),
                "districtName": geo["districtName"],
                "districtCode": str(geo["districtCode"]),
                "postalCode": None,
                "scheduleDate": disp, "dispatchDate": disp,
                "shippingByAgency": False,
                "shippingCost": sh.get("shippingCost") or 0,
                "senderPhone": phone,
            },
        }
        if dry_run:
            return {"dry_run": True, "order_id": o.get("id"),
                    "orderNumber": o.get("orderNumber"), "payload": payload}
        st, body = await self.api_json(email, password, "/order",
                                       method="POST", data=payload)
        return {"dry_run": False, "status": st, "order_id": o.get("id"),
                "response": body, "payload": payload}


_session = AliclikSession()


# ═══════════════════════════════════════════════════════════════════════════
# API MODELS + ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════

class _Base(BaseModel):
    secret: str
    email: str
    password: str


class ResolveGeoReq(_Base):
    district: str
    province: Optional[str] = None
    department: Optional[str] = None
    country: str = "PER"


class FindOrderReq(_Base):
    query: str
    start: Optional[str] = None
    end: Optional[str] = None


class FixAddressReq(_Base):
    order_id: str
    name: str
    last_name: str = ""
    address: str
    address2: str = ""
    reference: str = ""
    phone: str = ""
    gps: str = "0,0"
    # Provide EITHER resolved district_code OR raw names to resolve here.
    district_code: Optional[str] = None
    district_name: Optional[str] = None
    district: Optional[str] = None
    province: Optional[str] = None
    department: Optional[str] = None
    dry_run: bool = True


class DispatchReq(_Base):
    order_ids: list[str]
    dry_run: bool = True


class NoteReq(_Base):
    order_ids: list[str]
    note: str
    dry_run: bool = True


class ShalomReq(_Base):
    contains: Optional[str] = None


class ConfirmReq(_Base):
    order_query: str
    customer_name: str
    customer_phone: str
    address: str
    reference: str = ""
    department: str
    province: str
    district: str
    product_name: str
    quantity: int = 1
    amount: Optional[float] = None
    gps: Optional[str] = None
    transport_id: int = 1          # 1 = ALIDRIVER
    dispatch_date: Optional[str] = None
    dry_run: bool = True


def _geo_status(order):
    """Is this order's geo broken (needs a recycle fix)?

    The resolved geo lives on the order's `shipping` object — NOT on
    `orderDeliveries` (which is usually empty). districtCode is the source of
    truth: in Peru it uniquely determines province+department (aliclik derives
    the names downstream), so a present districtCode + no "No se encontró"
    marker means the geo is valid.
    """
    ship = order.get("shipping") or {}
    delivery = (order.get("orderDeliveries") or [{}])[0] or {}
    src = ship if (ship.get("districtCode") or ship.get("districtName")
                   or ship.get("address1")) else delivery
    note = _norm(order.get("note"))
    dist_code = src.get("districtCode")
    broken = ("NO SE ENCONTRO" in note) or not dist_code
    return {
        "broken": broken,
        "address": src.get("address1") or src.get("address") or order.get("note"),
        "department": src.get("departmentName"),
        "province": src.get("provinceName"),
        "district": src.get("districtName"),
        "districtCode": dist_code,
        "orderNumber": order.get("orderNumber"),
        "callStatus": order.get("callStatus"),
        "dispatchStatus": order.get("dispatchStatus"),
    }


class ScreenshotReq(_Base):
    path: str = "/order/orders"
    query: Optional[str] = None


class DetailReq(_Base):
    order_id: str


class RawReq(_Base):
    path: str
    params: Optional[dict] = None


@router.post("/whoami")
async def whoami(req: _Base):
    _verify_secret(req.secret)
    return await _session.whoami(req.email, req.password)


@router.post("/screenshot")
async def screenshot(req: ScreenshotReq):
    _verify_secret(req.secret)
    return await _session.screenshot(req.email, req.password,
                                     path=req.path, query=req.query)


@router.post("/order-detail")
async def order_detail(req: DetailReq):
    _verify_secret(req.secret)
    return await _session.deliveries(req.email, req.password, req.order_id)


@router.post("/raw")
async def raw(req: RawReq):
    """Read-only GET passthrough for reconnaissance (build the confirm flow)."""
    _verify_secret(req.secret)
    st, body = await _session.api_json(req.email, req.password, req.path,
                                       params=req.params)
    return {"status": st, "body": body}


@router.post("/test-connection")
async def test_connection(req: _Base):
    _verify_secret(req.secret)
    try:
        who = await _session.whoami(req.email, req.password)
        return {"success": True, "user": who}
    except HTTPException:
        raise
    except Exception as e:
        return {"success": False, "message": str(e)}


@router.post("/resolve-geo")
async def resolve_geo(req: ResolveGeoReq):
    _verify_secret(req.secret)
    res = await _session.resolve_geo(
        req.email, req.password, district=req.district,
        province=req.province, department=req.department, country=req.country)
    if not res:
        raise HTTPException(status_code=404, detail="ubigeo not found for given names")
    return res


@router.post("/find-order")
async def find_order(req: FindOrderReq):
    _verify_secret(req.secret)
    o = await _session.find_order(req.email, req.password, req.query,
                                  start=req.start, end=req.end)
    if not o:
        return {"found": False}
    return {"found": True, "id": o.get("id"), "geo": _geo_status(o), "raw": o}


@router.post("/verify-order")
async def verify_order(req: FindOrderReq):
    _verify_secret(req.secret)
    o = await _session.find_order(req.email, req.password, req.query,
                                  start=req.start, end=req.end)
    if not o:
        return {"found": False}
    return {"found": True, "id": o.get("id"), "geo": _geo_status(o)}


@router.post("/fix-address")
async def fix_address(req: FixAddressReq):
    _verify_secret(req.secret)
    district_code = req.district_code
    district_name = req.district_name
    if not district_code:
        if not req.district:
            raise HTTPException(status_code=400,
                                detail="provide district_code or district name")
        geo = await _session.resolve_geo(
            req.email, req.password, district=req.district,
            province=req.province, department=req.department)
        if not geo:
            raise HTTPException(status_code=404, detail="could not resolve district")
        district_code = geo["districtCode"]
        district_name = district_name or geo["districtName"]
    return await _session.fix_address(
        req.email, req.password, order_id=req.order_id, name=req.name,
        last_name=req.last_name, address=req.address, address2=req.address2,
        reference=req.reference, phone=req.phone, gps=req.gps,
        district_code=district_code, district_name=district_name,
        dry_run=req.dry_run)


@router.post("/dispatch")
async def dispatch(req: DispatchReq):
    _verify_secret(req.secret)
    return await _session.dispatch(req.email, req.password, req.order_ids,
                                   dry_run=req.dry_run)


@router.post("/note")
async def note(req: NoteReq):
    _verify_secret(req.secret)
    return await _session.note(req.email, req.password, req.order_ids, req.note,
                               dry_run=req.dry_run)


@router.post("/shalom-agencies")
async def shalom_agencies(req: ShalomReq):
    _verify_secret(req.secret)
    return await _session.shalom_agencies(req.email, req.password, contains=req.contains)


@router.post("/confirm-order")
async def confirm_order(req: ConfirmReq):
    _verify_secret(req.secret)
    return await _session.confirm_order(
        req.email, req.password, order_query=req.order_query,
        customer_name=req.customer_name, customer_phone=req.customer_phone,
        address=req.address, reference=req.reference, department=req.department,
        province=req.province, district=req.district,
        product_name=req.product_name, quantity=req.quantity, amount=req.amount,
        gps=req.gps, transport_id=req.transport_id,
        dispatch_date=req.dispatch_date, dry_run=req.dry_run)
