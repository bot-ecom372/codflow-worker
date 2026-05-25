"""
CodFlow Worker — Spedisci Online integration
Handles: login (CSRF + 2FA TOTP), CSV upload, tracking fetch, reconciliation

Criticità risolte:
- #2: CSRF doppio (_token + X-XSRF-TOKEN, prende SEMPRE ultimo cookie)
- #3: Ghost orders (marca caricato SOLO dopo "importato con successo")
- #4: Duplicati (single-flight + pre-check + reconciliation endpoint)
- #5: 2 endpoint (ordersData per check, shippingsdata per tracking)
- #6: HTML nel tracking (regex extraction)
- #7: Email destinatario sempre vuoto
- #8: TOTP timing (3 retry con sleep 5s)
- #9: Campo "image" per upload CSV
- #10: Sessione scaduta (verifica + invalidazione su errore)
- #11: Importo zero (filtro amount > 0)
- #12: Job bloccato (try/except per singola spedizione)
- #13: Matching multiplo (order_id, order_number, original_order_id, reference)
- #14: Prodotto in note
"""

import os
import re
import csv
import io
import time
import random
import asyncio
import threading
from typing import Optional
from urllib.parse import unquote

import pyotp
import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="CodFlow Worker", version="1.2.0")

# Single-flight lock
_upload_lock = threading.Lock()

# Session cache (in-memory, per base_url:email)
_sessions: dict[str, requests.Session] = {}

WORKER_SECRET = os.getenv("WORKER_SECRET", "codflow-worker-2026")


# ═══════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════

class Credentials(BaseModel):
    base_url: str = "https://speedy.spedisci.online"
    email: str
    password: str
    totp_secret: str
    sender_name: str = "CodFlow Store"


class Order(BaseModel):
    order_id: str
    customer_name: str
    address: str
    cap: str
    city: str
    province: str
    country: str = "IT"
    phone: str = ""
    email: str = ""
    amount: float = 0.0
    product_name: str = ""


class UploadRequest(BaseModel):
    secret: str
    credentials: Credentials
    orders: list[Order]
    force: bool = False  # Skip duplicate pre-check (for manual uploads)


class TrackingRequest(BaseModel):
    secret: str
    credentials: Credentials
    days_back: int = 14


class TestRequest(BaseModel):
    secret: str
    credentials: Credentials


class ReconcileRequest(BaseModel):
    secret: str
    credentials: Credentials
    order_ids: list[str]  # IDs that are "caricato" in our DB


# ═══════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════

def _extract_csrf(html: str) -> Optional[str]:
    """Extract CSRF _token from HTML."""
    m = re.search(r'name="_token"\s+value="([^"]+)"', html)
    return m.group(1) if m else None


def _get_xsrf_token(session: requests.Session) -> str:
    """Get the LAST XSRF-TOKEN cookie value (Criticità #2: multiple cookies)."""
    values = [unquote(c.value) for c in session.cookies if c.name == "XSRF-TOKEN"]
    return values[-1] if values else ""


def _login(creds: Credentials) -> requests.Session:
    """Login to Spedisci: CSRF → credentials → 2FA TOTP."""
    s = requests.Session()
    base = creds.base_url.rstrip("/")

    # Step 1: GET login page → CSRF token
    r = s.get(f"{base}/login", timeout=15)
    r.raise_for_status()
    csrf = _extract_csrf(r.text)
    if not csrf:
        raise Exception("CSRF token not found on login page")

    # Step 2: POST login
    r = s.post(f"{base}/login", data={
        "_token": csrf,
        "email": creds.email,
        "password": creds.password,
    }, allow_redirects=True, timeout=15)
    r.raise_for_status()

    # Check if we landed on 2FA page
    csrf_2fa = _extract_csrf(r.text)
    if not csrf_2fa:
        if "/home" in r.url:
            return s
        raise Exception("Login failed — no 2FA page found. Check credentials.")

    # Step 3: POST 2FA with TOTP (retry up to 3 times — Criticità #8)
    totp = pyotp.TOTP(creds.totp_secret)
    for attempt in range(3):
        otp_code = totp.now()
        r = s.post(f"{base}/2fa", data={
            "_token": csrf_2fa,
            "one_time_password": otp_code,
        }, allow_redirects=True, timeout=15)

        if "/home" in r.url:
            return s

        if attempt < 2:
            time.sleep(5)  # Wait for next TOTP cycle

    raise Exception("2FA failed after 3 attempts")


def _get_session(creds: Credentials) -> requests.Session:
    """Get or create an authenticated session (Criticità #10: session invalidation)."""
    key = f"{creds.base_url}:{creds.email}"

    # Try existing session
    if key in _sessions:
        s = _sessions[key]
        try:
            r = s.get(f"{creds.base_url.rstrip('/')}/home", timeout=10, allow_redirects=False)
            if r.status_code == 200:
                return s
        except:
            pass
        # Session invalid — remove it
        del _sessions[key]

    # Fresh login
    s = _login(creds)
    _sessions[key] = s
    return s


def _invalidate_session(creds: Credentials):
    """Force invalidate a cached session (Criticità #10)."""
    key = f"{creds.base_url}:{creds.email}"
    _sessions.pop(key, None)


def _verify_secret(secret: str):
    if secret != WORKER_SECRET:
        raise HTTPException(status_code=401, detail="Invalid worker secret")


# ═══════════════════════════════════════════
# CSV GENERATION
# ═══════════════════════════════════════════

def _generate_csv(orders: list[Order], sender_name: str) -> str:
    """Generate CSV in Spedisci format."""
    output = io.StringIO()
    writer = csv.writer(output, delimiter=";", quoting=csv.QUOTE_MINIMAL)

    # Header
    writer.writerow([
        "destinatario", "indirizzo", "cap", "localita", "provincia",
        "country", "peso", "colli", "contrassegno", "rif_mittente",
        "rif_destinatario", "note", "telefono", "email_destinatario",
        "contenuto", "order_id", "totale_ordine"
    ])

    for o in orders:
        # Clean phone (remove +39 prefix, keep digits only)
        phone = re.sub(r'[^\d]', '', o.phone)
        if phone.startswith("39") and len(phone) > 10:
            phone = phone[2:]

        writer.writerow([
            o.customer_name,                    # destinatario
            o.address,                          # indirizzo
            o.cap,                              # cap
            o.city,                             # localita
            o.province[:2].upper(),             # provincia (2 letters)
            o.country,                          # country
            "1",                                # peso
            "1",                                # colli
            f"{o.amount:.2f}",                  # contrassegno
            sender_name,                        # rif_mittente
            o.customer_name,                    # rif_destinatario
            (o.product_name or "")[:50],        # note (Criticità #14)
            phone,                              # telefono
            "",                                 # email_destinatario (ALWAYS EMPTY — Criticità #7)
            (o.product_name or "Prodotto")[:50],# contenuto
            o.order_id,                         # order_id
            f"{o.amount:.2f}",                  # totale_ordine
        ])

    return output.getvalue()


# ═══════════════════════════════════════════
# PRE-CHECK ANTI-DUPLICATES
# ═══════════════════════════════════════════

def _get_existing_order_ids(session: requests.Session, base_url: str, days_back: int = 14) -> set[str]:
    """Get order IDs already on Spedisci (uses ordersData — Criticità #5)."""
    from datetime import datetime, timedelta
    base = base_url.rstrip("/")
    now = datetime.now()
    from_date = (now - timedelta(days=days_back)).strftime("%d/%m/%Y 12:00 am")
    to_date = now.strftime("%d/%m/%Y 11:59 pm")

    try:
        r = session.get(f"{base}/orders/ordersData", params={
            "draw": 1, "start": 0, "length": 5000,
            "dalla_data": from_date, "alla_data": to_date,
        }, headers={
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json",
        }, timeout=20)
        r.raise_for_status()
        data = r.json().get("data", [])
        ids = set()
        for item in data:
            # Check multiple fields (Criticità #13)
            for field in ["order_id", "order_number", "original_order_id", "reference"]:
                val = str(item.get(field) or "").strip().lstrip("#")
                if val:
                    ids.add(val)
        return ids
    except Exception as e:
        print(f"[Pre-check] Error fetching existing orders: {e}")
        return set()


# ═══════════════════════════════════════════
# UPLOAD
# ═══════════════════════════════════════════

def _upload_csv(session: requests.Session, base_url: str, csv_content: str) -> dict:
    """Upload CSV to Spedisci."""
    base = base_url.rstrip("/")

    # Step 1: Get CSRF token — try multiple pages since some may be JS-rendered
    csrf = None
    for page in ["/orders/import", "/home", "/orders"]:
        try:
            r = session.get(f"{base}{page}", timeout=15, allow_redirects=True)
            r.raise_for_status()
            csrf = _extract_csrf(r.text)
            if csrf:
                break
        except:
            continue

    if not csrf:
        # Fallback: get CSRF from meta tag
        try:
            r = session.get(f"{base}/home", timeout=15)
            m = re.search(r'<meta\s+name="csrf-token"\s+content="([^"]+)"', r.text)
            if m:
                csrf = m.group(1)
        except:
            pass

    if not csrf:
        raise Exception("CSRF token not found on any page — session may be invalid")

    # Get XSRF token (Criticità #2: always get LAST cookie)
    xsrf = _get_xsrf_token(session)

    # Step 2: Upload (Criticità #9: field name is "image")
    csv_bytes = csv_content.encode("utf-8")
    headers = {}
    if xsrf:
        headers["X-XSRF-TOKEN"] = xsrf

    r = session.post(f"{base}/imports/upload",
        data={"_token": csrf, "save_in_address_book": "0"},
        files={"image": ("orders.csv", csv_bytes, "text/csv")},
        headers=headers,
        timeout=30,
    )
    r.raise_for_status()

    # Criticità #3: only mark success if Spedisci confirms
    success = "importato con successo" in r.text.lower()
    return {"success": success, "status_code": r.status_code, "response_snippet": r.text[:200]}


# ═══════════════════════════════════════════
# TRACKING FETCH
# ═══════════════════════════════════════════

def _fetch_tracking(session: requests.Session, base_url: str, days_back: int = 14) -> list[dict]:
    """Fetch shipping/tracking data from Spedisci (uses shippingsdata — Criticità #5)."""
    from datetime import datetime, timedelta
    base = base_url.rstrip("/")
    now = datetime.now()
    from_date = (now - timedelta(days=days_back)).strftime("%d/%m/%Y 12:00 am")
    to_date = now.strftime("%d/%m/%Y 11:59 pm")

    r = session.get(f"{base}/shippingsdata", params={
        "draw": 1, "start": 0, "length": 5000,
        "dalla_data": from_date, "alla_data": to_date,
    }, headers={
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json",
    }, timeout=20)
    r.raise_for_status()

    data = r.json().get("data", [])
    results = []
    for item in data:
        # Criticità #12: try/except per singola spedizione
        try:
            # Criticità #13: check multiple ID fields
            order_id = ""
            for field in ["order_id", "order_number", "original_order_id", "reference"]:
                val = str(item.get(field) or "").strip().lstrip("#")
                if val:
                    order_id = val
                    break

            ldv_raw = str(item.get("ldv") or "")

            # Criticità #6: Extract tracking from HTML
            tracking = ldv_raw
            m = re.search(r">([^<]+)<", ldv_raw)
            if m:
                tracking = m.group(1).strip()
            else:
                tracking = re.sub(r"<[^>]+>", "", ldv_raw).strip()

            vector_id = item.get("vector_id")
            carrier = "GLS" if vector_id == 2 else "Poste Delivery" if vector_id == 17 else "BRT" if vector_id == 1 else f"Carrier_{vector_id}"

            if order_id and tracking:
                results.append({
                    "order_id": order_id,
                    "tracking_number": tracking,
                    "carrier": carrier,
                    "vector_id": vector_id,
                })
        except Exception as e:
            print(f"[Tracking] Error processing shipment: {e}")
            continue  # Don't block other shipments

    return results


# ═══════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════

@app.get("/")
def health():
    return {"status": "ok", "service": "codflow-worker", "version": "1.1.0"}


@app.post("/test-connection")
def test_connection(req: TestRequest):
    _verify_secret(req.secret)
    try:
        _invalidate_session(req.credentials)  # Force fresh login on test
        s = _login(req.credentials)
        _sessions[f"{req.credentials.base_url}:{req.credentials.email}"] = s
        return {"success": True, "message": "Connessione riuscita"}
    except Exception as e:
        return {"success": False, "message": str(e)}


@app.post("/upload-orders")
def upload_orders(req: UploadRequest):
    _verify_secret(req.secret)

    if not _upload_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Upload already in progress")

    try:
        if not req.orders:
            return {"success": True, "uploaded": 0, "skipped": 0, "message": "No orders to upload"}

        # Criticità #11: Filter out zero-amount orders
        valid_orders = [o for o in req.orders if o.amount > 0]
        if not valid_orders:
            return {"success": True, "uploaded": 0, "skipped": len(req.orders), "message": "All orders have zero amount"}

        # Get session (with auto-invalidation on failure — Criticità #10)
        try:
            session = _get_session(req.credentials)
        except Exception as e:
            _invalidate_session(req.credentials)
            raise Exception(f"Login failed: {e}")

        # Pre-check anti-duplicates (Criticità #4) — skip if force=True
        already_on_spedisci = []
        if req.force:
            # Force upload: skip pre-check entirely
            new_orders = valid_orders
            skipped = 0
        else:
            existing_ids = _get_existing_order_ids(session, req.credentials.base_url)
            new_orders = [o for o in valid_orders if o.order_id.lstrip("#") not in existing_ids]
            skipped = len(valid_orders) - len(new_orders)
            already_on_spedisci = [o.order_id for o in valid_orders if o.order_id.lstrip("#") in existing_ids]

            if not new_orders:
                return {
                    "success": True, "uploaded": 0, "skipped": skipped,
                    "already_on_spedisci": already_on_spedisci,
                    "message": "All orders already on Spedisci"
                }

        # Generate CSV
        csv_content = _generate_csv(new_orders, req.credentials.sender_name)

        # Upload (Criticità #3: only mark success after confirmation)
        try:
            result = _upload_csv(session, req.credentials.base_url, csv_content)
        except Exception as e:
            # Criticità #10: if upload fails, invalidate session for next attempt
            _invalidate_session(req.credentials)
            raise Exception(f"Upload error: {e}")

        if result["success"]:
            uploaded_ids = [o.order_id for o in new_orders]
            return {
                "success": True,
                "uploaded": len(new_orders),
                "uploaded_ids": uploaded_ids,
                "skipped": skipped,
                "already_on_spedisci": already_on_spedisci,
                "message": f"Upload riuscito: {len(new_orders)} ordini caricati"
            }
        else:
            # Upload didn't confirm success — invalidate session
            _invalidate_session(req.credentials)
            return {
                "success": False,
                "uploaded": 0,
                "message": f"Upload failed — Spedisci did not confirm. Response: {result.get('response_snippet', '')[:100]}"
            }

    except Exception as e:
        return {"success": False, "uploaded": 0, "message": str(e)}
    finally:
        _upload_lock.release()


@app.post("/fetch-tracking")
def fetch_tracking(req: TrackingRequest):
    _verify_secret(req.secret)
    try:
        try:
            session = _get_session(req.credentials)
        except Exception as e:
            _invalidate_session(req.credentials)
            raise Exception(f"Login failed: {e}")

        results = _fetch_tracking(session, req.credentials.base_url, req.days_back)
        return {"success": True, "tracking": results, "count": len(results)}
    except Exception as e:
        return {"success": False, "tracking": [], "message": str(e)}


@app.post("/reconcile")
def reconcile(req: ReconcileRequest):
    """Criticità #4: Reconciliation — check which 'caricato' orders actually exist on Spedisci.
    Returns list of order_ids that are NOT found on Spedisci (ghosts)."""
    _verify_secret(req.secret)
    try:
        session = _get_session(req.credentials)
        existing_ids = _get_existing_order_ids(session, req.credentials.base_url, days_back=30)

        ghost_ids = []
        for oid in req.order_ids:
            clean_oid = oid.lstrip("#")
            if clean_oid not in existing_ids:
                ghost_ids.append(oid)

        return {
            "success": True,
            "ghost_ids": ghost_ids,
            "confirmed_on_spedisci": len(req.order_ids) - len(ghost_ids),
            "message": f"{len(ghost_ids)} ordini fantasma trovati" if ghost_ids else "Tutti gli ordini sono su Spedisci"
        }
    except Exception as e:
        return {"success": False, "ghost_ids": [], "message": str(e)}


# ═══════════════════════════════════════════
# DEMO: SHOPIFY LIVE SESSIONS (Playwright)
# ═══════════════════════════════════════════

class SessionRequest(BaseModel):
    store_url: str
    sessions_count: int = 5

_MOBILE_UAS = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/125.0.6422.80 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
]

_DESKTOP_UAS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]

_PRODUCT_PATHS = [
    "/collections/all",
    "/products/camicia-in-maglia-bicolore-con-eleganti-contrasti-1-1-gratis",
    "/products/completo-estivo-t-shirt-e-shorts-coordinati-1-1-gratis",
    "/products/maglietta-aderente-a-righe-eleganza-moderna-1-1-gratis",
    "/products/polo-a-coste-con-bordi-a-contrasto-1-1-gratis",
    "/products/orologio-citizen-cronografo-eco-drive-quadrante-blu",
    "/products/orologio-serie-3-cronografo-sportivo-in-acciaio",
    "/products/polo-con-colletto-dalle-linee-sottili-ed-eleganti-1-1-gratis",
]


@app.get("/demo/test-playwright")
async def test_playwright():
    """Debug endpoint to verify Playwright works."""
    from playwright.async_api import async_playwright
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-setuid-sandbox"])
            page = await browser.new_page()
            await page.goto("https://shopbelmonti.com", timeout=30000)
            title = await page.title()
            await browser.close()
            return {"success": True, "title": title}
    except Exception as e:
        import traceback
        return {"success": False, "error": str(e), "traceback": traceback.format_exc()}


_session_busy = False
_session_started_at: float = 0
_SESSION_MAX_AGE = 65  # Force-clear stale lock after this many seconds


def _session_script(store_url: str, count: int) -> str:
    """Generate a standalone Python script for subprocess execution."""
    paths = ["/", "/collections/all"] + _PRODUCT_PATHS
    mobile_uas = _MOBILE_UAS
    desktop_uas = _DESKTOP_UAS
    return f'''
import asyncio, random, sys, json

async def block_resources(route):
    if route.request.resource_type in ("image", "stylesheet", "font", "media"):
        await route.abort()
    else:
        await route.continue_()

async def main():
    from playwright.async_api import async_playwright
    store_url = {repr(store_url)}
    count = {count}
    paths = {repr(paths)}
    mobile_uas = {repr(mobile_uas)}
    desktop_uas = {repr(desktop_uas)}
    completed = 0
    errors = 0

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=[
            "--no-sandbox", "--disable-setuid-sandbox",
            "--disable-dev-shm-usage", "--disable-gpu",
            "--disable-extensions", "--disable-background-networking",
            "--disable-default-apps", "--disable-sync",
            "--metrics-recording-only", "--no-first-run",
        ])
        for i in range(count):
            ctx = None
            try:
                is_mobile = random.random() < 0.7
                ua = random.choice(mobile_uas if is_mobile else desktop_uas)
                ctx = await browser.new_context(
                    user_agent=ua,
                    viewport={{"width": 390, "height": 844}} if is_mobile else {{"width": 1440, "height": 900}},
                    locale="it-IT",
                    java_script_enabled=True,
                )
                page = await ctx.new_page()
                await page.route("**/*", block_resources)
                path = random.choice(paths)
                await page.goto(f"{{store_url}}{{path}}", wait_until="domcontentloaded", timeout=8000)
                await asyncio.sleep(2)
                completed += 1
            except Exception as e:
                errors += 1
                print(f"Visit {{i}} error: {{e}}", file=sys.stderr)
            finally:
                if ctx:
                    try:
                        await ctx.close()
                    except Exception:
                        pass
        try:
            await browser.close()
        except Exception:
            pass

    print(json.dumps({{"completed": completed, "errors": errors}}))

asyncio.run(main())
'''


@app.post("/demo/sessions")
async def demo_sessions(req: SessionRequest):
    import json as json_mod
    global _session_busy, _session_started_at

    count = min(req.sessions_count, 5)

    # Stale lock recovery: if busy for too long, force-clear
    if _session_busy:
        elapsed = time.time() - _session_started_at
        if elapsed < _SESSION_MAX_AGE:
            return {"success": True, "completed": 0, "errors": 0, "requested": req.sessions_count, "capped": count, "skipped": "busy", "elapsed": round(elapsed)}
        print(f"[Sessions] Stale lock recovered after {elapsed:.0f}s")

    _session_busy = True
    _session_started_at = time.time()

    completed = 0
    errors = 0

    debug_info = ""
    try:
        script = _session_script(req.store_url, count)
        proc = await asyncio.create_subprocess_exec(
            "python3", "-c", script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=55)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            debug_info = "timeout_55s"
            print("[Sessions] Subprocess killed after 55s timeout")
            errors = count
        else:
            stdout_str = stdout.decode().strip()
            stderr_str = stderr.decode().strip()
            if proc.returncode == 0 and stdout_str:
                last_line = stdout_str.split("\n")[-1]
                result = json_mod.loads(last_line)
                completed = result.get("completed", 0)
                errors = result.get("errors", 0)
            else:
                errors = count
                debug_info = f"rc={proc.returncode} stderr={stderr_str[:500]} stdout={stdout_str[:200]}"
                print(f"[Sessions] Subprocess failed: {debug_info}")
    except Exception as e:
        print(f"[Sessions] Error: {e}")
        debug_info = str(e)[:200]
        errors = count
    finally:
        _session_busy = False

    resp = {
        "success": True,
        "completed": completed,
        "errors": errors,
        "requested": req.sessions_count,
        "capped": count,
    }
    if debug_info:
        resp["debug"] = debug_info
    return resp
