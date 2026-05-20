"""
CodFlow Worker — Spedisci Online integration
Handles: login (CSRF + 2FA TOTP), CSV upload, tracking fetch
"""

import os
import re
import csv
import io
import json
import time
import threading
from typing import Optional
from urllib.parse import unquote

import pyotp
import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="CodFlow Worker", version="1.0.0")

# Single-flight lock
_upload_lock = threading.Lock()

# Session cache (in-memory, per base_url)
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


class TrackingRequest(BaseModel):
    secret: str
    credentials: Credentials
    days_back: int = 14


class TestRequest(BaseModel):
    secret: str
    credentials: Credentials


# ═══════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════

def _extract_csrf(html: str) -> Optional[str]:
    """Extract CSRF _token from HTML."""
    m = re.search(r'name="_token"\s+value="([^"]+)"', html)
    return m.group(1) if m else None


def _login(creds: Credentials, session: Optional[requests.Session] = None) -> requests.Session:
    """Login to Spedisci: CSRF → credentials → 2FA TOTP."""
    s = session or requests.Session()
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
        # Maybe already logged in or wrong creds
        if "/home" in r.url:
            return s
        raise Exception("Login failed — no 2FA page found. Check credentials.")

    # Step 3: POST 2FA with TOTP (retry up to 3 times)
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
    """Get or create an authenticated session."""
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

    # Fresh login
    s = _login(creds)
    _sessions[key] = s
    return s


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
            (o.product_name or "")[:50],        # note
            phone,                              # telefono
            "",                                 # email_destinatario (ALWAYS EMPTY)
            (o.product_name or "Prodotto")[:50],# contenuto
            o.order_id,                         # order_id
            f"{o.amount:.2f}",                  # totale_ordine
        ])

    return output.getvalue()


# ═══════════════════════════════════════════
# PRE-CHECK ANTI-DUPLICATES
# ═══════════════════════════════════════════

def _get_existing_order_ids(session: requests.Session, base_url: str, days_back: int = 14) -> set[str]:
    """Get order IDs already on Spedisci."""
    from datetime import datetime, timedelta
    base = base_url.rstrip("/")
    now = datetime.now()
    from_date = (now - timedelta(days=days_back)).strftime("%d/%m/%Y 12:00 am")
    to_date = now.strftime("%d/%m/%Y 11:59 pm")

    try:
        r = session.get(f"{base}/orders/ordersData", params={
            "draw": 1, "start": 0, "length": 2000,
            "dalla_data": from_date, "alla_data": to_date,
        }, headers={
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json",
        }, timeout=20)
        r.raise_for_status()
        data = r.json().get("data", [])
        ids = set()
        for item in data:
            oid = str(item.get("order_id") or item.get("order_number") or "")
            if oid:
                ids.add(oid)
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

    # Step 1: GET import page → CSRF
    r = session.get(f"{base}/orders/import", timeout=15)
    r.raise_for_status()
    csrf = _extract_csrf(r.text)
    if not csrf:
        raise Exception("CSRF token not found on import page")

    # Get XSRF token from cookies
    xsrf = ""
    for cookie in session.cookies:
        if cookie.name == "XSRF-TOKEN":
            xsrf = unquote(cookie.value)

    # Step 2: Upload
    csv_bytes = csv_content.encode("utf-8")
    r = session.post(f"{base}/imports/upload",
        data={"_token": csrf, "save_in_address_book": "0"},
        files={"image": ("orders.csv", csv_bytes, "text/csv")},
        headers={"X-XSRF-TOKEN": xsrf} if xsrf else {},
        timeout=30,
    )
    r.raise_for_status()

    success = "importato con successo" in r.text.lower()
    return {"success": success, "status_code": r.status_code}


# ═══════════════════════════════════════════
# TRACKING FETCH
# ═══════════════════════════════════════════

def _fetch_tracking(session: requests.Session, base_url: str, days_back: int = 14) -> list[dict]:
    """Fetch shipping/tracking data from Spedisci."""
    from datetime import datetime, timedelta
    base = base_url.rstrip("/")
    now = datetime.now()
    from_date = (now - timedelta(days=days_back)).strftime("%d/%m/%Y 12:00 am")
    to_date = now.strftime("%d/%m/%Y 11:59 pm")

    r = session.get(f"{base}/shippingsdata", params={
        "draw": 1, "start": 0, "length": 2000,
        "dalla_data": from_date, "alla_data": to_date,
    }, headers={
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json",
    }, timeout=20)
    r.raise_for_status()

    data = r.json().get("data", [])
    results = []
    for item in data:
        order_id = str(item.get("order_id") or item.get("order_number") or "")
        ldv_raw = str(item.get("ldv") or "")

        # Extract tracking from HTML if wrapped in <a> tag
        tracking = ldv_raw
        m = re.search(r">([^<]+)<", ldv_raw)
        if m:
            tracking = m.group(1).strip()

        vector_id = item.get("vector_id")
        carrier = "GLS" if vector_id == 2 else "Poste Delivery" if vector_id == 17 else f"Carrier_{vector_id}"

        if order_id and tracking:
            results.append({
                "order_id": order_id,
                "tracking_number": tracking,
                "carrier": carrier,
                "vector_id": vector_id,
            })

    return results


# ═══════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════

@app.get("/")
def health():
    return {"status": "ok", "service": "codflow-worker", "version": "1.0.0"}


@app.post("/test-connection")
def test_connection(req: TestRequest):
    _verify_secret(req.secret)
    try:
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

        # Filter out zero-amount orders
        valid_orders = [o for o in req.orders if o.amount > 0]
        if not valid_orders:
            return {"success": True, "uploaded": 0, "skipped": len(req.orders), "message": "All orders have zero amount"}

        # Get session
        session = _get_session(req.credentials)

        # Pre-check anti-duplicates
        existing_ids = _get_existing_order_ids(session, req.credentials.base_url)
        new_orders = [o for o in valid_orders if o.order_id not in existing_ids]
        skipped = len(valid_orders) - len(new_orders)
        already_on_spedisci = [o.order_id for o in valid_orders if o.order_id in existing_ids]

        if not new_orders:
            return {
                "success": True, "uploaded": 0, "skipped": skipped,
                "already_on_spedisci": already_on_spedisci,
                "message": "All orders already on Spedisci"
            }

        # Generate CSV
        csv_content = _generate_csv(new_orders, req.credentials.sender_name)

        # Upload
        result = _upload_csv(session, req.credentials.base_url, csv_content)

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
            return {
                "success": False,
                "uploaded": 0,
                "message": "Upload failed — Spedisci did not confirm success"
            }

    except Exception as e:
        return {"success": False, "uploaded": 0, "message": str(e)}
    finally:
        _upload_lock.release()


@app.post("/fetch-tracking")
def fetch_tracking(req: TrackingRequest):
    _verify_secret(req.secret)
    try:
        session = _get_session(req.credentials)
        results = _fetch_tracking(session, req.credentials.base_url, req.days_back)
        return {"success": True, "tracking": results, "count": len(results)}
    except Exception as e:
        return {"success": False, "tracking": [], "message": str(e)}
