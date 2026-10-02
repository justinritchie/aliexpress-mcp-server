#!/usr/bin/env python3
"""
AliExpress MCP Server

Search AliExpress, pull clean product details, check shipping to the
configured country (default: Canada, prices in CAD), and peek at the cart — all read-only.

Auth: Session cookies from MCP Auth Bridge extension at
~/.mcp-credentials/aliexpress.json
"""

import json
import os
import re
import time
import hashlib
import logging
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote_plus, quote

import httpx
from bs4 import BeautifulSoup
from mcp.server.fastmcp import FastMCP

# ─── Configuration ──────────────────────────────────────────────────────────

CREDENTIALS_PATH = Path(
    os.environ.get("ALIEXPRESS_CREDENTIALS", "~/.mcp-credentials/aliexpress.json")
).expanduser()

COUNTRY = os.environ.get("ALIEXPRESS_COUNTRY", "CA")
CURRENCY = os.environ.get("ALIEXPRESS_CURRENCY", "CAD")
LOCALE = os.environ.get("ALIEXPRESS_LOCALE", "en_US")

# Optional: inject an httpx transport (used by offline tests).
_TRANSPORT: Optional[httpx.BaseTransport] = None

BASE_URL = "https://www.aliexpress.com"
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aliexpress-mcp")


# ─── Auth ───────────────────────────────────────────────────────────────────

def _region_cookie() -> str:
    """aep_usuc_f controls ship-to region, display currency and locale."""
    return f"site=glo&c_tp={CURRENCY}&region={COUNTRY}&b_locale={LOCALE}"


def load_cookies() -> dict[str, str]:
    """
    Load session cookies (optional) from the MCP Auth Bridge credential file,
    then force the region cookie so prices/shipping are for COUNTRY/CURRENCY
    regardless of the account's or the IP's default.
    """
    cookies: dict[str, str] = {}
    if CREDENTIALS_PATH.exists():
        try:
            data = json.loads(CREDENTIALS_PATH.read_text())
            cookies = dict(data.get("cookies", {}) or {})
        except (json.JSONDecodeError, KeyError, AttributeError):
            cookies = {}
    cookies["aep_usuc_f"] = _region_cookie()
    return cookies


def has_login_session(cookies: dict[str, str]) -> bool:
    """True if cookies look like a logged-in session (not just our region cookie)."""
    return any(k in cookies for k in ("xman_us_t", "xman_t", "_m_h5_tk", "x_router_us_f", "aep_common_f"))


def get_client(require_auth: bool = False, referer: str = BASE_URL) -> httpx.Client:
    """Create an HTTP client with session cookies and realistic browser headers."""
    cookies = load_cookies()

    if require_auth and not has_login_session(cookies):
        raise ValueError(
            "No AliExpress session found. Open aliexpress.com in Chrome, "
            "log in, and click 'Save AliExpress' in the MCP Auth Bridge extension."
        )

    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items()) if cookies else ""

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": referer,
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
    }
    if cookie_str:
        headers["Cookie"] = cookie_str

    return httpx.Client(
        transport=_TRANSPORT,
        base_url=BASE_URL,
        headers=headers,
        follow_redirects=True,
        timeout=30.0,
    )


def check_auth_redirect(response: httpx.Response) -> bool:
    """Detect a redirect to the AliExpress login page (expired session)."""
    url = str(response.url).lower()
    return "login.aliexpress" in url or "/login.htm" in url or "passport" in url


AUTH_EXPIRED_MSG = (
    "AliExpress session expired or missing. Open aliexpress.com in Chrome, "
    "log in, and click 'Save AliExpress' in the MCP Auth Bridge extension."
)


# ─── MTOP API Client ────────────────────────────────────────────────────────
#
# The AliExpress product detail page is client-side-rendered — window.runParams
# is empty in the initial HTML. Real data loads via signed MTOP AJAX calls.
# We replicate the signing algorithm the `mtop.js` library uses in-browser:
#
#   token   = cookie `_m_h5_tk` split on `_` → first segment
#   appKey  = "12574478" (the public web app key)
#   t       = current timestamp in ms as a string
#   data    = JSON string of the request payload
#   sign    = md5( token + "&" + t + "&" + appKey + "&" + data )
#
# The response is wrapped in an HTTP envelope. When ret[0] starts with
# "FAIL_SYS_TOKEN_EMPTY" or "FAIL_SYS_TOKEN_EXOIRED" the server returns fresh
# `_m_h5_tk` cookies — the real browser retries; we can too.

MTOP_APP_KEY = "12574478"

# Anonymous/refreshed MTOP token cookies, kept in memory for the server's
# lifetime so the bootstrap round-trip happens once, not on every call.
_TOKEN_CACHE: dict[str, str] = {}
MTOP_BASE = "https://acs.aliexpress.com"


def _mtop_sign(token: str, t_ms: str, app_key: str, data: str) -> str:
    raw = f"{token}&{t_ms}&{app_key}&{data}"
    return hashlib.md5(raw.encode("utf-8")).hexdigest()


def _h5_token_prefix(cookies: dict[str, str]) -> Optional[str]:
    """Extract the signing token prefix from the _m_h5_tk cookie."""
    raw = cookies.get("_m_h5_tk", "")
    if not raw:
        return None
    # Cookie shape: <token>_<expiry-ms>
    return raw.split("_", 1)[0] or None


def mtop_call(
    api: str,
    version: str,
    payload: dict[str, Any],
    *,
    cookies: Optional[dict[str, str]] = None,
    retries: int = 1,
    referer: Optional[str] = None,
) -> dict:
    """
    Make a signed MTOP request. Returns the parsed JSON response dict on success.

    Raises RuntimeError on signing/network failure.
    """
    if cookies is None:
        cookies = {**load_cookies(), **_TOKEN_CACHE}

    # No token yet (anonymous use): sign with an empty token. MTOP replies
    # FAIL_SYS_TOKEN_EMPTY and sets a fresh _m_h5_tk cookie; the retry below
    # then signs properly — the same dance mtop.js does in a fresh browser.
    token = _h5_token_prefix(cookies) or ""
    if not token and retries < 1:
        raise RuntimeError("MTOP token bootstrap failed (no _m_h5_tk issued).")

    data_str = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    t_ms = str(int(time.time() * 1000))
    sign = _mtop_sign(token, t_ms, MTOP_APP_KEY, data_str)

    params = {
        "jsv": "2.6.2",
        "appKey": MTOP_APP_KEY,
        "t": t_ms,
        "sign": sign,
        "api": api,
        "v": version,
        "type": "originaljson",
        "dataType": "json",
        "timeout": "20000",
        "AntiCreep": "true",
        "AntiFlood": "true",
        "data": data_str,
    }

    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": referer or f"{BASE_URL}/",
        "Origin": BASE_URL,
        "Cookie": cookie_str,
    }
    url = f"{MTOP_BASE}/h5/{api}/{version}/"

    with httpx.Client(timeout=30.0, follow_redirects=True, transport=_TRANSPORT) as c:
        resp = c.get(url, params=params, headers=headers)

        # MTOP sometimes wraps valid JSON inside `mtopjsonp1({...})` even when
        # we request originaljson. Strip the wrapper if present.
        text = resp.text.strip()
        if text.startswith("mtopjsonp") and text.endswith(")"):
            inner = text.split("(", 1)[1][:-1]
            text = inner

        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"MTOP returned non-JSON: {text[:200]}") from e

        ret = data.get("ret", [])
        ret_str = ret[0] if ret else ""

        # Retry once if the token expired (the server will have set fresh cookies).
        # httpx.Response.cookies iterates as cookie-name strings, so pull values by key.
        if retries > 0 and any(
            s in ret_str for s in ("FAIL_SYS_TOKEN_EMPTY", "FAIL_SYS_TOKEN_EXOIRED", "TOKEN_EMPTY", "TOKEN_EXPIRED")
        ):
            new_cookies = dict(cookies)
            for name in resp.cookies:
                val = resp.cookies.get(name)
                if val is not None:
                    new_cookies[name] = val
            if _h5_token_prefix(new_cookies) is None:
                return data  # server didn't issue a token; surface the failure
            for k in ("_m_h5_tk", "_m_h5_tk_enc"):
                if k in new_cookies:
                    _TOKEN_CACHE[k] = new_cookies[k]
            return mtop_call(api, version, payload, cookies=new_cookies, retries=retries - 1, referer=referer)

        return data


def _walk_find(obj: Any, match_keys: set) -> Any:
    """Depth-first walk; return the first value whose key is in match_keys."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in match_keys and v not in (None, "", {}, []):
                return v
        for v in obj.values():
            r = _walk_find(v, match_keys)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = _walk_find(v, match_keys)
            if r is not None:
                return r
    return None


# ─── Parsing Helpers ────────────────────────────────────────────────────────

CURRENCY_TOKENS = r"(?:₪|ILS|NIS|C\$|CA\$|US\$|A\$|\$|€|EUR|£|GBP|CAD|USD)"
# Symbol before ("₪12.34", "US $5") or after ("12.34₪", "1,234.50 ILS").
# Assumes en_US number format (comma = thousands separator).
PRICE_RE = re.compile(CURRENCY_TOKENS + r"\s*([\d,]+(?:\.\d{1,2})?)")
PRICE_AFTER_RE = re.compile(r"([\d,]+(?:\.\d{1,2})?)\s*" + CURRENCY_TOKENS)
ANY_PRICE_RE = re.compile(r"(?:" + CURRENCY_TOKENS + r"\s*)?[\d,]+\.\d{2}(?:\s*" + CURRENCY_TOKENS + r")?")


def fmt_money(v: Optional[float], currency: Optional[str] = None) -> str:
    return f"{v:,.2f} {currency or CURRENCY}" if v is not None else "?"
ITEM_ID_RE = re.compile(r"/item/(\d+)\.html")


def parse_price(text: str) -> Optional[float]:
    """Pull the first price-looking number out of a string."""
    if not text:
        return None
    m = PRICE_RE.search(text) or PRICE_AFTER_RE.search(text)
    if m:
        try:
            return float(m.group(1).replace(",", ""))
        except ValueError:
            return None
    # Fallback: bare number
    m = re.search(r"([\d,]+\.\d{2})", text)
    if m:
        try:
            return float(m.group(1).replace(",", ""))
        except ValueError:
            return None
    return None


def _extract_embedded_json(html: str, var_names: list[str]) -> Optional[dict]:
    """
    AliExpress embeds product/search data in <script> tags like:
        window.runParams = {...}
        window._d_c_._hycdylydh = function() { ... data: {...} }
    Try to grab the JSON blob.
    """
    for name in var_names:
        pattern = re.compile(
            r"window\." + re.escape(name) + r"\s*=\s*(\{.*?\});?\s*\n",
            re.DOTALL,
        )
        m = pattern.search(html)
        if m:
            blob = m.group(1)
            try:
                return json.loads(blob)
            except json.JSONDecodeError:
                pass

    # Generic: look for `data: {...}` inside the runParams pattern
    m = re.search(r"window\.runParams\s*=\s*(\{.*?\});", html, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            return None
    return None


_ITEMLIST_KEY = '"itemList":{"content":'


def _search_items_from_itemlist(html: str) -> list[dict]:
    """
    Current (verified live, Oct 2026) search layout: product cards are embedded
    as `"itemList":{"content":[...]}` inside the _dida_config_ init blob, not in
    window.runParams. Locate the array and JSON-decode it in place.
    """
    i = html.find(_ITEMLIST_KEY)
    if i < 0:
        return []
    try:
        arr, _ = json.JSONDecoder().raw_decode(html, i + len(_ITEMLIST_KEY))
    except json.JSONDecodeError:
        return []
    out: list[dict] = []
    for it in arr if isinstance(arr, list) else []:
        if not isinstance(it, dict):
            continue
        pid = it.get("productId") or it.get("redirectedId")
        t = it.get("title")
        title = t.get("displayTitle") if isinstance(t, dict) else t
        if not pid or not title:
            continue
        prices = it.get("prices") or {}
        sp = prices.get("salePrice") or {}
        op = prices.get("originalPrice") or {}
        price = sp.get("minPrice") if isinstance(sp, dict) else None
        orig = op.get("minPrice") if isinstance(op, dict) else None
        disc = sp.get("discount") if isinstance(sp, dict) else None
        if disc is None and price and orig and orig > price:
            disc = round((1 - price / orig) * 100)
        ev = it.get("evaluation") or {}
        rating = ev.get("starRating") if isinstance(ev, dict) else None
        tags = []
        for sp_ in it.get("sellingPoints") or []:
            tc = (sp_ or {}).get("tagContent") or {}
            txt = tc.get("tagText") or tc.get("displayTagText")
            if txt:
                tags.append(str(txt))
        out.append({
            "item_id": str(pid),
            "title": str(title).strip(),
            "price": float(price) if isinstance(price, (int, float)) else None,
            "original_price": float(orig) if isinstance(orig, (int, float)) else None,
            "currency": (sp.get("currencyCode") if isinstance(sp, dict) else None) or CURRENCY,
            "discount_pct": int(disc) if isinstance(disc, (int, float)) and disc else None,
            "rating": float(rating) if isinstance(rating, (int, float)) else None,
            "sold_count": (it.get("trade") or {}).get("tradeDesc"),
            "tags": tags,
            "url": f"{BASE_URL}/item/{pid}.html",
        })
    return out


def parse_search_results(html: str) -> list[dict]:
    """Parse product cards from an AliExpress search results page."""
    current = _search_items_from_itemlist(html)
    if current:
        return current

    # Legacy layouts below (window.runParams / HTML cards), kept as fallbacks.
    products: list[dict] = []
    seen_ids: set[str] = set()

    # Approach 1: extract from embedded JSON (most reliable)
    data = _extract_embedded_json(html, ["runParams", "_dida_"])
    if data:
        # Walk the structure looking for lists of items
        items_pool: list[dict] = []

        def walk(obj):
            if isinstance(obj, dict):
                # Common keys where items live
                for k in ("mods", "items", "itemList", "resultList"):
                    v = obj.get(k)
                    if isinstance(v, list):
                        for it in v:
                            if isinstance(it, dict):
                                items_pool.append(it)
                for v in obj.values():
                    walk(v)
            elif isinstance(obj, list):
                for v in obj:
                    walk(v)

        walk(data)

        for it in items_pool:
            # Heuristic: needs a productId or itemId
            pid = (
                it.get("productId")
                or it.get("itemId")
                or it.get("product_id")
                or it.get("id")
            )
            title = (
                it.get("title", {}).get("displayTitle")
                if isinstance(it.get("title"), dict)
                else it.get("title")
            ) or it.get("subject") or it.get("name")
            if not pid or not title:
                continue
            pid = str(pid)
            if pid in seen_ids:
                continue

            price_info = it.get("prices") or it.get("price") or {}
            sale_price = None
            original_price = None
            if isinstance(price_info, dict):
                sp = price_info.get("salePrice") or price_info.get("formattedPrice")
                op = price_info.get("originalPrice") or price_info.get("strikePrice")
                if isinstance(sp, dict):
                    sale_price = sp.get("minPrice") or parse_price(sp.get("formattedPrice", ""))
                elif sp:
                    sale_price = parse_price(str(sp))
                if isinstance(op, dict):
                    original_price = op.get("minPrice") or parse_price(op.get("formattedPrice", ""))
                elif op:
                    original_price = parse_price(str(op))

            discount_pct = None
            d = it.get("discount") or (price_info.get("discount") if isinstance(price_info, dict) else None)
            if d:
                dm = re.search(r"(\d+)", str(d))
                if dm:
                    discount_pct = int(dm.group(1))

            trade = it.get("trade") or {}
            sold_count = trade.get("tradeDesc") if isinstance(trade, dict) else None

            rating = None
            ev = it.get("evaluation") or {}
            if isinstance(ev, dict):
                r = ev.get("starRating") or ev.get("rating")
                if r:
                    try:
                        rating = float(r)
                    except (TypeError, ValueError):
                        rating = None

            seen_ids.add(pid)
            products.append({
                "item_id": pid,
                "title": title.strip(),
                "price": sale_price,
                "original_price": original_price,
                "discount_pct": discount_pct,
                "rating": rating,
                "sold_count": sold_count,
                "url": f"{BASE_URL}/item/{pid}.html",
            })

        if products:
            return products

    # Approach 2: HTML fallback
    soup = BeautifulSoup(html, "html.parser")
    for link in soup.select("a[href*='/item/']"):
        href = link.get("href", "")
        m = ITEM_ID_RE.search(href)
        if not m:
            continue
        pid = m.group(1)
        if pid in seen_ids:
            continue

        # Climb up to the card container
        card = link.find_parent(["div", "article", "li"]) or link
        title_el = card.select_one("h1, h2, h3, [class*='title'], [class*='Title']")
        title = title_el.get_text(strip=True) if title_el else link.get("title") or ""
        if not title:
            continue

        card_text = card.get_text(" ", strip=True)
        sale_price = parse_price(card_text)

        # Try to find a second (higher) price for original
        original_price = None
        all_prices = [parse_price(t) for t in ANY_PRICE_RE.findall(card_text)]
        all_prices = [p for p in all_prices if p is not None]
        if len(all_prices) >= 2:
            sale_price = min(all_prices)
            original_price = max(all_prices)

        discount_pct = None
        dm = re.search(r"-?(\d{1,2})%", card_text)
        if dm:
            discount_pct = int(dm.group(1))

        sold_match = re.search(r"([\d,]+\+?)\s*sold", card_text, re.IGNORECASE)
        sold_count = sold_match.group(0) if sold_match else None

        rating = None
        rmatch = re.search(r"\b([0-4]\.\d|5\.0)\b", card_text)
        if rmatch:
            try:
                rating = float(rmatch.group(1))
            except ValueError:
                pass

        seen_ids.add(pid)
        products.append({
            "item_id": pid,
            "title": title[:200],
            "price": sale_price,
            "original_price": original_price,
            "discount_pct": discount_pct,
            "rating": rating,
            "sold_count": sold_count,
            "url": f"{BASE_URL}/item/{pid}.html",
        })

    return products


def parse_product_detail(html: str, item_id: str) -> dict:
    """Parse a product detail page."""
    soup = BeautifulSoup(html, "html.parser")

    details = {
        "item_id": item_id,
        "url": f"{BASE_URL}/item/{item_id}.html",
        "title": None,
        "price": None,
        "original_price": None,
        "discount_pct": None,
        "rating": None,
        "sold_count": None,
        "seller_name": None,
        "shipping_cost": None,
        "shipping_estimate": None,
        "variants": [],
    }

    # Title
    if soup.title:
        t = soup.title.get_text(strip=True)
        # AliExpress titles often have " | AliExpress" or similar suffix
        t = re.sub(r"\s*[|–-]\s*(AliExpress|aliexpress).*$", "", t, flags=re.IGNORECASE)
        details["title"] = t or None

    h1 = soup.select_one("h1")
    if h1 and h1.get_text(strip=True):
        details["title"] = h1.get_text(strip=True)

    # Try embedded JSON first
    data = _extract_embedded_json(html, ["runParams"])
    if data:
        # Walk for useful nuggets
        def find_first(obj, keys):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k in keys and v not in (None, "", {}):
                        return v
                    r = find_first(v, keys)
                    if r is not None:
                        return r
            elif isinstance(obj, list):
                for v in obj:
                    r = find_first(v, keys)
                    if r is not None:
                        return r
            return None

        price_node = find_first(data, {"priceModule", "price", "priceInfo"})
        if isinstance(price_node, dict):
            sp = price_node.get("minActivityAmount") or price_node.get("formatedActivityPrice") or price_node.get("formatedPrice")
            op = price_node.get("formatedPrewarmingPrice") or price_node.get("maxAmount")
            if isinstance(sp, dict):
                details["price"] = sp.get("value") or parse_price(sp.get("formattedPrice", ""))
            elif sp:
                details["price"] = parse_price(str(sp))
            if isinstance(op, dict):
                details["original_price"] = op.get("value")
            elif op:
                details["original_price"] = parse_price(str(op))

        title_node = find_first(data, {"title", "subject"})
        if isinstance(title_node, str) and not details["title"]:
            details["title"] = title_node

        seller_node = find_first(data, {"storeName", "sellerName", "storeInfo"})
        if isinstance(seller_node, str):
            details["seller_name"] = seller_node
        elif isinstance(seller_node, dict):
            details["seller_name"] = seller_node.get("name") or seller_node.get("storeName")

        ship_node = find_first(data, {"shippingModule", "logistics"})
        if isinstance(ship_node, dict):
            details["shipping_cost"] = parse_price(str(ship_node.get("formattedFreight", "")))
            details["shipping_estimate"] = ship_node.get("deliveryDate") or ship_node.get("etd")

    # Fallbacks from rendered HTML body text
    body_text = soup.get_text(" ", strip=True)

    if details["price"] is None:
        # Look for a currency-prefixed price near the top
        price_el = soup.select_one("[class*='price'], [class*='Price']")
        if price_el:
            details["price"] = parse_price(price_el.get_text(" ", strip=True))

    # Discount
    dmatch = re.search(r"-(\d{1,2})%", body_text)
    if dmatch:
        details["discount_pct"] = int(dmatch.group(1))

    # Rating
    rmatch = re.search(r"\b([0-4]\.\d|5\.0)\s*(?:out of|/)\s*5", body_text)
    if rmatch:
        try:
            details["rating"] = float(rmatch.group(1))
        except ValueError:
            pass
    elif details["rating"] is None:
        rmatch = re.search(r"\b([0-4]\.\d|5\.0)\b\s*\(?\d", body_text)
        if rmatch:
            try:
                details["rating"] = float(rmatch.group(1))
            except ValueError:
                pass

    # Sold count
    sold_match = re.search(r"([\d,]+\+?)\s*sold", body_text, re.IGNORECASE)
    if sold_match:
        details["sold_count"] = sold_match.group(0)

    return details


def parse_cart(html: str) -> dict:
    """Parse cart page HTML for item list and totals."""
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text("\n", strip=True)

    result: dict = {
        "items": [],
        "subtotal": None,
        "shipping_total": None,
        "grand_total": None,
        "raw_snippet": None,
    }

    # Extract item links
    items_by_id: dict[str, dict] = {}
    for link in soup.select("a[href*='/item/']"):
        href = link.get("href", "")
        m = ITEM_ID_RE.search(href)
        if not m:
            continue
        pid = m.group(1)
        if pid in items_by_id:
            continue
        title = link.get("title") or link.get_text(strip=True)
        if not title or len(title) < 4:
            continue

        card = link.find_parent(["div", "li", "article"]) or link
        card_text = card.get_text(" ", strip=True)
        all_prices = [parse_price(t) for t in ANY_PRICE_RE.findall(card_text)]
        all_prices = [p for p in all_prices if p is not None]
        sale_price = min(all_prices) if all_prices else None

        qty_match = re.search(r"(?:Qty|Quantity|x)\s*[:\s]\s*(\d+)", card_text, re.IGNORECASE)
        qty = int(qty_match.group(1)) if qty_match else 1

        items_by_id[pid] = {
            "item_id": pid,
            "title": title[:200],
            "price": sale_price,
            "quantity": qty,
            "url": f"{BASE_URL}/item/{pid}.html",
        }

    result["items"] = list(items_by_id.values())

    # Totals — search body text
    for label, key in [
        (r"Subtotal", "subtotal"),
        (r"Shipping", "shipping_total"),
        (r"(?:Grand\s*)?Total", "grand_total"),
    ]:
        m = re.search(label + r"[^\n]*?(" + ANY_PRICE_RE.pattern + r")", text, re.IGNORECASE)
        if m:
            result[key] = parse_price(m.group(1))

    result["raw_snippet"] = text[:500]
    return result


# ─── MCP Server ─────────────────────────────────────────────────────────────

mcp = FastMCP("aliexpress", dependencies=["httpx", "beautifulsoup4"])


@mcp.tool()
def search_products(
    query: str,
    min_rating: float = 0,
    max_price: float = 0,
    sort_by: str = "best_match",
) -> str:
    """
    Search AliExpress for products.

    Args:
        query: Search term (e.g., "groudon plush", "usb c cable")
        min_rating: Minimum rating (0-5, e.g., 4.5). 0 disables filter.
            Unrated listings are excluded when this is set.
        max_price: Maximum price in the configured currency (default CAD). 0 disables filter.
        sort_by: One of "best_match", "orders", "price_asc", "price_desc"
            (all four verified live).
    """
    # AliExpress URL slug pattern
    slug = quote_plus(query.strip()).replace("+", "-")
    url_path = f"/w/wholesale-{slug}.html"

    sort_map = {
        "best_match": None,
        "orders": "total_tranpro_desc",
        "price_asc": "price_asc",
        "price_desc": "price_desc",
    }
    params = {}
    if sort_map.get(sort_by):
        params["SortType"] = sort_map[sort_by]

    client = get_client()
    try:
        resp = client.get(url_path, params=params)
        if check_auth_redirect(resp):
            return AUTH_EXPIRED_MSG
        resp.raise_for_status()

        products = parse_search_results(resp.text)

        # Apply filters
        if min_rating > 0:
            products = [p for p in products if p.get("rating") and p["rating"] >= min_rating]
        if max_price > 0:
            products = [p for p in products if p.get("price") is not None and p["price"] <= max_price]

        if not products:
            filters = []
            if min_rating > 0:
                filters.append(f"rating ≥ {min_rating}")
            if max_price > 0:
                filters.append(f"price ≤ {fmt_money(max_price)}")
            suffix = f" with {', '.join(filters)}" if filters else ""
            return f"No products found for '{query}'{suffix}."

        lines = [f"Found {len(products)} result(s) for '{query}' (sort: {sort_by}):"]
        for p in products[:25]:
            line = f"- {p['title']}"
            if p["price"] is not None:
                line += f" — {fmt_money(p['price'], p.get('currency'))}"
            if p["original_price"] is not None and p["original_price"] > (p["price"] or 0):
                line += f" (was {fmt_money(p['original_price'])})"
            if p["discount_pct"]:
                line += f" [-{p['discount_pct']}%]"
            if p["rating"]:
                line += f" ★{p['rating']}"
            if p["sold_count"]:
                line += f" · {p['sold_count']}"
            useful = [t for t in p.get("tags", []) if not t.lower().startswith("save ")]
            if useful:
                line += f" · {'; '.join(useful[:2])}"
            line += f"\n  item_id: {p['item_id']}"
            lines.append(line)
        return "\n".join(lines)
    finally:
        client.close()


def _fetch_pdp_mtop(item_id: str) -> Optional[dict]:
    """
    Call the PDP MTOP endpoint and return the raw response dict, or None on failure.
    Tries the PC endpoint first, then the msite endpoint as a fallback.
    """
    referer = f"{BASE_URL}/item/{item_id}.html"
    payload = {
        "productId": item_id,
        "_currency": CURRENCY,
        "_lang": LOCALE,
        "country": COUNTRY,
        "channel": "",
        "sourceType": "pc",
        "pdp_ext_f": "",
    }

    for api, version in [
        ("mtop.aliexpress.pdp.pc.query", "1.0"),
        ("mtop.aliexpress.itemdetail.pc.asyncPCDetail", "1.0"),
        ("mtop.aliexpress.itemdetail.msite", "1.0"),
    ]:
        try:
            resp = mtop_call(api, version, payload, referer=referer)
        except Exception as e:
            logger.debug("MTOP %s failed: %s", api, e)
            continue
        ret = resp.get("ret", [])
        if ret and any("SUCCESS" in r for r in ret):
            return resp
        # Some endpoints return data even without SUCCESS::API_SUCCESS in ret
        if resp.get("data") and isinstance(resp["data"], dict) and resp["data"]:
            return resp
        logger.debug("MTOP %s ret=%s", api, ret)
    return None


def _extract_pdp_fields(mtop_resp: dict, item_id: str) -> dict:
    """
    Pull fields we care about from an MTOP PDP response.

    The response uses a component layout keyed by uppercase section names:
    PRODUCT_TITLE, PRICE, PC_RATING, SHIPPING, SHOP_CARD_PC, HEADER_IMAGE_PC, …
    Field paths below were reverse-engineered from a live response (Apr 2026).
    """
    d: dict[str, Any] = {
        "item_id": item_id,
        "url": f"{BASE_URL}/item/{item_id}.html",
        "title": None,
        "price": None,
        "price_range": None,
        "original_price": None,
        "discount_pct": None,
        "rating": None,
        "review_count": None,
        "sold_count": None,
        "seller_name": None,
        "store_url": None,
        "seller_positive_rate": None,
        "seller_total_reviews": None,
        "shipping_cost": None,
        "shipping_estimate": None,
        "ship_from": None,
        "ship_days_min": None,
        "ship_days_max": None,
        "image_url": None,
    }

    result = mtop_resp.get("data", {}).get("result", {})
    if not isinstance(result, dict):
        return d

    # ── Title ──────────────────────────────────────────────────────────
    pt = result.get("PRODUCT_TITLE")
    if isinstance(pt, dict):
        d["title"] = (
            pt.get("text")          # the real location
            or pt.get("subject")
            or pt.get("title")
            or pt.get("displayTitle")
        )
    if not d["title"]:
        gd = result.get("GLOBAL_DATA", {}).get("globalData", {})
        if isinstance(gd, dict):
            d["title"] = gd.get("subject")

    # ── Price ──────────────────────────────────────────────────────────
    # Real paths (seen live Apr 2026):
    #   PRICE.targetSkuPriceInfo.salePriceString         e.g. "C$9.76"
    #   PRICE.targetSkuPriceInfo.originalPrice.value     e.g. 12.19
    # For variant listings, PRICE.skuPriceInfoMap is a dict of per-SKU prices;
    # we report the min/max range when targetSku isn't enough.
    pn = result.get("PRICE")
    if isinstance(pn, dict):
        tsp = pn.get("targetSkuPriceInfo") or {}
        if isinstance(tsp, dict):
            sp = tsp.get("salePriceString")
            if isinstance(sp, str):
                d["price"] = parse_price(sp)
            op = tsp.get("originalPrice")
            if isinstance(op, dict):
                v = op.get("value")
                if isinstance(v, (int, float)):
                    d["original_price"] = float(v)
                elif op.get("formatedAmount"):
                    d["original_price"] = parse_price(op["formatedAmount"])

        # If this is a variant listing, compute a price range from skuPriceInfoMap
        sku_map = pn.get("skuPriceInfoMap")
        if isinstance(sku_map, dict) and sku_map:
            prices = []
            for sku in sku_map.values():
                if isinstance(sku, dict):
                    sp = sku.get("salePriceString")
                    if isinstance(sp, str):
                        p = parse_price(sp)
                        if p is not None:
                            prices.append(p)
            if prices:
                lo, hi = min(prices), max(prices)
                if lo != hi:
                    d["price_range"] = (lo, hi)
                if d["price"] is None:
                    d["price"] = lo

    if d["discount_pct"] is None and d["price"] and d["original_price"] and d["original_price"] > d["price"]:
        d["discount_pct"] = round((1 - d["price"] / d["original_price"]) * 100)

    # ── Rating / sold count ────────────────────────────────────────────
    rating_mod = result.get("PC_RATING")
    if isinstance(rating_mod, dict):
        r = rating_mod.get("rating")
        if r:
            try:
                d["rating"] = float(r)
            except (TypeError, ValueError):
                pass
        rc = rating_mod.get("totalValidNum")
        if rc is not None:
            try:
                d["review_count"] = int(rc)
            except (TypeError, ValueError):
                pass
        other = rating_mod.get("otherText") or ""
        sm = re.search(r"([\d,]+\+?)\s*sold", other, re.IGNORECASE)
        if sm:
            d["sold_count"] = sm.group(0)

    # ── Seller / store ─────────────────────────────────────────────────
    shop = result.get("SHOP_CARD_PC")
    if isinstance(shop, dict):
        d["seller_name"] = shop.get("storeName")
        si = shop.get("sellerInfo") or {}
        store_url = si.get("storeURL") or shop.get("storeHomePage")
        if isinstance(store_url, str):
            if store_url.startswith("//"):
                store_url = "https:" + store_url
            d["store_url"] = store_url
        pr = shop.get("sellerPositiveRate")
        if pr:
            try:
                d["seller_positive_rate"] = float(pr)
            except (TypeError, ValueError):
                pass
        tn = shop.get("sellerTotalNum")
        if tn is not None:
            try:
                d["seller_total_reviews"] = int(tn)
            except (TypeError, ValueError):
                pass

    # ── Shipping ──────────────────────────────────────────────────────
    ship = result.get("SHIPPING")
    if isinstance(ship, dict):
        # bizData lives inside originalLayoutResultList[0] or deliveryLayoutInfo[0]
        layouts = ship.get("originalLayoutResultList") or ship.get("deliveryLayoutInfo") or []
        biz = None
        if isinstance(layouts, list) and layouts:
            l0 = layouts[0]
            if isinstance(l0, dict):
                biz = l0.get("bizData")
        if isinstance(biz, dict):
            amt = biz.get("displayAmount")
            if amt is not None:
                try:
                    d["shipping_cost"] = float(amt)
                except (TypeError, ValueError):
                    d["shipping_cost"] = parse_price(str(amt))
            if d["shipping_cost"] is None and biz.get("logisticsComposeThreshold"):
                # e.g., "C$0.00" — sometimes the "threshold" is actually the freight text
                d["shipping_cost"] = parse_price(biz["logisticsComposeThreshold"])
            eta_min = biz.get("displayEtaMinDate")
            eta_max = biz.get("displayEtaMaxDate")
            if eta_min and eta_max:
                d["shipping_estimate"] = f"{eta_min} – {eta_max}"
            elif eta_min:
                d["shipping_estimate"] = eta_min
            d["ship_from"] = biz.get("shipFrom")
            dmin = biz.get("deliveryDayMin")
            dmax = biz.get("deliveryDayMax")
            if dmin is not None:
                try:
                    d["ship_days_min"] = int(dmin)
                except (TypeError, ValueError):
                    pass
            if dmax is not None:
                try:
                    d["ship_days_max"] = int(dmax)
                except (TypeError, ValueError):
                    pass

    # ── Image ─────────────────────────────────────────────────────────
    hdr = result.get("HEADER_IMAGE_PC")
    if isinstance(hdr, dict):
        imgs = hdr.get("imagePathList") or hdr.get("imgList")
        if isinstance(imgs, list) and imgs and isinstance(imgs[0], str):
            d["image_url"] = imgs[0]

    return d


@mcp.tool()
def get_product_details(item_id: str = "", url: str = "") -> str:
    """
    Get detailed info for a specific AliExpress product.

    Args:
        item_id: AliExpress item ID (e.g., "1005007655628250")
        url: Full product URL (alternative to item_id)
    """
    if not item_id and url:
        m = ITEM_ID_RE.search(url)
        if m:
            item_id = m.group(1)
    if not item_id:
        return "Provide either item_id or a full AliExpress product url."

    # Login not required: mtop_call bootstraps an anonymous token if needed.
    # Primary path: MTOP signed API
    d: Optional[dict] = None
    try:
        resp = _fetch_pdp_mtop(item_id)
        if resp:
            d = _extract_pdp_fields(resp, item_id)
    except Exception as e:
        logger.warning("MTOP PDP fetch failed: %s", e)

    # Fallback: HTML scrape (rarely useful since PDP is CSR, but kept for robustness)
    if not d or not (d.get("title") or d.get("price")):
        client = get_client(referer=f"{BASE_URL}/")
        try:
            r = client.get(f"/item/{item_id}.html")
            if check_auth_redirect(r):
                return AUTH_EXPIRED_MSG
            if r.status_code == 404:
                return f"Product not found: item_id {item_id}."
            r.raise_for_status()
            html_d = parse_product_detail(r.text, item_id)
            if not d:
                d = html_d
            else:
                for k, v in html_d.items():
                    if not d.get(k) and v:
                        d[k] = v
        finally:
            client.close()

    if not d or not (d.get("title") or d.get("price")):
        return (
            f"Could not extract product data for item {item_id}. "
            "The MTOP API returned no data — session may be expired or the item "
            "may be region-restricted. Try re-saving credentials."
        )

    lines = [f"# {d.get('title') or item_id}"]
    lines.append(f"URL: {d['url']}")
    if d.get("price") is not None:
        if d.get("price_range"):
            lo, hi = d["price_range"]
            line = f"Price: {lo:,.2f}–{hi:,.2f} {CURRENCY}"
        else:
            line = f"Price: {fmt_money(d['price'])}"
        if d.get("original_price") and d["original_price"] > d["price"]:
            line += f" (was {fmt_money(d['original_price'])}"
            if d.get("discount_pct"):
                line += f", -{d['discount_pct']}%"
            line += ")"
        lines.append(line)
    if d.get("rating"):
        rating_line = f"Rating: ★{d['rating']}"
        if d.get("review_count"):
            rating_line += f" ({d['review_count']} reviews)"
        lines.append(rating_line)
    if d.get("sold_count"):
        lines.append(f"Sold: {d['sold_count']}")
    if d.get("seller_name"):
        seller_line = f"Seller: {d['seller_name']}"
        if d.get("seller_positive_rate"):
            seller_line += f" — {d['seller_positive_rate']}% positive"
        if d.get("seller_total_reviews"):
            seller_line += f" ({d['seller_total_reviews']} reviews)"
        lines.append(seller_line)
        if d.get("store_url"):
            lines.append(f"Store: {d['store_url']}")
    if d.get("shipping_cost") is not None:
        ship_line = "Shipping: " + ("Free" if d["shipping_cost"] == 0 else fmt_money(d["shipping_cost"]))
        lines.append(ship_line)
    if d.get("shipping_estimate"):
        eta_line = f"Estimated delivery: {d['shipping_estimate']}"
        if d.get("ship_days_min") and d.get("ship_days_max"):
            eta_line += f" ({d['ship_days_min']}–{d['ship_days_max']} days)"
        lines.append(eta_line)
    if d.get("ship_from"):
        lines.append(f"Ships from: {d['ship_from']}")
    return "\n".join(lines)


@mcp.tool()
def get_shipping_estimate(item_id: str) -> str:
    """
    Check shipping time and cost for a product to the configured country
    (default: Canada; set ALIEXPRESS_COUNTRY to change).

    Args:
        item_id: AliExpress item ID (e.g., "1005007655628250")
    """
    try:
        resp = _fetch_pdp_mtop(item_id)
    except Exception as e:
        return f"MTOP call failed: {e}"

    if not resp:
        return (
            f"Could not fetch shipping data for item {item_id} — MTOP returned "
            "no usable response. Try re-saving AliExpress credentials."
        )

    d = _extract_pdp_fields(resp, item_id)
    if d.get("shipping_cost") is None and not d.get("shipping_estimate"):
        return (
            f"Shipping info not present in API response for item {item_id}. "
            "This can happen for items that need an interactive region selection."
        )

    lines = [f"Shipping to {COUNTRY} for item {item_id}:"]
    if d.get("shipping_cost") is not None:
        lines.append("  Cost: " + ("Free" if d["shipping_cost"] == 0 else fmt_money(d["shipping_cost"])))
    if d.get("shipping_estimate"):
        lines.append(f"  Estimated delivery: {d['shipping_estimate']}")
    if d.get("ship_from"):
        lines.append(f"  Ships from: {d['ship_from']}")
    return "\n".join(lines)


def _cents_to_float(amt_dict: Any) -> tuple[Optional[float], Optional[str]]:
    """AliExpress cart prices are nested dicts: {amount: {cent: 804, currencyCode: 'USD'}}."""
    if not isinstance(amt_dict, dict):
        return None, None
    amount = amt_dict.get("amount") if "amount" in amt_dict else amt_dict
    if isinstance(amount, dict):
        cent = amount.get("cent")
        code = amount.get("currencyCode")
        if isinstance(cent, (int, float)):
            return round(cent / 100.0, 2), code
    fmt = amt_dict.get("formattedAmount")
    if isinstance(fmt, str):
        return parse_price(fmt), None
    return None, None


def _extract_cart(render_response: dict) -> dict:
    """
    Pull structured cart content from a `mtop.aliexpress.trade.cart.render` v1.0
    response. The response's `data.data` is a flat block-map keyed by block ID.
    We recognize these tags:

        product_item_component  → a cart line
        store_title_component   → seller/shop heading
        summary_component       → totals / checkout summary
        cart_header_component   → the top bar (contains `count`)

    Each item block's `itemId` is the real product ID; prices live in
    `prices.children.retailPrice.amount.{cent,currencyCode}`; quantity is
    `quantity.current`; variant text is `sku.skuInfo`.
    """
    result: dict[str, Any] = {
        "items": [],
        "shops": {},              # sellerId -> shop dict
        "count": None,
        "currency": None,
        "subtotal": None,
        "shipping_fee": None,
        "total": None,
    }

    data = render_response.get("data", {})
    blocks = data.get("data", {}) if isinstance(data.get("data"), dict) else {}

    for bid, b in blocks.items():
        if not isinstance(b, dict):
            continue
        tag = b.get("tag") or ""
        fields = b.get("fields") or {}
        if not isinstance(fields, dict):
            continue

        if tag.startswith("cart_header_component"):
            c = fields.get("count")
            if c is not None:
                try:
                    result["count"] = int(c)
                except (TypeError, ValueError):
                    pass

        elif tag.startswith("store_title_component"):
            sid = fields.get("sellerId") or fields.get("shopId")
            url = fields.get("url") or ""
            if isinstance(url, str) and url.startswith("//"):
                url = "https:" + url
            result["shops"][str(sid)] = {
                "name": fields.get("title"),
                "url": url,
                "shop_id": fields.get("shopId"),
                "seller_id": sid,
            }

        elif tag.startswith("product_item_component"):
            item_id = fields.get("itemId") or fields.get("productId")
            title = fields.get("title")
            if not item_id or not title:
                continue

            item: dict[str, Any] = {
                "item_id": str(item_id),
                "title": str(title)[:200],
                "sku_info": (fields.get("sku") or {}).get("skuInfo") if isinstance(fields.get("sku"), dict) else None,
                "sku_id": fields.get("skuId"),
                "image_url": fields.get("img"),
                "url": f"{BASE_URL}/item/{item_id}.html",
                "valid": fields.get("valid", True),
                "status": fields.get("status"),
                "cart_id": fields.get("cartId"),
            }

            # Quantity
            q = fields.get("quantity") or {}
            if isinstance(q, dict):
                item["quantity"] = q.get("current") or q.get("origin") or 1
            else:
                try:
                    item["quantity"] = int(q)
                except (TypeError, ValueError):
                    item["quantity"] = 1

            # Prices: current sale price
            prices_node = fields.get("prices") or {}
            children = prices_node.get("children") if isinstance(prices_node, dict) else None
            if isinstance(children, dict):
                retail = children.get("retailPrice") or children.get("salePrice")
                if isinstance(retail, dict):
                    p, c = _cents_to_float(retail)
                    item["price"] = p
                    if c and not item.get("currency"):
                        item["currency"] = c

            # Original (strike) price
            orig = fields.get("originalPrice")
            if isinstance(orig, dict):
                fmt = orig.get("formattedAmount")
                if fmt:
                    item["original_price"] = parse_price(fmt)

            # Freight
            freight = fields.get("freightInfo") or {}
            svc_list = freight.get("availableFreightServices") if isinstance(freight, dict) else None
            if isinstance(svc_list, list) and svc_list:
                chosen = next((s for s in svc_list if s.get("chosen")), svc_list[0])
                if isinstance(chosen, dict):
                    fcost = chosen.get("freightCost") or ""
                    # Format: "Shipping: $1.99" or "Free shipping"
                    if isinstance(fcost, str):
                        if "free" in fcost.lower():
                            item["shipping_cost"] = 0.0
                        else:
                            item["shipping_cost"] = parse_price(fcost)
                    item["delivery_date"] = chosen.get("deliveryDate")

            result["items"].append(item)

        elif tag.startswith("summary_component"):
            # Real structure:
            #   fields.summary.priceMap.total
            #   fields.summary.priceDetail[*].priceMap.{subTotal, total, shippingFee}
            # Also fallback: fields.checkout.orderDetail[*].priceMap.*
            summary = fields.get("summary") or {}
            pm = summary.get("priceMap") if isinstance(summary, dict) else None
            if isinstance(pm, dict):
                t = pm.get("total")
                if isinstance(t, dict):
                    v, c = _cents_to_float(t)
                    result["total"] = v
                    if c:
                        result["currency"] = c

            # Walk priceDetail groups — they have subTotal/shippingFee per order group
            pd = summary.get("priceDetail") if isinstance(summary, dict) else None
            if isinstance(pd, list):
                for grp in pd:
                    grp_pm = grp.get("priceMap") if isinstance(grp, dict) else None
                    if not isinstance(grp_pm, dict):
                        continue
                    if result["subtotal"] is None and "subTotal" in grp_pm:
                        result["subtotal"] = _cents_to_float(grp_pm["subTotal"])[0]
                    if result["shipping_fee"] is None and "shippingFee" in grp_pm:
                        result["shipping_fee"] = _cents_to_float(grp_pm["shippingFee"])[0]
                    if result["total"] is None and "total" in grp_pm:
                        v, c = _cents_to_float(grp_pm["total"])
                        result["total"] = v
                        if c and not result.get("currency"):
                            result["currency"] = c

            # Last-ditch: checkout.orderDetail
            checkout = fields.get("checkout") or {}
            if isinstance(checkout, dict):
                for grp in checkout.get("orderDetail") or []:
                    grp_pm = grp.get("priceMap") if isinstance(grp, dict) else None
                    if not isinstance(grp_pm, dict):
                        continue
                    if result["total"] is None and "total" in grp_pm:
                        v, c = _cents_to_float(grp_pm["total"])
                        result["total"] = v
                        if c and not result.get("currency"):
                            result["currency"] = c

    return result


@mcp.tool()
def view_cart() -> str:
    """
    View current AliExpress cart contents (read-only).

    Calls the signed MTOP endpoint `mtop.aliexpress.trade.cart.render` v1.0.
    Requires a fresh session — if you see an empty cart despite having items,
    re-save AliExpress cookies via the MCP Auth Bridge extension.
    """
    cookies = load_cookies()
    if not has_login_session(cookies):
        return AUTH_EXPIRED_MSG + " (view_cart is the only tool that needs a login.)"

    try:
        resp = mtop_call(
            "mtop.aliexpress.trade.cart.render",
            "1.0",
            {"platformType": "DESKTOP"},
            cookies=cookies,
            referer=f"{BASE_URL}/p/shoppingcart/index.html",
        )
    except Exception as e:
        return f"Cart MTOP call failed: {e}"

    ret = resp.get("ret", [])
    ret_str = ret[0] if ret else ""
    if not any("SUCCESS" in r for r in ret):
        return (
            f"Cart API returned: {ret_str}. "
            "If this says TOKEN_EXPIRED, re-save AliExpress cookies via the MCP Auth Bridge."
        )

    cart = _extract_cart(resp)
    items = cart["items"]
    count = cart["count"]

    if not items:
        if count == 0:
            return (
                "Your AliExpress cart is empty (server count: 0). "
                "If you just added items, re-save AliExpress cookies via the "
                "MCP Auth Bridge extension to refresh the session, then retry."
            )
        return (
            f"Cart render succeeded but no item blocks matched. Server count: {count}. "
            "The cart-line block shape may have changed."
        )

    # Group items by shop
    by_shop: dict[str, list[dict]] = {}
    for it in items:
        # Each item's parentId would map to shop; we don't store that, so we
        # just use the first shop as the fallback label
        by_shop.setdefault("__all__", []).append(it)

    currency = cart.get("currency") or CURRENCY

    lines = [f"Cart ({len(items)} item(s), server count: {count}):"]

    # Show each shop header if we have shop info
    shop_labels = list(cart.get("shops", {}).values())
    if shop_labels:
        # Single-shop case: prepend shop name
        lines.append("")
        for s in shop_labels:
            if s.get("name"):
                lines.append(f"Shop: {s['name']}")
                if s.get("url"):
                    lines.append(f"  {s['url']}")

    lines.append("")
    for it in items:
        line = f"- {it['title']}"
        if it.get("price") is not None:
            line += f" — {fmt_money(it['price'], it.get('currency') or currency)}"
        if it.get("original_price") and it["original_price"] > (it.get("price") or 0):
            line += f" (was {fmt_money(it['original_price'], currency)})"
        qty = it.get("quantity") or 1
        try:
            if int(qty) != 1:
                line += f" × {qty}"
        except (TypeError, ValueError):
            pass
        if it.get("sku_info"):
            line += f"\n  variant: {it['sku_info']}"
        if it.get("shipping_cost") is not None:
            ship_str = "Free" if it["shipping_cost"] == 0 else fmt_money(it["shipping_cost"], currency)
            line += f"\n  shipping: {ship_str}"
        if it.get("delivery_date"):
            line += f"\n  delivery: {it['delivery_date']}"
        if not it.get("valid", True):
            line += "\n  ⚠️ invalid (sold out or removed)"
        line += f"\n  item_id: {it['item_id']}"
        lines.append(line)

    # Totals
    if cart.get("subtotal") is not None or cart.get("shipping_fee") is not None or cart.get("total") is not None:
        lines.append("")
        if cart.get("subtotal") is not None:
            lines.append(f"Subtotal: {fmt_money(cart['subtotal'], currency)}")
        if cart.get("shipping_fee") is not None:
            lines.append(f"Shipping: {fmt_money(cart['shipping_fee'], currency)}")
        if cart.get("total") is not None:
            lines.append(f"Estimated total: {fmt_money(cart['total'], currency)}")

    return "\n".join(lines)


# ─── Main ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
