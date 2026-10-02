import json, hashlib, httpx, pytest
import aliexpress_mcp_server as m

@pytest.fixture(autouse=True)
def _region(monkeypatch):
    # Fixtures below were captured for IL/USD; pin it so tests don't depend on defaults.
    monkeypatch.setattr(m, "COUNTRY", "IL")
    monkeypatch.setattr(m, "CURRENCY", "USD")

@pytest.mark.parametrize("txt,val", [
    ("US $12.34", 12.34), ("$1,234.50", 1234.50), ("₪45.90", 45.90),
    ("45.90 ILS", 45.90), ("C$9.76", 9.76), ("€3.20", 3.20), ("Free", None),
])
def test_parse_price(txt, val):
    assert m.parse_price(txt) == val

def test_sign_matches_mtop_js():
    raw = "tok&1700000000000&12574478&{\"a\":1}"
    assert m._mtop_sign("tok", "1700000000000", "12574478", '{"a":1}') == hashlib.md5(raw.encode()).hexdigest()

def test_region_cookie_forced(tmp_path, monkeypatch):
    f = tmp_path / "c.json"
    f.write_text(json.dumps({"cookies": {"aep_usuc_f": "region=CA&c_tp=CAD", "xman_t": "x"}}))
    monkeypatch.setattr(m, "CREDENTIALS_PATH", f)
    c = m.load_cookies()
    assert "c_tp=USD" in c["aep_usuc_f"] and "region=IL" in c["aep_usuc_f"]
    assert m.has_login_session(c)

def test_anonymous_token_bootstrap(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "CREDENTIALS_PATH", tmp_path / "missing.json")
    m._TOKEN_CACHE.clear()
    calls = []
    def handler(req):
        q = dict(req.url.params); calls.append(q)
        if len(calls) == 1:
            # expect empty-token signature on first call
            assert q["sign"] == m._mtop_sign("", q["t"], m.MTOP_APP_KEY, q["data"])
            return httpx.Response(200, json={"ret": ["FAIL_SYS_TOKEN_EMPTY::token empty"]},
                headers=[("set-cookie", "_m_h5_tk=abc123_9999; Path=/"),
                         ("set-cookie", "_m_h5_tk_enc=enc; Path=/")])
        assert q["sign"] == m._mtop_sign("abc123", q["t"], m.MTOP_APP_KEY, q["data"])
        assert "c_tp=USD" in req.headers["cookie"]
        return httpx.Response(200, json={"ret": ["SUCCESS::ok"], "data": {"result": {}}})
    monkeypatch.setattr(m, "_TRANSPORT", httpx.MockTransport(handler))
    r = m.mtop_call("mtop.x", "1.0", {"productId": "1"})
    assert r["ret"][0].startswith("SUCCESS") and len(calls) == 2
    assert m._TOKEN_CACHE["_m_h5_tk"] == "abc123_9999"
    m.mtop_call("mtop.x", "1.0", {"productId": "1"})  # cached: one call only
    assert len(calls) == 3

def test_pdp_extract_and_render(monkeypatch):
    resp = {"ret": ["SUCCESS"], "data": {"result": {
        "PRODUCT_TITLE": {"text": "USB-C cable 2m"},
        "PRICE": {"targetSkuPriceInfo": {"salePriceString": "US $3.49",
                  "originalPrice": {"value": 6.98}}},
        "PC_RATING": {"rating": "4.8", "totalValidNum": 1200, "otherText": "5,000+ sold"},
        "SHOP_CARD_PC": {"storeName": "Ugreen Official", "sellerPositiveRate": "97.5"},
        "SHIPPING": {"originalLayoutResultList": [{"bizData": {"displayAmount": 0,
                     "displayEtaMinDate": "Oct 12", "displayEtaMaxDate": "Oct 20", "shipFrom": "CN"}}]},
    }}}
    monkeypatch.setattr(m, "_fetch_pdp_mtop", lambda i: resp)
    out = m.get_product_details(item_id="1005")
    assert "3.49 USD" in out and "was 6.98 USD" in out and "-50%" in out
    assert "Shipping: Free" in out and "Ugreen" in out and "$" not in out

# Item shape captured live from aliexpress.com search (Oct 2026), trimmed.
LIVE_ITEM = {"redirectedId":"1005006505041416","itemType":"productV3","productId":"1005006505041416",
 "title":{"displayTitle":"UGREEN PD100W USB Type C To USB C Cable 5A E-Marker Chip"},
 "prices":{"currencySymbol":"US $","originalPrice":{"currencyCode":"USD","minPrice":5.69,"formattedPrice":"US $5.69","cent":569},
   "salePrice":{"discount":7,"currencyCode":"USD","minPrice":5.27,"formattedPrice":"US $5.27","cent":527},"taxRate":"0"},
 "trade":{"tradeDesc":"50,000+ sold"},"evaluation":{"starRating":4.9},
 "sellingPoints":[{"tagContent":{}},{"tagContent":{"tagText":"Save US $0.42"}},{"tagContent":{"tagText":"Free shipping over US $12"}}]}

def _page(items):
    return ('<html><script>window._dida_config_._init_data_={data:{x:1}};var z={"sortCopy":"x",'
            '"itemList":{"content":' + json.dumps(items) + '},"other":{}}</script></html>')

def test_search_parser_current_layout():
    items = m.parse_search_results(_page([LIVE_ITEM, {"itemType": "ad"}]))
    assert len(items) == 1
    it = items[0]
    assert (it["price"], it["original_price"], it["discount_pct"], it["rating"]) == (5.27, 5.69, 7, 4.9)
    assert it["currency"] == "USD" and "Free shipping over US $12" in it["tags"]

def test_search_tool_output(monkeypatch):
    def handler(req):
        assert req.url.path == "/w/wholesale-usb-c-cable.html"
        assert req.url.params.get("SortType") == "price_asc"
        assert "region=IL" in req.headers["cookie"]
        return httpx.Response(200, text=_page([LIVE_ITEM]))
    monkeypatch.setattr(m, "_TRANSPORT", httpx.MockTransport(handler))
    out = m.search_products("usb c cable", sort_by="price_asc", max_price=6)
    assert "5.27 USD" in out and "Free shipping over US $12" in out and "Save US" not in out

# PDP response captured live via mtop.aliexpress.pdp.pc.query v1.0 (Oct 2026, IL/USD), trimmed.
LIVE_PDP = {"ret":["SUCCESS::调用成功"],"data":{"result":{
 "PRODUCT_TITLE":{"text":"UGREEN PD100W USB Type C To USB C Cable"},
 "PRICE":{"targetSkuPriceInfo":{"salePriceString":"$4.62","originalPrice":{"currency":"USD","formatedAmount":"$4.98","value":4.98}},
   "skuPriceInfoMap":{"a":{"salePriceString":"$4.62"},"b":{"salePriceString":"$8.76"}}},
 "PC_RATING":{"rating":"4.9","totalValidNum":5755,"otherText":"50,000+ sold"},
 "SHOP_CARD_PC":{"storeName":"Ugreen Official Store","sellerPositiveRate":"98.5","sellerTotalNum":5233188},
 "SHIPPING":{"originalLayoutResultList":[{"bizData":{"displayAmount":1.99,"displayEtaMinDate":"Oct. 07",
   "displayEtaMaxDate":"Oct. 13","shipFrom":"China","deliveryDayMin":6,"deliveryDayMax":12}}]}}}}

def test_pdp_live_shape():
    d = m._extract_pdp_fields(LIVE_PDP, "1005006505041416")
    assert d["price_range"] == (4.62, 8.76) and d["original_price"] == 4.98
    assert d["shipping_cost"] == 1.99 and (d["ship_days_min"], d["ship_days_max"]) == (6, 12)
    assert d["seller_positive_rate"] == 98.5 and d["review_count"] == 5755
