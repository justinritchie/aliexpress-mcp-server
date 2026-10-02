"""Live smoke test: python smoke_test.py  (hits aliexpress.com, ~5 requests)."""
import re, aliexpress_mcp_server as m
print(f"Region {m.COUNTRY}, currency {m.CURRENCY}\n")
out = m.search_products("usb c cable", sort_by="orders")
print("\n".join(out.splitlines()[:7]), "\n")
ids = re.findall(r"item_id: (\d+)", out)
if not ids:
    raise SystemExit("FAIL: search returned no items")
print(m.get_product_details(item_id=ids[0]), "\n")
print(m.get_shipping_estimate(ids[0]))
