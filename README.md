# AliExpress MCP Server

An MCP server that wraps AliExpress search and product detail scraping. Defaults to shipping to Canada with prices in CAD; set `ALIEXPRESS_COUNTRY` / `ALIEXPRESS_CURRENCY` (and optionally `ALIEXPRESS_LOCALE`) for another region.

Search, product details and shipping work without logging in; only `view_cart` needs session cookies. Run the offline tests with `pytest tests`, or `python smoke_test.py` for a live check.

Read-only by design: it searches, fetches product details, and checks shipping. It does **not** add to cart, check out, or pay.

## Tools

- `search_products(query, min_rating, max_price, sort_by)` — searches the public wholesale search URL and parses the embedded JSON.
- `get_product_details(item_id | url)` — title, price, discount, rating, sold count, seller, shipping cost & ETA.
- `get_shipping_estimate(item_id)` — shipping cost + ETA to the configured country.
- `view_cart()` — current cart contents via the signed `mtop.aliexpress.trade.cart.render` endpoint. Read-only.

## How it works

The initial product page is a client-side-rendered shell (`window._d_c_.isCSR = true`, `window.runParams = {}`) — real product data loads over AJAX from AliExpress's MTOP API after the JS runs. So HTML scraping doesn't work for PDP data.

Instead, this server replicates what `mtop.js` does in the browser: it makes signed calls to `mtop.aliexpress.pdp.pc.query` using the session's `_m_h5_tk` cookie as the HMAC token. The signing algorithm:

```
sign = md5(token + "&" + t_ms + "&" + "12574478" + "&" + json_payload)
```

where `token` is the prefix of `_m_h5_tk` before the underscore, and `12574478` is AliExpress's public web `appKey`. Token refresh on `FAIL_SYS_TOKEN_EXPIRED` is handled automatically.

Search still uses the simpler HTML path — no signed calls needed. `window.runParams` no longer exists on search pages, so cards are read from the embedded `"itemList":{"content":[...]}` array in the SSR HTML.

## Setup

1. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

2. *(Optional, only for `view_cart`)* Install the [MCP Auth Bridge](https://github.com/justinritchie/mcp-auth-bridge) Chrome extension. The `aliexpress` entry is already in its `sites.json`.

3. Open `https://www.aliexpress.com`, log in, then click **Save AliExpress** in the extension popup. This writes cookies to `~/.mcp-credentials/aliexpress.json`.

4. Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

   ```json
   {
     "mcpServers": {
       "aliexpress": {
         "command": "python3",
         "args": ["/Users/YOUR_USER/justinritchie-mcp-servers/aliexpress-mcp-server/aliexpress_mcp_server.py"],
         "env": {
           "ALIEXPRESS_CREDENTIALS": "~/.mcp-credentials/aliexpress.json",
           "ALIEXPRESS_COUNTRY": "CA",
           "ALIEXPRESS_CURRENCY": "CAD"
         }
       }
     }
   }
   ```

5. Restart Claude Desktop.

## Known limitations

- **Low-volume / brand-new listings** sometimes return empty MTOP responses (endpoint returns `SUCCESS` but an empty data block). Likely a region/visibility gate. Search results still show the listing fine.
- **Cookies expire / lag the cart.** When tool calls start returning "session expired" — or `view_cart` reports an empty cart despite having items — re-open aliexpress.com in Chrome and click **Save AliExpress** again to capture fresh session cookies. The `_m_h5_tk` token and cart state rotate together; stale cookies show an empty server-side cart.
- **Rate limiting** is the user's responsibility. The server sends realistic Chrome headers but doesn't throttle; don't hammer the search.

## Architecture

Follows the pattern of [dekudeals-mcp-server](../dekudeals-mcp-server/) — FastMCP + httpx + BeautifulSoup — with added MTOP client code in `aliexpress_mcp_server.py`. Session cookies come from the shared credential file written by the [MCP Auth Bridge](https://github.com/justinritchie/mcp-auth-bridge) Chrome extension.

The MTOP response field paths (`PRODUCT_TITLE.text`, `PRICE.targetSkuPriceInfo.salePriceString`, `PC_RATING.rating`, `SHIPPING.originalLayoutResultList[0].bizData.displayAmount`, etc.) were reverse-engineered live from a real response in April 2026 and are documented inline in `_extract_pdp_fields()`. If AliExpress reorganizes the component layout, that function is the place to update.
