# Dumb Broker

A single-purpose HTTP service. It is a **dumb fetch pipe**: fetch a URL it is
told to fetch, and return the raw result. It does not know anything about the
caller's business, does not parse or interpret what it fetches, and has no
opinion about the content.

Built as a **TanStack Start** app (TypeScript) so it deploys directly on
**Lovable** — the service endpoints are server routes in `src/routes/`, the
stack Lovable generates and hosts.

## Stack

- TanStack Start (TypeScript, React shell page) — Lovable's project shape
- `POST /fetch` and `GET /health` are plain server routes (Request → Response)
- No database, no build-time secrets, no extra services

## Environment

| Var         | Required | Description                                              |
| ----------- | -------- | -------------------------------------------------------- |
| `FETCH_KEY` | yes      | Shared secret. `npm start` refuses to run if unset.       |
| `PORT`      | no       | Listen port (default `3000`). Binds `0.0.0.0`.            |

## Endpoints

### `POST /fetch`

Auth: `x-key: <FETCH_KEY>` header, compared in constant time. Missing or wrong
key → `401 { "error": "unauthorized" }`.

Request body (JSON):

```json
{
  "url": "https://example.com/api/thing?id=1",
  "method": "GET",
  "headers": { "accept": "application/json", "referer": "https://example.com/" },
  "body": "optional string, only used when method is POST",
  "timeoutMs": 15000
}
```

- `url` — required, must be `http:` or `https:`.
- `method` — optional, default `GET`. Only `GET`, `POST`, `HEAD`.
- `headers` — optional object of strings, passed through to the outbound
  request as given. Exception: `x-key` and `host` are never forwarded. If you
  do not pass a `user-agent`, one is set (`dumb-broker`) because many APIs
  reject requests without one. Your own value always wins.
- `body` — optional raw string, passed through as given (only sent with `POST`).
- `timeoutMs` — optional, default `15000`, clamped to `1000`–`30000`, applied
  to the whole outbound operation.

Response is always HTTP `200` with this envelope — **including when the
outbound request failed**:

```json
{
  "status": 200,
  "headers": { "content-type": "application/json" },
  "body": "{\"raw\":\"response body exactly as received, as a UTF-8 string\"}"
}
```

```json
{
  "status": 0,
  "headers": {},
  "body": "",
  "error": "ECONNRESET"
}
```

- `status` — outbound HTTP status. `0` means the request never got a response.
- `headers` — outbound response headers, flattened to a plain object.
- `body` — the response body as a string, unmodified. Never parsed here.
- `error` — only present when `status` is `0`. The network error code.

Extra markers added to the returned `headers` object:

- `"x-truncated": "1"` — the response exceeded 10 MB; reading stopped at the
  cap and `body` holds exactly what was read (at most 10 MB).
- `"x-encoding": "base64"` — the response `content-type` is not text-like, so
  `body` is the raw bytes base64-encoded. Text-like means it starts with
  `text/`, or contains `json`, `xml`, `javascript`, or `mpegurl`.

Request-level rejections (not envelopes):

- `400 { "error": "blocked" }` — SSRF guard: the URL is not http/https, or the
  host resolves to a private, loopback, link-local, or metadata address
  (`10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`, `::1`, `fc00::/7`,
  `0.0.0.0`, …). Checked before every outbound request, including each
  redirect hop.
- `400 { "error": "bad_request" }` / `400 { "error": "invalid_json" }` —
  malformed input.

Behavior notes:

- **No parsing** of the fetched content. JSON in, raw string out; what the body
  means is the caller's business.
- **No caching.** Every request goes out.
- **No retries.** Failures are reported as-is; the caller decides.
- **Redirects** are followed, up to 5, returning the final status and body.
- Logging is one line per request: `timestamp method host status durationMs`.
  Never keys, request bodies, or response bodies.

### `GET /health`

`200 { "ok": true }` — no auth, no other data. Everything else is
`404 { "error": "not_found" }`.

## Run locally

```bash
export FETCH_KEY="the-key-shown-when-this-service-was-generated"
export PORT=3000           # the host usually sets this
npm install
npm start                  # builds and serves on 0.0.0.0:$PORT
```

`npm run dev` runs the TanStack Start dev server (port 3000). `npm run typecheck`
checks types. `npx tsx scripts/test-pipe.ts` runs the offline test harness
(mocked network: redirect-hop SSRF, size cap, redirect semantics, headers).

## Acceptance test

```bash
curl -sS -X POST "$MIDDLEMAN_URL/fetch" \
  -H "content-type: application/json" \
  -H "x-key: $FETCH_KEY" \
  -d '{"url":"https://api.github.com/zen"}' | head -c 300
```

Expected: JSON containing `"status": 200` and a `body` string with a short
quote in it.

```bash
curl -sS -X POST "$MIDDLEMAN_URL/fetch" \
  -H "content-type: application/json" \
  -H "x-key: $FETCH_KEY" \
  -d '{"url":"https://this-host-does-not-exist.invalid/"}'
```

Expected: JSON containing `"status": 0` and an `error` field.

## Deploying on Lovable

This repo is a TanStack Start project in Lovable's shape (`src/routes/`,
`vite.config.ts`, `package.json`):

1. Connect the GitHub repo in Lovable (Git settings) or import the project.
2. Set `FETCH_KEY` in Lovable's environment/secrets settings.
3. Publish. The endpoints live at `https://<your-app>.lovable.app/fetch` and
   `/health`; the service runs in the app's SSR server routes.

Self-hosting (any small Node instance) works too: `npm start`, or build with a
Nitro preset (`NITRO_PRESET=node-server npm run build` → `npm run serve`).
