// Dumb fetch pipe.
//
// One job: fetch a URL it is told to fetch, and return the raw result.
// It does not parse or interpret what it fetches, does not cache, does not
// retry, and has no opinion about the content. The caller decides what the
// body means. This service never does.

import { BlockedError, resolveAndValidate } from './guard'

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const MAX_BODY_BYTES = 10 * 1024 * 1024 // read at most 10 MB of response body
const MAX_REDIRECTS = 5
const DEFAULT_TIMEOUT_MS = 15000
const MIN_TIMEOUT_MS = 1000
const MAX_TIMEOUT_MS = 30000
const DEFAULT_USER_AGENT = 'dumb-broker'
const ALLOWED_METHODS = new Set(['GET', 'POST', 'HEAD'])
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])

// Header names and values the outbound request will accept (RFC 9110 tokens).
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/
const HEADER_VALUE_RE = /^[\t\x20-\x7e\x80-\xff]*$/

function getFetchKey(): string {
  // Read lazily: edge runtimes hydrate env after module evaluation.
  return typeof process !== 'undefined' ? (process.env?.FETCH_KEY ?? '') : ''
}

// ---------------------------------------------------------------------------
// Auth (constant time)
// ---------------------------------------------------------------------------

async function sha256(data: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data))
  return new Uint8Array(digest)
}

function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

async function keyMatches(provided: unknown): Promise<boolean> {
  if (typeof provided !== 'string') return false
  const key = getFetchKey()
  if (!key) return false
  return ctEqual(await sha256(provided), await sha256(key))
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

export function jsonRes(status: number, obj: unknown): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

export function notFoundJson(): Response {
  return jsonRes(404, { error: 'not_found' })
}

function logLine(method: string, host: string, status: number | string, ms: number): void {
  // timestamp, method, host, outbound status, duration in ms. Nothing else --
  // never keys, request bodies, or response bodies.
  console.log(`${new Date().toISOString()} ${method} ${host} ${status} ${ms}ms`)
}

// ---------------------------------------------------------------------------
// Outbound fetch (manual redirects, size cap, no retries)
// ---------------------------------------------------------------------------

type HopResult =
  | { kind: 'blocked'; host: string; method: string }
  | {
      kind: 'response'
      status: number
      headers: Record<string, string>
      body: Uint8Array
      truncated: boolean
      host: string
      method: string
    }
  | { kind: 'error'; code: string; host: string; method: string }

function extractErrorCode(err: unknown): string {
  const e = err as { cause?: { code?: string }; code?: string } | null
  if (e?.cause?.code) return String(e.cause.code)
  if (e?.code) return String(e.code)
  return 'EUNKNOWN'
}

function concatBytes(parts: Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

async function fetchOnce(
  target: URL,
  method: string,
  headers: Record<string, string>,
  body: string | undefined,
  timeLeftMs: number,
): Promise<HopResult> {
  const host = target.hostname.replace(/^\[|\]$/g, '')

  // SSRF guard: resolve the hostname and reject blocked addresses before
  // any bytes go out.
  try {
    await resolveAndValidate(target.hostname)
  } catch (err) {
    if (err instanceof BlockedError) return { kind: 'blocked', host, method }
    return { kind: 'error', code: extractErrorCode(err), host, method }
  }

  let timedOut = false
  const controller = new AbortController()
  const timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, Math.max(1, timeLeftMs))

  try {
    const init: RequestInit = {
      method,
      headers,
      redirect: 'manual',
      signal: controller.signal,
    }
    // Pass the body as bytes so the fetch implementation does not attach its
    // own content-type; it is passed through as given.
    if (body !== undefined && method === 'POST') {
      init.body = new TextEncoder().encode(body)
    }

    const res = await fetch(target, init)

    const parts: Uint8Array[] = []
    let total = 0
    let truncated = false

    if (res.body) {
      const reader = res.body.getReader()
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        const chunk = value as Uint8Array
        const remaining = MAX_BODY_BYTES - total
        if (chunk.length > remaining) {
          parts.push(chunk.slice(0, remaining))
          total += remaining
          truncated = true
          try {
            await reader.cancel() // stop reading: response is larger than the cap
          } catch {
            // ignore
          }
          break
        }
        parts.push(chunk)
        total += chunk.length
        // exactly at the cap: wait for the next chunk (truncated) or the end.
      }
    }

    return {
      kind: 'response',
      status: res.status,
      headers: Object.fromEntries(res.headers as unknown as Iterable<[string, string]>),
      body: concatBytes(parts, total),
      truncated,
      host,
      method,
    }
  } catch (err) {
    if (timedOut) return { kind: 'error', code: 'ETIMEDOUT', host, method }
    return { kind: 'error', code: extractErrorCode(err), host, method }
  } finally {
    clearTimeout(timer)
  }
}

function isRedirectStatus(status: number): boolean {
  return REDIRECT_STATUSES.has(status)
}

async function performFetch(
  startUrl: URL,
  method: string,
  headers: Record<string, string>,
  body: string | undefined,
  timeoutMs: number,
): Promise<HopResult> {
  const deadline = Date.now() + timeoutMs
  let target = startUrl
  let hopMethod = method
  let hopBody = body
  let hopHeaders = { ...headers }

  for (let redirects = 0; ; redirects++) {
    const timeLeft = Math.max(1, deadline - Date.now())
    const result = await fetchOnce(target, hopMethod, hopHeaders, hopBody, timeLeft)

    if (result.kind !== 'response') return result

    const location = result.headers['location']
    const isRedirect = isRedirectStatus(result.status) && typeof location === 'string'

    if (isRedirect && redirects < MAX_REDIRECTS) {
      let next: URL
      try {
        next = new URL(location, target)
      } catch {
        // Unfollowable location: the response we hold is the final one.
        return result
      }
      if (next.protocol !== 'http:' && next.protocol !== 'https:') {
        return {
          kind: 'blocked',
          host: next.hostname.replace(/^\[|\]$/g, '') || '-',
          method: hopMethod,
        }
      }

      // Standard redirect semantics: 303 becomes GET, as do 301/302 from POST.
      // 307/308 keep the method and body.
      let nextBody = hopBody
      let nextMethod = hopMethod
      if (result.status === 303) {
        nextMethod = hopMethod === 'HEAD' ? 'HEAD' : 'GET'
        nextBody = undefined
      } else if ((result.status === 301 || result.status === 302) && hopMethod === 'POST') {
        nextMethod = 'GET'
        nextBody = undefined
      }

      let nextHeaders = hopHeaders
      if (nextBody === undefined && hopBody !== undefined) {
        nextHeaders = { ...hopHeaders }
        for (const k of Object.keys(nextHeaders)) {
          const lk = k.toLowerCase()
          if (lk === 'content-length' || lk === 'transfer-encoding') delete nextHeaders[k]
        }
      }

      target = next
      hopMethod = nextMethod
      hopBody = nextBody
      hopHeaders = nextHeaders
      continue
    }

    return result
  }
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

// Text-like means it starts with text/, or contains json, xml, javascript, or
// mpegurl. Anything else (including a missing content-type) is binary.
function isTextLike(contentType: string | undefined): boolean {
  if (typeof contentType !== 'string') return false
  const ct = contentType.trim().toLowerCase()
  return (
    ct.startsWith('text/') ||
    ct.includes('json') ||
    ct.includes('xml') ||
    ct.includes('javascript') ||
    ct.includes('mpegurl')
  )
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  const CHUNK = 0x8000
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK))
  }
  return btoa(binary)
}

function buildEnvelope(result: Extract<HopResult, { kind: 'response' }>): Record<string, unknown> {
  const headersOut: Record<string, string> = { ...result.headers }
  let body: string
  if (isTextLike(headersOut['content-type'])) {
    body = new TextDecoder().decode(result.body)
  } else {
    body = bytesToBase64(result.body)
    headersOut['x-encoding'] = 'base64'
  }
  if (result.truncated) headersOut['x-truncated'] = '1'
  // Always the same shape: status, headers, body. `error` only when status 0.
  return { status: result.status, headers: headersOut, body }
}

function failureEnvelope(code: string): Record<string, unknown> {
  return { status: 0, headers: {}, body: '', error: code }
}

// ---------------------------------------------------------------------------
// Inbound request handling
// ---------------------------------------------------------------------------

interface ValidSpec {
  target: URL
  method: string
  headers: Record<string, string>
  body: string | undefined
  timeoutMs: number
}

function validateSpec(spec: unknown): { error: string } | ValidSpec {
  if (typeof spec !== 'object' || spec === null || Array.isArray(spec)) {
    return { error: 'bad_request' }
  }
  const s = spec as Record<string, unknown>

  // url -- required, must be http: or https:
  if (typeof s.url !== 'string' || s.url.length === 0) return { error: 'bad_request' }
  let target: URL
  try {
    target = new URL(s.url)
  } catch {
    return { error: 'blocked' } // not an http/https URL
  }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    return { error: 'blocked' }
  }

  // method -- optional, default GET, only GET/POST/HEAD
  let method = 'GET'
  if (s.method !== undefined) {
    if (typeof s.method !== 'string') return { error: 'bad_request' }
    method = s.method.toUpperCase()
    if (!ALLOWED_METHODS.has(method)) return { error: 'bad_request' }
  }

  // headers -- optional object of strings, passed through as given
  const headers: Record<string, string> = {}
  if (s.headers !== undefined) {
    if (typeof s.headers !== 'object' || s.headers === null || Array.isArray(s.headers)) {
      return { error: 'bad_request' }
    }
    for (const [k, v] of Object.entries(s.headers as Record<string, unknown>)) {
      if (typeof v !== 'string') return { error: 'bad_request' }
      if (!HEADER_NAME_RE.test(k) || !HEADER_VALUE_RE.test(v)) return { error: 'bad_request' }
      const lk = k.toLowerCase()
      if (lk === 'x-key' || lk === 'host') continue // never forwarded
      headers[k] = v
    }
  }

  // body -- optional raw string, only used when method is POST
  if (s.body !== undefined && typeof s.body !== 'string') return { error: 'bad_request' }
  let body = s.body as string | undefined
  if (method !== 'POST') body = undefined

  // timeoutMs -- optional, default 15000, clamped to 1000..30000
  let timeoutMs = DEFAULT_TIMEOUT_MS
  if (s.timeoutMs !== undefined) {
    if (typeof s.timeoutMs !== 'number' || !Number.isFinite(s.timeoutMs)) {
      return { error: 'bad_request' }
    }
    timeoutMs = Math.min(MAX_TIMEOUT_MS, Math.max(MIN_TIMEOUT_MS, s.timeoutMs))
  }

  if (!Object.keys(headers).some((k) => k.toLowerCase() === 'user-agent')) {
    headers['user-agent'] = DEFAULT_USER_AGENT
  }

  return { target, method, headers, body, timeoutMs }
}

function hostGuess(spec: unknown): string {
  try {
    const url = (spec as { url?: unknown }).url
    if (typeof url !== 'string') return '-'
    return new URL(url).hostname.replace(/^\[|\]$/g, '') || '-'
  } catch {
    return '-'
  }
}

export async function handleFetch(request: Request): Promise<Response> {
  const startedAt = Date.now()

  // Auth first: missing or wrong key -> 401 and nothing else.
  const providedKey = request.headers.get('x-key')
  if (!(await keyMatches(providedKey))) {
    logLine('POST', '-', 401, Date.now() - startedAt)
    return jsonRes(401, { error: 'unauthorized' })
  }

  let raw: string
  try {
    raw = await request.text()
  } catch {
    logLine('POST', '-', 400, Date.now() - startedAt)
    return jsonRes(400, { error: 'bad_request' })
  }

  let spec: unknown
  try {
    spec = JSON.parse(raw) // the request envelope only -- never the body field
  } catch {
    logLine('POST', '-', 400, Date.now() - startedAt)
    return jsonRes(400, { error: 'invalid_json' })
  }

  const v = validateSpec(spec)
  if ('error' in v) {
    logLine('POST', hostGuess(spec), 400, Date.now() - startedAt)
    return jsonRes(400, { error: v.error })
  }

  const result = await performFetch(v.target, v.method, v.headers, v.body, v.timeoutMs)
  const ms = Date.now() - startedAt

  if (result.kind === 'blocked') {
    logLine(result.method, result.host, 400, ms)
    return jsonRes(400, { error: 'blocked' })
  }
  if (result.kind === 'error') {
    // Always 200 with the envelope shape -- including when the outbound
    // request failed (status 0 + error).
    logLine(result.method, result.host, 0, ms)
    return jsonRes(200, failureEnvelope(result.code))
  }

  const envelope = buildEnvelope(result)
  logLine(result.method, result.host, result.status, ms)
  return jsonRes(200, envelope)
}

export async function handleHealth(): Promise<Response> {
  const startedAt = Date.now()
  logLine('GET', '-', 200, Date.now() - startedAt)
  return jsonRes(200, { ok: true })
}
