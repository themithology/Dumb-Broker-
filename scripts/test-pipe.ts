// In-process tests for the dumb fetch pipe: drives handleFetch() directly with
// a mocked network layer (global fetch + node:dns) to exercise redirect-hop
// SSRF blocking, size-cap boundaries, redirect semantics, and header rules.
//
// Run with: npx tsx scripts/test-pipe.ts

process.env.FETCH_KEY = 'test-key-0123456789abcdef'

import { promises as dnsPromises } from 'node:dns'
import { handleFetch } from '../src/server/pipe'

// ---- mocks ----------------------------------------------------------------

const DNS_MAP: Record<string, string> = {
  'hop-one.test': '203.0.113.10',
  'blocked-name.test': '127.0.0.1',
  'final.test': '203.0.113.11',
  'meta.test': '169.254.169.254',
}

const realLookup = dnsPromises.lookup.bind(dnsPromises)
;(dnsPromises as { lookup: unknown }).lookup = (
  host: string,
  opts?: { all?: boolean },
) => {
  const addr = DNS_MAP[host]
  if (addr) {
    const family = addr.includes(':') ? 6 : 4
    const res = [{ address: addr, family }]
    return Promise.resolve(opts?.all ? res : res[0])
  }
  return realLookup(host, opts as never)
}

const LOG: Array<{ url: string; method: string; headers: Record<string, string>; body: unknown }> = []
type Script = ((rec: (typeof LOG)[0]) => Response) | null
let scripts: Script[] = []

const realFetch = globalThis.fetch
;(globalThis as { fetch: unknown }).fetch = async (
  input: string | URL,
  init?: RequestInit,
) => {
  const rec = {
    url: String(input),
    method: (init?.method ?? 'GET') as string,
    headers: (init?.headers ?? {}) as Record<string, string>,
    body: init?.body,
  }
  LOG.push(rec)
  const script = scripts.shift()
  if (script === null) {
    // never respond, but honor abort so timeouts can fire
    return new Promise<Response>((_resolve, reject) => {
      const sig = init?.signal
      const onAbort = () => reject(new DOMException('Aborted', 'AbortError'))
      if (sig) {
        if (sig.aborted) onAbort()
        else sig.addEventListener('abort', onAbort, { once: true })
      }
    })
  }
  if (script === undefined) throw new Error('no scripted response for ' + rec.url)
  return script(rec)
}

function scripted(
  status: number,
  headers: Record<string, string>,
  body: string | Uint8Array = new Uint8Array(0),
): Script {
  return () =>
    new Response(body as unknown as BodyInit, { status, headers })
}

// ---- runner ---------------------------------------------------------------

function call(spec: unknown, extraHeaders: Record<string, string> = {}) {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'x-key': 'test-key-0123456789abcdef',
    ...extraHeaders,
  }
  return handleFetch(
    new Request('http://localhost/fetch', {
      method: 'POST',
      headers,
      body: typeof spec === 'string' ? spec : JSON.stringify(spec),
    }),
  )
}

let failures = 0
function check(label: string, cond: boolean, detail?: unknown) {
  if (cond) console.log('PASS  ' + label)
  else {
    failures++
    console.log('FAIL  ' + label + '  -> ' + JSON.stringify(detail))
  }
}

async function main() {
  // 1. redirect hop -> private IP literal must be blocked
  LOG.length = 0
  scripts = [scripted(302, { location: 'http://127.0.0.1:9/private' })]
  let r = await call({ url: 'https://hop-one.test/start', method: 'POST', body: 'x' })
  let j = (await r.json()) as Record<string, unknown>
  check('redirect to private IP literal -> 400 blocked', r.status === 400 && j.error === 'blocked', j)

  // 2. redirect hop -> name resolving to private must be blocked
  LOG.length = 0
  scripts = [scripted(302, { location: 'http://blocked-name.test/x' })]
  r = await call({ url: 'https://hop-one.test/start' })
  j = (await r.json()) as Record<string, unknown>
  check('redirect to private-resolving name -> 400 blocked', r.status === 400 && j.error === 'blocked', j)

  // 2b. redirect hop -> metadata address must be blocked
  LOG.length = 0
  scripts = [scripted(302, { location: 'http://meta.test/latest/' })]
  r = await call({ url: 'https://hop-one.test/start' })
  j = (await r.json()) as Record<string, unknown>
  check('redirect to metadata address -> 400 blocked', r.status === 400 && j.error === 'blocked', j)

  // 3. redirect hop -> non-http scheme must be blocked
  LOG.length = 0
  scripts = [scripted(302, { location: 'ftp://hop-one.test/x' })]
  r = await call({ url: 'https://hop-one.test/start' })
  j = (await r.json()) as Record<string, unknown>
  check('redirect to ftp: scheme -> 400 blocked', r.status === 400 && j.error === 'blocked', j)

  // 4. happy redirect chain -> final status and body
  LOG.length = 0
  scripts = [
    scripted(302, { location: 'https://final.test/end' }),
    scripted(200, { 'content-type': 'text/plain' }, 'hello there'),
  ]
  r = await call({ url: 'https://hop-one.test/start' })
  j = (await r.json()) as Record<string, unknown>
  check(
    'redirect followed -> final 200 + raw body',
    j.status === 200 && j.body === 'hello there' && LOG.length === 2,
    j,
  )

  // 5. redirect cap: 5 followed, 6th response returned as-is
  LOG.length = 0
  scripts = Array.from(
    { length: 6 },
    (_, i) => () =>
      new Response('stop', {
        status: 302,
        headers: { location: 'https://hop-one.test/r' + (i + 1), 'content-type': 'text/plain' },
      }),
  )
  r = await call({ url: 'https://hop-one.test/start' })
  j = (await r.json()) as Record<string, unknown>
  check(
    'redirects capped at 5 (6th response returned)',
    j.status === 302 && j.body === 'stop' && LOG.length === 6,
    { status: j.status, hops: LOG.length },
  )

  // 6. 303 turns POST into GET and drops the body
  LOG.length = 0
  scripts = [
    scripted(303, { location: 'https://final.test/end' }),
    scripted(200, { 'content-type': 'text/plain' }, 'ok'),
  ]
  r = await call({ url: 'https://hop-one.test/start', method: 'POST', body: 'raw-body' })
  j = (await r.json()) as Record<string, unknown>
  check(
    '303: POST -> GET, body dropped',
    j.status === 200 && LOG[1].method === 'GET' && LOG[1].body === undefined,
    LOG[1],
  )

  // 7. 307 keeps POST and the body
  LOG.length = 0
  scripts = [
    scripted(307, { location: 'https://final.test/end' }),
    scripted(200, { 'content-type': 'text/plain' }, 'ok'),
  ]
  r = await call({ url: 'https://hop-one.test/start', method: 'POST', body: 'raw-body' })
  j = (await r.json()) as Record<string, unknown>
  check(
    '307: POST kept, body passed through',
    j.status === 200 && LOG[1].method === 'POST' && new TextDecoder().decode(LOG[1].body as Uint8Array) === 'raw-body',
    { method: LOG[1].method, body: LOG[1].body },
  )

  // 8. headers passed through; x-key and host never forwarded; UA defaulted
  LOG.length = 0
  scripts = [scripted(200, { 'content-type': 'text/plain' }, 'ok')]
  r = await call({
    url: 'https://hop-one.test/start',
    headers: {
      accept: 'application/json',
      referer: 'https://example.com/',
      'x-key': 'sneak',
      host: 'evil.example',
      'X-KEY': 'sneak2',
      HOST: 'evil2',
    },
  })
  await r.json()
  const h = LOG[0].headers
  const hk = Object.keys(h).map((k) => k.toLowerCase())
  check('headers: passed through as given', h.accept === 'application/json' && h.referer === 'https://example.com/', h)
  check(
    'headers: x-key and host stripped',
    !hk.includes('x-key') && !hk.includes('host'),
    h,
  )
  check('headers: user-agent defaulted when absent', h['user-agent'] === 'dumb-broker', h)

  // 8b. caller-provided user-agent wins
  LOG.length = 0
  scripts = [scripted(200, { 'content-type': 'text/plain' }, 'ok')]
  r = await call({ url: 'https://hop-one.test/start', headers: { 'user-agent': 'my-agent/9' } })
  await r.json()
  check('headers: caller user-agent wins', LOG[0].headers['user-agent'] === 'my-agent/9', LOG[0].headers)

  // 9. size cap: 12 MB binary -> x-truncated, x-encoding base64, exactly 10 MB
  LOG.length = 0
  scripts = [scripted(200, { 'content-type': 'application/octet-stream' }, new Uint8Array(12 * 1024 * 1024).fill(7))]
  r = await call({ url: 'https://hop-one.test/big' })
  j = (await r.json()) as Record<string, unknown>
  const jh = j.headers as Record<string, string>
  const decoded = Buffer.from(j.body as string, 'base64')
  check('size cap: truncated at 10 MB', jh['x-truncated'] === '1' && decoded.length === 10 * 1024 * 1024, decoded.length)
  check('binary: base64 + x-encoding', jh['x-encoding'] === 'base64' && decoded[0] === 7, jh)

  // 9b. exactly 10 MB -> not truncated
  LOG.length = 0
  scripts = [scripted(200, { 'content-type': 'application/octet-stream' }, new Uint8Array(10 * 1024 * 1024).fill(3))]
  r = await call({ url: 'https://hop-one.test/exact' })
  j = (await r.json()) as Record<string, unknown>
  const jh2 = j.headers as Record<string, string>
  check(
    'size cap: exactly 10 MB not truncated',
    jh2['x-truncated'] === undefined && Buffer.from(j.body as string, 'base64').length === 10 * 1024 * 1024,
    jh2,
  )

  // 10. timeout -> status 0, ETIMEDOUT
  LOG.length = 0
  scripts = [null] // never respond
  const t0 = Date.now()
  r = await call({ url: 'https://hop-one.test/slow', timeoutMs: 1000 })
  j = (await r.json()) as Record<string, unknown>
  check(
    'timeout -> status 0 ETIMEDOUT',
    j.status === 0 && j.error === 'ETIMEDOUT' && Date.now() - t0 < 2500,
    j,
  )

  // 11. body never parsed: invalid JSON body returned exactly
  LOG.length = 0
  scripts = [scripted(200, { 'content-type': 'application/json' }, '{"broken":')]
  r = await call({ url: 'https://hop-one.test/odd' })
  j = (await r.json()) as Record<string, unknown>
  check('body unmodified (not parsed/pretty-printed)', j.body === '{"broken":', j.body)

  // 12. missing content-type -> treated as binary
  LOG.length = 0
  scripts = [scripted(200, {}, new Uint8Array([1, 2, 3]))]
  r = await call({ url: 'https://hop-one.test/nct' })
  j = (await r.json()) as Record<string, unknown>
  check('missing content-type -> base64', (j.headers as Record<string, string>)['x-encoding'] === 'base64' && j.body === 'AQID', j)

  // 13. timeoutMs clamping accepted (500 -> 1000 works)
  LOG.length = 0
  scripts = [scripted(200, { 'content-type': 'text/plain' }, 'ok')]
  r = await call({ url: 'https://hop-one.test/x', timeoutMs: 500 })
  j = (await r.json()) as Record<string, unknown>
  check('timeoutMs below floor clamped (accepted)', j.status === 200, j)

  // restore
  ;(globalThis as { fetch: unknown }).fetch = realFetch
  ;(dnsPromises as { lookup: unknown }).lookup = realLookup

  console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURES`)
  process.exit(failures === 0 ? 0 : 1)
}

main().catch((e) => {
  console.error('HARNESS ERROR', e)
  process.exit(2)
})
