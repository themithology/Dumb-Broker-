'use strict';

// Dumb fetch pipe.
//
// One job: fetch a URL it is told to fetch, and return the raw result.
// It does not parse or interpret what it fetches, does not cache, does not
// retry, and has no opinion about the content. The caller decides what the
// body means. This service never does.

const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns');
const net = require('node:net');
const crypto = require('node:crypto');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const FETCH_KEY = process.env.FETCH_KEY;
if (!FETCH_KEY) {
  console.error('refusing to start: FETCH_KEY is not set');
  process.exit(1);
}

const PORT = Number(process.env.PORT || 3000);
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  console.error('refusing to start: PORT must be an integer between 1 and 65535');
  process.exit(1);
}

const MAX_BODY_BYTES = 10 * 1024 * 1024; // read at most 10 MB of response body
const MAX_REDIRECTS = 5;
const DEFAULT_TIMEOUT_MS = 15000;
const MIN_TIMEOUT_MS = 1000;
const MAX_TIMEOUT_MS = 30000;
const DEFAULT_USER_AGENT = 'dumb-broker';
const ALLOWED_METHODS = new Set(['GET', 'POST', 'HEAD']);
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

// Header names and values the outbound request will accept (RFC 9110 tokens).
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const HEADER_VALUE_RE = /^[\t\x20-\x7e\x80-\xff]*$/;

// ---------------------------------------------------------------------------
// IP blocking (SSRF guard)
// ---------------------------------------------------------------------------

function parseIPv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const b = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (b.some((x) => x > 255)) return null;
  return b;
}

function parseIPv6(input) {
  let s = String(input).toLowerCase();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  if (!s.includes(':')) return null;

  // Convert an embedded IPv4 tail (::ffff:1.2.3.4) into two hextets.
  const dot = s.lastIndexOf('.');
  if (dot !== -1) {
    const colon = s.lastIndexOf(':', dot);
    const v4 = parseIPv4(s.slice(colon + 1));
    if (!v4) return null;
    const h1 = ((v4[0] << 8) | v4[1]).toString(16);
    const h2 = ((v4[2] << 8) | v4[3]).toString(16);
    s = s.slice(0, colon + 1) + h1 + ':' + h2;
  }

  const parts = s.split('::');
  if (parts.length > 2) return null;

  const parseGroups = (str) => {
    if (str === '') return [];
    const out = [];
    for (const g of str.split(':')) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };

  const left = parseGroups(parts[0]);
  const right = parts.length === 2 ? parseGroups(parts[1]) : [];
  if (left === null || right === null) return null;

  const total = left.length + right.length;
  if (parts.length === 2 ? total > 7 : total !== 8) return null;

  const groups = parts.length === 2
    ? [...left, ...Array(8 - total).fill(0), ...right]
    : left;

  const bytes = [];
  for (const g of groups) bytes.push(g >> 8, g & 0xff);
  return bytes;
}

function isBlockedIPv4(b) {
  return (
    b[0] === 0 ||                                    // 0.0.0.0/8
    b[0] === 10 ||                                   // 10.0.0.0/8
    b[0] === 127 ||                                  // 127.0.0.0/8
    (b[0] === 172 && b[1] >= 16 && b[1] <= 31) ||    // 172.16.0.0/12
    (b[0] === 192 && b[1] === 168) ||                // 192.168.0.0/16
    (b[0] === 169 && b[1] === 254)                   // 169.254.0.0/16 (link-local, metadata)
  );
}

function isBlockedIPv6(b) {
  const allZero = b.every((x) => x === 0);
  if (allZero) return true;                          // ::
  if (b.slice(0, 15).every((x) => x === 0) && b[15] === 1) return true; // ::1

  // IPv4-mapped ::ffff:a.b.c.d and IPv4-compatible ::a.b.c.d -> judge as IPv4
  const v4Mapped = b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff;
  const v4Compat = b.slice(0, 12).every((x) => x === 0);
  if (v4Mapped) return isBlockedIPv4(b.slice(12));
  if (v4Compat) return isBlockedIPv4(b.slice(12));

  if ((b[0] & 0xfe) === 0xfc) return true;           // fc00::/7
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true; // fe80::/10 link-local
  return false;
}

function isBlockedAddress(address) {
  const v4 = parseIPv4(address);
  if (v4) return isBlockedIPv4(v4);
  const v6 = parseIPv6(address);
  if (v6) return isBlockedIPv6(v6);
  return true; // unparseable -> fail closed
}

// Resolve the hostname and refuse private / loopback / link-local / metadata
// addresses. This function is also the resolver used to open the connection,
// so the address actually connected to is exactly the address that was vetted.
function safeLookup(hostname, options, callback) {
  const host = String(hostname).replace(/^\[|\]$/g, '');
  dns.lookup(host, { all: true, verbatim: true }, (err, addrs) => {
    if (err) return callback(err);
    if (!Array.isArray(addrs) || addrs.length === 0) {
      const e = new Error('ENOTFOUND');
      e.code = 'ENOTFOUND';
      return callback(e);
    }
    for (const a of addrs) {
      if (isBlockedAddress(a.address)) {
        const e = new Error('blocked address');
        e.code = 'EBLOCKED';
        return callback(e);
      }
    }
    let list = addrs;
    if (options && (options.family === 4 || options.family === 6)) {
      const filtered = addrs.filter((a) => a.family === options.family);
      if (filtered.length > 0) list = filtered;
    }
    if (options && options.all) {
      return callback(null, list.map((a) => ({ address: a.address, family: a.family })));
    }
    return callback(null, list[0].address, list[0].family);
  });
}

// ---------------------------------------------------------------------------
// Outbound fetch (manual redirects, size cap, no retries)
// ---------------------------------------------------------------------------

function fetchOnce(target, method, headers, body, timeLeftMs) {
  return new Promise((resolve) => {
    const mod = target.protocol === 'https:' ? https : http;
    let settled = false;
    let timer = null;
    let response = null;
    let truncated = false;

    const settle = (value) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(value);
    };

    let req;
    try {
      req = mod.request(target, {
        method,
        headers,
        agent: false,
        lookup: safeLookup,
      }, (res) => {
        response = res;
        const parts = [];
        let total = 0;

        res.on('data', (chunk) => {
          if (settled) return;
          const remaining = MAX_BODY_BYTES - total;
          if (chunk.length > remaining) {
            parts.push(chunk.slice(0, remaining));
            truncated = true;
            res.destroy(); // stop reading: response is larger than the cap
            settle({
              kind: 'response',
              status: res.statusCode,
              headers: res.headers,
              body: Buffer.concat(parts),
              truncated: true,
            });
            return;
          }
          parts.push(chunk);
          total += chunk.length;
          // exactly at the cap: wait for 'end' (not truncated) or more data
          // (truncated) before deciding.
        });

        res.on('end', () => {
          settle({
            kind: 'response',
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(parts),
            truncated,
          });
        });

        res.on('error', (err) => {
          if (truncated) return;
          settle({ kind: 'error', code: err.code || 'EUNKNOWN' });
        });
      });
    } catch (err) {
      settle({ kind: 'error', code: err.code || 'EUNKNOWN' });
      return;
    }

    timer = setTimeout(() => {
      if (response) response.destroy();
      req.destroy();
      settle({ kind: 'error', code: 'ETIMEDOUT' });
    }, timeLeftMs);

    req.on('error', (err) => {
      if (err.code === 'EBLOCKED') settle({ kind: 'blocked' });
      else settle({ kind: 'error', code: err.code || 'EUNKNOWN' });
    });

    if (body !== undefined && method === 'POST') req.end(body);
    else req.end();
  });
}

function flattenHeaders(raw) {
  const out = {};
  for (const [k, v] of Object.entries(raw)) {
    out[k] = Array.isArray(v) ? v.join(', ') : String(v);
  }
  return out;
}

// Text-like means it starts with text/, or contains json, xml, javascript, or
// mpegurl. Anything else (including a missing content-type) is binary.
function isTextLike(contentType) {
  if (typeof contentType !== 'string') return false;
  const ct = contentType.trim().toLowerCase();
  return (
    ct.startsWith('text/') ||
    ct.includes('json') ||
    ct.includes('xml') ||
    ct.includes('javascript') ||
    ct.includes('mpegurl')
  );
}

async function performFetch(startUrl, method, headers, body, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let target = startUrl;
  let hopMethod = method;
  let hopBody = body;
  let hopHeaders = { ...headers };

  for (let redirects = 0; ; redirects++) {
    // IP literals never reach the DNS lookup, so the SSRF guard runs here too:
    // node's socket layer skips lookup() when the host is already an IP.
    const bareHost = target.hostname.replace(/^\[|\]$/g, '');
    if (net.isIP(bareHost) && isBlockedAddress(bareHost)) {
      return { blocked: true, host: bareHost, method: hopMethod };
    }

    const timeLeft = Math.max(1, deadline - Date.now());
    const result = await fetchOnce(target, hopMethod, hopHeaders, hopBody, timeLeft);

    if (result.kind === 'blocked') {
      return { blocked: true, host: target.hostname.replace(/^\[|\]$/g, ''), method: hopMethod };
    }

    if (result.kind === 'error') {
      return {
        envelope: { status: 0, headers: {}, body: '', error: result.code },
        host: target.hostname.replace(/^\[|\]$/g, ''),
        method: hopMethod,
      };
    }

    const locRaw = result.headers.location;
    const location = Array.isArray(locRaw) ? locRaw[0] : locRaw;
    const isRedirect = REDIRECT_STATUSES.has(result.status) && typeof location === 'string';

    if (isRedirect && redirects < MAX_REDIRECTS) {
      let next;
      try {
        next = new URL(location, target);
      } catch {
        // Unfollowable location: the response we hold is the final one.
        return finish(result, target, hopMethod);
      }
      if (next.protocol !== 'http:' && next.protocol !== 'https:') {
        return { blocked: true, host: next.hostname.replace(/^\[|\]$/g, '') || '-', method: hopMethod };
      }

      // Standard redirect semantics: 303 becomes GET, as do 301/302 from POST.
      // 307/308 keep the method and body.
      let nextBody = hopBody;
      let nextMethod = hopMethod;
      if (result.status === 303) {
        nextMethod = hopMethod === 'HEAD' ? 'HEAD' : 'GET';
        nextBody = undefined;
      } else if ((result.status === 301 || result.status === 302) && hopMethod === 'POST') {
        nextMethod = 'GET';
        nextBody = undefined;
      }

      let nextHeaders = hopHeaders;
      if (nextBody === undefined && hopBody !== undefined) {
        nextHeaders = { ...hopHeaders };
        for (const k of Object.keys(nextHeaders)) {
          const lk = k.toLowerCase();
          if (lk === 'content-length' || lk === 'transfer-encoding') delete nextHeaders[k];
        }
      }

      target = next;
      hopMethod = nextMethod;
      hopBody = nextBody;
      hopHeaders = nextHeaders;
      continue;
    }

    return finish(result, target, hopMethod);
  }
}

function finish(result, target, method) {
  const headersOut = flattenHeaders(result.headers);
  let body;
  if (isTextLike(headersOut['content-type'])) {
    body = result.body.toString('utf8');
  } else {
    body = result.body.toString('base64');
    headersOut['x-encoding'] = 'base64';
  }
  if (result.truncated) headersOut['x-truncated'] = '1';
  return {
    envelope: { status: result.status, headers: headersOut, body },
    host: target.hostname.replace(/^\[|\]$/g, ''),
    method,
  };
}

// ---------------------------------------------------------------------------
// Inbound request handling
// ---------------------------------------------------------------------------

function keyMatches(provided) {
  if (typeof provided !== 'string') return false;
  const a = crypto.createHash('sha256').update(provided).digest();
  const b = crypto.createHash('sha256').update(FETCH_KEY).digest();
  return crypto.timingSafeEqual(a, b);
}

function sendJson(res, status, obj) {
  const payload = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(payload);
}

function logLine(method, host, status, ms) {
  // timestamp, method, host, outbound status, duration in ms. Nothing else --
  // never keys, request bodies, or response bodies.
  console.log(`${new Date().toISOString()} ${method} ${host} ${status} ${ms}ms`);
}

function readInboundBody(req, cb) {
  const chunks = [];
  let done = false;
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    if (done) return;
    done = true;
    cb(null, Buffer.concat(chunks).toString('utf8'));
  });
  req.on('error', () => {
    if (done) return;
    done = true;
    cb(new Error('request error'));
  });
}

function validateSpec(spec) {
  if (typeof spec !== 'object' || spec === null || Array.isArray(spec)) {
    return { error: 'bad_request' };
  }

  // url -- required, must be http: or https:
  if (typeof spec.url !== 'string' || spec.url.length === 0) {
    return { error: 'bad_request' };
  }
  let target;
  try {
    target = new URL(spec.url);
  } catch {
    return { error: 'blocked' }; // not an http/https URL
  }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    return { error: 'blocked' };
  }

  // method -- optional, default GET, only GET/POST/HEAD
  let method = 'GET';
  if (spec.method !== undefined) {
    if (typeof spec.method !== 'string') return { error: 'bad_request' };
    method = spec.method.toUpperCase();
    if (!ALLOWED_METHODS.has(method)) return { error: 'bad_request' };
  }

  // headers -- optional object of strings, passed through as given
  const headers = {};
  if (spec.headers !== undefined) {
    if (typeof spec.headers !== 'object' || spec.headers === null || Array.isArray(spec.headers)) {
      return { error: 'bad_request' };
    }
    for (const [k, v] of Object.entries(spec.headers)) {
      if (typeof v !== 'string') return { error: 'bad_request' };
      if (!HEADER_NAME_RE.test(k) || !HEADER_VALUE_RE.test(v)) return { error: 'bad_request' };
      const lk = k.toLowerCase();
      if (lk === 'x-key' || lk === 'host') continue; // never forwarded
      headers[k] = v;
    }
  }

  // body -- optional raw string, only used when method is POST
  if (spec.body !== undefined && typeof spec.body !== 'string') {
    return { error: 'bad_request' };
  }
  let body = spec.body;
  if (method !== 'POST') body = undefined;
  if (body !== undefined && !Object.keys(headers).some((k) => k.toLowerCase() === 'content-length')) {
    if (!Object.keys(headers).some((k) => k.toLowerCase() === 'transfer-encoding')) {
      headers['content-length'] = String(Buffer.byteLength(body));
    }
  }

  // timeoutMs -- optional, default 15000, clamped to 1000..30000
  let timeoutMs = DEFAULT_TIMEOUT_MS;
  if (spec.timeoutMs !== undefined) {
    if (typeof spec.timeoutMs !== 'number' || !Number.isFinite(spec.timeoutMs)) {
      return { error: 'bad_request' };
    }
    timeoutMs = Math.min(MAX_TIMEOUT_MS, Math.max(MIN_TIMEOUT_MS, spec.timeoutMs));
  }

  if (!Object.keys(headers).some((k) => k.toLowerCase() === 'user-agent')) {
    headers['user-agent'] = DEFAULT_USER_AGENT;
  }

  return { target, method, headers, body, timeoutMs };
}

function handleFetch(req, res, startedAt) {
  const providedKey = req.headers['x-key'];
  if (!keyMatches(providedKey)) {
    sendJson(res, 401, { error: 'unauthorized' });
    logLine('POST', '-', 401, Date.now() - startedAt);
    return;
  }

  readInboundBody(req, (err, raw) => {
    if (err) {
      sendJson(res, 400, { error: 'bad_request' });
      logLine('POST', '-', 400, Date.now() - startedAt);
      return;
    }

    let spec;
    try {
      spec = JSON.parse(raw);
    } catch {
      sendJson(res, 400, { error: 'invalid_json' });
      logLine('POST', '-', 400, Date.now() - startedAt);
      return;
    }

    const v = validateSpec(spec);
    if (v.error) {
      const hostGuess = typeof spec.url === 'string'
        ? (() => { try { return new URL(spec.url).hostname.replace(/^\[|\]$/g, '') || '-'; } catch { return '-'; } })()
        : '-';
      sendJson(res, 400, { error: v.error });
      logLine('POST', hostGuess, 400, Date.now() - startedAt);
      return;
    }

    performFetch(v.target, v.method, v.headers, v.body, v.timeoutMs).then((result) => {
      const ms = Date.now() - startedAt;
      if (result.blocked) {
        sendJson(res, 400, { error: 'blocked' });
        logLine(result.method, result.host, 400, ms);
        return;
      }
      // Always 200 with the envelope shape -- including when the outbound
      // request failed (status 0 + error).
      sendJson(res, 200, result.envelope);
      logLine(result.method, result.host, result.envelope.status, ms);
    });
  });
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const server = http.createServer((req, res) => {
  const startedAt = Date.now();
  const rawUrl = req.url || '/';
  const qIdx = rawUrl.indexOf('?');
  const pathname = qIdx === -1 ? rawUrl : rawUrl.slice(0, qIdx);

  if (pathname === '/health' && req.method === 'GET') {
    sendJson(res, 200, { ok: true });
    logLine('GET', '-', 200, Date.now() - startedAt);
    return;
  }

  if (pathname === '/fetch' && req.method === 'POST') {
    handleFetch(req, res, startedAt);
    return;
  }

  sendJson(res, 404, { error: 'not_found' });
  logLine(req.method || '-', '-', 404, Date.now() - startedAt);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`dumb fetch pipe listening on 0.0.0.0:${PORT}`);
});
