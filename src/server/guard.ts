// SSRF guard: IP parsing and blocking rules.
//
// Blocks private, loopback, link-local, and metadata addresses:
// 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
// 169.254.0.0/16, ::, ::1, fe80::/10, fc00::/7, and IPv4-mapped /
// IPv4-compatible IPv6 forms of any blocked IPv4 range.

export function parseIPv4(s: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s)
  if (!m) return null
  const b = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])]
  if (b.some((x) => x > 255)) return null
  return b
}

export function parseIPv6(input: string): number[] | null {
  let s = String(input).toLowerCase()
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1)
  if (!s.includes(':')) return null

  // Convert an embedded IPv4 tail (::ffff:1.2.3.4) into two hextets.
  const dot = s.lastIndexOf('.')
  if (dot !== -1) {
    const colon = s.lastIndexOf(':', dot)
    const v4 = parseIPv4(s.slice(colon + 1))
    if (!v4) return null
    const h1 = ((v4[0] << 8) | v4[1]).toString(16)
    const h2 = ((v4[2] << 8) | v4[3]).toString(16)
    s = s.slice(0, colon + 1) + h1 + ':' + h2
  }

  const parts = s.split('::')
  if (parts.length > 2) return null

  const parseGroups = (str: string): number[] | null => {
    if (str === '') return []
    const out: number[] = []
    for (const g of str.split(':')) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null
      out.push(parseInt(g, 16))
    }
    return out
  }

  const left = parseGroups(parts[0])
  const right = parts.length === 2 ? parseGroups(parts[1]) : []
  if (left === null || right === null) return null

  const total = left.length + right.length
  if (parts.length === 2 ? total > 7 : total !== 8) return null

  const groups =
    parts.length === 2
      ? [...left, ...Array(8 - total).fill(0), ...right]
      : left

  const bytes: number[] = []
  for (const g of groups) bytes.push(g >> 8, g & 0xff)
  return bytes
}

function isBlockedIPv4(b: number[]): boolean {
  return (
    b[0] === 0 || // 0.0.0.0/8
    b[0] === 10 || // 10.0.0.0/8
    b[0] === 127 || // 127.0.0.0/8
    (b[0] === 172 && b[1] >= 16 && b[1] <= 31) || // 172.16.0.0/12
    (b[0] === 192 && b[1] === 168) || // 192.168.0.0/16
    (b[0] === 169 && b[1] === 254) // 169.254.0.0/16 (link-local, metadata)
  )
}

function isBlockedIPv6(b: number[]): boolean {
  if (b.every((x) => x === 0)) return true // ::
  if (b.slice(0, 15).every((x) => x === 0) && b[15] === 1) return true // ::1

  // IPv4-mapped ::ffff:a.b.c.d and IPv4-compatible ::a.b.c.d -> judge as IPv4
  const v4Mapped =
    b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff
  const v4Compat = b.slice(0, 12).every((x) => x === 0)
  if (v4Mapped) return isBlockedIPv4(b.slice(12))
  if (v4Compat) return isBlockedIPv4(b.slice(12))

  if ((b[0] & 0xfe) === 0xfc) return true // fc00::/7
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true // fe80::/10
  return false
}

export function isBlockedAddress(address: string): boolean {
  const v4 = parseIPv4(address)
  if (v4) return isBlockedIPv4(v4)
  const v6 = parseIPv6(address)
  if (v6) return isBlockedIPv6(v6)
  return true // unparseable -> fail closed
}

export function isIpLiteral(host: string): boolean {
  return parseIPv4(host) !== null || parseIPv6(host) !== null
}

export class BlockedError extends Error {
  code = 'EBLOCKED'
  constructor() {
    super('blocked address')
  }
}

function notFoundError(): Error {
  const e = new Error('ENOTFOUND')
  ;(e as { code?: string }).code = 'ENOTFOUND'
  return e
}

// Resolve the hostname and refuse private / loopback / link-local / metadata
// addresses. Runs before every outbound request (including each redirect hop).
export async function resolveAndValidate(hostname: string): Promise<void> {
  const host = hostname.replace(/^\[|\]$/g, '')

  // IP literals need no DNS: judge them directly.
  if (isIpLiteral(host)) {
    if (isBlockedAddress(host)) throw new BlockedError()
    return
  }

  const dns = await import('node:dns')
  const addrs = await dns.promises.lookup(host, { all: true, verbatim: true })
  if (!Array.isArray(addrs) || addrs.length === 0) throw notFoundError()
  for (const a of addrs) {
    if (isBlockedAddress(a.address)) throw new BlockedError()
  }
}
