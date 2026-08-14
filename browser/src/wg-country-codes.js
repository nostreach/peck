/**
 * wg-country-codes.js — Country Code lookup for IP addresses.
 *
 * Single-layer lookup via geoip2-ipv4 (MaxMind GeoLite2-derived) dataset.
 * ~560k CIDR entries covering all global IPv4. Binary search, fully offline.
 *
 * Source: https://github.com/datasets/geoip2-ipv4 (same as server's EU geo-check)
 * No external API calls, no CORS, no tracking.
 *
 * geoip-data.js (~2.5MB gzipped) is loaded lazily on first lookup.
 */

/** Regional indicator letters → flag emoji offset. */
const FLAG_OFFSET = 0x1F1E6

// Lazy-loaded GeoIP data
let _geoipLoaded = false
let _geoipCcs = null
let _geoipEntries = null
let _geoipLoadPromise = null

async function _ensureGeoip() {
  if (_geoipLoaded) return
  if (_geoipLoadPromise) return _geoipLoadPromise
  _geoipLoadPromise = (async () => {
    const mod = await import('./geoip-data.js')
    _geoipCcs = mod.GEOIP_CCS
    _geoipEntries = mod.GEOIP_ENTRIES
    _geoipLoaded = true
  })()
  return _geoipLoadPromise
}

/** Resolves when geoip-data.js has loaded. Safe to call multiple times. */
export function _whenGeoipReady() {
  return _ensureGeoip()
}

export function ccToFlag(cc) {
  if (!cc || cc.length !== 2) return '❓'
  const upper = cc.toUpperCase()
  const c1 = FLAG_OFFSET + (upper.charCodeAt(0) - 65)
  const c2 = FLAG_OFFSET + (upper.charCodeAt(1) - 65)
  return String.fromCodePoint(c1, c2)
}

/**
 * Look up country code for an IP address.
 * Returns ISO 3166-1 alpha-2 code (e.g., 'DK') or null.
 * First call triggers lazy load of geoip-data.js (~2.5MB gzipped).
 */
export function lookupCountry(ip) {
  if (!_geoipLoaded) {
    // Trigger async load — caller gets null on first call,
    // subsequent calls after load completes will return the CC.
    _ensureGeoip()
    return null
  }
  return _doLookup(ip)
}

function _doLookup(ip) {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || !parts.every(p => p >= 0 && p <= 255)) {
    return null
  }

  const ipNum = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
  const arr = _geoipEntries
  let lo = 0, hi = arr.length - 1, result = -1

  while (lo <= hi) {
    const mid = (lo + hi) >> 1
    if (arr[mid][0] <= ipNum) {
      result = mid
      lo = mid + 1
    } else {
      hi = mid - 1
    }
  }

  if (result < 0) return null

  const [start, prefix, ccIdx] = arr[result]
  const mask = prefix === 0 ? 0 : ((0xFFFFFFFF << (32 - prefix)) >>> 0)

  if ((ipNum & mask) === (start & mask)) {
    return _geoipCcs[ccIdx] || null
  }
  return null
}

/**
 * Sync lookup — only works after geoip-data.js has loaded.
 * Returns null if data isn't loaded yet (call lookupCountry first to trigger load).
 */
export function getCachedCountry(ip) {
  if (!_geoipLoaded) return null
  return _doLookup(ip)
}
