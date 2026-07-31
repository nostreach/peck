/**
 * peck Service Worker — sub-asset tunnel proxy
 *
 * The main page handles HTML navigation directly (fetch through tunnel).
 * The SW intercepts sub-asset requests (CSS, JS, images, fetch()) and
 * routes them through the WebRTC tunnel via MessageChannel.
 *
 * Lifecycle: When a new page registers, it sends REGISTER with a fresh
 * MessageChannel port. The SW stores the latest port in tunnelPort,
 * replacing any stale port from a previous page load. This ensures
 * reloads don't hang on a dead tunnel reference.
 */

const SW_VERSION = 'peck-sw-v6'
const UI_PREFIXES = ['/sw.js', '/client.html', '/client.bundle.js', '/src/', '/wg-country-codes.js', '/geoip-data.js']

let tunnelPort = null
let tunnelPortClient = null  // track which client owns the port

self.addEventListener('install', () => {
  // Take over immediately on first install
  self.skipWaiting()
})

self.addEventListener('activate', (event) => {
  // Claim all clients so the new SW controls the page immediately
  event.waitUntil(
    self.clients.claim().then(() => {
      console.log('[peck-sw] activated, version:', SW_VERSION)
    })
  )
})

self.addEventListener('message', (event) => {
  const msg = event.data
  if (msg?.type === 'REGISTER' && event.ports.length > 0) {
    // Replace any existing port — new page load takes over
    tunnelPort = event.ports[0]
    tunnelPortClient = event.source?.id || null
    tunnelPort.start()
    console.log('[peck-sw] tunnel registered by client:', tunnelPortClient)
    event.source?.postMessage({ type: 'REGISTERED' })
    return
  }
  // Client went away — clear stale port
  if (msg?.type === 'UNREGISTER') {
    if (tunnelPortClient === event.source?.id) {
      tunnelPort = null
      tunnelPortClient = null
      console.log('[peck-sw] tunnel unregistered by client:', event.source?.id)
    }
    return
  }
})

// Detect client unload to clear stale port
self.addEventListener('messageerror', () => {
  // ignore
})

function isUIAsset(url) {
  const u = new URL(url)
  // Parent page with npub param
  if (u.pathname === '/' && u.search.includes('npub=')) return true
  // Known peck UI assets
  if (u.pathname === '/sw.js' || u.pathname === '/client.html' || u.pathname === '/client.bundle.js') return true
  if (UI_PREFIXES.some(p => u.pathname.startsWith(p))) return true
  // Navigation requests (mode=navigate) are handled by the page, not SW
  return false
}

let requestCounter = 0
const pendingRequests = new Map()

self.addEventListener('fetch', (event) => {
  const request = event.request

  // Cross-origin requests (e.g. DoH lookups to dns.google, relay
  // WebSockets) MUST bypass the SW entirely — the tunnel only proxies
  // same-origin sub-assets.
  const url = new URL(request.url)
  if (url.origin !== self.location.origin) {
    return  // Let the browser handle it natively
  }

  // Navigation requests: always fetch from network (bypass all caches).
  if (request.mode === 'navigate') {
    event.respondWith(fetch(request, { cache: 'no-store' }))
    return
  }

  // UI assets: force network fetch (bypass browser HTTP cache).
  if (isUIAsset(request.url)) {
    event.respondWith(fetch(request, { cache: 'no-store' }))
    return
  }

  // No tunnel → fail fast with 503 instead of hanging
  if (!tunnelPort) {
    event.respondWith(new Response('peck tunnel disconnected', {
      status: 503,
      headers: { 'Content-Type': 'text/plain' }
    }))
    return
  }

  event.respondWith(routeThroughTunnel(request))
})

async function routeThroughTunnel(request) {
  const url = new URL(request.url)
  const id = ++requestCounter
  const path = url.pathname + url.search
  const method = request.method

  const headers = {}
  for (const [k, v] of request.headers.entries()) headers[k] = v

  let body = null
  if (method !== 'GET' && method !== 'HEAD') {
    const raw = await request.arrayBuffer()
    body = Array.from(new Uint8Array(raw))
  }

  const responsePromise = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      pendingRequests.delete(id)
      reject(new Error('Tunnel timeout (30s)'))
    }, 30000)
    pendingRequests.set(id, { resolve, reject, timeout })
  })

  const handler = (event) => {
    const msg = event.data
    if (msg?.id !== id) return
    const pending = pendingRequests.get(id)
    if (!pending) return
    clearTimeout(pending.timeout)
    pendingRequests.delete(id)
    tunnelPort.removeEventListener('message', handler)

    if (msg.error) {
      reject(new Error(msg.error))
    } else {
      const responseHeaders = new Headers()
      for (const [k, v] of Object.entries(msg.headers || {})) {
        responseHeaders.set(k, v)
      }
      resolve(new Response(
        msg.body ? new Uint8Array(msg.body) : new Uint8Array(0),
        { status: msg.status || 200, headers: responseHeaders }
      ))
    }
  }

  tunnelPort.addEventListener('message', handler)
  tunnelPort.postMessage({ type: 'TUNNEL_REQUEST', id, method, path, headers, body })

  return responsePromise
}
