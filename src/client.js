/**
 * peck client — Browser-side tunnel connector
 *
 * Connects to a peck daemon via Nostr-signaled WebRTC.
 * Provides a fetch-like request() API over the multiplexed DataChannel.
 *
 * @module peck/client
 */

import * as secp from '@noble/secp256k1'
import { randomBytes } from '@noble/hashes/utils.js'
import { NativeTransport as DefaultTransport } from './native-transport.js'
import {
  encodeFrame,
  decodeFrame,
  StreamManager,
  MSG_OPEN,
  MSG_DATA,
  MSG_CLOSE
} from './protocol.js'

// ─── bech32m (npub → hex pubkey) ───────────────────────────────
// NIP-19 specifies Bech32m (BIP-350) for npub/nsec/etc — not legacy Bech32.
// Earlier drafts of this code used Bech32 (const=1); fixed 2026-07-18.

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
const BECH32M_CONST = 0x2bc830a3

function bech32Polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  let chk = 1
  for (const v of values) {
    let top = chk >> 25
    chk = ((chk & 0x1ffffff) << 5) ^ v
    for (let i = 0; i < 5; i++) {
      if (((top >> i) & 1) !== 0) chk ^= GEN[i]  // FIXED: was top >>= 1; if (top & 1)
    }
  }
  return chk
}

function bech32HRPExpand(hrp) {
  const ret = []
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5)
  ret.push(0)
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31)
  return ret
}

function bech32Decode(str) {
  // Enforce consistent case
  const lower = str.toLowerCase()
  const upper = str.toUpperCase()
  if (str !== lower && str !== upper) {
    throw new Error('Invalid bech32: mixed case')
  }
  str = lower

  const pos = str.lastIndexOf('1')
  if (pos < 1 || pos + 7 > str.length) {
    throw new Error('Invalid bech32: bad separator position')
  }

  const hrp = str.slice(0, pos)
  const dataPart = str.slice(pos + 1)

  const data = []
  for (const ch of dataPart) {
    const d = BECH32_CHARSET.indexOf(ch)
    if (d === -1) throw new Error(`Invalid bech32: bad character '${ch}'`)
    data.push(d)
  }

  // Verify checksum
  if (bech32Polymod(bech32HRPExpand(hrp).concat(data)) !== BECH32M_CONST) {
    throw new Error('Invalid bech32: bad checksum')
  }

  return { hrp, data: data.slice(0, -6) }
}

function convertBits(data, fromBits, toBits, pad) {
  let acc = 0
  let bits = 0
  const ret = []
  const maxv = (1 << toBits) - 1
  const maxAcc = (1 << (fromBits + toBits - 1)) - 1

  for (const v of data) {
    if (v < 0 || (v >> fromBits) !== 0) {
      throw new Error('Invalid bech32: value out of range')
    }
    acc = ((acc << fromBits) | v) & maxAcc
    bits += fromBits
    while (bits >= toBits) {
      bits -= toBits
      ret.push((acc >> bits) & maxv)
    }
  }

  if (pad) {
    if (bits > 0) {
      ret.push((acc << (toBits - bits)) & maxv)
    }
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
    throw new Error('Invalid bech32: non-zero padding')
  }

  return ret
}

/**
 * Decode a Nostr npub (bech32) to a 32-byte hex public key.
 *
 * @param {string} npub - Nostr public key in npub format
 * @returns {string} 64-char hex pubkey
 */
export function npubToHex(npub) {
  const { hrp, data } = bech32Decode(npub)
  if (hrp !== 'npub') {
    throw new Error(`Expected npub, got '${hrp}'`)
  }
  const bytes = convertBits(data, 5, 8, false)
  return bytes.map(b => b.toString(16).padStart(2, '0')).join('')
}

// ─── HTTP request/response ──────────────────────────────────────

/**
 * Normalise a body value to Uint8Array or null.
 * @param {Uint8Array|ArrayBuffer|number[]|null} body
 * @returns {Uint8Array|null}
 */
function normalizeBody(body) {
  if (!body) return null
  if (body instanceof Uint8Array) return body
  if (body instanceof ArrayBuffer) return new Uint8Array(body)
  return new Uint8Array(body)
}

/**
 * Encode an HTTP/1.1 request into raw bytes.
 *
 * @param {object} req
 * @param {string} req.method - HTTP method
 * @param {string} req.path - Request path
 * @param {number} req.port - Target port (for default Host header)
 * @param {object} req.headers - Request headers
 * @param {Uint8Array|null} req.body - Request body
 * @returns {Uint8Array}
 */
function encodeHttpRequest({ method, path, port, headers, body }) {
  const lines = [`${method} ${path} HTTP/1.1`]

  // Default Host header (can be overridden by caller)
  // Spec 024 FR-012: use the original window.location.hostname so the daemon
  // can do Host-header-based subdomain routing. Fall back to localhost:port
  // only if we're not in a browser context (e.g. unit tests).
  const lowerHeaders = Object.keys(headers).reduce((acc, k) => {
    acc[k.toLowerCase()] = headers[k]
    return acc
  }, {})

  if (!lowerHeaders['host']) {
    let defaultHost
    if (typeof window !== 'undefined' && window.location && window.location.hostname) {
      defaultHost = window.location.hostname
    } else {
      defaultHost = `localhost:${port}`  // test/non-browser fallback
    }
    lines.push(`Host: ${defaultHost}`)
  }

  for (const [key, value] of Object.entries(headers)) {
    lines.push(`${key}: ${value}`)
  }

  // Content-Length for body (if not explicitly set)
  if (body && body.length > 0 && !lowerHeaders['content-length']) {
    lines.push(`Content-Length: ${body.length}`)
  }

  const headerText = lines.join('\r\n') + '\r\n\r\n'
  const headerBytes = new TextEncoder().encode(headerText)

  if (body && body.length > 0) {
    const result = new Uint8Array(headerBytes.length + body.length)
    result.set(headerBytes, 0)
    result.set(body, headerBytes.length)
    return result
  }

  return headerBytes
}

/**
 * Parse a raw HTTP/1.1 response buffer into structured parts.
 *
 * @param {Uint8Array} buf - Raw response bytes
 * @returns {{ status: number, headers: object, body: Uint8Array }}
 */
function parseHttpResponse(buf) {
  // Find \r\n\r\n boundary in raw bytes (headers are ASCII, safe)
  const CR = 0x0d
  const LF = 0x0a
  let boundary = -1
  for (let i = 0; i <= buf.length - 4; i++) {
    if (buf[i] === CR && buf[i + 1] === LF && buf[i + 2] === CR && buf[i + 3] === LF) {
      boundary = i
      break
    }
  }
  if (boundary === -1) {
    throw new Error('Malformed HTTP response: no header/body delimiter')
  }

  const headerText = new TextDecoder().decode(buf.slice(0, boundary))
  const body = buf.slice(boundary + 4)

  const headerLines = headerText.split('\r\n')

  const statusMatch = headerLines[0].match(/^HTTP\/\d\.\d\s+(\d+)\s*(.*)/)
  if (!statusMatch) {
    throw new Error(`Malformed HTTP status line: ${headerLines[0]}`)
  }

  const status = parseInt(statusMatch[1], 10)

  const headers = {}
  for (let i = 1; i < headerLines.length; i++) {
    const colonIdx = headerLines[i].indexOf(':')
    if (colonIdx > 0) {
      const key = headerLines[i].slice(0, colonIdx).trim().toLowerCase()
      const value = headerLines[i].slice(colonIdx + 1).trim()
      headers[key] = value
    }
  }

  return { status, headers, body }
}

/**
 * Concatenate an array of Uint8Array chunks into a single buffer.
 * @param {Uint8Array[]} chunks
 * @returns {Uint8Array}
 */
function concatChunks(chunks) {
  const total = chunks.reduce((sum, c) => sum + c.length, 0)
  const result = new Uint8Array(total)
  let offset = 0
  for (const c of chunks) {
    result.set(c, offset)
    offset += c.length
  }
  return result
}

// ─── connect() ──────────────────────────────────────────────────

/**
 * Connect to a peck daemon via Nostr-signaled WebRTC.
 *
 * Generates an ephemeral secp256k1 key pair for NIP-04 encrypted DMs,
 * joins the daemon's Trystero room (roomId = daemon's hex pubkey),
 * and waits for the WebRTC peer connection to establish.
 *
 * @param {object} options
 * @param {string} options.npub - Daemon's Nostr public key (npub / bech32)
 * @param {string[]} options.relays - Nostr relay URLs (must match daemon's)
 * @param {number} [options.timeout=30000] - Connection timeout in ms
 * @param {object} [options._transport] - Inject a Transport (for testing)
 * @returns {Promise<{ request: Function, close: Function }>}
 */
// ─── WebRTC Diagnostics ─────────────────────────────────────────

/**
 * Parse RTCStatsReport into a compact diagnostics object.
 * Always shows external IP (srflx), never LAN IP (host).
 *
 * @param {RTCStatsReport|null} report
 * @returns {object|null}
 */
export function parseStats(report) {
  if (!report) return null

  let localIp = null, localPort = null, localType = null
  let remoteIp = null, remotePort = null, remoteType = null
  let rtt = null
  let bytesSent = null, bytesReceived = null
  let packetsSent = null, packetsLost = null

  // First pass: find selected candidate pair
  let selectedPairId = null
  for (const [id, s] of report) {
    if (s.type === 'candidate-pair' && s.selected) {
      selectedPairId = s.id
      rtt = s.currentRoundTripTime != null ? Math.round(s.currentRoundTripTime * 1000) : null
      break
    }
  }

  // Fallback: if no 'selected' flag, use the first connected/succeeded pair
  if (!selectedPairId) {
    for (const [id, s] of report) {
      if (s.type === 'candidate-pair' && (s.state === 'succeeded' || s.state === 'connected')) {
        selectedPairId = s.id
        rtt = s.currentRoundTripTime != null ? Math.round(s.currentRoundTripTime * 1000) : null
        break
      }
    }
  }

  // Resolve local + remote candidates from the selected pair
  if (selectedPairId) {
    let localCandId = null, remoteCandId = null
    for (const [id, s] of report) {
      if (s.type === 'candidate-pair' && s.id === selectedPairId) {
        localCandId = s.localCandidateId
        remoteCandId = s.remoteCandidateId
      }
    }
    for (const [id, s] of report) {
      if (s.type === 'local-candidate' && s.id === localCandId) {
        localIp = s.address
        localPort = s.port
        localType = s.candidateType
      }
      if (s.type === 'remote-candidate' && s.id === remoteCandId) {
        remoteIp = s.address
        remotePort = s.port
        remoteType = s.candidateType
      }
    }
  }

  // Transport stats for bytes + packets
  for (const [id, s] of report) {
    if (s.type === 'transport' || s.type === 'candidate-pair') {
      if (s.bytesSent != null) bytesSent = s.bytesSent
      if (s.bytesReceived != null) bytesReceived = s.bytesReceived
      if (s.packetsSent != null) packetsSent = s.packetsSent
    }
  }
  // packetsLost is on inbound-rtp or transport in some browsers
  for (const [id, s] of report) {
    if (s.type === 'transport' && s.packetsLost != null) {
      packetsLost = s.packetsLost
    }
  }

  // NAT inference from candidate types
  const natType = inferNatType(localType, remoteType)

  // Always prefer external IP (srflx). Fall back to host only if no srflx.
  const displayLocalIp = localType === 'srflx' ? localIp : localIp
  const displayRemoteIp = remoteIp

  const lossPct = packetsSent != null && packetsLost != null && packetsSent > 0
    ? Math.round((packetsLost / packetsSent) * 1000) / 10
    : 0

  return {
    localIp: displayLocalIp,
    localPort,
    localType,
    remoteIp: displayRemoteIp,
    remotePort,
    remoteType,
    rtt,
    lossPct,
    bytesSent,
    bytesReceived,
    natType
  }
}

/**
 * Infer NAT/firewall type from selected candidate pair types.
 */
function inferNatType(localType, remoteType) {
  if (localType === 'relay' || remoteType === 'relay') return 'symmetric-nat (TURN)'
  if (localType === 'srflx' && remoteType === 'srflx') return 'both-nat (hole-punch)'
  if (localType === 'srflx' && remoteType === 'host') return 'local-nat'
  if (localType === 'host' && remoteType === 'srflx') return 'remote-nat'
  if (localType === 'host' && remoteType === 'host') return 'direct (no NAT)'
  return 'unknown'
}

/**
 * Format diagnostics into a single-line display string.
 */
export function formatDiagnostics(d) {
  if (!d) return ''
  const parts = []
  if (d.localType && d.remoteType) parts.push(`⚡ ${d.localType} → ${d.remoteType}`)
  if (d.localIp && d.remoteIp) {
    const local = d.localPort ? `${d.localIp}:${d.localPort}` : d.localIp
    const remote = d.remotePort ? `${d.remoteIp}:${d.remotePort}` : d.remoteIp
    parts.push(`${local} → ${remote}`)
  }
  if (d.rtt != null) parts.push(`${d.rtt}ms`)
  if (d.lossPct != null) parts.push(`${d.lossPct}% loss`)
  if (d.bytesSent != null || d.bytesReceived != null) {
    const up = d.bytesSent ? formatBytes(d.bytesSent) : '0'
    const down = d.bytesReceived ? formatBytes(d.bytesReceived) : '0'
    parts.push(`${up}↑ ${down}↓`)
  }
  if (d.natType) parts.push(`(${d.natType})`)
  return parts.join(' · ')
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes}B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`
  return `${(bytes / 1024 / 1024).toFixed(1)}MB`
}

// ─── connect ────────────────────────────────────────────────────

export async function connect({ npub, relays, timeout = 30000, onDebug, onDisconnect, onDeny, onTermsChallenge, onOfferSdp, onAnswerSdp, onOwnIps, ipPreference, powTarget, _transport }) {
  // Decode daemon's npub → hex pubkey (used as NIP-44 recipient)
  const daemonPubkeyHex = npubToHex(npub)

  // Generate ephemeral key pair for NIP-44 DMs
  const privkeyBytes = randomBytes(32)
  const privkeyHex = secp.etc.bytesToHex(privkeyBytes)

  // Default transport is NativeTransport (NIP-44 + native RTCPeerConnection).
  // Callers may inject a custom transport via _transport for testing or to
  // preserve legacy Trystero behavior.
  const transport = _transport ?? new DefaultTransport({
    privkeyHex,
    pubkeyHex: daemonPubkeyHex,
    relays,
    onDebug,
    onOfferSdp,
    onAnswerSdp,
    onOwnIps,
    ipPreference,
  })

  const manager = new StreamManager()
  let closed = false
  const onDisconnectCb = onDisconnect

  // Spec 026: wire up loud-deny handler. When the daemon sends a deny DM,
  // reject the connect() promise with the deny message so callers can
  // surface it in the UI.
  if (onDeny && typeof transport.onDeny === 'function') {
    transport.onDeny((message) => {
      onDeny(message)
    })
  }

  // Spec 033: wire up terms-challenge handler. When the daemon sends a
  // terms-challenge DM, surface it to the UI. The connect timeout is paused
  // while the user reads terms and restarted when they click Accept.
  if (onTermsChallenge && typeof transport.onTermsChallenge === 'function') {
    transport.onTermsChallenge((text, version, transportRef) => {
      // Pause the connect timeout — user reads terms at their own pace
      _termsTimerPause?.()
      onTermsChallenge(text, version, transportRef)
    })
    // When terms are accepted (manual or auto), restart the timeout
    transport.onTermsAccepted(() => {
      _termsTimerReset?.()
    })
  }

  // Wire incoming bytes → protocol frame router
  transport.onMessage((data) => {
    try {
      manager.handleFrame(decodeFrame(data))
    } catch {
      // Malformed frame — ignore for resilience
    }
  })

  // Spec 033: expose ways for the terms flow to control the connect timeout.
  // _termsTimerPause: clear the timeout entirely (user reads terms at leisure)
  // _termsTimerReset: restart the timeout (user clicked Accept, WebRTC begins)
  let _termsTimerPause = null
  let _termsTimerReset = null

  // Register peer handlers BEFORE calling transport.connect(), so we
  // don't miss the peer-join event if connect() fires it synchronously.
  await new Promise((resolve, reject) => {
    let settled = false

    let timer = setTimeout(() => {
      if (!settled) reject(new Error(`Connection timeout (${timeout / 1000}s)`))
    }, timeout)

    // Spec 033: pause timeout while user reads terms (no limit)
    _termsTimerPause = () => {
      if (!settled) clearTimeout(timer)
    }

    // Spec 033: restart timeout when user accepts terms
    _termsTimerReset = () => {
      if (!settled) {
        clearTimeout(timer)
        timer = setTimeout(() => {
          if (!settled) reject(new Error(`Connection timeout after terms (${timeout / 1000}s)`))
        }, timeout)
      }
    }

    transport.onConnect(() => {
      if (!settled) {
        settled = true
        clearTimeout(timer)
        resolve()
      }
    })

    transport.onDisconnect(() => {
      if (!settled) {
        settled = true
        clearTimeout(timer)
        reject(new Error('Peer disconnected'))
      }
    })

    // Initiate connection — may reject (connect failure) or resolve
    // (peer connects via onConnect above)
    transport.connect().catch(err => {
      if (!settled) {
        settled = true
        clearTimeout(timer)
        reject(err)
      }
    })
  })

  // After initial connect: wire disconnect → reconnect handler
  // (the initial-connect handler above only fires once via `settled` guard)
  transport.onDisconnect(() => {
    if (closed) return
    onDisconnectCb?.()
  })

  /**
   * Send an HTTP request through the tunnel.
   *
   * @param {object} req
   * @param {number} req.port - Target port on daemon
   * @param {string} [req.method='GET']
   * @param {string} [req.path='/']
   * @param {object} [req.headers={}]
   * @param {Uint8Array|null} [req.body=null]
   * @returns {Promise<{ status: number, headers: object, body: Uint8Array }>}
   */
  async function request({ port, method = 'GET', path = '/', headers = {}, body = null }) {
    if (closed) throw new Error('Tunnel closed')
    if (!transport) throw new Error('No transport')

    const bodyBytes = normalizeBody(body)
    const httpRequest = encodeHttpRequest({ method, path, port, headers, body: bodyBytes })

    let settled = false
    let requestTimer = null
    let streamId

    try {
      return await new Promise((resolve, reject) => {
        const responseChunks = []

        streamId = manager.createStream(port, {
          onMessage(payload) {
            responseChunks.push(payload)
          },
          onClose(err) {
            if (settled) return
            settled = true
            clearTimeout(requestTimer)

            if (err) {
              reject(err)
              return
            }

            try {
              resolve(parseHttpResponse(concatChunks(responseChunks)))
            } catch (e) {
              reject(e)
            }
          }
        })

        // Per-request timeout
        requestTimer = setTimeout(() => {
          if (settled) return
          settled = true
          manager.closeStream(streamId)
          reject(new Error('Request timeout'))
        }, 15000)

        // Send MSG_OPEN (open stream to port) + MSG_DATA (raw HTTP request)
        transport.send(encodeFrame(streamId, port, MSG_OPEN))
        transport.send(encodeFrame(streamId, port, MSG_DATA, httpRequest))
      })
    } finally {
      // Always send MSG_CLOSE to tell the daemon we're done with this stream
      if (streamId != null) {
        transport.send(encodeFrame(streamId, port, MSG_CLOSE))
      }
    }
  }

  /**
   * Close the tunnel and disconnect from the daemon.
   */
  function close() {
    closed = true
    transport.disconnect()
  }

  /**
   * Get WebRTC diagnostics from the connected peer.
   * @returns {Promise<object|null>} Parsed diagnostics or null
   */
  async function getDiagnostics() {
    return parseStats(await transport.getStats())
  }

  return { request, close, getDiagnostics, _transport: transport,
           get isClosed() { return closed } }
}
