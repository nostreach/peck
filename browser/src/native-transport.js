/**
 * peck — NativeTransport
 *
 * Browser-side transport: NIP-44 v2 DMs + native RTCPeerConnection.
 * Uses direct NIP-44 encrypted DMs over native WebSocket + native RTCPeerConnection.
 * No Trystero, no werift, no patch-package, no globalThis hacks.
 *
 * Signaling protocol (4 message types, matches Python daemon.py v4):
 *   client → daemon : {"peerId":"...","type":"announce"}
 *   daemon → client : {"type":"offer","sdp":"..."}
 *   client → daemon : {"type":"answer","sdp":"..."}
 *   bidirectional   : {"type":"candidate","sdp":"..."}   (trickle ICE)
 *
 * All messages are NIP-44 v2 encrypted and carried in kind=4 Nostr events.
 *
 * @module peck/native-transport
 */

import * as secp from '@noble/secp256k1'
import { sha256 } from '@noble/hashes/sha2.js'
import { hmac } from '@noble/hashes/hmac.js'
import { randomBytes } from '@noble/hashes/utils.js'
import { encrypt as nip44Encrypt, decrypt as nip44Decrypt } from './nip44-browser.js'

// Wire up synchronous hash providers for @noble/secp256k1 Schnorr signing.
secp.hashes.sha256 = sha256
secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg)

const STUN_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
]

/**
 * NativeTransport — raw byte transport over a direct WebRTC peer connection.
 *
 * Wire format on the DataChannel is the peck binary stream protocol
 * (see src/protocol.js). This class only owns signaling + DataChannel lifecycle.
 */
export class NativeTransport {
  /**
   * @param {object} options
   * @param {string} options.privkeyHex - ephemeral Nostr private key (64 hex chars)
   * @param {string} options.pubkeyHex - daemon's x-only pubkey (64 hex chars)
   * @param {string[]} options.relays - Nostr relay URLs
   * @param {Function} [options.onDebug] - debug event callback
   * @param {Function} [options.onOfferSdp] - Spec 034: called with the daemon's offer SDP so the client can extract exit IPs
   * @param {string} [options.ipPreference] - Spec 034: "ipv4" | "ipv6" | "both" (default: "both")
   */
  constructor(options = {}) {
    const { privkeyHex, pubkeyHex, relays, onDebug, onOfferSdp, onAnswerSdp, onOwnIps, ipPreference, autoAcceptTerms } = options
    this.privkeyHex = privkeyHex
    this.pubkeyHex = pubkeyHex
    this.relays = relays
    this.onDebug = onDebug
    this.onOfferSdp = onOfferSdp
    this.onAnswerSdp = onAnswerSdp
    this.onOwnIps = onOwnIps
    this.ipPreference = ipPreference || 'both'
    this.autoAcceptTerms = autoAcceptTerms || false

    this.pubkey = (() => {
      // secp.getPublicKey expects Uint8Array, not hex string.
      // Returns 33-byte compressed key (0x02/0x03 prefix). Slice to 32-byte x-only.
      const privBytes = secp.etc.hexToBytes(privkeyHex)
      const compressed = secp.getPublicKey(privBytes, true)
      return secp.etc.bytesToHex(compressed.slice(1))
    })()
    this.peerId = Array.from(randomBytes(8)).map(b => b.toString(16).padStart(2, '0')).join('')

    this.pc = null
    this.channel = null
    this.websockets = []
    this.subscriptionId = 'peck-' + randomBytes(6).reduce((s, b) => s + b.toString(16).padStart(2, '0'), '')

    this._onMessage = null
    this._onConnect = null
    this._onDisconnect = null
    this._onDeny = null
    this._onTermsChallenge = null
    this._onTermsAccepted = null
    this._closed = false

    this._debug('init', { peerId: this.peerId, pubkey: this.pubkey.slice(0, 16) + '…' })
  }

  // ─── Public API (matches TrysteroTransport) ──────────────────────────────

  /**
   * Connect to the daemon: subscribe to relays, send announce DM, await
   * WebRTC offer from the daemon, apply it, and complete the handshake.
   * @returns {Promise<void>}
   */
  async connect() {
    this.pc = new RTCPeerConnection({ iceServers: STUN_SERVERS })

    // Daemon is the offerer and creates the DataChannel. We receive it here.
    this.pc.addEventListener('datachannel', (event) => {
      this._debug('datachannel_received', { label: event.channel.label })
      this._setupChannel(event.channel)
    })

    // Trickle ICE candidates → send to daemon as they arrive
    this.pc.addEventListener('icecandidate', (event) => {
      if (event.candidate && event.candidate.candidate) {
        this._sendSignaling({ type: 'candidate', sdp: event.candidate.candidate }).catch(() => {})
      }
    })

    this.pc.addEventListener('connectionstatechange', () => {
      const state = this.pc.connectionState
      this._debug('pc_state', { state })
      if (state === 'connected') this._onConnect?.()
      else if (state === 'failed' || state === 'closed' || state === 'disconnected') {
        this._onDisconnect?.()
      }
    })

    // Open relay subscriptions
    await this._openRelays()

    // Spec 026 FR-009: resolve client IP via STUN before announce.
    // The self-declared srflx IP is sent in the announce-DM so the
    // daemon's access-control policy has both pubkey and IP at the
    // first (and only) decision point. Failure is non-fatal — the
    // daemon tolerates a missing client_ip field (pubkey-only policy).
    const { ipv4: clientIp, all: allClientIps } = await this._resolveClientIp()
    const announce = { peerId: this.peerId, type: 'announce' }
    if (clientIp) announce.client_ip = clientIp
    // Spec 034: send ip_preference so the daemon can filter WG tunnels
    if (this.ipPreference && this.ipPreference !== 'both') {
      announce.ip_preference = this.ipPreference
    }

    // Send announce
    await this._sendSignaling(announce)
    this._debug('announce_sent', { peerId: this.peerId, client_ip: clientIp || null })
    // Spec 034: surface STUN-resolved own IPs (bypasses mDNS obfuscation)
    if (this.onOwnIps && allClientIps.length) {
      this.onOwnIps(allClientIps)
    }
  }

  /**
   * Resolve the client's server-reflexive IPs via STUN queries.
   * Uses a dedicated RTCPeerConnection + a no-op offer/answer round-trip
   * to gather ICE candidates without polluting the main connection.
   *
   * Spec 023 (wire format, 2026-07-19 amendment) + Spec 026 (access control).
   *
   * @returns {Promise<{ipv4: string|null, all: string[]}>} IPv4 dotted-quad
   *   for announce compatibility, plus all resolved public IPs (v4+v6).
   */
  async _resolveClientIp() {
    const probePc = new RTCPeerConnection({ iceServers: STUN_SERVERS })
    // m-line so the browser actually gathers candidates
    probePc.createDataChannel('probe')
    const srflxIps = []
    try {
      const offer = await probePc.createOffer()
      await probePc.setLocalDescription(offer)
      // Wait for ICE gathering to complete (need all srflx candidates
      // including IPv6, which may arrive after IPv4).
      await new Promise((resolve) => {
        let settled = false
        const done = () => {
          if (settled) return
          settled = true
          resolve()
        }
        const onState = () => {
          if (probePc.iceGatheringState === 'complete') done()
        }
        const onCandidate = (event) => {
          const c = event.candidate
          if (!c || !c.candidate) { done(); return } // end-of-candidates
          if (c.candidate.includes(' typ srflx ')) {
            // Extract IP address (v4 or v6) from candidate string
            const parts = c.candidate.split(' ')
            if (parts.length >= 5) {
              const ip = parts[4]
              if (ip && !srflxIps.includes(ip)) srflxIps.push(ip)
            }
          }
        }
        probePc.addEventListener('icecandidate', onCandidate)
        probePc.addEventListener('icegatheringstatechange', onState)
        setTimeout(done, 3000) // generous timeout for IPv6 gathering
      })
    } catch (err) {
      this._debug('client_ip_resolve_failed', { error: String(err) })
    } finally {
      try { probePc.close() } catch (_) {}
    }
    const ipv4 = srflxIps.find(ip => ip.match(/^\d{1,3}(\.\d{1,3}){3}$/)) || null
    this._debug('client_ip_resolved', { ip: ipv4, all: srflxIps })
    return { ipv4, all: srflxIps }
  }

  /**
   * Wire up a DataChannel: route incoming bytes to _onMessage.
   * @param {RTCDataChannel} channel
   */
  _setupChannel(channel) {
    this.channel = channel
    channel.binaryType = 'arraybuffer'

    channel.addEventListener('open', () => {
      this._debug('channel_open', { label: channel.label })
    })

    channel.addEventListener('message', (event) => {
      const data = event.data instanceof ArrayBuffer
        ? new Uint8Array(event.data)
        : event.data
      if (data instanceof Uint8Array) {
        this._onMessage?.(data)
      }
    })

    channel.addEventListener('close', () => {
      this._debug('channel_close', { label: channel.label })
    })

    channel.addEventListener('error', (event) => {
      this._debug('channel_error', { error: event.error?.message || String(event) })
    })
  }

  /**
   * Send raw bytes to the connected peer.
   * @param {Uint8Array} data
   */
  send(data) {
    if (this.channel && this.channel.readyState === 'open') {
      try {
        this.channel.send(data)
      } catch (err) {
        this._debug('send_error', { error: err.message })
      }
    }
  }

  /** @param {(data: Uint8Array) => void} cb */
  onMessage(cb) { this._onMessage = cb }

  /** @param {() => void} cb */
  onConnect(cb) { this._onConnect = cb }

  /** @param {() => void} cb */
  onDisconnect(cb) { this._onDisconnect = cb }

  /**
   * Spec 026: register a callback fired when the daemon sends a loud-deny DM.
   * The callback receives the (trimmed, de-padded) deny message.
   * @param {(message: string) => void} cb
   */
  onDeny(cb) { this._onDeny = cb }

  /**
   * Spec 033: register a callback fired when the daemon sends a terms-challenge DM.
   * The callback receives (text, version). The caller must display the terms
   * and call acceptTerms(version) when the user accepts. If auto_accept_terms
   * is enabled, acceptTerms() is called immediately by the transport.
   * @param {(text: string, version: string) => void} cb
   */
  onTermsChallenge(cb) { this._onTermsChallenge = cb }

  /**
   * Get WebRTC stats from the RTCPeerConnection.
   * @returns {Promise<RTCStatsReport | null>}
   */
  async getStats() {
    if (!this.pc) return null
    return this.pc.getStats()
  }

  /**
   * Tear down: close peer connection, close websockets.
   */
  disconnect() {
    this._closed = true
    if (this.channel) {
      try { this.channel.close() } catch {}
      this.channel = null
    }
    if (this.pc) {
      try { this.pc.close() } catch {}
      this.pc = null
    }
    for (const ws of this.websockets) {
      try { ws.close() } catch {}
    }
    this.websockets = []
  }

  // ─── Relay handling ──────────────────────────────────────────────────────

  async _openRelays() {
    const reqFilter = { kinds: [4], '#p': [this.pubkey] }
    const reqMsg = JSON.stringify(['REQ', this.subscriptionId, reqFilter])

    await Promise.all(this.relays.map(async (url) => {
      try {
        const ws = new WebSocket(url)
        await new Promise((resolve, reject) => {
          ws.addEventListener('open', resolve, { once: true })
          ws.addEventListener('error', () => reject(new Error(`ws open failed: ${url}`)), { once: true })
        })
        ws.addEventListener('message', (event) => this._onRelayMessage(event, url))
        ws.addEventListener('close', () => this._debug('relay_closed', { url }))
        ws.send(reqMsg)
        this.websockets.push(ws)
        this._debug('relay_connected', { url })
      } catch (err) {
        this._debug('relay_failed', { url, error: err.message })
      }
    }))

    if (this.websockets.length === 0) {
      throw new Error('no relays connected')
    }
  }

  async _onRelayMessage(event, url) {
    let data
    try {
      data = JSON.parse(event.data)
    } catch {
      return
    }
    // Log every relay message for debugging
    const dataPreview = JSON.stringify(data).slice(0, 200)
    this._debug('relay_msg', { url, type: data[0], preview: dataPreview })

    if (!Array.isArray(data) || data.length < 3) return
    if (data[0] !== 'EVENT') return

    const evt = data[2]
    if (evt.kind !== 4) return

    // Log all DMs we see (before filtering)
    this._debug('dm_seen', {
      from: evt.pubkey.slice(0, 8),
      to: (evt.tags.find(t => t[0] === 'p') || [])[1]?.slice(0, 8) || '?',
      ourPubkey: this.pubkey.slice(0, 8),
      daemonPubkey: this.pubkeyHex.slice(0, 8)
    })

    // Filter for events addressed to us from the daemon
    if (evt.pubkey !== this.pubkeyHex) return
    const tagged = (evt.tags || []).some(t => t[0] === 'p' && t[1] === this.pubkey)
    if (!tagged) return

    let plaintext
    try {
      plaintext = nip44Decrypt(evt.content, this.privkeyHex, evt.pubkey)
    } catch (err) {
      this._debug('nip44_decrypt_failed', { error: err.message })
      return
    }

    let msg
    try {
      msg = JSON.parse(plaintext)
    } catch {
      return
    }

    this._debug('dm_received', { from: evt.pubkey.slice(0, 8), type: msg.type, len: evt.content.length })
    await this._handleSignal(msg)
  }

  /**
   * Spec 034: Filter ICE candidates in an SDP string by IP family.
   * Strips candidates that don't match the requested preference.
   *
   * @param {string} sdp - Raw SDP string
   * @param {string} preference - "ipv4" or "ipv6"
   * @returns {string} Filtered SDP
   */
  _filterSdpByIpFamily(sdp, preference) {
    const lines = sdp.split('\r\n')
    const filtered = lines.filter(line => {
      if (!line.startsWith('a=candidate:')) return true
      // Candidate format: a=candidate:ID COMPONENT PROTO Priority ADDR PORT ...
      // The address is the 5th space-separated field (index 4)
      const parts = line.split(' ')
      const addr = parts[4] || ''
      const isIPv6 = addr.includes(':')
      if (preference === 'ipv6' && !isIPv6) return false
      if (preference === 'ipv4' && isIPv6) return false
      return true
    })
    return filtered.join('\r\n')
  }

  async _handleSignal(msg) {
    if (msg.type === 'offer') {
      try {
        // Spec 034: surface the offer SDP to the client so it can
        // extract daemon exit IPs from ICE candidates.
        if (msg.sdp && this.onOfferSdp) {
          this.onOfferSdp(msg.sdp)
        }
        // Spec 034: client-side IP preference filtering.
        // If ipPreference is ipv4 or ipv6, strip the other family's
        // candidates from the remote offer before setRemoteDescription.
        // The ICE agent can only pair matching-family candidates, so
        // removing IPv4 remote candidates forces IPv6-only connectivity.
        let offerSdp = msg.sdp
        if (this.ipPreference && this.ipPreference !== 'both') {
          offerSdp = this._filterSdpByIpFamily(offerSdp, this.ipPreference)
          this._debug('offer_ip_filtered', { preference: this.ipPreference })
        }
        await this.pc.setRemoteDescription({ type: 'offer', sdp: offerSdp })
        const answer = await this.pc.createAnswer()
        await this.pc.setLocalDescription(answer)
        // Send answer back to daemon
        await this._sendSignaling({ type: 'answer', sdp: this.pc.localDescription.sdp })
        this._debug('answer_sent', {})
        // Spec 034: surface the answer SDP so client can extract own IPs.
        // ICE candidates are gathered asynchronously — listen for
        // icegatheringstatechange to fire when gathering is complete.
        if (this.onAnswerSdp) {
          const fireAnswerSdp = () => {
            if (this.pc.iceGatheringState === 'complete') {
              this.onAnswerSdp(this.pc.localDescription.sdp)
              this.pc.removeEventListener('icegatheringstatechange', fireAnswerSdp)
            }
          }
          if (this.pc.iceGatheringState === 'complete') {
            this.onAnswerSdp(this.pc.localDescription.sdp)
          } else {
            this.pc.addEventListener('icegatheringstatechange', fireAnswerSdp)
            // Fallback: fire after 3s even if gathering doesn't complete
            setTimeout(() => {
              if (this.pc.localDescription?.sdp && this.pc.iceGatheringState !== 'complete') {
                this.onAnswerSdp(this.pc.localDescription.sdp)
              }
            }, 3000)
          }
        }
      } catch (err) {
        this._debug('offer_apply_error', { error: err.message })
      }
    } else if (msg.type === 'candidate') {
      try {
        // The "candidate" field is a candidate string. Wrap into RTCIceCandidate.
        // Daemon sends {"type":"candidate","sdp":"candidate:..."}
        await this.pc.addIceCandidate({ candidate: msg.sdp, sdpMid: '0', sdpMLineIndex: 0 })
      } catch (err) {
        this._debug('candidate_apply_error', { error: err.message })
      }
    } else if (msg.type === 'deny') {
      // Spec 026: loud-deny. Daemon sent us a byte-padded deny message.
      // Trim padding (null bytes) and surface to the UI via _onDeny callback.
      const message = (msg.message || '').replace(/\x00.*$/, '').trim()
      this._debug('deny_received', { message })
      this._onDeny?.(message || 'access denied')
      // Don't auto-reconnect — daemon explicitly denied us.
      this._closed = true
    } else if (msg.type === 'terms-challenge') {
      // Spec 033: Terms of Service challenge from daemon.
      const text = msg.text || ''
      const version = msg.version || ''
      this._debug('terms_challenge', { version, textLen: text.length })

      // Check auto_accept_terms (resolved by caller, not read from localStorage directly)
      const autoAccept = this.autoAcceptTerms
      if (autoAccept) {
        this._debug('terms_auto_accepted', { version })
        this.acceptTerms(version)
      } else {
        // Surface to the UI — caller must show terms and call acceptTerms()
        this._onTermsChallenge?.(text, version, this)
      }
    } else if (msg.type === 'request-ip') {
      // Spec 033: Daemon requests client_ip. Re-resolve and re-announce.
      this._debug('request_ip_received', {})
      const { ipv4: clientIp, all: allClientIps } = await this._resolveClientIp()
      if (clientIp) {
        const announce = { peerId: this.peerId, type: 'announce' }
        announce.client_ip = clientIp
        await this._sendSignaling(announce)
        this._debug('re_announce_with_ip', { client_ip: clientIp })
      } else {
        // Could not resolve IP — re-announce without it (daemon will handle)
        const announce = { peerId: this.peerId, type: 'announce' }
        await this._sendSignaling(announce)
        this._debug('re_announce_without_ip', {})
      }
      // Spec 034: surface updated own IPs
      if (this.onOwnIps && allClientIps.length) {
        this.onOwnIps(allClientIps)
      }
    }
  }

  /**
   * Spec 033: register a callback fired whenever terms are accepted
   * (either manually via acceptTerms() or via auto_accept_terms).
   * Used by client.js to reset the connect timeout.
   * @param {() => void} cb
   */
  onTermsAccepted(cb) { this._onTermsAccepted = cb }

  /**
   * Spec 033: Accept terms with the given version string.
   * Called by the UI when the user clicks "Accept", or automatically
   * when auto_accept_terms is enabled.
   * @param {string} version
   */
  acceptTerms(version) {
    this._debug('terms_accept_sent', { version })
    this._onTermsAccepted?.()
    this._sendSignaling({ type: 'terms-accept', version })
  }

  // ─── NIP-44 encrypted DM sender ──────────────────────────────────────────

  async _sendSignaling(payload) {
    const plaintext = JSON.stringify(payload)
    const content = nip44Encrypt(plaintext, this.privkeyHex, this.pubkeyHex)
    const event = await this._buildSignedEvent(content)
    const eventMsg = JSON.stringify(['EVENT', event])

    // Send to ALL connected relays for redundancy. The daemon may be
    // listening on a different relay than the first one we connected to.
    let sent = 0
    for (const ws of this.websockets) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(eventMsg)
        sent++
      }
    }
    if (sent > 0) {
      this._debug('dm_sent', {
        type: payload.type,
        relays: sent,
        len: content.length,
      })
    } else {
      this._debug('dm_no_relay', { type: payload.type })
    }
  }

  /**
   * Build and sign a NIP-01 kind=4 event with BIP-340 Schnorr signature.
   */
  async _buildSignedEvent(content) {
    const createdAt = Math.floor(Date.now() / 1000)
    const tags = [['p', this.pubkeyHex]]
    const canonical = JSON.stringify([0, this.pubkey, createdAt, 4, tags, content])
    const eventId = sha256(new TextEncoder().encode(canonical))
    // secp.schnorr.sign expects (msgHash: Uint8Array, privateKey: Uint8Array).
    const privBytes = secp.etc.hexToBytes(this.privkeyHex)
    const sig = await secp.schnorr.sign(eventId, privBytes)

    return {
      kind: 4,
      content,
      tags,
      created_at: createdAt,
      pubkey: this.pubkey,
      id: secp.etc.bytesToHex(eventId),
      sig: secp.etc.bytesToHex(sig),
    }
  }

  // ─── Debug helper ────────────────────────────────────────────────────────

  _debug(msg, data) {
    // Match TrysteroTransport's calling convention: onDebug(msg, data)
    this.onDebug?.(msg, data)
  }
}
