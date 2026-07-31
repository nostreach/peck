/**
 * NIP-44 v2 encryption for browsers.
 *
 * Reference: https://github.com/nostr-protocol/nips/blob/master/44.md
 * Test vectors: https://github.com/paulmillr/nip44/blob/main/nip44.vectors.json
 *
 * Design (matches the Python reference in nostreach-peck-py/nip44.py):
 * - ECDH on secp256k1 (UNHASHED X coordinate, BIP-340 style — NOT SHA-256 like NIP-04)
 * - HKDF-Extract with SHA-256, salt = 'nip44-v2'
 * - Per-message: 32-byte random nonce
 * - HKDF-Expand(PRK=conversation_key, info=nonce, L=76) → (chacha_key[32], chacha_nonce[12], hmac_key[32])
 * - Custom padding (powers-of-two, min 32 bytes; 2-byte or 6-byte length prefix)
 * - ChaCha20 (RFC 8439, 4-byte counter starts at 0)
 * - HMAC-SHA256(key=hmac_key, msg=concat(nonce, ciphertext)) → 32-byte MAC
 * - payload = base64(version=0x02 || nonce[32] || ciphertext || mac[32])
 *
 * Browser deps (resolved via importmap):
 *   @noble/secp256k1        — ECDH + Schnorr signing (only used for key derivation here)
 *   @noble/hashes/sha2.js   — sha256
 *   @noble/hashes/hmac.js   — hmac
 *   @noble/hashes/utils.js  — randomBytes, bytesToHex, hexToBytes
 *   @noble/ciphers/chacha.js — RFC 8439 ChaCha20 stream
 *
 * @module peck/nip44-browser
 */

import * as secp from '@noble/secp256k1'
import { sha256 } from '@noble/hashes/sha2.js'
import { hmac } from '@noble/hashes/hmac.js'
import { randomBytes } from '@noble/hashes/utils.js'
import { chacha20 } from '@noble/ciphers/chacha.js'

// ─── Constants ─────────────────────────────────────────────────────────────

export const VERSION = 2
const VERSION_BYTE = 0x02
const MIN_PLAINTEXT_SIZE = 1
const MAX_PLAINTEXT_SIZE = 2 ** 32 - 1
const EXTENDED_PREFIX_THRESHOLD = 65536
const SALT = new TextEncoder().encode('nip44-v2')

// Wire up synchronous hash providers for @noble/secp256k1 (required for any
// schnorr.sign/verify usage in the broader app; harmless if not called here).
secp.hashes.sha256 = sha256
secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg)

// ─── Base64 helpers (UTF-8 safe, works in browsers and Node ≥ 16) ──────────

function base64Encode(bytes) {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary)
}

function base64Decode(str) {
  const binary = atob(str)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

// ─── secp256k1 ECDH (UNHASHED X coordinate) ────────────────────────────────

/**
 * Compute the UNHASHED 32-byte X coordinate of ECDH(privkey, pubkey).
 *
 * NIP-44 explicitly does NOT hash the ECDH output (unlike NIP-04 which uses
 * SHA-256). We use @noble/secp256k1's getSharedSecret with isCompressed=false
 * (returns 65 bytes: 0x04 || X[32] || Y[32]) and slice off the X coordinate.
 *
 * @param {Uint8Array} privBytes - 32-byte private key
 * @param {Uint8Array} pubXOnlyBytes - 32-byte x-only public key
 * @returns {Uint8Array} 32-byte unhashed shared X coordinate
 */
function ecdhSharedX(privBytes, pubXOnlyBytes) {
  if (pubXOnlyBytes.length === 32) {
    // Prepend 0x02 (even Y) — @noble accepts either prefix as long as the
    // point is valid; both yield the same X coordinate.
    const compressed = new Uint8Array(33)
    compressed[0] = 0x02
    compressed.set(pubXOnlyBytes, 1)
    pubXOnlyBytes = compressed
  }
  // isCompressed=false → 65-byte uncompressed (0x04 || X || Y)
  const shared = secp.getSharedSecret(privBytes, pubXOnlyBytes, false)
  return shared.slice(1, 33) // X coordinate
}

// ─── HKDF (RFC 5869, SHA-256) ──────────────────────────────────────────────

function hkdfExtract(salt, ikm) {
  // RFC 5869: if salt is empty, use 32 zero bytes. Our salt is always
  // 'nip44-v2' (8 bytes), but keep the guard for completeness.
  if (salt.length === 0) salt = new Uint8Array(32)
  return hmac(sha256, salt, ikm)
}

function hkdfExpand(prk, info, length) {
  if (length > 255 * 32) throw new Error('HKDF expand length too large')
  const n = Math.ceil(length / 32)
  const okmChunks = []
  let t = new Uint8Array(0)
  for (let i = 1; i <= n; i++) {
    const input = new Uint8Array(t.length + info.length + 1)
    input.set(t, 0)
    input.set(info, t.length)
    input[t.length + info.length] = i
    t = hmac(sha256, prk, input)
    okmChunks.push(t)
  }
  const okm = new Uint8Array(n * 32)
  for (let i = 0; i < n; i++) okm.set(okmChunks[i], i * 32)
  return okm.slice(0, length)
}

// ─── Conversation key + per-message keys ───────────────────────────────────

/**
 * Long-term conversation key between two peers.
 * conv(Apriv, Bpub) == conv(Bpriv, Apub) because ECDH is symmetric.
 *
 * @param {string|Uint8Array} privkey - sender's private key (hex string or 32 bytes)
 * @param {string|Uint8Array} pubkeyXOnly - recipient's x-only pubkey (hex string or 32 bytes)
 * @returns {Uint8Array} 32-byte conversation key
 */
export function getConversationKey(privkey, pubkeyXOnly) {
  const privBytes = typeof privkey === 'string'
    ? secp.etc.hexToBytes(privkey)
    : privkey
  const pubBytes = typeof pubkeyXOnly === 'string'
    ? secp.etc.hexToBytes(pubkeyXOnly)
    : pubkeyXOnly
  const sharedX = ecdhSharedX(privBytes, pubBytes)
  return hkdfExtract(SALT, sharedX)
}

/**
 * Derive per-message keys from the conversation key + nonce.
 * @param {Uint8Array} conversationKey - 32-byte HKDF PRK
 * @param {Uint8Array} nonce - 32-byte per-message nonce
 * @returns {{chachaKey: Uint8Array, chachaNonce: Uint8Array, hmacKey: Uint8Array}}
 */
export function getMessageKeys(conversationKey, nonce) {
  if (conversationKey.length !== 32) throw new Error('invalid conversation_key length')
  if (nonce.length !== 32) throw new Error('invalid nonce length')
  const keys = hkdfExpand(conversationKey, nonce, 76)
  return {
    chachaKey: keys.slice(0, 32),
    chachaNonce: keys.slice(32, 44),
    hmacKey: keys.slice(44, 76),
  }
}

// ─── Padding (powers-of-two scheme) ────────────────────────────────────────

function floorLog2(n) {
  if (n <= 0) throw new Error('log2 of non-positive number')
  // For 32-bit safe integers, bit_length - 1 = floor(log2(n))
  return n.toString(2).length - 1
}

/**
 * Calculate the padded length for a given unpadded length.
 * Mirrors nip44.py:calc_padded_len exactly.
 */
export function calcPaddedLen(unpaddedLen) {
  if (unpaddedLen <= 32) return 32
  const nextPower = 1 << (floorLog2(unpaddedLen - 1) + 1)
  const chunk = nextPower <= 256 ? 32 : nextPower >> 3
  return chunk * (Math.floor((unpaddedLen - 1) / chunk) + 1)
}

/**
 * Pad plaintext to a fixed length using the powers-of-two scheme.
 * Format: [len_prefix][plaintext][zero_padding]
 *   - len_prefix is 2 bytes (big-endian) for unpadded_len < 65536
 *   - len_prefix is 6 bytes (0x0000 + 4-byte BE) for unpadded_len >= 65536
 */
export function pad(plaintext) {
  const unpadded = new TextEncoder().encode(plaintext)
  const unpaddedLen = unpadded.length
  if (unpaddedLen < MIN_PLAINTEXT_SIZE || unpaddedLen > MAX_PLAINTEXT_SIZE) {
    throw new Error('invalid plaintext length')
  }

  let prefix
  if (unpaddedLen >= EXTENDED_PREFIX_THRESHOLD) {
    // 6-byte prefix: 0x00 0x00 + 4-byte BE length
    prefix = new Uint8Array(6)
    new DataView(prefix.buffer).setUint32(2, unpaddedLen, false)
  } else {
    // 2-byte prefix: BE length
    prefix = new Uint8Array(2)
    new DataView(prefix.buffer).setUint16(0, unpaddedLen, false)
  }

  const suffixLen = calcPaddedLen(unpaddedLen) - unpaddedLen
  const result = new Uint8Array(prefix.length + unpaddedLen + suffixLen)
  result.set(prefix, 0)
  result.set(unpadded, prefix.length)
  // suffix is already zero-filled by Uint8Array default
  return result
}

/**
 * Remove padding. Mirrors nip44.py:unpad.
 */
export function unpad(padded) {
  const firstTwo = new DataView(padded.buffer, padded.byteOffset, 2).getUint16(0, false)
  let unpaddedLen, prefixLen
  if (firstTwo === 0) {
    unpaddedLen = new DataView(padded.buffer, padded.byteOffset, 6).getUint32(2, false)
    if (unpaddedLen < EXTENDED_PREFIX_THRESHOLD) throw new Error('invalid padding')
    prefixLen = 6
  } else {
    unpaddedLen = firstTwo
    prefixLen = 2
  }

  const unpadded = padded.slice(prefixLen, prefixLen + unpaddedLen)
  if (
    unpaddedLen === 0 ||
    unpadded.length !== unpaddedLen ||
    padded.length !== prefixLen + calcPaddedLen(unpaddedLen)
  ) {
    throw new Error('invalid padding')
  }
  return new TextDecoder().decode(unpadded)
}

// ─── HMAC with AAD ─────────────────────────────────────────────────────────

/**
 * HMAC-SHA256(key, concat(aad, message)). AAD must be 32 bytes.
 */
function hmacAAD(key, message, aad) {
  if (aad.length !== 32) throw new Error('AAD must be 32 bytes')
  const input = new Uint8Array(aad.length + message.length)
  input.set(aad, 0)
  input.set(message, aad.length)
  return hmac(sha256, key, input)
}

// ─── Public API ────────────────────────────────────────────────────────────

/**
 * Encrypt a plaintext string to a recipient's x-only pubkey.
 * Returns base64 payload. A fresh 32-byte nonce is generated per call.
 *
 * @param {string} plaintext
 * @param {string|Uint8Array} privkey - sender's private key (hex or 32 bytes)
 * @param {string|Uint8Array} recipientPubkeyXOnly - recipient's x-only pubkey (hex or 32 bytes)
 * @returns {string} base64 payload
 */
export function encrypt(plaintext, privkey, recipientPubkeyXOnly) {
  const conversationKey = getConversationKey(privkey, recipientPubkeyXOnly)
  const nonce = randomBytes(32)
  return encryptWithKey(plaintext, conversationKey, nonce)
}

/**
 * Encrypt with an explicit conversation_key + nonce (for testing / deterministic flows).
 *
 * @param {string} plaintext
 * @param {Uint8Array} conversationKey - 32-byte PRK
 * @param {Uint8Array} nonce - 32-byte nonce
 * @returns {string} base64 payload
 */
export function encryptWithKey(plaintext, conversationKey, nonce) {
  const { chachaKey, chachaNonce, hmacKey } = getMessageKeys(conversationKey, nonce)
  const padded = pad(plaintext)
  // RFC 8439 ChaCha20 with counter starting at 0.
  // @noble/ciphers chacha20(key, nonce12, data, output, counter=0) — counter defaults to 0.
  const ciphertext = chacha20(chachaKey, chachaNonce, padded)
  const mac = hmacAAD(hmacKey, ciphertext, nonce)
  const payload = new Uint8Array(1 + nonce.length + ciphertext.length + mac.length)
  payload[0] = VERSION_BYTE
  payload.set(nonce, 1)
  payload.set(ciphertext, 1 + nonce.length)
  payload.set(mac, 1 + nonce.length + ciphertext.length)
  return base64Encode(payload)
}

/**
 * Decrypt a base64 payload from a sender's x-only pubkey.
 *
 * @param {string} payload - base64
 * @param {string|Uint8Array} privkey - receiver's private key (hex or 32 bytes)
 * @param {string|Uint8Array} senderPubkeyXOnly - sender's x-only pubkey (hex or 32 bytes)
 * @returns {string} plaintext
 */
export function decrypt(payload, privkey, senderPubkeyXOnly) {
  const conversationKey = getConversationKey(privkey, senderPubkeyXOnly)
  return decryptWithKey(payload, conversationKey)
}

/**
 * Decrypt with an explicit conversation_key (for testing).
 */
export function decryptWithKey(payload, conversationKey) {
  const { nonce, ciphertext, mac } = decodePayload(payload)
  const { chachaKey, chachaNonce, hmacKey } = getMessageKeys(conversationKey, nonce)
  const calculatedMac = hmacAAD(hmacKey, ciphertext, nonce)
  if (!constantTimeEqual(calculatedMac, mac)) throw new Error('invalid MAC')
  const padded = chacha20(chachaKey, chachaNonce, ciphertext)
  return unpad(padded)
}

/**
 * Decode a base64 payload → { nonce, ciphertext, mac }.
 */
export function decodePayload(payload) {
  if (payload.length === 0 || payload[0] === '#') throw new Error('unknown version')
  if (payload.length < 132) throw new Error('invalid payload size')
  const data = base64Decode(payload)
  const dlen = data.length
  if (dlen < 99) throw new Error('invalid data size')
  const version = data[0]
  if (version !== VERSION) throw new Error(`unknown version ${version}`)
  return {
    nonce: data.slice(1, 33),
    ciphertext: data.slice(33, dlen - 32),
    mac: data.slice(dlen - 32, dlen),
  }
}

// ─── Constant-time comparison ──────────────────────────────────────────────

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}
