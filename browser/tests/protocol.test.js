/**
 * peck protocol tests
 *
 * Tests for frame encoding/decoding and StreamManager.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { encodeFrame, decodeFrame, StreamManager, MSG_OPEN, MSG_DATA, MSG_CLOSE, MSG_RST } from '../src/protocol.js'

// ─── Frame encode/decode ────────────────────────────────────────

test('encode + decode frame roundtrip', () => {
  const payload = new TextEncoder().encode('GET / HTTP/1.1\r\n\r\n')
  const frame = encodeFrame(42, 80, MSG_DATA, payload)

  const decoded = decodeFrame(frame)

  assert.equal(decoded.streamId, 42)
  assert.equal(decoded.port, 80)
  assert.equal(decoded.type, MSG_DATA)
  assert.deepEqual(Array.from(decoded.payload), Array.from(payload))
})

test('encode frame with empty payload', () => {
  const frame = encodeFrame(1, 443, MSG_OPEN)

  const decoded = decodeFrame(frame)

  assert.equal(decoded.streamId, 1)
  assert.equal(decoded.port, 443)
  assert.equal(decoded.type, MSG_OPEN)
  assert.equal(decoded.payload.length, 0)
})

test('encode frame with large payload', () => {
  const payload = new Uint8Array(16000)
  payload.fill(0xAB)

  const frame = encodeFrame(100, 8080, MSG_DATA, payload)
  const decoded = decodeFrame(frame)

  assert.equal(decoded.payload.length, 16000)
  assert.equal(decoded.payload[0], 0xAB)
  assert.equal(decoded.payload[15999], 0xAB)
})

test('decode rejects too-short frame', () => {
  const shortFrame = new Uint8Array([0x00, 0x01, 0x02])

  assert.throws(() => decodeFrame(shortFrame), /Frame too short/)
})

test('MSG_RST produces correct type', () => {
  const frame = encodeFrame(5, 22, MSG_RST)
  const decoded = decodeFrame(frame)

  assert.equal(decoded.type, MSG_RST)
})

// ─── StreamManager ──────────────────────────────────────────────

test('StreamManager allocates unique stream IDs', () => {
  const manager = new StreamManager()
  const id1 = manager.allocateStreamId()
  const id2 = manager.allocateStreamId()

  assert.notEqual(id1, id2)
})

test('StreamManager creates and routes streams', () => {
  const manager = new StreamManager()
  const messages = []

  const streamId = manager.createStream(80, {
    onMessage: (data) => messages.push(data),
  })

  manager.handleFrame({
    streamId,
    port: 80,
    type: MSG_DATA,
    payload: new TextEncoder().encode('hello')
  })

  assert.equal(messages.length, 1)
  assert.equal(new TextDecoder().decode(messages[0]), 'hello')
})

test('StreamManager closes streams', () => {
  const manager = new StreamManager()
  let closed = false

  const streamId = manager.createStream(443, {
    onClose: () => { closed = true },
  })

  manager.handleFrame({
    streamId,
    port: 443,
    type: MSG_CLOSE,
    payload: new Uint8Array(0)
  })

  assert.ok(closed)
  assert.ok(!manager.getActiveStreams().includes(streamId))
})

test('StreamManager handles RST with error', () => {
  const manager = new StreamManager()
  let closeError = null

  const streamId = manager.createStream(22, {
    onClose: (err) => { closeError = err },
  })

  manager.handleFrame({
    streamId,
    port: 22,
    type: MSG_RST,
    payload: new Uint8Array(0)
  })

  assert.ok(closeError instanceof Error)
})

test('StreamManager wraps around at 65535', () => {
  const manager = new StreamManager()
  manager._nextStreamId = 65535

  const id1 = manager.allocateStreamId() // 65535
  const id2 = manager.allocateStreamId() // should wrap to 1

  assert.equal(id1, 65535)
  assert.equal(id2, 1)
})
