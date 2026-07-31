/**
 * peck — Nostr-signaled WebRTC hole-punching
 *
 * Protocol layer on top of Trystero's DataChannel.
 * Adds multiplexed stream routing (port-based) over a single WebRTC connection.
 *
 * @module peck/protocol
 */

// ─── Message Types ──────────────────────────────────────────────

export const MSG_OPEN = 0x00  // Open new stream to a port
export const MSG_DATA = 0x01  // Data for existing stream
export const MSG_CLOSE = 0x02 // Gracefully close stream
export const MSG_RST = 0x03   // Reset/error stream

// ─── Frame Format ───────────────────────────────────────────────
//
// ┌──────────┬──────────┬──────────┬──────────────┐
// │ StreamID │ Port     │ Type     │ Payload      │
// │ 2 bytes  │ 2 bytes  │ 1 byte   │ variable     │
// └──────────┴──────────┴──────────┴──────────────┘
//
// All multi-byte fields are big-endian (network byte order).
// Payload is raw bytes for DATA, empty for OPEN/CLOSE/RST.

const HEADER_SIZE = 5 // 2 + 2 + 1

/**
 * Encode a peck protocol message.
 *
 * @param {number} streamId - 16-bit stream identifier
 * @param {number} port - 16-bit target port
 * @param {number} type - Message type (MSG_OPEN, MSG_DATA, MSG_CLOSE, MSG_RST)
 * @param {Uint8Array} [payload] - Optional payload bytes
 * @returns {Uint8Array} Encoded frame
 */
export function encodeFrame(streamId, port, type, payload = new Uint8Array(0)) {
  const frame = new Uint8Array(HEADER_SIZE + payload.length)
  const view = new DataView(frame.buffer)

  view.setUint16(0, streamId, false) // big-endian
  view.setUint16(2, port, false)
  view.setUint8(4, type)

  if (payload.length > 0) {
    frame.set(payload, HEADER_SIZE)
  }

  return frame
}

/**
 * Decode a peck protocol message.
 *
 * @param {Uint8Array} frame - Raw frame bytes
 * @returns {{ streamId: number, port: number, type: number, payload: Uint8Array }}
 */
export function decodeFrame(frame) {
  if (frame.length < HEADER_SIZE) {
    throw new Error(`Frame too short: ${frame.length} bytes (need at least ${HEADER_SIZE})`)
  }

  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength)
  const streamId = view.getUint16(0, false)
  const port = view.getUint16(2, false)
  const type = view.getUint8(4)
  const payload = frame.slice(HEADER_SIZE)

  return { streamId, port, type, payload }
}

// ─── Stream Manager ─────────────────────────────────────────────

/**
 * Multiplexes multiple logical streams over a single DataChannel.
 * Each stream targets a specific port on the server.
 */
export class StreamManager {
  constructor() {
    this._nextStreamId = 1
    this._streams = new Map() // streamId → { port, onMessage, onClose }
    this._portHandlers = new Map() // port → Set<streamId>
  }

  /**
   * Allocate a new stream ID.
   * @returns {number}
   */
  allocateStreamId() {
    const id = this._nextStreamId++
    if (this._nextStreamId > 65535) {
      this._nextStreamId = 1 // Wrap around (avoid 0 = invalid)
    }
    return id
  }

  /**
   * Register a new stream.
   * @param {number} port - Target port
   * @param {object} handlers - { onMessage, onClose }
   * @returns {number} streamId
   */
  createStream(port, { onMessage, onClose } = {}) {
    const streamId = this.allocateStreamId()
    this._streams.set(streamId, { port, onMessage, onClose })

    if (!this._portHandlers.has(port)) {
      this._portHandlers.set(port, new Set())
    }
    this._portHandlers.get(port).add(streamId)

    return streamId
  }

  /**
   * Route an incoming decoded frame to the correct stream.
   * @param {{ streamId: number, port: number, type: number, payload: Uint8Array }} frame
   */
  handleFrame({ streamId, port, type, payload }) {
    const stream = this._streams.get(streamId)

    switch (type) {
      case MSG_OPEN:
        // Server acknowledges stream open
        break

      case MSG_DATA:
        if (stream?.onMessage) {
          stream.onMessage(payload)
        }
        break

      case MSG_CLOSE:
      case MSG_RST:
        if (stream?.onClose) {
          stream.onClose(type === MSG_RST ? new Error('Stream reset') : null)
        }
        this._cleanupStream(streamId, port)
        break
    }
  }

  /**
   * Close and remove a stream.
   * @param {number} streamId
   */
  closeStream(streamId) {
    const stream = this._streams.get(streamId)
    if (stream) {
      this._cleanupStream(streamId, stream.port)
    }
  }

  _cleanupStream(streamId, port) {
    this._streams.delete(streamId)
    const handlers = this._portHandlers.get(port)
    if (handlers) {
      handlers.delete(streamId)
      if (handlers.size === 0) {
        this._portHandlers.delete(port)
      }
    }
  }

  /**
   * Get all active streams.
   * @returns {number[]} Array of stream IDs
   */
  getActiveStreams() {
    return Array.from(this._streams.keys())
  }
}
