/**
 * IP/TCP/UDP checksum calculation (RFC 1071).
 *
 * Used by the WG UDP tunnel to construct valid raw IP packets.
 */

/**
 * Calculate IP header checksum (16-bit one's complement).
 * @param {Buffer} header - IP header (set checksum field to 0 before calling)
 * @returns {number} 16-bit checksum
 */
export function ipChecksum(header) {
  let sum = 0
  for (let i = 0; i < header.length; i += 2) {
    sum += header.readUInt16BE(i)
  }
  while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16)
  return ~sum & 0xFFFF
}

/**
 * Calculate TCP or UDP checksum with IPv4 pseudo-header.
 * @param {string} srcIp - Source IPv4 (e.g. "10.0.0.1")
 * @param {string} dstIp - Destination IPv4
 * @param {Buffer} segment - TCP/UDP segment (checksum field set to 0)
 * @returns {number} 16-bit checksum
 */
export function tcpChecksum(srcIp, dstIp, segment) {
  const src = srcIp.split('.').map(Number)
  const dst = dstIp.split('.').map(Number)

  // Pseudo-header: srcIP(4) + dstIP(4) + zero(1) + protocol(1) + length(2)
  const pseudo = Buffer.alloc(12)
  pseudo[0] = src[0]; pseudo[1] = src[1]; pseudo[2] = src[2]; pseudo[3] = src[3]
  pseudo[4] = dst[0]; pseudo[5] = dst[1]; pseudo[6] = dst[2]; pseudo[7] = dst[3]
  pseudo[8] = 0
  pseudo[9] = 6 // TCP
  pseudo.writeUInt16BE(segment.length, 10)

  let sum = 0
  for (let i = 0; i < pseudo.length; i += 2) sum += pseudo.readUInt16BE(i)
  for (let i = 0; i < segment.length - 1; i += 2) sum += segment.readUInt16BE(i)
  if (segment.length % 2 === 1) sum += (segment[segment.length - 1] << 8) // pad odd byte

  while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16)
  return ~sum & 0xFFFF
}

/**
 * Calculate UDP checksum with IPv4 pseudo-header.
 * Same algorithm as TCP, just protocol = 17.
 * If result is 0, return 0xFFFF (per RFC 768).
 */
export function udpChecksum(srcIp, dstIp, segment) {
  const src = srcIp.split('.').map(Number)
  const dst = dstIp.split('.').map(Number)

  const pseudo = Buffer.alloc(12)
  pseudo[0] = src[0]; pseudo[1] = src[1]; pseudo[2] = src[2]; pseudo[3] = src[3]
  pseudo[4] = dst[0]; pseudo[5] = dst[1]; pseudo[6] = dst[2]; pseudo[7] = dst[3]
  pseudo[8] = 0
  pseudo[9] = 17 // UDP
  pseudo.writeUInt16BE(segment.length, 10)

  let sum = 0
  for (let i = 0; i < pseudo.length; i += 2) sum += pseudo.readUInt16BE(i)
  for (let i = 0; i < segment.length - 1; i += 2) sum += segment.readUInt16BE(i)
  if (segment.length % 2 === 1) sum += (segment[segment.length - 1] << 8)

  while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16)
  const result = ~sum & 0xFFFF
  return result === 0 ? 0xFFFF : result
}
