#!/usr/bin/env python3
"""
peck minimal tunnel — reference P2P client.

Demonstrates the full peck connection flow in ~140 lines:
  1. Generate ephemeral Nostr keypair
  2. Connect to Nostr relays via WebSocket
  3. Send NIP-44 encrypted announce DM to the daemon
  4. Receive WebRTC offer (SDP) from daemon
  5. Send WebRTC answer back
  6. Exchange ICE candidates (trickle)
  7. Open DataChannel, send HTTP request, receive response

This is NOT production code — it's a reference for protocol implementers.
For the full client, see browser/src/native-transport.js.

Requirements:
    pip install aiohttp aiortc coincurve

Usage:
    # The daemon npub (64 hex chars, NOT npub1...)
    python minimal-tunnel.py <daemon_npub_hex>

    # Or with a specific relay
    python minimal-tunnel.py <daemon_npub_hex> wss://relay.primal.net

Example:
    python minimal-tunnel.py 79bff2e0f78c9e3e6f4d2a1b3c5e7f9a...
"""

import asyncio
import json
import hashlib
import secrets
import sys

import aiohttp
from aiortc import RTCPeerConnection, RTCSessionDescription
import coincurve


# ─── Nostr + crypto helpers (inline — see daemon/crypto_helpers.py for full) ───

RELAYS = [
    "wss://relay.primal.net",
    "wss://no.str.cr",
]

STUN_SERVERS = [
    "stun:stun.l.google.com:19302",
]


def get_pubkey(privkey_hex: str) -> str:
    """Derive x-only pubkey (32 bytes, 64 hex) from a private key."""
    sk = coincurve.PrivateKey(bytes.fromhex(privkey_hex))
    return sk.public_key.format(compressed=True)[1:].hex()


def make_event(privkey_hex: str, recipient_pubkey: str, content: str) -> dict:
    """Create and sign a Nostr kind=4 (DM) event."""
    import time
    pub = get_pubkey(privkey_hex)
    created_at = int(time.time())
    tags = [["p", recipient_pubkey]]
    canonical = json.dumps([0, pub, created_at, 4, tags, content], separators=(",", ":"))
    event_id = hashlib.sha256(canonical.encode()).hexdigest()
    sk = coincurve.PrivateKey(bytes.fromhex(privkey_hex))
    sig = sk.sign_schnorr(bytes.fromhex(event_id))
    return {
        "kind": 4,
        "content": content,
        "tags": tags,
        "created_at": created_at,
        "pubkey": pub,
        "id": event_id,
        "sig": sig.hex(),
    }


# ─── NIP-44 import (from daemon/nip44.py) ────────────────────────────────────
# In production, use the full implementation. Here we import from daemon/.
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent / "daemon"))
from nip44 import encrypt as nip44_encrypt, decrypt as nip44_decrypt


# ─── Main connection flow ────────────────────────────────────────────────────

async def connect(daemon_pubkey: str, relay_urls: list[str] | None = None):
    """Establish a peck tunnel to the daemon and send a test HTTP request."""
    relays = relay_urls or RELAYS

    # 1. Generate ephemeral Nostr keypair
    privkey = secrets.token_hex(32)
    my_pubkey = get_pubkey(privkey)
    peer_id = secrets.token_hex(8)
    print(f"[client] ephemeral pubkey: {my_pubkey[:16]}…")
    print(f"[client] peer_id: {peer_id}")
    print(f"[client] daemon: {daemon_pubkey[:16]}…")

    # 2. Connect to relays
    session = aiohttp.ClientSession()
    websockets = []
    for url in relays:
        try:
            ws = await session.ws_connect(url)
            websockets.append(ws)
            sub_filter = {"kinds": [4], "#p": [my_pubkey]}
            await ws.send_str(json.dumps(["REQ", "peck-" + peer_id, sub_filter]))
            print(f"[relay] ✓ connected to {url}")
        except Exception as e:
            print(f"[relay] ✗ {url}: {e}")

    if not websockets:
        print("[error] No relays connected")
        return

    # Helper: send a NIP-44 encrypted DM to the daemon
    async def send_dm(msg: dict):
        plaintext = json.dumps(msg)
        encrypted = nip44_encrypt(plaintext, privkey, daemon_pubkey)
        event = make_event(privkey, daemon_pubkey, encrypted)
        payload = json.dumps(["EVENT", event])
        for ws in websockets:
            if not ws.closed:
                await ws.send_str(payload)

    # Helper: wait for a specific message type from the daemon
    async def wait_for_msg(types: list[str], timeout: float = 15.0) -> dict:
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"Timed out waiting for {types}")
            for ws in websockets:
                try:
                    msg = await asyncio.wait_for(ws.receive(), timeout=remaining)
                except asyncio.TimeoutError:
                    continue
                if msg.type != aiohttp.WSMsgType.TEXT:
                    continue
                data = json.loads(msg.data)
                if data[0] != "EVENT" or len(data) < 3:
                    continue
                event = data[2]
                if event.get("kind") != 4:
                    continue
                if event.get("pubkey") != daemon_pubkey:
                    continue
                try:
                    plaintext = nip44_decrypt(event["content"], privkey, daemon_pubkey)
                    parsed = json.loads(plaintext)
                except Exception:
                    continue
                if parsed.get("type") in types:
                    return parsed
            await asyncio.sleep(0.1)

    # 3. Set up WebRTC peer connection
    pc = RTCPeerConnection({"iceServers": [{"urls": s} for s in STUN_SERVERS]})
    channel_ready = asyncio.Event()

    # The daemon creates the DataChannel (it is the offerer)
    @pc.on("datachannel")
    def on_datachannel(channel):
        print(f"[webrtc] DataChannel received: {channel.label}")

        @channel.on("message")
        def on_message(message):
            if isinstance(message, bytes):
                print(f"[channel] ← received {len(message)} bytes:")
                print(f"           {message[:200]}")
                channel_ready.set()
            else:
                print(f"[channel] ← {message}")

    # Trickle ICE — send each candidate to the daemon
    @pc.on("icecandidate")
    def on_icecandidate(event):
        if event.candidate:
            candidate_str = event.candidate.candidate
            asyncio.ensure_future(send_dm({"type": "candidate", "sdp": candidate_str}))
            print(f"[ice] → candidate sent")

    # 4. Send announce
    announce = {"peerId": peer_id, "type": "announce"}
    await send_dm(announce)
    print("[client] → announce sent")

    # 5. Wait for offer
    print("[client] waiting for offer…")
    offer_msg = await wait_for_msg(["offer", "terms-challenge"])

    if offer_msg["type"] == "terms-challenge":
        print(f"[terms] challenge received: {offer_msg.get('version')}")
        await send_dm({"type": "terms-accept", "version": offer_msg["version"]})
        print("[terms] → accepted")
        offer_msg = await wait_for_msg(["offer"])

    # 6. Apply offer, create answer
    offer = RTCSessionDescription(sdp=offer_msg["sdp"], type="offer")
    await pc.setRemoteDescription(offer)
    print("[webrtc] offer applied")

    answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)
    print("[webrtc] answer created")

    # 7. Send answer
    await send_dm({"type": "answer", "sdp": pc.localDescription.sdp})
    print("[client] → answer sent")

    # 8. Listen for late candidates from daemon (optional, non-blocking)
    async def listen_candidates():
        try:
            while True:
                msg = await wait_for_msg(["candidate"], timeout=30.0)
                from aiortc.sdp import candidate_from_sdp
                cand = candidate_from_sdp(msg["sdp"])
                await pc.addIceCandidate(cand)
                print("[ice] ← candidate from daemon")
        except (TimeoutError, asyncio.CancelledError):
            pass

    candidate_task = asyncio.create_task(listen_candidates())

    # 9. Wait for DataChannel to open, then send an HTTP request
    print("[client] waiting for DataChannel…")
    try:
        await asyncio.wait_for(channel_ready.wait(), timeout=15.0)
    except asyncio.TimeoutError:
        # DataChannel might be open but no message yet — try sending anyway
        pass

    # Find the DataChannel (set by on_datachannel callback)
    for receiver in pc.getReceivers():
        if hasattr(receiver, "transport") and receiver.transport:
            break

    # Send a simple HTTP GET over the DataChannel
    channel = None
    for ch in pc.sctp.transport.dataChannels if pc.sctp else []:
        channel = ch
        break

    if channel and channel.readyState == "open":
        http_request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        # peck binary frame: [StreamID:2][Port:2][Type:1][Payload]
        import struct
        frame = struct.pack(">HHB", 1, 80, 0x00) + http_request  # OPEN, port 80
        channel.send(frame)
        print(f"[channel] → HTTP GET sent ({len(frame)} bytes)")
        await asyncio.sleep(3)  # wait for response
    else:
        print("[error] DataChannel not open")

    candidate_task.cancel()
    await pc.close()
    for ws in websockets:
        await ws.close()
    await session.close()
    print("[client] done")


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python minimal-tunnel.py <daemon_npub_hex> [relay_url]")
        print()
        print("  daemon_npub_hex  — 64 hex char x-only pubkey (NOT npub1...)")
        print("  relay_url        — optional, defaults to " + ", ".join(RELAYS))
        sys.exit(1)

    daemon_npub = sys.argv[1]
    relays = [sys.argv[2]] if len(sys.argv) > 2 else None

    try:
        asyncio.run(connect(daemon_npub, relays))
    except KeyboardInterrupt:
        print("\n[interrupted]")
