#!/usr/bin/env python3
"""
peck minimal tunnel — two-process P2P reference.

Demonstrates the full peck protocol in one self-contained script.
No dependency on the peck daemon — run two instances that talk to each other:

    Terminal 1 (daemon):
        python minimal-tunnel.py

    Terminal 2 (client):
        python minimal-tunnel.py <daemon_npub_hex>

No args = daemon, one npub arg = client.

The daemon prints its npub on startup. The client connects, and they
exchange "ping" / "pong" over a direct WebRTC DataChannel — signaled
entirely through NIP-44 encrypted Nostr DMs.

Protocol flow (see docs/PROTOCOL.md for the full spec):
    1. Both sides connect to Nostr relays, subscribe for kind=4 DMs
    2. Client sends announce DM (NIP-44 encrypted)
    3. Daemon creates WebRTC offer, sends it
    4. Client sends answer
    5. Trickle ICE candidates exchanged via DMs
    6. DataChannel opens — client sends "ping", daemon responds "pong"

Requirements:
    pip install aiohttp aiortc coincurve
"""

import asyncio
import hashlib
import json
import secrets
import struct
import sys
import time

import aiohttp
from aiortc import RTCPeerConnection, RTCConfiguration, RTCIceServer, RTCSessionDescription
import coincurve

# ─── Config ──────────────────────────────────────────────────────────────────

RELAYS = [
    "wss://relay.primal.net",
    "wss://no.str.cr",
]

STUN_SERVERS = ["stun:stun.l.google.com:19302"]


# ─── Nostr + crypto helpers ──────────────────────────────────────────────────

def get_pubkey(privkey_hex: str) -> str:
    sk = coincurve.PrivateKey(bytes.fromhex(privkey_hex))
    return sk.public_key.format(compressed=True)[1:].hex()


def make_event(privkey_hex: str, recipient_pubkey: str, content: str) -> dict:
    pub = get_pubkey(privkey_hex)
    created_at = int(time.time())
    tags = [["p", recipient_pubkey]]
    canonical = json.dumps([0, pub, created_at, 4, tags, content], separators=(",", ":"))
    event_id = hashlib.sha256(canonical.encode()).hexdigest()
    sk = coincurve.PrivateKey(bytes.fromhex(privkey_hex))
    sig = sk.sign_schnorr(bytes.fromhex(event_id))
    return {
        "kind": 4, "content": content, "tags": tags,
        "created_at": created_at, "pubkey": pub,
        "id": event_id, "sig": sig.hex(),
    }


# ─── NIP-44 (inline minimal impl; production code uses daemon/nip44.py) ──────

def _nip44_encrypt(plaintext: str, privkey_hex: str, recipient_pubkey_hex: str) -> str:
    """NIP-44 v2 encrypt. Delegates to the daemon's nip44.py if available,
    otherwise raises with install instructions."""
    try:
        sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent / "daemon"))
        from nip44 import encrypt
        return encrypt(plaintext, privkey_hex, recipient_pubkey_hex)
    except ImportError:
        raise ImportError(
            "nip44.py not found. Run from the peck repo root, or copy "
            "daemon/nip44.py next to this script."
        )


def _nip44_decrypt(payload: str, privkey_hex: str, sender_pubkey_hex: str) -> str:
    try:
        sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent / "daemon"))
        from nip44 import decrypt
        return decrypt(payload, privkey_hex, sender_pubkey_hex)
    except ImportError:
        raise ImportError("nip44.py not found. See _nip44_encrypt for instructions.")


# ─── Shared relay manager ────────────────────────────────────────────────────

class RelayManager:
    """Manages WebSocket connections to multiple Nostr relays."""

    def __init__(self, privkey: str):
        self.privkey = privkey
        self.pubkey = get_pubkey(privkey)
        self.session: aiohttp.ClientSession | None = None
        self.websockets: list[aiohttp.ClientWebSocketResponse] = []
        self._seen: dict[str, bool] = {}

    async def connect(self):
        self.session = aiohttp.ClientSession()
        sub_id = "peck-" + secrets.token_hex(4)
        for url in RELAYS:
            try:
                ws = await self.session.ws_connect(url)
                await ws.send_str(json.dumps(["REQ", sub_id, {"kinds": [4], "#p": [self.pubkey]}]))
                self.websockets.append(ws)
                print(f"  [relay] ✓ {url}")
            except Exception as e:
                print(f"  [relay] ✗ {url}: {e}")

    async def send_dm(self, recipient_pubkey: str, msg: dict):
        """Encrypt msg as NIP-44 DM, publish as kind=4 event to all relays."""
        plaintext = json.dumps(msg)
        encrypted = _nip44_encrypt(plaintext, self.privkey, recipient_pubkey)
        event = make_event(self.privkey, recipient_pubkey, encrypted)
        payload = json.dumps(["EVENT", event])
        for ws in self.websockets:
            if not ws.closed:
                await ws.send_str(payload)

    async def recv_dm(self, sender_pubkey: str, timeout: float = 20.0,
                      expected_types: list[str] | None = None) -> dict:
        """Wait for a NIP-44 DM from sender_pubkey. Returns decrypted JSON.

        If expected_types is given, skip messages whose 'type' field doesn't
        match — this handles duplicate announce DMs arriving via relay
        redundancy.
        """
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for DM")
            for ws in self.websockets:
                try:
                    raw = await asyncio.wait_for(ws.receive(), timeout=min(remaining, 1.0))
                except asyncio.TimeoutError:
                    continue
                if raw.type != aiohttp.WSMsgType.TEXT:
                    continue
                data = json.loads(raw.data)
                if data[0] != "EVENT" or len(data) < 3:
                    continue
                event = data[2]
                if event.get("kind") != 4 or event.get("pubkey") != sender_pubkey:
                    continue
                eid = event.get("id", "")
                if eid in self._seen:
                    continue
                self._seen[eid] = True
                plaintext = _nip44_decrypt(event["content"], self.privkey, sender_pubkey)
                parsed = json.loads(plaintext)
                if expected_types and parsed.get("type") not in expected_types:
                    continue
                return parsed
            await asyncio.sleep(0.05)

    async def close(self):
        for ws in self.websockets:
            await ws.close()
        if self.session:
            await self.session.close()


# ─── WebRTC config helper ────────────────────────────────────────────────────

def rtc_config() -> RTCConfiguration:
    return RTCConfiguration(iceServers=[RTCIceServer(urls=STUN_SERVERS)])


# ─── Daemon mode ─────────────────────────────────────────────────────────────

async def run_daemon():
    """Listen for announce DMs, create WebRTC offer, respond to pings."""
    privkey = secrets.token_hex(32)
    relay = RelayManager(privkey)

    print("╔══ peck minimal-tunnel — DAEMON ══╗")
    print(f"║  npub (hex): {relay.pubkey}")
    print(f"║  Copy this for the client!       ")
    print("╚══════════════════════════════════╝")
    print("\nConnecting to relays…")
    await relay.connect()

    # Wait for announce
    print("\nWaiting for client announce…")
    # We don't know the client pubkey yet — poll for any DM
    client_pubkey = None
    while client_pubkey is None:
        for ws in relay.websockets:
            try:
                raw = await asyncio.wait_for(ws.receive(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            if raw.type != aiohttp.WSMsgType.TEXT:
                continue
            data = json.loads(raw.data)
            if data[0] != "EVENT" or len(data) < 3:
                continue
            event = data[2]
            if event.get("kind") != 4 or event.get("pubkey") == relay.pubkey:
                continue
            client_pubkey = event["pubkey"]
            plaintext = _nip44_decrypt(event["content"], privkey, client_pubkey)
            msg = json.loads(plaintext)
            if "peerId" in msg:
                print(f"  ← announce from {client_pubkey[:12]}… (peerId={msg['peerId'][:8]})")
                break
        await asyncio.sleep(0.1)

    # Create WebRTC connection (daemon is the offerer)
    pc = RTCPeerConnection(configuration=rtc_config())
    channel = pc.createDataChannel("peck", ordered=True)

    @channel.on("message")
    def on_datachannel_message(message):
        if isinstance(message, bytes):
            text = message.decode("utf-8", errors="replace").strip()
            print(f"  ← data: {text!r}")
            if text == "ping":
                response = b"pong"
                channel.send(response)
                print(f"  → sent: pong")
        elif isinstance(message, str):
            print(f"  ← text: {message!r}")
            if message.strip() == "ping":
                channel.send("pong")
                print(f"  → sent: pong")

    @pc.on("connectionstatechange")
    async def on_state():
        print(f"  [webrtc] state={pc.connectionState}")

    # Create offer, wait for ICE gathering, send
    print("  Gathering ICE candidates…")
    offer = await pc.createOffer()
    await pc.setLocalDescription(offer)
    # Wait for ICE gathering to complete (non-trickle on daemon side)
    await _wait_for_ice_gathering(pc)
    print(f"  ✓ ICE gathering done")

    await relay.send_dm(client_pubkey, {"type": "offer", "sdp": pc.localDescription.sdp})
    print("  → offer sent")

    # Wait for answer
    answer_msg = await relay.recv_dm(client_pubkey, timeout=20.0, expected_types=["answer"])
    await pc.setRemoteDescription(RTCSessionDescription(sdp=answer_msg["sdp"], type="answer"))
    print("  ← answer applied")

    # Listen for client trickle candidates
    async def listen_candidates():
        while True:
            try:
                msg = await relay.recv_dm(client_pubkey, timeout=30.0, expected_types=["candidate"])
                from aiortc.sdp import candidate_from_sdp
                cand = candidate_from_sdp(msg["sdp"])
                await pc.addIceCandidate(cand)
                print("  ← ICE candidate from client")
            except (TimeoutError, asyncio.CancelledError):
                break

    cand_task = asyncio.create_task(listen_candidates())

    # Keep alive until connection closes
    print("\n  Tunnel up — waiting for ping…")
    try:
        while pc.connectionState not in ("closed", "failed"):
            await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        cand_task.cancel()
        await pc.close()
        await relay.close()
        print("\n  Daemon shut down.")


# ─── Client mode ─────────────────────────────────────────────────────────────

async def run_client(daemon_pubkey: str):
    """Send announce, complete WebRTC handshake, send ping over DataChannel."""
    privkey = secrets.token_hex(32)
    relay = RelayManager(privkey)
    peer_id = secrets.token_hex(8)

    print("╔══ peck minimal-tunnel — CLIENT ══╗")
    print(f"║  ephemeral: {relay.pubkey[:20]}…")
    print(f"║  daemon:    {daemon_pubkey[:20]}…")
    print("╚══════════════════════════════════╝")
    print("\nConnecting to relays…")
    await relay.connect()

    # Set up WebRTC (client is the answerer — receives DataChannel)
    pc = RTCPeerConnection(configuration=rtc_config())
    received_channel: list = []  # will hold the DataChannel once it arrives
    got_pong = asyncio.Event()

    @pc.on("datachannel")
    def on_datachannel(channel):
        print(f"  [webrtc] DataChannel opened: {channel.label}")
        received_channel.append(channel)

        @channel.on("message")
        def on_message(message):
            text = message.decode() if isinstance(message, bytes) else message
            print(f"  ← received: {text!r}")
            got_pong.set()

    @pc.on("icecandidate")
    def on_icecandidate(event):
        if event.candidate:
            asyncio.ensure_future(
                relay.send_dm(daemon_pubkey, {"type": "candidate", "sdp": event.candidate.candidate})
            )
            print("  → ICE candidate sent (trickle)")

    @pc.on("connectionstatechange")
    async def on_state():
        print(f"  [webrtc] state={pc.connectionState}")

    # Send announce
    await relay.send_dm(daemon_pubkey, {"peerId": peer_id, "type": "announce"})
    print("\n  → announce sent")

    # Wait for offer
    print("  Waiting for offer…")
    offer_msg = await relay.recv_dm(daemon_pubkey, timeout=20.0, expected_types=["offer"])

    # Apply offer, create answer
    await pc.setRemoteDescription(RTCSessionDescription(sdp=offer_msg["sdp"], type="offer"))
    print("  ← offer applied")
    answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)
    print("  ✓ answer created")

    # Send answer
    await relay.send_dm(daemon_pubkey, {"type": "answer", "sdp": pc.localDescription.sdp})
    print("  → answer sent")

    # Wait for WebRTC to connect, then send ping
    print("\n  Waiting for DataChannel…")
    deadline = asyncio.get_event_loop().time() + 30.0
    while not received_channel:
        if asyncio.get_event_loop().time() > deadline:
            print("  ✗ DataChannel never opened")
            await pc.close()
            await relay.close()
            return
        await asyncio.sleep(0.5)

    channel = received_channel[0]
    # Wait until channel is open
    while channel.readyState != "open":
        if asyncio.get_event_loop().time() > deadline:
            print(f"  ✗ DataChannel state: {channel.readyState}")
            break
        await asyncio.sleep(0.5)

    if channel.readyState == "open":
        print("\n  ═══ Tunnel established ═══")
        channel.send(b"ping")
        print('  → sent: "ping"')
        # Wait for pong
        try:
            await asyncio.wait_for(got_pong.wait(), timeout=10.0)
            print('\n  ✓ Got "pong" — tunnel works!')
        except asyncio.TimeoutError:
            print("\n  ✗ No pong received (timeout)")
    else:
        print(f"  ✗ DataChannel not open (state={channel.readyState})")

    await asyncio.sleep(1)
    await pc.close()
    await relay.close()
    print("\n  Client shut down.")


# ─── Helpers ─────────────────────────────────────────────────────────────────

async def _wait_for_ice_gathering(pc: RTCPeerConnection, timeout: float = 10.0):
    """Wait until ICE gathering is complete."""
    deadline = asyncio.get_event_loop().time() + timeout
    while pc.iceGatheringState != "complete":
        if asyncio.get_event_loop().time() > deadline:
            break
        await asyncio.sleep(0.2)


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args:
        # No pubkey → daemon mode
        try:
            asyncio.run(run_daemon())
        except KeyboardInterrupt:
            print("\n[interrupted]")
    elif len(args) == 1 and args[0] not in ("-h", "--help"):
        # Pubkey provided → client mode
        try:
            asyncio.run(run_client(args[0]))
        except KeyboardInterrupt:
            print("\n[interrupted]")
    else:
        print("peck minimal tunnel — reference P2P implementation")
        print()
        print("Usage:")
        print("  Terminal 1:  python minimal-tunnel.py                  # daemon")
        print("  Terminal 2:  python minimal-tunnel.py <daemon_npub>     # client")
        print()
        print("No args = daemon. One npub arg = client.")
        print()
        print("Requirements:  pip install aiohttp aiortc coincurve")
        print("               + daemon/nip44.py from the peck repo")
        sys.exit(1)


if __name__ == "__main__":
    main()
