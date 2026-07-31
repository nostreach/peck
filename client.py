"""
peck-py client v2: NIP-44 + binary stream protocol.

Mirrors the browser client's protocol so we can validate end-to-end
before the browser client is finished.

Flow:
1. Client sends announce DM (NIP-44 encrypted) to daemon
2. Daemon creates WebRTC offer, sends via NIP-44 DM
3. Client applies offer, creates answer, sends via NIP-44 DM
4. DataChannel established — speak binary stream protocol
5. Client sends MSG_OPEN + MSG_DATA(raw HTTP) + MSG_CLOSE
6. Daemon forwards to backend, returns MSG_DATA(raw HTTP response) + MSG_CLOSE
"""

import argparse
import asyncio
import json
import logging
import secrets
import struct
import sys
import time

import aiohttp
import aioice.ice
import coincurve
from aiortc import RTCPeerConnection, RTCSessionDescription

sys.path.insert(0, '~/peck')
from daemon import (
    get_pubkey, make_event, encode_frame, decode_frame,
    MSG_OPEN, MSG_DATA, MSG_CLOSE, MSG_RST,
    parse_http_request, compose_http_response,
)
from nip44 import encrypt as nip44_encrypt, decrypt as nip44_decrypt

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] CLIENT %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("aioice").setLevel(logging.WARNING)
logging.getLogger("aiortc").setLevel(logging.WARNING)
log = logging.getLogger("peck-client")


class PeckClient:
    def __init__(self, daemon_pubkey: str, relays: list):
        self.privkey = secrets.token_hex(32)
        self.pubkey = get_pubkey(self.privkey)
        self.daemon_pubkey = daemon_pubkey
        self.relays = relays
        self.pc: RTCPeerConnection = None
        self.channel = None
        self.http_session: aiohttp.ClientSession = None
        self.subscription_id = "peck-client-" + secrets.token_hex(8)
        self.connected = asyncio.Event()
        self.received_data = bytearray()
        self.stream_completed = asyncio.Event()
        self.peer_id = secrets.token_hex(8)

    async def setup_webrtc(self):
        self.pc = RTCPeerConnection()

        @self.pc.on("datachannel")
        def on_datachannel(channel):
            log.info(f"📡 datachannel received: {channel.label}")
            self.channel = channel

            @channel.on("message")
            def on_message(message):
                if isinstance(message, (bytes, bytearray)):
                    self._handle_frame(bytes(message))

        @self.pc.on("connectionstatechange")
        async def on_state():
            state = self.pc.connectionState
            log.info(f"🔌 state={state}")
            if state == "connected":
                self.connected.set()
            elif state in ("failed", "closed"):
                self.connected.clear()

    def _handle_frame(self, frame: bytes):
        try:
            stream_id, port, msg_type, payload = decode_frame(frame)
        except ValueError:
            return

        if msg_type == MSG_DATA:
            self.received_data.extend(payload)
            log.info(f"← DATA stream={stream_id} port={port} {len(payload)} bytes")
        elif msg_type == MSG_CLOSE:
            log.info(f"← CLOSE stream={stream_id}")
            self.stream_completed.set()
        elif msg_type == MSG_RST:
            log.error(f"← RST stream={stream_id}: {payload.decode('latin1', errors='replace')}")
            self.stream_completed.set()

    async def handle_offer(self, sdp: str):
        offer = RTCSessionDescription(sdp=sdp, type="offer")
        await self.pc.setRemoteDescription(offer)
        answer = await self.pc.createAnswer()
        await self.pc.setLocalDescription(answer)
        # Brief wait for ICE
        await self._wait_for_ice()
        return self.pc.localDescription.sdp

    async def _wait_for_ice(self, timeout: float = 5.0):
        if self.pc.iceGatheringState == "complete":
            return
        try:
            await asyncio.wait_for(self._gather_loop(), timeout)
        except asyncio.TimeoutError:
            pass

    async def _gather_loop(self):
        while self.pc.iceGatheringState != "complete":
            await asyncio.sleep(0.1)

    async def send_dm(self, msg: dict):
        plaintext = json.dumps(msg)
        encrypted = nip44_encrypt(plaintext, self.privkey, self.daemon_pubkey)
        event = make_event(self.privkey, self.daemon_pubkey, encrypted)
        for url in self.relays:
            try:
                async with self.http_session.ws_connect(url) as ws:
                    await ws.send_str(json.dumps(["EVENT", event]))
                    try:
                        await asyncio.wait_for(ws.receive(), timeout=2.0)
                    except asyncio.TimeoutError:
                        pass
                    return
            except Exception as e:
                log.warning(f"send via {url} failed: {e}")

    async def connect(self, timeout: float = 30.0):
        await self.setup_webrtc()
        self.http_session = aiohttp.ClientSession()

        # Open relay connections and subscribe
        ws_pool = []
        for url in self.relays:
            try:
                ws = await self.http_session.ws_connect(url)
                ws_pool.append((ws, url))
                req_filter = {"kinds": [4], "#p": [self.pubkey]}
                await ws.send_str(json.dumps(["REQ", self.subscription_id, req_filter]))
                log.info(f"✓ subscribed to {url}")
            except Exception as e:
                log.warning(f"relay connect {url} failed: {e}")

        if not ws_pool:
            raise RuntimeError("no relays connected")

        listen_tasks = await self._listen(ws_pool)

        # Send announce
        log.info(f"→ announce (peerId={self.peer_id})")
        await self.send_dm({"peerId": self.peer_id, "type": "announce"})

        log.info(f"⏳ waiting for WebRTC connection (timeout {timeout}s)…")
        try:
            await asyncio.wait_for(self.connected.wait(), timeout=timeout)
            log.info("✓ CONNECTED")
        except asyncio.TimeoutError:
            log.error(f"✗ timeout after {timeout}s")
            return False

        return True

    async def _listen(self, ws_pool):
        async def listen(ws, url):
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        if data[0] == "EVENT" and len(data) >= 3:
                            event = data[2]
                            if event.get("kind") != 4:
                                continue
                            tags_p = [t for t in event.get("tags", []) if len(t) >= 2 and t[0] == "p" and t[1] == self.pubkey]
                            if not tags_p:
                                continue
                            if event["pubkey"] != self.daemon_pubkey:
                                continue
                            try:
                                plaintext = nip44_decrypt(event["content"], self.privkey, event["pubkey"])
                                signal = json.loads(plaintext)
                            except Exception as e:
                                log.warning(f"decrypt failed: {e}")
                                continue
                            await self._handle_signal(signal)
                    except Exception as e:
                        log.debug(f"parse error: {e}")

        return [asyncio.create_task(listen(ws, url)) for ws, url in ws_pool]

    async def _handle_signal(self, signal: dict):
        sig_type = signal.get("type")
        if sig_type == "offer":
            log.info(f"← offer from daemon ({len(signal.get('sdp', ''))} bytes SDP)")
            answer_sdp = await self.handle_offer(signal["sdp"])
            await self.send_dm({"type": "answer", "sdp": answer_sdp})
            log.info(f"→ answer sent to daemon")
        elif sig_type == "candidate":
            log.info(f"← ICE candidate")
            # Trickle ICE — apply candidate
            try:
                from aiortc.sdp import candidate_from_sdp
                cand = candidate_from_sdp(signal["sdp"])
                cand.sdpMid = "0"
                cand.sdpMLineIndex = 0
                await self.pc.addIceCandidate(cand)
            except Exception as e:
                log.warning(f"candidate apply: {e}")

    async def http_request(self, method: str = "GET", path: str = "/", body: bytes = None):
        """Send an HTTP request through the tunnel using binary stream protocol."""
        if not self.channel:
            log.warning("no datachannel yet")
            return None

        stream_id = 1  # simple: one stream at a time
        port = 80

        # Compose raw HTTP request
        http_req = compose_http_request(method, path, body)
        log.info(f"→ {method} {path} ({len(http_req)} bytes)")

        # Send MSG_OPEN + MSG_DATA + MSG_CLOSE
        self.channel.send(encode_frame(stream_id, port, MSG_OPEN))
        self.channel.send(encode_frame(stream_id, port, MSG_DATA, http_req))
        self.channel.send(encode_frame(stream_id, port, MSG_CLOSE))

        # Wait for response
        try:
            await asyncio.wait_for(self.stream_completed.wait(), timeout=15.0)
        except asyncio.TimeoutError:
            log.error("timeout waiting for response")
            return None

        # Parse the response
        try:
            text = self.received_data.decode("latin1")
            sep = text.find("\r\n\r\n")
            if sep < 0:
                log.error(f"malformed response: {text[:200]}")
                return None
            head = text[:sep]
            body = text[sep + 4:]
            status_line = head.split("\r\n")[0]
            status = int(status_line.split(" ")[1])
            headers = {}
            for line in head.split("\r\n")[1:]:
                colon = line.find(":")
                if colon > 0:
                    headers[line[:colon].strip()] = line[colon + 1:].strip()
            return {"status": status, "headers": headers, "body": body}
        except Exception as e:
            log.error(f"parse response: {e}")
            return None

    async def close(self):
        if self.pc:
            await self.pc.close()
        if self.http_session:
            await self.http_session.close()


def compose_http_request(method: str, path: str, body: bytes = None) -> bytes:
    """Compose a raw HTTP/1.1 request."""
    head = f"{method} {path} HTTP/1.1\r\n"
    head += f"Host: example.com\r\n"
    if body:
        head += f"Content-Length: {len(body)}\r\n"
    head += "\r\n"
    body_bytes = body if body else b""
    return head.encode("latin1") + body_bytes


def parse_args():
    p = argparse.ArgumentParser(description="peck-py test client (NIP-44 + binary stream)")
    p.add_argument("--daemon-npub", required=True, help="daemon pubkey (hex)")
    p.add_argument("--relays", default="wss://relay.primal.net,wss://no.str.cr")
    p.add_argument("--path", default="/", help="HTTP path to request after connect")
    p.add_argument("--timeout", type=float, default=30.0)
    return p.parse_args()


async def main():
    args = parse_args()
    relays = [r.strip() for r in args.relays.split(",")]

    client = PeckClient(daemon_pubkey=args.daemon_npub, relays=relays)
    log.info(f"client pubkey: {client.pubkey}")
    log.info(f"daemon pubkey: {client.daemon_pubkey}")

    try:
        ok = await client.connect(timeout=args.timeout)
        if not ok:
            sys.exit(1)

        await asyncio.sleep(1.0)
        response = await client.http_request("GET", args.path)

        if response:
            log.info(f"✓ HTTP {response['status']} {len(response['body'])} bytes")
            # Show a snippet
            body_preview = response['body'][:200].replace('\n', ' ')
            log.info(f"  body: {body_preview}")
        else:
            log.warning("✗ no response")

    finally:
        await client.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("interrupted")
