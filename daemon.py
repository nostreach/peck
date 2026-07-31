"""
peck-py: Nostr-signaled WebRTC daemon (Python spike, v4 — NIP-44).

Uses NIP-44 v2 for encrypted DMs (ChaCha20 + HMAC-SHA256, audited 2023.12).
Speaks the SAME binary stream protocol as the Node daemon (src/protocol.js),
so the existing browser client works once its transport layer is swapped.

Protocol:
- Client → daemon: NIP-44 DM with JSON content {"peerId": "..."} (announce)
- Daemon → client: WebRTC offer (signaling message {"type":"offer","sdp":"..."})
- Client → daemon: answer/candidate (signaling messages)
- Established WebRTC DataChannel: peck binary stream protocol
    - Frame format: [StreamID:2][Port:2][Type:1][Payload:var]  (big-endian)
    - Types: OPEN=0, DATA=1, CLOSE=2, RST=3
    - HTTP/1.1 requests/responses are carried as raw bytes in DATA frames

Run (inside peck netns):
  python daemon.py --nsec-file ~/.config/peck/nsec \\
                    --ports 80:http://10.200.200.1:8081 \\
                    --wg-ips 10.0.0.1,10.0.0.2,10.0.0.3 \\
                    --relays wss://relay.primal.net,wss://no.str.cr
"""

import argparse
import asyncio
import gc
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import secrets
import socket
import struct
import subprocess
import time
from typing import Optional

import aiohttp
import aioice.ice
import coincurve
from aiortc import RTCPeerConnection, RTCSessionDescription

# NIP-44 implementation (validated against official test vectors, 104/104 pass)
from nip44 import encrypt as nip44_encrypt, decrypt as nip44_decrypt

# Spec 024: Multi-Level Subdomain Routing
from route_table import RouteTable, pubkey_hex_to_npub
from ports import PortsMap, parse_path_prefix, load_ports_config, from_ports_legacy, PortsConfigError

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("aioice").setLevel(logging.WARNING)
logging.getLogger("aiortc").setLevel(logging.WARNING)
log = logging.getLogger("peck")

# Spec 026: module-global stash so SIGHUP handler can reach the daemon
# instance to trigger policy_engine.reload(). Only set in main().
_DAEMON_INSTANCE: dict = {}


# ─── Binary stream protocol (mirror of src/protocol.js) ─────────────────────

MSG_OPEN = 0x00
MSG_DATA = 0x01
MSG_CLOSE = 0x02
MSG_RST = 0x03
HEADER_SIZE = 5  # 2 + 2 + 1


def encode_frame(stream_id: int, port: int, msg_type: int, payload: bytes = b"") -> bytes:
    """Encode a peck protocol frame: [StreamID:2][Port:2][Type:1][Payload:var]."""
    return struct.pack(">HHB", stream_id, port, msg_type) + payload


def decode_frame(frame: bytes) -> tuple:
    """Decode a peck protocol frame. Returns (stream_id, port, type, payload)."""
    if len(frame) < HEADER_SIZE:
        raise ValueError(f"Frame too short: {len(frame)} bytes")
    stream_id, port, msg_type = struct.unpack(">HHB", frame[:HEADER_SIZE])
    payload = frame[HEADER_SIZE:]
    return stream_id, port, msg_type, payload


# ─── HTTP parsing/composition (mirror of src/server.js) ─────────────────────

STATUS_TEXTS = {
    200: "OK", 201: "Created", 204: "No Content",
    301: "Moved Permanently", 302: "Found", 304: "Not Modified",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
    500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
}


def parse_http_request(raw: bytes) -> dict:
    """Parse raw HTTP/1.1 request bytes into method, path, headers, body."""
    sep = raw.find(b"\r\n\r\n")
    if sep < 0:
        header_text = raw.decode("latin1")
        body = b""
    else:
        header_text = raw[:sep].decode("latin1")
        body = raw[sep + 4:]

    lines = header_text.split("\r\n")
    if not lines or not lines[0]:
        return {"method": "GET", "path": "/", "headers": {}, "body": None}

    first = lines[0].split(" ", 2)
    method = first[0] if len(first) > 0 else "GET"
    path = first[1] if len(first) > 1 else "/"

    headers = {}
    for line in lines[1:]:
        colon = line.find(":")
        if colon > 0:
            key = line[:colon].strip()
            value = line[colon + 1:].strip()
            headers[key] = value

    return {
        "method": method,
        "path": path,
        "headers": headers,
        "body": body if body else None,
    }


def compose_http_response(status: int, headers: dict, body: bytes) -> bytes:
    """Compose a raw HTTP/1.1 response.

    Normalisation: if the backend used `Transfer-Encoding: chunked`, we have
    already de-chunked the body into `body`. We must strip the chunked header
    (otherwise the client receives both Transfer-Encoding AND Content-Length,
    which is HTTP/1.1-illegal and causes the client to misparse the body —
    manifests as broken image/SVG blobs with naturalWidth=0).
    """
    status_text = STATUS_TEXTS.get(status, "OK")
    head = f"HTTP/1.1 {status} {status_text}\r\n"

    seen = set()
    for key, value in headers.items():
        # Skip Transfer-Encoding — we always send a de-chunked body with
        # explicit Content-Length below.
        if key.lower() == "transfer-encoding":
            continue
        head += f"{key}: {value}\r\n"
        seen.add(key.lower())
    if "content-length" not in seen:
        head += f"Content-Length: {len(body)}\r\n"
    head += "\r\n"

    return head.encode("latin1") + body


# ─── Constant-size 404 response (Spec 024 FR-008: anti-enumeration) ────────

_404_BODY = b"404 Not Found\n"
_404_HEADERS = {
    "Content-Type": "text/plain; charset=utf-8",
    "Content-Length": str(len(_404_BODY)),
    "Connection": "close",
}
NOT_FOUND_RESPONSE = compose_http_response(404, _404_HEADERS, _404_BODY)

_400_BODY = b"400 Bad Request\n"
_400_HEADERS = {
    "Content-Type": "text/plain; charset=utf-8",
    "Content-Length": str(len(_400_BODY)),
    "Connection": "close",
}
BAD_REQUEST_RESPONSE = compose_http_response(400, _400_HEADERS, _400_BODY)


# ─── secp256k1 pubkey helpers ───────────────────────────────────────────────

def get_pubkey(privkey_hex: str) -> str:
    """Derive x-only pubkey (32 bytes / 64 hex) from privkey."""
    sk = coincurve.PrivateKey(bytes.fromhex(privkey_hex))
    return sk.public_key.format(compressed=True)[1:].hex()


# ─── NIP-01 event building ──────────────────────────────────────────────────

def make_event(privkey_hex: str, recipient_pubkey: str, content: str, kind: int = 4) -> dict:
    """Create and sign a Nostr event (BIP-340 Schnorr signature)."""
    pub = get_pubkey(privkey_hex)
    created_at = int(time.time())
    tags = [["p", recipient_pubkey]] if kind == 4 else []

    canonical = json.dumps([0, pub, created_at, kind, tags, content], separators=(",", ":"))
    event_id = hashlib.sha256(canonical.encode()).hexdigest()

    sk = coincurve.PrivateKey(bytes.fromhex(privkey_hex))
    sig_bytes = sk.sign_schnorr(bytes.fromhex(event_id))

    return {
        "kind": kind,
        "content": content,
        "tags": tags,
        "created_at": created_at,
        "pubkey": pub,
        "id": event_id,
        "sig": sig_bytes.hex(),
    }


# ─── WebRTC peer session ────────────────────────────────────────────────────

class PeerSession:
    """
    One WebRTC peer session per client pubkey.

    Speaks the peck binary stream protocol over the DataChannel.
    WG binding is achieved by monkey-patching aioice.ice.get_host_addresses.
    """

    def __init__(self, daemon_privkey: str, client_pubkey: str, wg_ip: str,
                 relays: list, port_map: dict, http_session: aiohttp.ClientSession,
                 route_table: Optional[RouteTable] = None,
                 idle_timeout: float = 1200.0, connect_timeout: float = 15.0,
                 on_dispose=None,
                 ports_map: Optional["PortsMap"] = None,
                 daemon: Optional["PeckDaemon"] = None,
                 relay_mode: bool = False,
                 wg_ip6: Optional[str] = None):
        self.daemon_privkey = daemon_privkey
        self.daemon_pubkey = get_pubkey(daemon_privkey)
        self.client_pubkey = client_pubkey
        self.wg_ip = wg_ip
        self.wg_ip6 = wg_ip6
        self.relays = relays
        self.port_map = port_map
        self.http_session = http_session
        # Spec 024: route table for multi-backend routing
        self.route_table = route_table
        # Spec 029: optional PortsMap + back-reference to daemon for hot-reload
        self._daemon = daemon
        self.pc: Optional[RTCPeerConnection] = None
        self.channel = None
        self.created_at = time.time()
        self.last_activity = time.time()
        self.streams = {}

        # Spec 033: Terms of Service state
        self.awaiting_terms = False
        self.terms_version_expected: Optional[str] = None
        self.terms_timeout_task = None

        # Spec 031: Relay mode — frames are forwarded to a partner session
        self.relay_mode = relay_mode
        self.relay_partner: Optional["PeerSession"] = None

        # Lifecycle state machine (spec 021, FR-014)
        # Valid transitions:
        #   connecting → active | closed
        #   active     → closing → closed
        #   closing    → closed
        self.state = "connecting"

        # Configurable timeouts
        self.idle_timeout = idle_timeout        # FR-016: default 20 min
        self.connect_timeout = connect_timeout  # FR-015: 15 s

        # Background timers (asyncio tasks)
        self._connect_timer: Optional[asyncio.Task] = None
        self._idle_timer: Optional[asyncio.Task] = None

        # Callback into the daemon registry when this session dies
        self._on_dispose = on_dispose

        mode_label = "relay" if relay_mode else "serve"
        log.info(f"📝 session [{mode_label}] for {client_pubkey[:8]} → {wg_ip}, ports={list(port_map.keys())} (idle={int(idle_timeout)}s)")

    @property
    def daemon(self) -> Optional["PeckDaemon"]:
        """Back-reference to the owning PeckDaemon (set when daemon constructed the session)."""
        return self._daemon

    def _transition(self, new_state: str):
        """State machine guard. Logs transitions. Idempotent on closed."""
        if self.state == "closed" and new_state != "closed":
            return  # already gone
        if self.state == new_state:
            return
        old = self.state
        # Validate allowed transitions
        allowed = {
            "connecting": {"active", "closing", "closed"},
            "active":     {"closing", "closed"},
            "closing":    {"closed"},
            "closed":     set(),
        }
        if new_state not in allowed.get(old, set()):
            log.warning(f"⚠ invalid transition {old}→{new_state} for {self.client_pubkey[:8]}")
            return
        self.state = new_state
        log.debug(f"state {old}→{new_state} for {self.client_pubkey[:8]}")

    def _cancel_timers(self):
        for t in (self._connect_timer, self._idle_timer):
            if t and not t.done():
                t.cancel()
        self._connect_timer = None
        self._idle_timer = None

    def _start_connect_timer(self):
        """FR-015: Dispose the session if it's still 'connecting' after 15 s."""
        async def _timeout():
            try:
                await asyncio.sleep(self.connect_timeout)
            except asyncio.CancelledError:
                return
            if self.state == "connecting":
                log.warning(f"⏱ connect timeout ({int(self.connect_timeout)}s) for {self.client_pubkey[:8]}")
                await self.close(reason="connect_timeout")
        self._connect_timer = asyncio.create_task(_timeout())

    def _arm_idle_timer(self):
        """FR-016: Dispose the session after `idle_timeout` seconds of inactivity."""
        async def _timeout():
            try:
                await asyncio.sleep(self.idle_timeout)
            except asyncio.CancelledError:
                return
            idle_for = int(time.time() - self.last_activity)
            if self.state == "active":
                log.info(f"💤 idle timeout for {self.client_pubkey[:8]} (idle {idle_for}s)")
                await self.close(reason="idle_timeout")
        # Cancel any previous idle timer and start a fresh one
        if self._idle_timer and not self._idle_timer.done():
            self._idle_timer.cancel()
        self._idle_timer = asyncio.create_task(_timeout())

    def _touch(self):
        """Mark activity (called on every inbound frame). Resets idle timer."""
        self.last_activity = time.time()
        if self.state == "active":
            self._arm_idle_timer()

    async def setup(self):
        # Collect host addresses — IPv4 + IPv6 (if configured)
        host_addrs = [self.wg_ip]
        if self.wg_ip6:
            host_addrs.append(self.wg_ip6)
        aioice.ice.get_host_addresses = lambda use_ipv4, use_ipv6: host_addrs

        from aiortc import RTCConfiguration, RTCIceServer
        config = RTCConfiguration(iceServers=[
            RTCIceServer(urls=["stun:stun.l.google.com:19302"]),
        ])
        self.pc = RTCPeerConnection(configuration=config)

        # IPv6 srflx: aioice only does STUN for IPv4. Since the WG exit
        # does 1:1 NPTv6 (port preserved), we resolve the public IPv6 at
        # startup and patch the local description after ICE gathering.
        self._ipv6_public = None
        if self.wg_ip6:
            self._ipv6_public = await self._resolve_ipv6_srflx()
            if self._ipv6_public:
                log.info(f"🧊 IPv6 srflx: {self._ipv6_public} (NPTv6 1:1, port preserved)")
            else:
                # Retry with policy routing fix — ensure all IPv6 rules exist
                await self._ensure_ipv6_routing()
                self._ipv6_public = await self._resolve_ipv6_srflx()
                if self._ipv6_public:
                    log.info(f"🧊 IPv6 srflx (retry): {self._ipv6_public}")
                else:
                    log.warning(f"⚠ IPv6 srflx failed — IPv6 hole-punching disabled")
        self.channel = self.pc.createDataChannel("peck", ordered=True)

        @self.channel.on("message")
        def on_message(message):
            if isinstance(message, (bytes, bytearray)):
                self._handle_frame(bytes(message))

        @self.pc.on("connectionstatechange")
        async def on_state():
            state = self.pc.connectionState
            log.info(f"🔌 peer {self.client_pubkey[:8]} state={state}")
            if state == "connected":
                # Transition to active and arm idle timer
                if self.state == "connecting":
                    self._transition("active")
                    self._arm_idle_timer()
            elif state in ("failed", "closed", "disconnected"):
                await self.close(reason=f"pc_{state}")

        # Start connect timer (FR-015)
        self._start_connect_timer()

    async def _ensure_ipv6_routing(self):
        """Ensure IPv6 policy routing rules exist for all WG interfaces.
        peck-vpn.sh doesn't always set these reliably on restart."""
        import subprocess
        try:
            # Get current rules
            result = subprocess.run(
                ["ip", "-6", "rule", "show"],
                capture_output=True, text=True, timeout=2
            )
            existing = result.stdout

            # Map ULA prefixes to routing tables (matching peck-vpn.sh order)
            # wg0 → table 100, wg1 → table 101, wg2 → table 102
            rules_to_add = [
                ("fd00:4956:504e:ffff::ac13:c957", 100),
                ("fd00:4956:504e:ffff::ac14:d1ba", 101),
                ("fd00:4956:504e:ffff::ac10:85ee", 102),
            ]
            for src6, table in rules_to_add:
                if src6 not in existing:
                    subprocess.run(
                        ["ip", "-6", "rule", "add", "from", src6, "lookup", str(table)],
                        capture_output=True, timeout=2
                    )
                    log.info(f"🧊 IPv6 policy rule added: from {src6[:20]}... lookup {table}")
        except Exception as e:
            log.debug(f"IPv6 routing setup: {e}")

    async def _resolve_ipv6_srflx(self) -> Optional[str]:
        """Resolve public IPv6 exit address via STUN over IPv6.
        Uses 1:1 NPTv6 port preservation — the public address maps
        directly to our fd00 ULA address."""
        try:
            from aioice.stun import Message, Method, Class, parse_message
            loop = asyncio.get_event_loop()

            # Create IPv6 UDP socket bound to our ULA address
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.setblocking(False)
            sock.bind((self.wg_ip6, 0))

            # Send STUN binding request to Google STUN over IPv6
            request = Message(
                message_method=Method.BINDING,
                message_class=Class.REQUEST,
            )
            await loop.sock_sendto(sock, bytes(request), ('2001:4860:4864:5:8000::1', 19302))

            # Wait for response
            data = await asyncio.wait_for(loop.sock_recv(sock, 2048), timeout=5.0)
            response = parse_message(data)

            # Extract XOR-MAPPED-ADDRESS
            if "XOR-MAPPED-ADDRESS" in response.attributes:
                host, port = response.attributes["XOR-MAPPED-ADDRESS"]
                if ":" in str(host):  # IPv6
                    sock.close()
                    return str(host)

            sock.close()
        except Exception as e:
            log.warning(f"IPv6 srflx resolution failed: {e}", exc_info=True)
        return None

    async def create_offer(self) -> dict:
        offer = await self.pc.createOffer()
        await self.pc.setLocalDescription(offer)
        await self._wait_for_ice_gathering()

        # Inject IPv6 srflx candidate if we resolved a public IPv6 exit.
        # aioice doesn't do STUN for IPv6, so we add it manually.
        # The port is the same as the IPv6 host candidate (1:1 NPTv6).
        local_sdp = self.pc.localDescription.sdp
        if hasattr(self, '_ipv6_public') and self._ipv6_public:
            local_sdp = self._inject_ipv6_srflx(local_sdp)

        # Spec 034: Safety-net SDP candidate filter.
        # Only allow candidates whose IP matches our selected WG IP(s).
        # This prevents accidental leakage of host/veth IPs if aioice
        # discovers additional interfaces despite the monkey-patch.
        allowed_ips = {self.wg_ip}
        if self.wg_ip6:
            allowed_ips.add(self.wg_ip6)
            if hasattr(self, '_ipv6_public') and self._ipv6_public:
                allowed_ips.add(self._ipv6_public)
        # Also allow STUN srflx candidates (Google STUN reflexive addresses)
        local_sdp = self._filter_sdp_candidates(local_sdp, allowed_ips)

        # Log gathered candidates for debugging
        for line in local_sdp.split("\n"):
            if line.startswith("a=candidate"):
                log.info(f"🧊 local candidate: {line[12:]}")
        log.info(f"📡 offer size: {len(local_sdp)} bytes")
        return {"type": "offer", "sdp": local_sdp}

    def _filter_sdp_candidates(self, sdp: str, allowed_ips: set) -> str:
        """Spec 034: Remove a=candidate lines whose IP is not in allowed_ips.

        Keeps: host candidates matching our WG IPs, srflx candidates from STUN
        (they carry our public IP — needed for NAT traversal).
        Removes: any host candidate for an interface we didn't select.
        """
        lines = sdp.split("\n")
        filtered = []
        removed = 0
        for line in lines:
            if not line.startswith("a=candidate"):
                filtered.append(line)
                continue
            # Parse candidate IP: a=candidate: ... <ip> <port> typ <type> ...
            parts = line.split()
            if len(parts) < 8:
                filtered.append(line)
                continue
            ip = parts[4]
            cand_type_idx = parts.index("typ") + 1 if "typ" in parts else -1
            cand_type = parts[cand_type_idx] if cand_type_idx > 0 else "host"

            if ip in allowed_ips:
                filtered.append(line)
            elif cand_type == "srflx":
                # STUN reflexive — always allow (needed for NAT traversal)
                filtered.append(line)
            else:
                removed += 1
                log.warning(f"🚫 SDP filter: removed candidate {ip} (type={cand_type}, not in allowed={allowed_ips})")

        if removed:
            log.info(f"🛡 SDP safety filter: removed {removed} candidate(s)")
        return "\n".join(filtered)

    def _inject_ipv6_srflx(self, sdp: str) -> str:
        """Add an IPv6 srflx candidate by replacing the fd00 host address
        with the public NPTv6 address in a copy of the host candidate line."""
        lines = sdp.split("\n")
        new_lines = []
        for line in lines:
            new_lines.append(line)
            if line.startswith("a=candidate") and self.wg_ip6 in line and "typ host" in line:
                # Replace the fd00 address with the public address, change type to srflx
                srflx_line = line.replace(self.wg_ip6, self._ipv6_public)
                srflx_line = srflx_line.replace("typ host", f"typ srflx raddr {self.wg_ip6}")
                new_lines.append(srflx_line)
                log.info(f"🧊 injected IPv6 srflx: {srflx_line[12:]}")
        return "\n".join(new_lines)

    async def receive_answer(self, sdp: str):
        answer = RTCSessionDescription(sdp=sdp, type="answer")
        await self.pc.setRemoteDescription(answer)

        # Spec 033: ICE second filter — check srflx IPs in remote SDP
        if self._daemon and self._daemon.policy_engine and getattr(self._daemon, "geoip_active", False):
            await self._check_remote_ice_ips(sdp)

    async def receive_candidate(self, candidate_str: str):
        from aiortc.sdp import candidate_from_sdp
        try:
            cand = candidate_from_sdp(candidate_str)
            cand.sdpMid = "0"
            cand.sdpMLineIndex = 0
            await self.pc.addIceCandidate(cand)
        except Exception as e:
            log.warning(f"⚠ candidate parse error: {e}")

    async def _check_remote_ice_ips(self, sdp: str):
        """Spec 033: Extract srflx IPs from remote SDP and run policy check."""
        import re
        # Look for a=candidate lines with typ srflx
        for line in sdp.split("\n"):
            line = line.strip()
            if line.startswith("a=candidate:") and "srflx" in line:
                # Extract IP from candidate line
                # Format: a=candidate: foundation component proto priority IP port typ srflx ...
                parts = line.split()
                if len(parts) >= 8:
                    ip = parts[4]
                    try:
                        ipaddress.ip_address(ip)
                        decision = self._daemon.policy_engine.decide(self.client_pubkey, ip)
                        if decision.effect in ("deny", "loud-deny"):
                            log.warning(
                                f"🚫 ICE policy violation: srflx IP {ip} "
                                f"blocked for {self.client_pubkey[:8]} "
                                f"(rule={decision.matched_comment or 'default'})"
                            )
                            await self.close()
                            return
                    except ValueError:
                        pass  # not an IP, skip

    async def _wait_for_ice_gathering(self, timeout: float = 5.0):
        if self.pc.iceGatheringState == "complete":
            return
        try:
            await asyncio.wait_for(self._gather_wait(), timeout)
        except asyncio.TimeoutError:
            pass

    async def _gather_wait(self):
        while self.pc.iceGatheringState != "complete":
            await asyncio.sleep(0.1)

    def _handle_frame(self, frame: bytes):
        # Track activity for idle timeout (FR-016)
        self._touch()

        # Spec 031: In relay mode, forward every frame verbatim to the partner
        if self.relay_mode:
            if self.relay_partner and self.relay_partner.state == "active":
                self.relay_partner._send(frame)
            elif self.relay_mode:
                # No bridge partner yet — respond with RST on OPEN frames
                try:
                    stream_id, port, msg_type, _ = decode_frame(frame)
                    if msg_type == MSG_OPEN:
                        err = b"no bridge partner assigned"
                        self._send(encode_frame(stream_id, port, MSG_RST, err))
                except ValueError:
                    pass
            return

        try:
            stream_id, port, msg_type, payload = decode_frame(frame)
        except ValueError:
            return

        if msg_type == MSG_OPEN:
            # Spec 029: Wire-port is just a hint. The actual routing
            # decision happens in _proxy_request based on:
            #   1. Path-prefix /_p<port>/ (Spec 029)
            #   2. Host-header (Spec 024)
            #   3. Wire-port (legacy)
            # Accept all MSG_OPEN frames; _proxy_request will send 404 or
            # RST if the effective port is unknown. This was previously
            # `if port not in self.port_map: send RST`, but that broke
            # Spec 029 because the browser sends wire-port 80 (its
            # default) while the daemon's default_port may be different.
            self.streams[stream_id] = {"port": port}

        elif msg_type == MSG_DATA:
            stream = self.streams.get(stream_id)
            if not stream:
                self._send(encode_frame(stream_id, port, MSG_RST))
                return
            asyncio.create_task(self._proxy_request(stream_id, port, payload))

        elif msg_type in (MSG_CLOSE, MSG_RST):
            self.streams.pop(stream_id, None)

    async def _proxy_request(self, stream_id: int, port: int, payload: bytes):
        # ─── Spec 024: Multi-Level Subdomain Routing ───────────────────
        # If a route table is configured, resolve the backend from the
        # HTTP Host header. Otherwise fall back to the legacy port_map.
        if self.route_table is not None:
            req = parse_http_request(payload)
            host_header = req["headers"].get("Host") or req["headers"].get("host") or ""

            # FR-017: RFC 1035 length sanity → 400
            if len(host_header) > 253:
                self._send(encode_frame(stream_id, port, MSG_DATA, BAD_REQUEST_RESPONSE))
                self._send(encode_frame(stream_id, port, MSG_CLOSE))
                self.streams.pop(stream_id, None)
                return

            # ─── Spec 029: Path-Prefix Multi-Port ──────────────────────
            # The browser may or may not strip the /_p<port>/ prefix before
            # sending. See the legacy-mode branch below for the full strategy.
            effective_port = port
            effective_path = req["path"]
            if self.daemon.ports_map is not None:
                try:
                    parsed_port, parsed_path = parse_path_prefix(
                        req["path"], self.daemon.ports_map.default_port
                    )
                except ValueError:
                    # Out-of-range port in /_p<port>/
                    self._send(encode_frame(stream_id, port, MSG_DATA, BAD_REQUEST_RESPONSE))
                    self._send(encode_frame(stream_id, port, MSG_CLOSE))
                    self.streams.pop(stream_id, None)
                    return
                path_has_prefix = req["path"].startswith("/_p")
                if path_has_prefix:
                    effective_port = parsed_port
                    effective_path = parsed_path
                elif port in self.daemon.ports_map:
                    # Trust wire-port (peck-aware client that already stripped)
                    effective_port = port
                    effective_path = req["path"]
                else:
                    effective_port = self.daemon.ports_map.default_port
                    effective_path = req["path"]

            backend_url = self.route_table.resolve_host(host_header)
            if backend_url is None:
                # FR-008: constant-size 404 (anti-enumeration)
                log.info(f"🌐 {req['method']} {req['path'][:60]} Host={host_header[:40]} → 404 (no route)")
                self._send(encode_frame(stream_id, port, MSG_DATA, NOT_FOUND_RESPONSE))
                self._send(encode_frame(stream_id, port, MSG_CLOSE))
                self.streams.pop(stream_id, None)
                return

            # Spec 029: if path-prefix port is not in ports_map, FR-005 → 404
            if self.daemon.ports_map is not None and effective_port not in self.daemon.ports_map:
                log.info(f"🌐 {req['method']} {req['path'][:60]} → 404 (port {effective_port} not configured)")
                self._send(encode_frame(stream_id, port, MSG_DATA, NOT_FOUND_RESPONSE))
                self._send(encode_frame(stream_id, port, MSG_CLOSE))
                self.streams.pop(stream_id, None)
                return

            url = backend_url.rstrip("/") + effective_path
            log.info(f"🌐 {req['method']} {req['path'][:60]} Host={host_header[:40]} port={effective_port} → {backend_url}")

            body = req["body"] if req["body"] else None
            try:
                async with self.http_session.request(
                    req["method"], url,
                    headers=req["headers"],
                    data=body,
                    allow_redirects=False,
                ) as resp:
                    body_bytes = await resp.read()
                    resp_headers = {k: v for k, v in resp.headers.items()}
                    raw_response = compose_http_response(resp.status, resp_headers, body_bytes)

                    self._send(encode_frame(stream_id, port, MSG_DATA, raw_response))
                    self._send(encode_frame(stream_id, port, MSG_CLOSE))
            except Exception as e:
                log.error(f"proxy error: {e}")
                err_msg = str(e).encode("latin1")
                self._send(encode_frame(stream_id, port, MSG_RST, err_msg))
            finally:
                self.streams.pop(stream_id, None)
            return

        # ─── Spec 029: Path-Prefix Multi-Port (legacy --ports mode) ────
        # The browser may or may not strip the /_p<port>/ prefix before
        # sending. Two cases:
        #   1. Peck-aware client: strip client-side, sends wire-port=8082
        #      with path '/'. Trust the wire-port.
        #   2. Raw HTTP client (curl, future native CLI): no stripping,
        #      sends wire-port=80 and path '/_p8082/foo'. Parse the prefix.
        # Strategy: if the path has /_p<port>/, use that port (case 2).
        # Otherwise, use the wire-port (case 1) if it's in ports_map;
        # fall back to default_port for unknown wire-ports (backwards-compat).
        if self.daemon.ports_map is not None:
            req = parse_http_request(payload)
            try:
                prefix_port, prefix_path = parse_path_prefix(
                    req["path"], self.daemon.ports_map.default_port
                )
            except ValueError:
                self._send(encode_frame(stream_id, port, MSG_DATA, BAD_REQUEST_RESPONSE))
                self._send(encode_frame(stream_id, port, MSG_CLOSE))
                self.streams.pop(stream_id, None)
                return
            # Detect whether path actually had a prefix (vs. defaulted)
            path_has_prefix = req["path"].startswith("/_p")
            if path_has_prefix:
                effective_port = prefix_port
                effective_path = prefix_path
            elif port in self.daemon.ports_map:
                # Trust wire-port (peck-aware client that already stripped)
                effective_port = port
                effective_path = req["path"]
            else:
                # Unknown wire-port, no prefix — use default
                effective_port = self.daemon.ports_map.default_port
                effective_path = req["path"]

            backend_url = self.daemon.ports_map.get(effective_port)
            if backend_url is None:
                log.info(f"🌐 {req['method']} {req['path'][:60]} → 404 (port {effective_port} not configured)")
                self._send(encode_frame(stream_id, port, MSG_DATA, NOT_FOUND_RESPONSE))
                self._send(encode_frame(stream_id, port, MSG_CLOSE))
                self.streams.pop(stream_id, None)
                return

            url = backend_url.rstrip("/") + effective_path
            log.info(f"🌐 {req['method']} {req['path'][:60]} → {backend_url} (port={effective_port})")

            body = req["body"] if req["body"] else None
            try:
                async with self.http_session.request(
                    req["method"], url,
                    headers=req["headers"],
                    data=body,
                    allow_redirects=False,
                ) as resp:
                    body_bytes = await resp.read()
                    resp_headers = {k: v for k, v in resp.headers.items()}
                    raw_response = compose_http_response(resp.status, resp_headers, body_bytes)

                    self._send(encode_frame(stream_id, port, MSG_DATA, raw_response))
                    self._send(encode_frame(stream_id, port, MSG_CLOSE))
            except Exception as e:
                log.error(f"proxy error: {e}")
                err_msg = str(e).encode("latin1")
                self._send(encode_frame(stream_id, port, MSG_RST, err_msg))
            finally:
                self.streams.pop(stream_id, None)
            return

        # ─── Legacy: port-based routing (--ports mode, pre-Spec-029) ────
        backend_url = self.port_map.get(port)
        try:
            req = parse_http_request(payload)
            url = backend_url.rstrip("/") + req["path"]

            log.info(f"🌐 {req['method']} {req['path'][:60]} → {backend_url}")

            body = req["body"] if req["body"] else None
            async with self.http_session.request(
                req["method"], url,
                headers=req["headers"],
                data=body,
                allow_redirects=False,
            ) as resp:
                body_bytes = await resp.read()
                resp_headers = {k: v for k, v in resp.headers.items()}
                raw_response = compose_http_response(resp.status, resp_headers, body_bytes)

                self._send(encode_frame(stream_id, port, MSG_DATA, raw_response))
                self._send(encode_frame(stream_id, port, MSG_CLOSE))

        except Exception as e:
            log.error(f"proxy error: {e}")
            err_msg = str(e).encode("latin1")
            self._send(encode_frame(stream_id, port, MSG_RST, err_msg))
        finally:
            self.streams.pop(stream_id, None)

    def _send(self, data: bytes):
        if self.channel and self.state != "closed":
            try:
                self.channel.send(data)
            except Exception as e:
                log.warning(f"send failed: {e}")

    async def send_signaling(self, msg: dict):
        """Send a signaling message to client via NIP-44 encrypted DM.

        Round-robin across relays (per-session rotation counter). Falls back
        to the next relay if the current one fails. Spec 005.
        """
        plaintext = json.dumps(msg)
        encrypted = nip44_encrypt(plaintext, self.daemon_privkey, self.client_pubkey)
        event = make_event(self.daemon_privkey, self.client_pubkey, encrypted)
        payload = json.dumps(["EVENT", event])

        # Round-robin starting index per session
        if not hasattr(self, "_relay_idx"):
            self._relay_idx = 0
        n = len(self.relays)
        sig_type = msg.get("type", "?")

        for attempt in range(n):
            url = self.relays[self._relay_idx % n]
            self._relay_idx = (self._relay_idx + 1) % n
            try:
                async with self.http_session.ws_connect(url) as ws:
                    await ws.send_str(payload)
                    try:
                        await asyncio.wait_for(ws.receive(), timeout=2.0)
                    except asyncio.TimeoutError:
                        pass
                    log.info(f"→ {sig_type} via {url.split('//')[1][:20]}")
                    return
            except Exception as e:
                log.warning(f"relay send failed {url}: {e}")

        log.error(f"all {n} relays failed for {sig_type} message")

    async def close(self, reason: str = "unspecified"):
        """Dispose the session. Idempotent. Cancels timers, closes PC,
        notifies the daemon registry so it can prune its map.

        Args:
            reason: human-readable reason for closing (logged, not parsed)
        """
        if self.state == "closed":
            return
        self._transition("closing")
        self._cancel_timers()
        age = int(time.time() - self.created_at)
        log.info(f"✗ closing session for {self.client_pubkey[:8]} (age {age}s, reason={reason})")
        if self.pc:
            # Close ICE connections gracefully before PC disposal to avoid
            # aioice Transaction.__retry() crashes on dead sockets.
            try:
                for transceiver in getattr(self.pc, '_transceivers', []):
                    pass
                # Cancel all pending STUN transactions by closing the PC sync
                await asyncio.wait_for(self.pc.close(), timeout=2.0)
            except Exception:
                pass
        self._transition("closed")
        # Notify registry to prune
        if self._on_dispose:
            try:
                self._on_dispose(self.client_pubkey)
            except Exception:
                pass


# ─── Daemon ────────────────────────────────────────────────────────────────

def get_connected_wg_ips() -> dict:
    """Spec 034: Return IPs of WG interfaces with active handshake.

    Runs `wg show all` and parses interface names + latest handshake timestamps.
    Then maps interface names to their assigned IPs via `ip addr`.

    Returns:
        {interface_name: {"ipv4": "x.x.x.x", "ipv6": "fd00:...", "handshake_ago": seconds}}
        Only interfaces with a handshake within the last 5 minutes are included.
    """
    HANDSHAKE_MAX_AGE = 300  # 5 minutes

    try:
        result = subprocess.run(
            ["wg", "show", "all"],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode != 0:
            log.warning(f"wg show all failed: {result.stderr.strip()}")
            return {}
    except Exception as e:
        log.warning(f"wg show all error: {e}")
        return {}

    # Parse wg output: "interface: wgN" blocks with "latest handshake: N ago"
    connected = {}  # iface -> handshake_ago_seconds
    current_iface = None
    for line in result.stdout.split("\n"):
        m = re.match(r"interface:\s+(\S+)", line)
        if m:
            current_iface = m.group(1)
            connected[current_iface] = None
            continue
        hm = re.search(r"latest handshake:\s+(\d+).+?ago", line)
        if hm and current_iface:
            connected[current_iface] = int(hm.group(1))

    # Filter: only interfaces with recent handshake
    active_ifaces = {iface for iface, age in connected.items()
                     if age is not None and age <= HANDSHAKE_MAX_AGE}

    if not active_ifaces:
        log.warning(f"no WG interfaces with active handshake (checked: {list(connected.keys())})")
        return {}

    # Map interface → IPs via `ip addr show`
    try:
        result = subprocess.run(
            ["ip", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=3
        )
    except Exception as e:
        log.warning(f"ip addr show error: {e}")
        return {}

    iface_info = {}
    for line in result.stdout.split("\n"):
        # Format: "1630: wg0    inet 10.0.0.1/32 scope global wg0"
        parts = line.split()
        if len(parts) < 4:
            continue
        iface = parts[1]
        if iface not in active_ifaces:
            continue
        if iface not in iface_info:
            iface_info[iface] = {"ipv4": None, "ipv6": None, "handshake_ago": connected[iface]}

        if parts[2] == "inet":
            ip_cidr = parts[3]
            ip_str = ip_cidr.split("/")[0]
            iface_info[iface]["ipv4"] = ip_str
        elif parts[2] == "inet6":
            ip_cidr = parts[3]
            ip_str = ip_cidr.split("/")[0]
            # Skip link-local addresses
            if not ip_str.startswith("fe80"):
                iface_info[iface]["ipv6"] = ip_str

    return iface_info


class PeckDaemon:
    def __init__(self, privkey_hex: str, relays: list, wg_ips: list, port_mappings: dict,
                 route_table: Optional[RouteTable] = None,
                 idle_timeout: float = 1200.0,
                 connect_timeout: float = 15.0,
                 policy_engine: Optional["PolicyEngine"] = None,
                 ports_map: Optional["PortsMap"] = None,
                 relay_mode: bool = False,
                 relay_price: int = 0,
                 wg_ip6s: Optional[list] = None):
        self.privkey = privkey_hex
        self.pubkey = get_pubkey(privkey_hex)
        self.relays = relays
        self.wg_ips = wg_ips
        self.wg_ip6s = wg_ip6s or []
        self.port_map = port_mappings
        # Spec 024: optional route table for multi-backend routing
        self.route_table = route_table
        # Spec 029: optional PortsMap for path-prefix multi-port
        self.ports_map = ports_map
        self.peers: dict = {}
        self.http_session: Optional[aiohttp.ClientSession] = None
        # Event-id dedup set for multi-relay (spec 005)
        self._seen_event_ids: set = set()
        # Lifecycle config (spec 021)
        self.idle_timeout = idle_timeout
        self.connect_timeout = connect_timeout
        # Spec 026: Access Control
        self.policy_engine = policy_engine
        # Spec 033: GeoIP active flag (set when --geoip-db is loaded)
        self.geoip_active = False

        # Spec 031: Relay mode
        self.relay_mode = relay_mode
        self.relay_price = relay_price  # sat/min, 0 = free
        self.pending_requests: dict = {}  # {requester_npub: target_npub}
        self.bridges: dict = {}  # {npub_a: npub_b} bidirectional

        mode_label = " [RELAY MODE]" if relay_mode else ""
        price_label = f" ({relay_price} sat/min)" if relay_price > 0 else " (free)" if relay_mode else ""
        log.info(f"peck daemon ready{mode_label}{price_label} — pubkey {self.pubkey[:16]}…")
        log.info(f"  relays: {', '.join(r.split('//')[1][:25] for r in relays)}")
        log.info(f"  wg_ips: {', '.join(wg_ips)}")
        if route_table is not None:
            log.info(f"  route_table: {route_table}")
        elif ports_map is not None:
            log.info(f"  ports_map: {len(ports_map)} ports, default={ports_map.default_port}")
        else:
            log.info(f"  ports: {port_mappings}")
        log.info(f"  lifecycle: idle_timeout={int(idle_timeout)}s, connect_timeout={int(connect_timeout)}s")

    def pick_wg_ip(self) -> str:
        return random.choice(self.wg_ips)

    def pick_wg_ip6(self) -> Optional[str]:
        if self.wg_ip6s:
            return random.choice(self.wg_ip6s)
        return None

    def pick_wg_pair(self, ip_preference: str = "both") -> tuple:
        """Spec 034: Pick a correlated (IPv4, IPv6) pair from a connected WG tunnel.

        Filters by:
        1. Active WireGuard handshake (within last 5 min) — prevents stale tunnel IPs
        2. ip_preference: "ipv4" / "ipv6" / "both" — only pick tunnels with matching addresses

        Graceful degradation: if no tunnel matches the preference, falls back to
        all configured wg_ips (legacy behavior).

        Returns:
            (ipv4_str_or_None, ipv6_str_or_None)
        """
        connected = get_connected_wg_ips()

        if not connected:
            # No handshake data — fall back to configured IPs
            log.debug("no handshake data, using configured wg_ips")
            idx = random.randint(0, len(self.wg_ips) - 1)
            ip4 = self.wg_ips[idx]
            ip6 = self.wg_ip6s[idx] if idx < len(self.wg_ip6s) else None
            return (ip4, ip6)

        # Build candidate list from connected tunnels
        candidates = []
        for iface, info in connected.items():
            ip4 = info["ipv4"]
            ip6 = info["ipv6"]

            # Filter by ip_preference
            if ip_preference == "ipv4" and not ip4:
                continue
            if ip_preference == "ipv6" and not ip6:
                continue
            # "both" or matched preference
            if not ip4 and not ip6:
                continue
            candidates.append((ip4, ip6))

        if not candidates:
            # No tunnel matches preference — fall back to all connected
            log.info(f"no tunnel matches ip_preference={ip_preference}, falling back to all connected")
            for iface, info in connected.items():
                ip4 = info["ipv4"]
                ip6 = info["ipv6"]
                if ip4 or ip6:
                    candidates.append((ip4, ip6))

        if not candidates:
            # Still nothing — ultimate fallback to configured IPs
            log.warning("no connected WG tunnels with IPs, falling back to configured wg_ips")
            idx = random.randint(0, len(self.wg_ips) - 1)
            ip4 = self.wg_ips[idx]
            ip6 = self.wg_ip6s[idx] if idx < len(self.wg_ip6s) else None
            return (ip4, ip6)

        return random.choice(candidates)

    def _on_session_dispose(self, client_pubkey: str):
        """Called by PeerSession.close() so the registry can prune."""
        # Spec 031: If this peer is part of a bridge, tear down the partner
        if client_pubkey in self.bridges and self.relay_mode:
            asyncio.create_task(self._teardown_bridge(client_pubkey))

        # Only delete if it's still us (a REPLACE may have already swapped us out)
        existing = self.peers.get(client_pubkey)
        if existing is not None and getattr(existing, "state", None) == "closed":
            self.peers.pop(client_pubkey, None)
            # Spec 031: Also clean up pending requests for this pubkey
            self.pending_requests.pop(client_pubkey, None)

    def _get_or_create_session(self, client_pubkey: str, ip_preference: str = "both") -> PeerSession:
        if client_pubkey in self.peers:
            log.info(f"♻ replace existing session for {client_pubkey[:8]}")
            asyncio.create_task(self.peers[client_pubkey].close(reason="replaced"))
            del self.peers[client_pubkey]

        wg_ip, wg_ip6 = self.pick_wg_pair(ip_preference=ip_preference)
        session = PeerSession(
            daemon_privkey=self.privkey,
            client_pubkey=client_pubkey,
            wg_ip=wg_ip,
            relays=self.relays,
            port_map=self.port_map,
            http_session=self.http_session,
            route_table=self.route_table,
            idle_timeout=self.idle_timeout,
            connect_timeout=self.connect_timeout,
            on_dispose=self._on_session_dispose,
            ports_map=self.ports_map,
            daemon=self,
            relay_mode=self.relay_mode,
            wg_ip6=wg_ip6,
        )
        self.peers[client_pubkey] = session

        # Spec 031: In relay mode, check if this session completes a pending bridge
        if self.relay_mode:
            asyncio.create_task(self._check_bridge())

        return session

    async def handle_announce(self, client_pubkey: str, client_ip: Optional[str] = None,
                              ip_preference: str = "both"):
        """
        Spec 023 (2026-07-19 amendment): accept optional client_ip field
        from the announce payload.
        Spec 026: consult self.policy_engine before doing any WebRTC work.
        Spec 033: Region blocking, Terms of Service, request-ip DM.
        """
        # Spec 026: Policy decision (single filter point)
        if self.policy_engine is not None:
            # Spec 033: If client_ip is missing and policy has IP-based rules, request it
            if not client_ip and self._policy_has_ip_rules():
                log.info(f"📤 request-ip sent to {client_pubkey[:8]} (no client_ip, IP rules active)")
                await self._send_dm(client_pubkey, {"type": "request-ip"})
                return

            decision = self.policy_engine.decide(client_pubkey, client_ip)
            if decision.effect == "deny":
                # Silent drop.
                return
            if decision.effect == "loud-deny":
                # Send a byte-identical-size deny-DM (FR-008 anti-enumeration).
                from policy import pad_message
                await self._send_dm(client_pubkey, {
                    "type": "deny",
                    "message": pad_message(decision.message),
                })
                log.info(f"🚫 loud-deny sent to {client_pubkey[:8]} (rule={decision.matched_comment or 'default'})")
                return

            # effect == "allow"
            # Spec 033: Terms of Service gate
            if decision.terms_text and decision.terms_version:
                log.info(f"📄 terms-challenge sent to {client_pubkey[:8]} (version={decision.terms_version})")
                await self._send_dm(client_pubkey, {
                    "type": "terms-challenge",
                    "text": decision.terms_text,
                    "version": decision.terms_version,
                })
                # Store pending terms state in the session
                session = self._get_or_create_session(client_pubkey, ip_preference=ip_preference)
                session.awaiting_terms = True
                session.terms_version_expected = decision.terms_version
                # Start 30s timeout
                session.terms_timeout_task = asyncio.create_task(
                    self._terms_timeout(client_pubkey, 30.0)
                )
                return

        # Normal path: create session + send offer
        session = self._get_or_create_session(client_pubkey, ip_preference=ip_preference)
        await session.setup()
        offer = await session.create_offer()
        await session.send_signaling(offer)
        log.info(f"📡 offer sent to {client_pubkey[:8]}")

    async def handle_terms_accept(self, client_pubkey: str, version: str):
        """Spec 033: Handle terms-accept DM from client."""
        session = self.peers.get(client_pubkey)
        if session is None or not getattr(session, "awaiting_terms", False):
            # No pending terms or session doesn't exist — ignore
            return

        if version != session.terms_version_expected:
            # Version mismatch → re-send challenge
            log.info(f"📄 terms version mismatch ({version} ≠ {session.terms_version_expected}), re-challenge")
            await self._send_dm(client_pubkey, {
                "type": "terms-challenge",
                "text": session.terms_text or "",
                "version": session.terms_version_expected or "",
            })
            return

        # Version matches — proceed with offer
        session.awaiting_terms = False
        if getattr(session, "terms_timeout_task", None):
            session.terms_timeout_task.cancel()
            session.terms_timeout_task = None
        log.info(f"✅ terms accepted by {client_pubkey[:8]}, proceeding with offer")

        await session.setup()
        offer = await session.create_offer()
        await session.send_signaling(offer)
        log.info(f"📡 offer sent to {client_pubkey[:8]} (after terms)")

    async def _terms_timeout(self, client_pubkey: str, timeout: float):
        """Spec 033: Terms acceptance timeout. Discards session if no accept."""
        await asyncio.sleep(timeout)
        session = self.peers.get(client_pubkey)
        if session and getattr(session, "awaiting_terms", False):
            log.info(f"⏱ terms timeout for {client_pubkey[:8]} — discarding session")
            session.awaiting_terms = False
            await session.close()

    def _policy_has_ip_rules(self) -> bool:
        """Check if the current policy has any IP-based rules (country, asn, region, client_ips)."""
        if self.policy_engine is None:
            return False
        for rule in self.policy_engine._policy.rules:
            if rule.country or rule.asn or rule.region_countries or rule.region_asns or rule.client_ips:
                return True
        return False

    async def _send_dm(self, recipient_pubkey: str, payload: dict) -> None:
        """Send a NIP-44 DM to recipient_pubkey. Used for loud-deny (spec 026).

        Mirrors PeerSession.send_signaling pattern: encrypt with daemon's
        privkey, publish via round-robin across relays.
        """
        import nip44  # imported lazily to avoid import cycles
        try:
            plaintext = json.dumps(payload)
            encrypted = nip44.encrypt(plaintext, self.privkey, recipient_pubkey)
            event = make_event(self.privkey, recipient_pubkey, encrypted)
            event_payload = json.dumps(["EVENT", event])

            n = len(self.relays)
            for attempt in range(n):
                url = self.relays[attempt % n]
                try:
                    async with self.http_session.ws_connect(url) as ws:
                        await ws.send_str(event_payload)
                        try:
                            await asyncio.wait_for(ws.receive(), timeout=2.0)
                        except asyncio.TimeoutError:
                            pass
                    return  # success on first relay
                except Exception as e:
                    log.debug(f"relay {url} publish failed: {e}")
            log.warning(f"all relays failed for loud-deny DM to {recipient_pubkey[:8]}")
        except Exception as e:
            log.warning(f"failed to send DM to {recipient_pubkey[:8]}: {e}")

    # ─── Spec 031: Relay Mode ──────────────────────────────────────────

    async def handle_relay_request(self, requester: str, target_npub: str):
        """Coordinate relay between requester and target.

        1. Store the pending request: requester → target
        2. Send relay-offer DM to target
        3. Start timeout — if target doesn't respond in 30s, notify requester
        """
        if not self.relay_mode:
            return  # Not a relay daemon — ignore

        # Normalize target to hex (strip bech32 npub1 prefix if present)
        target = target_npub
        if target.startswith("npub1"):
            try:
                from route_table import npub_to_pubkey_hex
                target = npub_to_pubkey_hex(target)
            except Exception:
                log.warning(f"relay-request: could not decode target npub {target_npub[:16]}")
                await self._send_dm(requester, {
                    "type": "relay-error",
                    "message": "invalid target npub",
                })
                return

        self.pending_requests[requester] = target
        log.info(f"🔄 relay-request from {requester[:8]} → {target[:8]}")

        await self._send_dm(target, {
            "type": "relay-offer",
            "relay": self.pubkey,
            "peer": requester,
            "sat_per_minute": self.relay_price,
        })

        # Start timeout
        asyncio.create_task(self._relay_timeout(requester, target))

    async def _relay_timeout(self, requester: str, target: str, timeout: float = 30.0):
        """If target doesn't connect within timeout, notify requester."""
        await asyncio.sleep(timeout)
        # Check if the bridge was established
        if requester in self.bridges or target in self.bridges:
            return  # Bridge active — timeout moot
        # Check if both sessions are active (might be mid-ICE)
        if requester in self.peers and target in self.peers:
            return  # Both connected, bridge should form soon
        # Timeout — clean up and notify
        self.pending_requests.pop(requester, None)
        if requester in self.peers:
            log.info(f"⏱ relay timeout: target {target[:8]} didn't respond for {requester[:8]}")
            await self._send_dm(requester, {
                "type": "relay-timeout",
                "message": f"target peer did not respond within {int(timeout)}s",
            })

    async def _check_bridge(self):
        """Check if any pending request now has both peers connected.

        Called after each new session in relay mode. Waits briefly for
        DataChannels to open, then bridges if both sides are ready.
        """
        for requester, target in list(self.pending_requests.items()):
            sa = self.peers.get(requester)
            sb = self.peers.get(target)
            if not sa or not sb:
                continue
            if sa.state != "active" or sb.state != "active":
                continue
            # Both active — wait for DataChannels to be open
            # Give a short grace period for ICE+DTLS to settle
            await asyncio.sleep(0.5)
            if sa.state != "active" or sb.state != "active":
                continue
            # Payment check (Spec 031 FR-020) — stub for now
            # When --relay-price > 0, check Breez SDK Spark stream here
            # For now, free relay mode always bridges

            await self._activate_bridge(sa, sb)
            self.pending_requests.pop(requester, None)

    async def _activate_bridge(self, sa: "PeerSession", sb: "PeerSession"):
        """Link two PeerSessions as relay partners."""
        sa.relay_partner = sb
        sb.relay_partner = sa
        self.bridges[sa.client_pubkey] = sb.client_pubkey
        self.bridges[sb.client_pubkey] = sa.client_pubkey

        log.info(f"🔗 bridge active: {sa.client_pubkey[:8]} ↔ {sb.client_pubkey[:8]}")

        # Notify both peers
        await self._send_dm(sa.client_pubkey, {
            "type": "relay-active",
            "peer": sb.client_pubkey,
            "relay": self.pubkey,
        })
        await self._send_dm(sb.client_pubkey, {
            "type": "relay-active",
            "peer": sa.client_pubkey,
            "relay": self.pubkey,
        })

    async def _teardown_bridge(self, npub: str, reason: str = "peer-disconnected"):
        """When one peer of a bridge disconnects, close the other side."""
        partner_npub = self.bridges.get(npub)
        if not partner_npub:
            return

        log.info(f"🔌 bridge teardown: {npub[:8]} ↔ {partner_npub[:8]} ({reason})")

        # Notify the surviving peer
        await self._send_dm(partner_npub, {
            "type": "relay-stop",
            "reason": reason,
        })

        # Close the partner session
        partner_session = self.peers.get(partner_npub)
        if partner_session:
            partner_session.relay_partner = None
            asyncio.create_task(partner_session.close(reason=f"bridge_{reason}"))

        # Clean up bridge mapping
        self.bridges.pop(npub, None)
        self.bridges.pop(partner_npub, None)

    async def handle_signal(self, client_pubkey: str, msg: dict):
        session = self.peers.get(client_pubkey)
        if not session:
            # BUGFIX (2026-07-18): this was Warning-level and produced ~294
            # log entries/day because clients keep sending ICE candidates
            # for sessions that already hit their idle/close timeout. This
            # is normal client behavior during teardown, not an error. Demote
            # to debug to keep the journal readable.
            log.debug(f"signal from unknown peer {client_pubkey[:8]} — session gone")
            return

        if msg.get("type") == "answer":
            await session.receive_answer(msg["sdp"])
            log.info(f"📡 answer received from {client_pubkey[:8]}")
        elif msg.get("type") == "candidate":
            await session.receive_candidate(msg["sdp"])

    async def handle_dm(self, event: dict):
        sender = event.get("pubkey", "")
        if sender == self.pubkey:
            return

        # Dedup by event id — same event may arrive via multiple relays (spec 005)
        event_id = event.get("id", "")
        if not event_id:
            return
        if event_id in self._seen_event_ids:
            return
        self._seen_event_ids.add(event_id)
        # Prune at 1000 entries (keep recent 500)
        if len(self._seen_event_ids) > 1000:
            self._seen_event_ids = set(list(self._seen_event_ids)[-500:])

        tags_p = [t for t in event.get("tags", []) if len(t) >= 2 and t[0] == "p" and t[1] == self.pubkey]
        if not tags_p:
            return

        try:
            plaintext = nip44_decrypt(event["content"], self.privkey, sender)
            msg = json.loads(plaintext)
        except Exception:
            return  # not for us, or malformed, or wrong encryption scheme

        if "peerId" in msg:
            client_ip = msg.get("client_ip")  # Spec 023 (2026-07-19 amendment) — optional
            ip_pref = msg.get("ip_preference", "both")  # Spec 034 — optional
            # Validate ip_preference
            if ip_pref not in ("ipv4", "ipv6", "both"):
                ip_pref = "both"
            log.info(
                f"← announce from {sender[:8]} (peerId={msg['peerId'][:16]}"
                + (f", client_ip={client_ip}" if client_ip else "")
                + (f", ip_preference={ip_pref}" if ip_pref != "both" else "")
                + ")"
            )
            asyncio.create_task(self.handle_announce(sender, client_ip=client_ip,
                                                     ip_preference=ip_pref))
        elif msg.get("type") == "terms-accept":
            # Spec 033: Client accepted terms
            version = msg.get("version", "")
            log.info(f"← terms-accept from {sender[:8]} (version={version})")
            asyncio.create_task(self.handle_terms_accept(sender, version))
        elif msg.get("type") == "relay-request":
            # Spec 031: Peer requests relay to another peer
            target = msg.get("target", "")
            if target:
                asyncio.create_task(self.handle_relay_request(sender, target))
            else:
                log.debug(f"relay-request from {sender[:8]} missing 'target' field")
        elif msg.get("type") in ("answer", "candidate"):
            await self.handle_signal(sender, msg)
        else:
            log.debug(f"unhandled msg type: {list(msg.keys())}")

    async def subscribe_relays(self):
        subscription_id = "peck-" + secrets.token_hex(8)
        req_filter = {"kinds": [4], "#p": [self.pubkey]}

        self.http_session = aiohttp.ClientSession()
        ws_connections = []
        relay_urls_active = []

        for url in self.relays:
            try:
                ws = await self.http_session.ws_connect(url)
                ws_connections.append(ws)
                relay_urls_active.append(url)
                await ws.send_str(json.dumps(["REQ", subscription_id, req_filter]))
                log.info(f"✓ subscribed to {url.split('//')[1][:25]}")
            except Exception as e:
                log.warning(f"failed to connect relay {url}: {e}")

        if not ws_connections:
            log.error("no relays connected, exiting")
            return

        # Per-relay last-message timestamps (used by keepalive liveness check)
        last_msg_at = {url: time.time() for url in relay_urls_active}

        async def listen(ws, url):
            async for msg in ws:
                last_msg_at[url] = time.time()
                if msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        if data[0] == "EVENT" and len(data) >= 3:
                            event = data[2]
                            if event.get("kind") == 4:
                                await self.handle_dm(event)
                    except Exception as e:
                        log.debug(f"parse error from {url}: {e}")
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    log.error(f"relay {url} error: {ws.exception()}")
                    break

        async def keepalive(url, interval=120.0, probe_timeout=5.0):
            """Per-relay keepalive (spec 013).

            Every `interval` seconds, send a tiny REQ that returns immediately,
            then wait for any response within `probe_timeout`. If nothing
            arrives, the relay is treated as dead and we reconnect.
            """
            ws_idx = relay_urls_active.index(url)

            async def _reconnect():
                """Tear down current WS (if any) and establish a fresh one."""
                old_ws = ws_connections[ws_idx] if ws_idx < len(ws_connections) else None
                if old_ws is not None:
                    try:
                        await old_ws.close()
                    except Exception:
                        pass
                try:
                    new_ws = await self.http_session.ws_connect(url)
                    await new_ws.send_str(json.dumps(["REQ", subscription_id, req_filter]))
                    ws_connections[ws_idx] = new_ws
                    last_msg_at[url] = time.time()
                    log.info(f"↻ reconnected to {url.split('//')[1][:20]}")
                    # Spawn a fresh listener for the new socket
                    asyncio.create_task(listen(new_ws, url))
                    return True
                except Exception as e:
                    log.error(f"reconnect to {url.split('//')[1][:20]} failed: {e}")
                    return False

            while True:
                await asyncio.sleep(interval)
                ws = ws_connections[ws_idx] if ws_idx < len(ws_connections) else None
                # BUGFIX (2026-07-18): previously, when ws was already closed
                # we just `continue`d forever — never reconnecting. The daemon
                # silently went deaf until manual restart. Now we reconnect.
                if ws is None or ws.closed:
                    log.warning(f"relay {url.split('//')[1][:20]} already closed — reconnecting")
                    await _reconnect()
                    continue

                probe_sub = "peck-ping-" + secrets.token_hex(4)
                probe_filter = {"kinds": [0], "limit": 0}  # always-empty result
                try:
                    await ws.send_str(json.dumps(["REQ", probe_sub, probe_filter]))
                    await ws.send_str(json.dumps(["CLOSE", probe_sub]))
                except Exception as e:
                    log.warning(f"relay {url.split('//')[1][:20]} keepalive send failed: {e}")
                    await _reconnect()
                    continue

                # Check liveness: did we get any message after the probe?
                await asyncio.sleep(probe_timeout)
                if time.time() - last_msg_at[url] > interval:
                    log.warning(f"⚡ relay {url.split('//')[1][:20]} dead — reconnecting")
                    await _reconnect()

        tasks = [asyncio.create_task(listen(ws, url)) for ws, url in zip(ws_connections, relay_urls_active)]
        # One keepalive task per relay
        tasks += [asyncio.create_task(keepalive(url)) for url in relay_urls_active]

        # Graceful shutdown: when main task is cancelled, close WS explicitly
        # before http_session.close() to avoid "Event loop is closed" errors.
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            log.info("closing relay subscriptions…")
            # Explicitly cancel listener + keepalive tasks first so they
            # unblock from their `async for msg in ws` loops. Without this,
            # gather() can hang 5-10s waiting for them to notice the cancel
            # — with many relays that blows past systemd's TimeoutStopSec.
            for task in tasks:
                if not task.done():
                    task.cancel()
            # Give them a moment to unwind, then close the sockets.
            await asyncio.gather(*[t for t in tasks if not t.done()], return_exceptions=True)
            for ws, url in zip(ws_connections, relay_urls_active):
                try:
                    await ws.close()
                except Exception:
                    pass
            # Also tear down any live WebRTC peer sessions. Each pc.close() can
            # block for the ICE disconnect timeout (10-30s), so cap each one at
            # 2s. With N peers the worst case is N*2s — for systemd's
            # TimeoutStopSec=10 that means up to ~4 concurrent peers.
            for pubkey, sess in list(self.peers.items()):
                try:
                    await asyncio.wait_for(sess.close(), timeout=2.0)
                except asyncio.TimeoutError:
                    log.warning(f"session {pubkey[:8]} close timed out after 2s — abandoning")
                except Exception:
                    pass
            raise
        finally:
            # Run a GC cycle before closing the http_session — aiohttp's
            # ClientResponse objects are collected lazily and their __del__
            # tries to use the loop, raising "Event loop is closed" if we
            # close the loop first. Forcing collection here avoids that.
            gc.collect()
            if self.http_session and not self.http_session.closed:
                await self.http_session.close()


# ─── CLI ───────────────────────────────────────────────────────────────────

def load_nsec(path: str) -> str:
    """Load a Nostr private key from a file.

    Accepts both formats:
    - Hex (64 chars, no prefix)
    - Bech32 (nsec1...)  — decoded to hex internally
    """
    with open(path) as f:
        content = f.read().strip()
    if content.startswith("nsec1"):
        return _nsec_to_hex(content)
    return content


def _nsec_to_hex(nsec: str) -> str:
    """Decode a Nostr nsec (Bech32m) to a 32-byte hex string."""
    if nsec.count("1") < 1:
        raise ValueError(f"invalid nsec: no separator: {nsec[:20]}…")
    hrp, _, data_part = nsec.rpartition("1")
    if hrp != "nsec":
        raise ValueError(f"invalid nsec hrp: {hrp!r} (expected 'nsec')")
    # Reuse bech32 decoder from policy.py
    from policy import _BECH32_CHARSET, _bech32_verify_checksum, _convertbits
    data = [_BECH32_CHARSET.find(c) for c in data_part]
    if any(d < 0 for d in data):
        raise ValueError(f"invalid character in nsec: {nsec[:20]}…")
    if not _bech32_verify_checksum(hrp, data):
        raise ValueError(f"invalid nsec checksum: {nsec[:20]}…")
    decoded = _convertbits(data[:-6], 5, 8, False)
    if len(decoded) != 32:
        raise ValueError(f"nsec decoded to {len(decoded)} bytes, expected 32")
    return bytes(decoded).hex()


def parse_args():
    p = argparse.ArgumentParser(description="peck Python daemon")
    p.add_argument("--nsec-file", required=True)
    p.add_argument("--relays", required=True, help="comma-separated relay URLs")
    p.add_argument("--wg-ips", required=True, help="comma-separated WG interface IPs")
    p.add_argument("--wg-ip6s", default=None,
                   help="comma-separated WG IPv6 interface IPs (optional, enables IPv6 ICE candidates)")
    # Backwards-compatible port mapping (legacy mode)
    p.add_argument("--ports", default=None,
                   help="80:http://backend:8081,... (legacy — single backend per port)")
    # Spec 024: Multi-Level Subdomain Routing
    p.add_argument("--backends", default=None,
                   help="path to YAML/JSON route-table file (spec 024 — multi-backend)")
    p.add_argument("--domain-suffix", default="localhost",
                   help="domain suffix for Host-header parsing (default: localhost)")
    p.add_argument("--context-alias", default=None,
                   help="alias for this daemon's context-root (default: derived from npub)")
    # Spec 029: Path-Prefix Multi-Port
    p.add_argument("--ports-config", default=None,
                   help="path to YAML/JSON ports config (spec 029). Replaces --ports for "
                        "multi-backend setups. Schema: {default_port: 9090, ports: {80: url, 9090: url}}")
    # Lifecycle (spec 021, FR-015/FR-016)
    p.add_argument("--idle-timeout", type=float, default=None,
                   help="session idle timeout in seconds (default 1200 = 20 min; "
                        "env PECK_IDLE_TIMEOUT; range 900-1800)")
    p.add_argument("--connect-timeout", type=float, default=None,
                   help="WebRTC connect timeout in seconds (default 15; "
                        "env PECK_CONNECT_TIMEOUT)")
    # Spec 026: Access Control
    p.add_argument("--policy-file", default=None,
                   help="path to YAML access-control policy (spec 026). "
                        "If omitted, daemon runs default-allow (backwards compat).")
    p.add_argument("--audit-log", default=None,
                   help="path to JSON-Lines audit log for deny/loud-deny decisions (spec 026). "
                        "Optional. Pubkeys/IPs are hashed by default.")
    p.add_argument("--audit-log-plaintext", action="store_true",
                   help="write plaintext pubkeys/IPs to audit log (NOT recommended; default: hashed)")
    # Spec 033: Region Blocking & Terms
    p.add_argument("--geoip-db", default=None,
                   help="path to MaxMind GeoLite2 Country .mmdb file (spec 033). "
                        "Required for region/country/asn rules to match.")
    # Spec 031: Relay Mode
    p.add_argument("--relay-mode", action="store_true",
                   help="run as relay daemon (spec 031). Bridges two peers whose "
                        "hole-punching failed. No local HTTP backend needed.")
    p.add_argument("--relay-price", type=int, default=0,
                   help="streaming payment rate in sat/min (spec 031). 0 = free relay. "
                        "When > 0, the relay checks for an active Breez SDK Spark payment "
                        "stream before activating the bridge.")
    return p.parse_args()


async def main():
    args = parse_args()
    privkey = load_nsec(args.nsec_file)
    relays = [r.strip() for r in args.relays.split(",")]
    wg_ips = [ip.strip() for ip in args.wg_ips.split(",")]
    wg_ip6s = None
    if args.wg_ip6s:
        wg_ip6s = [ip.strip() for ip in args.wg_ip6s.split(",")]

    # ─── Build the route table (Spec 024) ─────────────────────────────
    # Precedence: --backends > --ports-config > --ports (backwards compat).
    # Exactly one is required.
    route_table: Optional[RouteTable] = None
    port_mappings: dict = {}
    ports_map: Optional[PortsMap] = None

    # Derive the daemon's context-root: alias if given, else the daemon's npub.
    daemon_pubkey_hex = get_pubkey(privkey)
    context_root = args.context_alias
    if context_root is None:
        # Default context-root: the daemon's npub1… (Bech32m-encoded pubkey)
        context_root = pubkey_hex_to_npub(daemon_pubkey_hex)

    if args.backends:
        if args.ports:
            log.warning("--backends overrides --ports (both given, using --backends)")
        # Load route table from YAML/JSON file
        if args.backends.endswith(".json"):
            with open(args.backends) as f:
                config = json.load(f)
            route_table = RouteTable.from_dict(
                config, context_root=context_root, domain_suffix=args.domain_suffix,
            )
        else:
            route_table = RouteTable.from_yaml(
                args.backends, context_root=context_root, domain_suffix=args.domain_suffix,
            )
        log.info(f"  context_root: {context_root}")
        log.info(f"  domain_suffix: {args.domain_suffix}")
    elif args.ports_config:
        # Spec 029: Path-Prefix Multi-Port — YAML/JSON ports config
        try:
            ports_map_loaded = load_ports_config(args.ports_config)
        except (PortsConfigError, FileNotFoundError) as e:
            log.error(f"failed to load ports config from {args.ports_config}: {e}")
            return
        # Populate port_mappings from ports_map for backwards compat
        port_mappings = dict(ports_map_loaded.ports)
        ports_map = ports_map_loaded
        log.info(f"  ports config loaded: {len(ports_map_loaded)} ports, "
                 f"default={ports_map_loaded.default_port}")
    elif args.ports:
        # Legacy mode: build port_map from --ports string
        for mapping in args.ports.split(","):
            port_str, url = mapping.split(":", 1)
            port_mappings[int(port_str)] = url
        # Spec 029: auto-wrap legacy port_map into PortsMap so path-prefix
        # parsing kicks in. First port becomes default.
        try:
            ports_map = from_ports_legacy(port_mappings)
        except PortsConfigError as e:
            log.error(f"invalid --ports config: {e}")
            return
    elif not args.relay_mode:
        log.error("either --backends, --ports-config, --ports, or --relay-mode must be specified")
        return

    # Spec 031: In relay mode, no backend config needed
    if args.relay_mode and not (route_table or ports_map or port_mappings):
        log.info("  relay mode: no HTTP backend configured (bridging only)")

    # Lifecycle config: CLI takes precedence, then env, then default
    default_idle = 1200.0
    default_connect = 15.0
    idle_timeout = args.idle_timeout
    if idle_timeout is None:
        env_idle = os.environ.get("PECK_IDLE_TIMEOUT")
        if env_idle:
            try:
                idle_timeout = float(env_idle)
            except ValueError:
                log.warning(f"invalid PECK_IDLE_TIMEOUT={env_idle!r}, using default {default_idle}s")
                idle_timeout = default_idle
        else:
            idle_timeout = default_idle
    # Clamp idle timeout to spec range (900-1800 s = 15-30 min)
    if idle_timeout < 900 or idle_timeout > 1800:
        log.warning(f"idle_timeout={idle_timeout}s out of spec range (900-1800), clamping")
        idle_timeout = max(900.0, min(1800.0, idle_timeout))

    connect_timeout = args.connect_timeout
    if connect_timeout is None:
        env_connect = os.environ.get("PECK_CONNECT_TIMEOUT")
        if env_connect:
            try:
                connect_timeout = float(env_connect)
            except ValueError:
                connect_timeout = default_connect
        else:
            connect_timeout = default_connect

    # Spec 026: Access Control — load policy engine if --policy-file given
    # Spec 033: GeoIP lookup wired into PolicyEngine
    policy_engine = None
    geoip_lookup_fn = None

    # Spec 033: GeoIP2 database (optional, lazy import)
    if args.geoip_db:
        try:
            import geoip2.database
            reader = geoip2.database.Reader(args.geoip_db)
            def geoip_lookup_fn(ip: str) -> dict:
                try:
                    resp = reader.country(ip)
                    return {"country": resp.country.iso_code}
                except Exception:
                    return {}
            log.info(f"GeoIP database loaded from {args.geoip_db}")
        except ImportError:
            log.error("geoip2 library not installed — run: pip install geoip2")
            log.error("region/country/asn rules will NOT match (no GeoIP lookup)")
            geoip_lookup_fn = None
        except Exception as e:
            log.error(f"failed to load GeoIP database from {args.geoip_db}: {e}")
            geoip_lookup_fn = None
    elif args.policy_file:
        log.warning("policy file given but no --geoip-db — region/country/asn rules will NOT match")

    if args.policy_file:
        from policy import PolicyEngine, AuditLogger
        audit_logger = None
        if args.audit_log:
            audit_logger = AuditLogger(
                args.audit_log,
                plaintext=args.audit_log_plaintext,
            )
        try:
            policy_engine = PolicyEngine.from_path(
                args.policy_file,
                audit_logger=audit_logger,
                geoip_lookup=geoip_lookup_fn,
            )
            log.info(f"policy engine active: {policy_engine.rule_count} rules, default={policy_engine.default_effect}")
            # Spec 033: mark GeoIP as active for ICE second filter
            if geoip_lookup_fn:
                policy_engine.geoip_lookup = geoip_lookup_fn  # already passed, but be explicit
        except Exception as e:
            log.error(f"failed to load policy from {args.policy_file}: {e}")
            log.error("daemon refusing to start with invalid policy (fail-closed)")
            return
    elif args.audit_log:
        log.warning("--audit-log given without --policy-file — audit log will not be written (no policy engine)")

    daemon = PeckDaemon(
        privkey_hex=privkey,
        relays=relays,
        wg_ips=wg_ips,
        port_mappings=port_mappings,
        route_table=route_table,
        idle_timeout=idle_timeout,
        connect_timeout=connect_timeout,
        policy_engine=policy_engine,
        ports_map=ports_map,
        relay_mode=args.relay_mode,
        relay_price=args.relay_price,
        wg_ip6s=wg_ip6s,
    )
    # Spec 026: stash daemon instance so SIGHUP handler can reach policy engine
    _DAEMON_INSTANCE["daemon"] = daemon
    # Spec 033: set geoip_active flag after daemon creation
    if geoip_lookup_fn:
        daemon.geoip_active = True
    await daemon.subscribe_relays()


if __name__ == "__main__":
    import signal

    async def _runner():
        main_task = asyncio.current_task()

        def _shutdown():
            log.info("received shutdown signal — cancelling main task")
            if main_task and not main_task.done():
                main_task.cancel()

        # loop.add_signal_handler() schedules the callback on the loop thread,
        # which is the correct asyncio pattern. signal.signal() runs in the
        # main thread but the cancellation doesn't reach blocked awaits
        # reliably because of how Python interlaces signal handling with
        # asyncio's internals — manifests as shutdown hangs.
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _shutdown)
            except (NotImplementedError, RuntimeError):
                # Windows doesn't implement add_signal_handler — fall back.
                signal.signal(sig, lambda *_: _shutdown())

        # Spec 026 / Spec 029: SIGHUP triggers policy + ports hot-reload.
        # The daemon instance is stashed in a module-global so the SIGHUP
        # handler can reach both subsystems.
        def _sighup_handler():
            log.info("received SIGHUP — reloading policy + ports")
            d = _DAEMON_INSTANCE.get("daemon")
            if d is None:
                log.info("no daemon instance — SIGHUP no-op")
                return
            # Spec 026: policy reload
            if getattr(d, "policy_engine", None) is not None:
                try:
                    d.policy_engine.reload()
                except Exception as e:
                    log.warning(f"policy reload failed: {e}")
            else:
                log.info("no policy engine configured")
            # Spec 029: ports_map reload
            if getattr(d, "ports_map", None) is not None:
                try:
                    new_pm = d.ports_map.reload()
                    d.ports_map = new_pm
                    log.info(f"ports reloaded: {len(new_pm)} ports, default={new_pm.default_port}")
                except Exception as e:
                    log.warning(f"ports reload failed (keeping old config): {e}")
            else:
                log.info("no ports_map configured")

        try:
            loop.add_signal_handler(signal.SIGHUP, _sighup_handler)
        except (NotImplementedError, RuntimeError, AttributeError):
            # Some platforms don't have SIGHUP (Windows) — skip silently.
            pass

        try:
            await main()
        except asyncio.CancelledError:
            log.info("shutdown complete")
            raise

    try:
        asyncio.run(_runner())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
