"""
peck binary stream protocol + HTTP parsing/composition helpers.

Extracted from daemon.py — pure protocol logic with no class dependencies.

Binary frame format (mirror of src/protocol.js):
    [StreamID:2][Port:2][Type:1][Payload:var]  (big-endian)
    Types: OPEN=0, DATA=1, CLOSE=2, RST=3

HTTP/1.1 requests/responses are carried as raw bytes in DATA frames.
"""

import struct

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


# ─── Response header sanitizer (Spec 044) ───────────────────────────────────
#
# Hard-coded by design (NOT configurable): hop-by-hop stripping is an RFC
# 7230 §6.1 proxy obligation, and the topology list is the privacy invariant
# itself — a config switch would be a switch to break it. Site-fingerprint
# headers (Server, X-Powered-By, X-Runtime) are deliberately PASSED THROUGH:
# they describe the site, not the tunnel infrastructure, and would be equally
# visible under direct hosting. An additive per-port strip list may be added
# later if a real backend ever needs it (see Spec 044).

# RFC 7230 §6.1: end-to-end vs hop-by-hop — a proxy MUST NOT forward these.
HOP_BY_HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "upgrade",
})

# Headers that disclose internal topology behind the backend (set by reverse
# proxies, load balancers, or framework internals) — removed before the
# response enters the tunnel.
TOPOLOGY_HEADERS = frozenset({
    "via", "forwarded",
    "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
    "x-forwarded-port", "x-forwarded-server", "x-forwarded-path",
    "x-real-ip", "x-client-ip", "x-client-port",
    "x-served-by", "x-backend-server", "x-upstream-address",
    "x-upstream-server", "x-upstream-status", "x-upstream-response-time",
    "x-aspnet-version", "x-aspnetmvc-version",
})

_STRIP_RESPONSE_HEADERS = HOP_BY_HOP_HEADERS | TOPOLOGY_HEADERS


def sanitize_response_headers(headers) -> list:
    """Filter backend response headers for forwarding to the client.

    Removes hop-by-hop headers (RFC 7230 §6.1) and internal-topology
    headers (Spec 044). Accepts a mapping or a (key, value) pair list —
    duplicate response headers (e.g. multiple Set-Cookie) survive as
    separate pairs, which dict-comprehension forwarding used to collapse.
    Transfer-Encoding is also dropped here (compose_http_response
    re-adds Content-Length for the de-chunked body).

    Returns a list of (key, value) tuples.
    """
    if hasattr(headers, "items"):
        pairs = list(headers.items())
    else:
        pairs = [(k, v) for k, v in headers]

    filtered = []
    for key, value in pairs:
        if key.lower() in _STRIP_RESPONSE_HEADERS:
            continue
        if key.lower() == "transfer-encoding":
            continue
        filtered.append((key, value))
    return filtered


def compose_http_response(status: int, headers, body: bytes) -> bytes:
    """Compose a raw HTTP/1.1 response.

    Normalisation: if the backend used `Transfer-Encoding: chunked`, we have
    already de-chunked the body into `body`. We must strip the chunked header
    (otherwise the client receives both Transfer-Encoding AND Content-Length,
    which is HTTP/1.1-illegal and causes the client to misparse the body —
    manifests as broken image/SVG blobs with naturalWidth=0).
    """
    status_text = STATUS_TEXTS.get(status, "OK")
    head = f"HTTP/1.1 {status} {status_text}\r\n"

    # Spec 044: accept mappings (back-compat) or (key, value) pair lists
    # (preserves duplicate response headers like multiple Set-Cookie).
    if hasattr(headers, "items"):
        header_pairs = list(headers.items())
    else:
        header_pairs = [(k, v) for k, v in headers]

    seen = set()
    for key, value in header_pairs:
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


# ─── 502 Bad Gateway (backend unreachable) ─────────────────────────────────

# Static HTML — the daemon may serve this when the tunnel is up but the
# configured backend is down. No details about the backend (address/port)
# are included: the client only learns that an upstream failure occurred.
_502_BODY = b"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>502 \xe2\x80\x94 Backend unreachable</title>
<style>
  :root { color-scheme: dark; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center;
    justify-content: center; background: #0d1117; color: #c9d1d9;
    font: 16px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif;
    text-align: center; padding: 24px;
  }
  .box { max-width: 32rem; }
  h1 { font-size: 3rem; margin: 0 0 .5rem; color: #f85149; }
  p { margin: .5rem 0; color: #8b949e; }
  code {
    background: #161b22; border: 1px solid #30363d; border-radius: 6px;
    padding: .15rem .4rem; font-size: .9em; color: #79c0ff;
  }
  .hint { margin-top: 1.5rem; font-size: .9rem; }
</style>
</head>
<body>
  <div class="box">
    <h1>502</h1>
    <p><strong>The tunnel is working,</strong> but the service behind it
       did not respond.</p>
    <p class="hint">This is a temporary problem on the operator's side
       &mdash; nothing is wrong with your connection. Please try again later.</p>
  </div>
</body>
</html>
"""
_502_HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": str(len(_502_BODY)),
    "Cache-Control": "no-store",
    "Connection": "close",
}
BAD_GATEWAY_RESPONSE = compose_http_response(502, _502_HEADERS, _502_BODY)
