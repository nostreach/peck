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
