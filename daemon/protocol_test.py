"""
peck protocol test suite — binary frames + HTTP parsing/composition.

Run: python protocol_test.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from protocol import (
    MSG_OPEN, MSG_DATA, MSG_CLOSE, MSG_RST,
    HEADER_SIZE,
    encode_frame, decode_frame,
    parse_http_request, compose_http_response,
    NOT_FOUND_RESPONSE, BAD_REQUEST_RESPONSE,
)

PASS = 0
FAIL = 0

def check(condition, label):
    global PASS, FAIL
    if condition:
        PASS += 1
    else:
        FAIL += 1
        print(f"  ✗ {label}")


# ─── encode_frame / decode_frame roundtrip ─────────────────────────────────

def test_frame_roundtrip():
    print("── frame roundtrip ──")
    for stream_id in [0, 1, 65535]:
        for port in [0, 80, 443, 65535]:
            for msg_type in [MSG_OPEN, MSG_DATA, MSG_CLOSE, MSG_RST]:
                payload = b"hello" if msg_type == MSG_DATA else b""
                frame = encode_frame(stream_id, port, msg_type, payload)
                sid, p, t, pl = decode_frame(frame)
                check(sid == stream_id, f"stream_id mismatch: {sid} != {stream_id}")
                check(p == port, f"port mismatch: {p} != {port}")
                check(t == msg_type, f"type mismatch: {t} != {msg_type}")
                check(pl == payload, f"payload mismatch: {pl} != {payload}")


def test_frame_empty_payload():
    print("── frame empty payload ──")
    frame = encode_frame(42, 8080, MSG_OPEN)
    sid, port, t, payload = decode_frame(frame)
    check(sid == 42, "stream_id")
    check(port == 8080, "port")
    check(t == MSG_OPEN, "type")
    check(payload == b"", "empty payload")


def test_frame_large_payload():
    print("── frame large payload ──")
    big = b"x" * 65536
    frame = encode_frame(1, 80, MSG_DATA, big)
    sid, port, t, payload = decode_frame(frame)
    check(payload == big, "large payload roundtrip")
    check(len(payload) == 65536, f"large payload size: {len(payload)}")


def test_frame_too_short():
    print("── frame too short ──")
    try:
        decode_frame(b"\x00\x01")
        check(False, "should raise ValueError")
    except ValueError:
        check(True, "correctly raised")


# ─── parse_http_request ────────────────────────────────────────────────────

def test_parse_simple_get():
    print("── parse HTTP GET ──")
    raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    req = parse_http_request(raw)
    check(req["method"] == "GET", f"method: {req['method']}")
    check(req["path"] == "/", f"path: {req['path']}")
    check(req["headers"].get("Host") == "example.com", f"Host: {req['headers'].get('Host')}")
    check(req["body"] is None, f"body: {req['body']}")


def test_parse_post_with_body():
    print("── parse HTTP POST ──")
    raw = b"POST /api/submit HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"key\": \"val\"}"
    req = parse_http_request(raw)
    check(req["method"] == "POST", "method")
    check(req["path"] == "/api/submit", "path")
    check(req["body"] == b'{"key": "val"}', f"body: {req['body']}")


def test_parse_query_string():
    print("── parse query string ──")
    raw = b"GET /search?q=hello&p=world HTTP/1.1\r\nHost: x\r\n\r\n"
    req = parse_http_request(raw)
    check(req["path"] == "/search?q=hello&p=world", f"path with query: {req['path']}")


def test_parse_empty_request():
    print("── parse empty request ──")
    req = parse_http_request(b"")
    check(req["method"] == "GET", "default method")
    check(req["path"] == "/", "default path")


def test_parse_multiple_headers():
    print("── parse multiple headers ──")
    raw = b"GET / HTTP/1.1\r\nHost: a.com\r\nAccept: text/html\r\nX-Custom: value123\r\n\r\n"
    req = parse_http_request(raw)
    check(len(req["headers"]) == 3, f"header count: {len(req['headers'])}")
    check(req["headers"].get("X-Custom") == "value123", "custom header")


def test_parse_headers_case_sensitive():
    print("── parse header casing ──")
    raw = b"GET / HTTP/1.1\r\nHost: a.com\r\n\r\n"
    req = parse_http_request(raw)
    check(req["headers"].get("Host") == "a.com", "exact case key")
    # Note: parser preserves original case, caller handles case-insensitive lookup


# ─── compose_http_response ─────────────────────────────────────────────────

def test_compose_simple_response():
    print("── compose HTTP response ──")
    body = b"Hello World"
    resp = compose_http_response(200, {"Content-Type": "text/plain"}, body)
    check(b"HTTP/1.1 200 OK" in resp, "status line")
    check(b"Content-Length: 11" in resp, "content-length")
    check(b"Content-Type: text/plain" in resp, "content-type header")
    check(resp.endswith(body), "body at end")


def test_compose_empty_body():
    print("── compose empty body ──")
    resp = compose_http_response(204, {}, b"")
    check(b"HTTP/1.1 204 No Content" in resp, "204 status")
    check(b"Content-Length: 0" in resp, "zero content-length")


def test_compose_strips_transfer_encoding():
    print("── compose strips Transfer-Encoding ──")
    body = b"x" * 100
    resp = compose_http_response(200, {"Transfer-Encoding": "chunked", "Content-Type": "text/html"}, body)
    check(b"Transfer-Encoding" not in resp, "Transfer-Encoding stripped")
    check(b"Content-Length: 100" in resp, "Content-Length added")
    check(b"Content-Type: text/html" in resp, "Content-Type preserved")


def test_compose_adds_content_length_if_missing():
    print("── compose adds Content-Length ──")
    body = b"data"
    resp = compose_http_response(200, {"Content-Type": "text/plain"}, body)
    check(b"Content-Length: 4" in resp, "auto Content-Length")


def test_compose_doesnt_double_content_length():
    print("── compose respects existing Content-Length ──")
    body = b"hello"
    resp = compose_http_response(200, {"Content-Length": "5"}, body)
    # Should only have one Content-Length
    count = resp.count(b"Content-Length:")
    check(count == 1, f"only one Content-Length: found {count}")


# ─── Constant-size error responses ─────────────────────────────────────────

def test_constant_error_responses():
    print("── constant error responses ──")
    check(b"404 Not Found" in NOT_FOUND_RESPONSE, "404 body")
    check(b"400 Bad Request" in BAD_REQUEST_RESPONSE, "400 body")
    check(NOT_FOUND_RESPONSE != BAD_REQUEST_RESPONSE, "different responses")
    # Verify deterministic — same output each time
    from protocol import _404_BODY, _404_HEADERS
    expected = compose_http_response(404, _404_HEADERS, _404_BODY)
    check(NOT_FOUND_RESPONSE == expected, "404 is deterministic")


if __name__ == "__main__":
    print()
    test_frame_roundtrip()
    test_frame_empty_payload()
    test_frame_large_payload()
    test_frame_too_short()
    test_parse_simple_get()
    test_parse_post_with_body()
    test_parse_query_string()
    test_parse_empty_request()
    test_parse_multiple_headers()
    test_parse_headers_case_sensitive()
    test_compose_simple_response()
    test_compose_empty_body()
    test_compose_strips_transfer_encoding()
    test_compose_adds_content_length_if_missing()
    test_compose_doesnt_double_content_length()
    test_constant_error_responses()

    print(f"\n{'='*40}")
    print(f"protocol tests: {PASS} passed, {FAIL} failed")
    if FAIL > 0:
        sys.exit(1)
    print("All tests passed ✅")
