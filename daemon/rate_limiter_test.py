"""
peck rate limiter test suite — Spec 038 (SEC-3 DoS Prevention).

Run: python rate_limiter_test.py
"""
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rate_limiter import RateLimiter, RateLimitConfig

PASS = 0
FAIL = 0

def check(condition, label):
    global PASS, FAIL
    if condition:
        PASS += 1
    else:
        FAIL += 1
        print(f"  ✗ {label}")


def test_per_npub_announce_limit():
    print("── per-npub announce limit ──")
    config = RateLimitConfig(max_announces_per_npub=3, window_seconds=60, max_announces_global=0)
    rl = RateLimiter(config)
    npub = "a" * 64

    results = [rl.check_announce(npub) for _ in range(5)]
    check(results == [True, True, True, False, False],
          f"3 allowed, 2 blocked: {results}")


def test_global_announce_limit():
    print("── global announce limit ──")
    config = RateLimitConfig(max_announces_per_npub=100, max_announces_global=2, window_seconds=60)
    rl = RateLimiter(config)
    results = [rl.check_announce(f"npub{i:062d}") for i in range(4)]
    check(results == [True, True, False, False],
          f"2 allowed, 2 blocked: {results}")


def test_unlimited_when_zero():
    print("── unlimited when 0 ──")
    config = RateLimitConfig(max_announces_per_npub=0, max_announces_global=0)
    rl = RateLimiter(config)
    npub = "a" * 64
    results = [rl.check_announce(npub) for _ in range(20)]
    check(all(results), "all allowed when 0 = unlimited")


def test_session_tracking():
    print("── session tracking ──")
    config = RateLimitConfig(max_sessions=2, max_sessions_per_npub=1)
    rl = RateLimiter(config)

    check(rl.check_session("a"), "session 1 allowed")
    rl.on_session_open("a")
    check(rl.check_session("b"), "session 2 allowed")
    rl.on_session_open("b")
    check(not rl.check_session("c"), "session 3 blocked (global cap)")
    rl.on_session_close("a")
    check(rl.check_session("c"), "session 3 allowed after close")


def test_session_close_cleanup():
    print("── session close cleanup ──")
    config = RateLimitConfig(max_sessions_per_npub=5)
    rl = RateLimiter(config)
    rl.on_session_open("x")
    rl.on_session_open("x")
    check(rl._active_sessions.get("x") == 2, "count=2")
    rl.on_session_close("x")
    check(rl._active_sessions.get("x") == 1, "count=1 after close")
    rl.on_session_close("x")
    check("x" not in rl._active_sessions, "entry removed at 0")


def test_session_close_never_negative():
    print("── session close never negative ──")
    rl = RateLimiter(RateLimitConfig())
    rl.on_session_close("never-opened")
    check(rl._global_session_count == 0, "count stays 0")
    check(rl._active_sessions.get("never-opened", 0) == 0, "no negative count")


def test_window_expiry():
    print("── window expiry ──")
    config = RateLimitConfig(max_announces_per_npub=2, window_seconds=0.3)
    rl = RateLimiter(config)
    npub = "x" * 64

    check(rl.check_announce(npub), "1st allowed")
    check(rl.check_announce(npub), "2nd allowed")
    check(not rl.check_announce(npub), "3rd blocked")
    time.sleep(0.35)
    check(rl.check_announce(npub), "4th allowed after window expiry")


def test_different_npubs_independent():
    print("── different npubs independent ──")
    config = RateLimitConfig(max_announces_per_npub=1, window_seconds=60, max_announces_global=0)
    rl = RateLimiter(config)

    check(rl.check_announce("a" * 64), "npub A 1st allowed")
    check(rl.check_announce("b" * 64), "npub B 1st allowed (different npub)")
    check(not rl.check_announce("a" * 64), "npub A 2nd blocked")
    check(not rl.check_announce("b" * 64), "npub B 2nd blocked")


def test_cleanup_removes_stale():
    print("── cleanup removes stale entries ──")
    config = RateLimitConfig(cooldown_seconds=0.1, max_announces_per_npub=5)
    rl = RateLimiter(config)
    rl.check_announce("stale" + "x" * 59)
    check(len(rl._announce_times) == 1, "entry exists")
    time.sleep(0.15)
    rl.cleanup()
    check(len(rl._announce_times) == 0, "stale entry removed")


def test_reload_config():
    print("── reload config ──")
    rl = RateLimiter(RateLimitConfig(max_announces_per_npub=3))
    rl.check_announce("a" * 64)
    rl.reload(RateLimitConfig(max_announces_per_npub=1))
    check(not rl.check_announce("a" * 64), "blocked after reload to 1 (already had 1)")


if __name__ == "__main__":
    print()
    test_per_npub_announce_limit()
    test_global_announce_limit()
    test_unlimited_when_zero()
    test_session_tracking()
    test_session_close_cleanup()
    test_session_close_never_negative()
    test_window_expiry()
    test_different_npubs_independent()
    test_cleanup_removes_stale()
    test_reload_config()

    print(f"\n{'='*40}")
    print(f"rate limiter tests: {PASS} passed, {FAIL} failed")
    if FAIL > 0:
        sys.exit(1)
    print("All tests passed ✅")
