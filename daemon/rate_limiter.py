"""
peck Rate Limiter — Spec 038 (SEC-3 DoS Prevention).

In-memory rate limiting for announce DMs and concurrent PeerSessions.
No persistence across restarts. All state is kept in dicts with TTL-based pruning.
"""

import logging
import time
from dataclasses import dataclass

log = logging.getLogger("peck.ratelimit")


@dataclass
class RateLimitConfig:
    """Rate limit configuration. 0 means unlimited for that dimension."""
    max_announces_per_npub: int = 3
    max_sessions_per_npub: int = 1
    max_sessions: int = 10
    max_announces_global: int = 20
    window_seconds: float = 60.0
    cooldown_seconds: float = 300.0


class RateLimiter:
    """In-memory rate limiter. Thread-unsafe — single asyncio event loop only."""

    def __init__(self, config: RateLimitConfig = None):
        self.config = config or RateLimitConfig()
        # npub → [timestamps of recent announces]
        self._announce_times: dict[str, list[float]] = {}
        # npub → active session count
        self._active_sessions: dict[str, int] = {}
        # Global announce timestamps
        self._global_announce_times: list[float] = []
        # Global active session count
        self._global_session_count: int = 0

    def reload(self, config: RateLimitConfig):
        """Hot-reload config without resetting existing state (Spec 038 FR-012)."""
        self.config = config
        log.info(f"rate limits reloaded: {config}")

    def check_announce(self, npub: str) -> bool:
        """Return True if announce is allowed, False if rate-limited."""
        now = time.time()
        window = self.config.window_seconds

        # Per-npub check
        c = self.config
        if c.max_announces_per_npub > 0:
            times = self._prune(self._announce_times.get(npub, []), now, window)
            if len(times) >= c.max_announces_per_npub:
                log.warning(
                    f"⚠ rate limit: npub {npub[:8]} exceeded announce limit "
                    f"({len(times)}/{int(c.max_announces_per_npub)} per {int(window)}s)"
                )
                return False

        # Global check
        if c.max_announces_global > 0:
            global_times = self._prune(self._global_announce_times, now, window)
            if len(global_times) >= c.max_announces_global:
                log.warning(
                    f"⚠ rate limit: global announce limit reached "
                    f"({len(global_times)}/{int(c.max_announces_global)} per {int(window)}s)"
                )
                return False

        # Allowed — record
        if c.max_announces_per_npub > 0:
            times = self._prune(self._announce_times.get(npub, []), now, window)
            times.append(now)
            self._announce_times[npub] = times

        if c.max_announces_global > 0:
            global_times = self._prune(self._global_announce_times, now, window)
            global_times.append(now)
            self._global_announce_times = global_times

        return True

    def check_session(self, npub: str) -> bool:
        """Return True if a new session is allowed, False if limit reached."""
        c = self.config

        if c.max_sessions_per_npub > 0:
            per_npub = self._active_sessions.get(npub, 0)
            if per_npub >= c.max_sessions_per_npub:
                # Spec 038 FR-009: old session will be replaced, allow it
                # by not blocking here — the replacement happens in _get_or_create_session
                pass  # We allow replacement, checked at announce level via rate limit

        if c.max_sessions > 0:
            if self._global_session_count >= c.max_sessions:
                log.warning(
                    f"⚠ rate limit: global session limit reached "
                    f"({self._global_session_count}/{int(c.max_sessions)})"
                )
                return False

        return True

    def on_session_open(self, npub: str):
        self._active_sessions[npub] = self._active_sessions.get(npub, 0) + 1
        self._global_session_count += 1

    def on_session_close(self, npub: str):
        self._active_sessions[npub] = max(0, self._active_sessions.get(npub, 0) - 1)
        self._global_session_count = max(0, self._global_session_count - 1)
        # Clean up zero-count entries
        if self._active_sessions.get(npub, 0) == 0:
            self._active_sessions.pop(npub, None)

    def cleanup(self):
        """Remove stale entries older than cooldown_seconds. Call periodically."""
        now = time.time()
        cutoff = now - self.config.cooldown_seconds

        stale = [npub for npub, times in self._announce_times.items()
                 if not times or max(times) < cutoff]
        for npub in stale:
            del self._announce_times[npub]

        if self._announce_times:
            log.debug(f"rate limiter cleanup: {len(stale)} stale npubs removed, "
                      f"{len(self._announce_times)} tracked")

    @staticmethod
    def _prune(times: list, now: float, window: float) -> list:
        """Keep only timestamps within the window."""
        return [t for t in times if now - t < window]
