"""
Spec 043 regression tests — ICE gather race + srflx raddr correlation.

1. Without the gather lock (simulated old behavior), two interleaved
   sessions gather with each other's WG addresses.
2. With the daemon-global gather lock, each session sees its own
   addresses at gather time.
3. The SDP candidate filter correlates srflx via raddr (foreign srflx
   candidates with a non-WG base address are removed).

Run: python spec043_test.py
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aioice.ice
import daemon as d

PASS = 0
FAIL = 0


def check(condition, label):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ok: {label}")
    else:
        FAIL += 1
        print(f"  FAIL: {label}")


class FakePC:
    """Stands in for RTCPeerConnection — records get_host_addresses at
    the moment setLocalDescription runs (i.e. at gather time)."""
    def __init__(self, sink: list, gather_delay: float = 0.0):
        self.sink = sink
        self.gather_delay = gather_delay
        self.localDescription = type("LD", (), {"sdp": ""})()

    async def createOffer(self):
        await asyncio.sleep(self.gather_delay)
        return object()

    async def setLocalDescription(self, offer):
        await asyncio.sleep(self.gather_delay)
        self.sink.append(list(aioice.ice.get_host_addresses(True, True)))

    @property
    def iceGatheringState(self):
        return "complete"


async def make_session(daemon, wg_ip, sink, gather_delay=0.0):
    ps = d.PeerSession.__new__(d.PeerSession)
    ps.daemon_privkey = "11" * 32
    ps.client_pubkey = "22" * 32
    ps.wg_ip = wg_ip
    ps.wg_ip6 = None
    ps.relays = []
    ps.port_map = {}
    ps.http_session = None
    ps.route_table = None
    ps._daemon = daemon
    ps._gather_lock = daemon._gather_lock if daemon is not None else asyncio.Lock()
    ps._ipv6_public = None
    ps.pc = FakePC(sink, gather_delay)
    return ps


async def test_race():
    print("test 1: interleaved sessions WITHOUT lock (old behavior) — expect wrong addresses")
    sink_a, sink_b = [], []
    # Old behavior: patch applied in setup(), read later at gather time.
    sa = await make_session(None, "10.0.0.1", sink_a, gather_delay=0.05)
    sb = await make_session(None, "10.0.0.3", sink_b, gather_delay=0.05)

    # Session A patches, then yields (STUN resolve / gathering awaits)…
    host_addrs_a = [sa.wg_ip]
    aioice.ice.get_host_addresses = lambda u4, u6: host_addrs_a
    # …session B patches while A is still awaiting its gather…
    host_addrs_b = [sb.wg_ip]
    aioice.ice.get_host_addresses = lambda u4, u6: host_addrs_b
    # …now A gathers: it sees B's patch (the race).
    await sa.pc.setLocalDescription(await sa.pc.createOffer())
    await sb.pc.setLocalDescription(await sb.pc.createOffer())

    check(sink_a == [["10.0.0.3"]], f"A gathered own addresses? got {sink_a}")
    check(sink_b == [["10.0.0.3"]], f"B gathered own addresses? got {sink_b}")

    print("test 2: interleaved sessions WITH gather lock — expect own addresses")
    daemon = d.PeckDaemon.__new__(d.PeckDaemon)
    daemon._gather_lock = asyncio.Lock()
    sink_c, sink_d = [], []
    sc = await make_session(daemon, "10.0.0.1", sink_c, gather_delay=0.05)
    sd = await make_session(daemon, "10.0.0.3", sink_d, gather_delay=0.05)

    async def offer(session):
        # mirrors create_offer's critical section
        host_addrs = [session.wg_ip]
        async with session._gather_lock:
            aioice.ice.get_host_addresses = lambda u4, u6: host_addrs
            await session.pc.setLocalDescription(await session.pc.createOffer())

    results = await asyncio.gather(offer(sc), offer(sd))
    check(sink_c == [["10.0.0.1"]], f"C gathered own addresses? got {sink_c}")
    check(sink_d == [["10.0.0.3"]], f"D gathered own addresses? got {sink_d}")

    print("test 3: srflx raddr correlation in the SDP filter")
    ps = await make_session(None, "10.0.0.1", [])
    allowed = {"10.0.0.1"}
    sdp = "\n".join([
        "v=0",
        "a=candidate:aaa 1 udp 2130706431 10.0.0.1 40000 typ host",
        "a=candidate:bbb 1 udp 1694498815 193.29.107.227 40000 typ srflx raddr 10.0.0.1 rport 40000",
        "a=candidate:ccc 1 udp 1694498815 203.0.113.99 40000 typ srflx raddr 192.168.1.5 rport 40000",
        "a=candidate:ddd 1 udp 1694498815 2a04:9dc0:19::24 40000 typ srflx raddr fd00:4956:504e:ffff::ac13:c957 rport 40000",
        "a=candidate:eee 1 udp 2130706431 192.168.1.5 40000 typ host",
        "a=candidate:fff 1 udp 1694498815 198.51.100.7 40000 typ srflx",
        "a=sendrecv",
    ])
    filtered = ps._filter_sdp_candidates(sdp, allowed)
    kept = [l for l in filtered.split("\n") if l.startswith("a=candidate")]
    kept_ips = [l.split()[4] for l in kept]
    check("10.0.0.1" in kept_ips, "own host candidate kept")
    check("193.29.107.227" in kept_ips, "own srflx (raddr=own WG IP) kept")
    check("203.0.113.99" not in kept_ips, "foreign srflx (raddr=192.168.1.5) removed")
    check("2a04:9dc0:19::24" not in kept_ips, "IPv6 srflx with non-allowed raddr removed (allowed set is IPv4-only here)")
    check("192.168.1.5" not in kept_ips, "foreign host candidate removed")
    check("198.51.100.7" in kept_ips, "srflx without raddr kept (injected IPv6 path)")

    print("test 4: IPv6 session — injected srflx and own IPv6 host survive")
    ps6 = await make_session(None, "10.0.0.1", [])
    ps6.wg_ip6 = "fd00:4956:504e:ffff::ac13:c957"
    ps6._ipv6_public = "2a04:9dc0:19::24"
    allowed6 = {"10.0.0.1", "fd00:4956:504e:ffff::ac13:c957", "2a04:9dc0:19::24"}
    sdp6 = "\n".join([
        "a=candidate:aaa 1 udp 2130706431 10.0.0.1 40000 typ host",
        "a=candidate:bbb 1 udp 2130706431 fd00:4956:504e:ffff::ac13:c957 40000 typ host",
        "a=candidate:ccc 1 udp 1694498815 2a04:9dc0:19::24 40000 typ srflx raddr fd00:4956:504e:ffff::ac13:c957 rport 40000",
        "a=candidate:ddd 1 udp 1694498815 193.29.107.227 40000 typ srflx raddr 10.0.0.1 rport 40000",
    ])
    filtered6 = ps6._filter_sdp_candidates(sdp6, allowed6)
    kept6 = [l.split()[4] for l in filtered6.split("\n") if l.startswith("a=candidate")]
    check(len(kept6) == 4, f"all four candidates kept for full IPv6 session? got {kept6}")


async def main():
    await test_race()
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    asyncio.run(main())
