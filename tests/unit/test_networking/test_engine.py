"""MangleEngine end-to-end tests with a fake PacketSource."""
from __future__ import annotations

import socket
import struct


from deepview.networking.engine import MangleEngine
from deepview.networking.ruleset import MangleRuleset


def _udp(src="10.0.0.1", dst="10.0.0.2", sport=5353, dport=53, payload=b"example.com") -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        20 + 8 + len(payload),
        0,
        0,
        64,
        socket.IPPROTO_UDP,
        0,
        socket.inet_pton(socket.AF_INET, src),
        socket.inet_pton(socket.AF_INET, dst),
    )
    return ip + udp + payload


class FakeHandle:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self.verdict: str | None = None
        self.mark: int | None = None
        self.modified: bytes | None = None

    def get_payload(self) -> bytes:
        return self._payload

    def accept(self) -> None:
        self.verdict = "accept"

    def drop(self) -> None:
        self.verdict = "drop"

    def set_payload(self, data: bytes) -> None:
        self.modified = data

    def set_mark(self, mark: int) -> None:
        self.mark = mark

    def repeat(self) -> None:
        self.verdict = "repeat"


class FakeSource:
    def run(self, handler):
        pass

    def close(self):
        pass


def _ruleset(rules_text: str, tmp_path) -> MangleRuleset:
    path = tmp_path / "r.yaml"
    path.write_text(rules_text)
    return MangleRuleset.load_yaml(path)


class TestDispatch:
    def test_drop_rule(self, tmp_path):
        rs = _ruleset(
            "rules:\n"
            "  - id: r1\n"
            "    match: 'packet.udp.dport == 53'\n"
            "    action: {type: drop}\n",
            tmp_path,
        )
        engine = MangleEngine(rs, FakeSource())
        handle = FakeHandle(_udp())
        engine.process_raw(handle._payload, handle)
        assert handle.verdict == "drop"
        assert engine.stats.dropped == 1
        assert engine.stats.accepted == 0

    def test_accept_default(self, tmp_path):
        rs = _ruleset(
            "rules:\n"
            "  - id: r1\n"
            "    match: 'packet.tcp.dport == 9999'\n"
            "    action: {type: drop}\n",
            tmp_path,
        )
        engine = MangleEngine(rs, FakeSource())
        handle = FakeHandle(_udp())
        engine.process_raw(handle._payload, handle)
        assert handle.verdict == "accept"
        assert engine.stats.dropped == 0
        assert engine.stats.accepted >= 1

    def test_rewrite_action(self, tmp_path):
        rs = _ruleset(
            "rules:\n"
            "  - id: rewrite_host\n"
            "    match: 'packet.udp.dport == 53'\n"
            "    action:\n"
            "      type: rewrite\n"
            "      operations:\n"
            "        - find: example.com\n"
            "          replace: honeypot.a\n",
            tmp_path,
        )
        engine = MangleEngine(rs, FakeSource())
        handle = FakeHandle(_udp())
        engine.process_raw(handle._payload, handle)
        assert handle.verdict == "accept"
        assert handle.modified is not None
        assert b"honeypot.a" in handle.modified
        assert engine.stats.rewritten == 1

    def test_dry_run_forces_accept(self, tmp_path):
        rs = _ruleset(
            "rules:\n"
            "  - id: would_drop\n"
            "    match: 'packet.udp.dport == 53'\n"
            "    action: {type: drop}\n",
            tmp_path,
        )
        engine = MangleEngine(rs, FakeSource(), dry_run=True)
        handle = FakeHandle(_udp())
        engine.process_raw(handle._payload, handle)
        assert handle.verdict == "accept"
        # Stats still tally the *would-be* drop so authors can preview.
        assert engine.stats.dropped == 1

    def test_passthrough_skips_ruleset(self, tmp_path):
        rs = _ruleset(
            "rules:\n"
            "  - id: would_drop\n"
            "    match: 'packet.udp.dport == 53'\n"
            "    action: {type: drop}\n",
            tmp_path,
        )
        engine = MangleEngine(rs, FakeSource())
        engine.set_passthrough(True)
        handle = FakeHandle(_udp())
        engine.process_raw(handle._payload, handle)
        assert handle.verdict == "accept"
        assert engine.stats.passthrough_hits == 1
        assert engine.stats.dropped == 0

    def test_action_exception_fails_open(self, tmp_path):
        rs = _ruleset(
            "rules:\n"
            "  - id: r1\n"
            "    match: 'packet.udp.dport == 53'\n"
            "    action: {type: accept}\n",
            tmp_path,
        )
        engine = MangleEngine(rs, FakeSource())

        # Monkey-patch the action to raise.
        def boom(view):
            raise RuntimeError("engine bug")

        rs.rules[0].action.apply = boom  # type: ignore[assignment]
        handle = FakeHandle(_udp())
        outcome = engine.process_raw(handle._payload, handle)
        assert handle.verdict == "accept"
        assert engine.stats.errors == 1
        assert outcome.verdict == "accept"

    def test_mark_action(self, tmp_path):
        rs = _ruleset(
            "rules:\n"
            "  - id: mark_dns\n"
            "    match: 'packet.udp.dport == 53'\n"
            "    action: {type: mark, fwmark: 0x1000}\n",
            tmp_path,
        )
        engine = MangleEngine(rs, FakeSource())
        handle = FakeHandle(_udp())
        engine.process_raw(handle._payload, handle)
        assert handle.verdict == "accept"
        assert handle.mark == 0x1000
        assert engine.stats.marked == 1
