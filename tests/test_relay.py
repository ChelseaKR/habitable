# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The optional ciphertext-only relay."""

from __future__ import annotations

import base64
import concurrent.futures
import contextlib
import hashlib
import http.client
import io
import json
import os
import socket
import stat
import struct
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from habitable import relay
from habitable.relay import (
    RelayStore,
    RoomAuthError,
    RoomFullError,
    _route_label,
    configure_logging,
    make_server,
)

# A stand-in room write-capability token for tests that drive the store/HTTP layer
# directly (the real client derives it from the channel; see habitable.sync).
_TOKEN = "test-room-token"
_TOKEN_HEADER = "X-Habitable-Room-Token"

# Fields every structured access-log line must carry (OBSERVABILITY-STANDARD §3,
# specialized to the relay's metadata-only contract).
_REQUIRED_LOG_FIELDS = {
    "ts",
    "level",
    "msg",
    "request_id",
    "method",
    "path",
    "status",
    "latency_ms",
}


class TestRelayStore:
    def test_non_finite_ttl_environment_falls_back_to_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for raw in ("nan", "inf", "-inf"):
            monkeypatch.setenv("HABITABLE_RELAY_TTL_SECONDS", raw)
            assert relay._ttl_from_env() == relay._DEFAULT_TTL_SECONDS
        monkeypatch.setenv("HABITABLE_RELAY_TTL_SECONDS", "0")
        assert relay._ttl_from_env() == 0.0  # explicit expiry disable remains supported

    def test_explicit_initial_state_enforces_room_token_and_record_invariants(self) -> None:
        normalized = RelayStore(rooms={"empty": []}, tokens={"empty": "token"})
        assert normalized.rooms == {}
        assert normalized.tokens == {}

        invalid_states: list[tuple[dict[str, list[tuple[float, bytes]]], dict[str, str]]] = [
            ({"bad/room": [(1.0, b"x")]}, {"bad/room": "token"}),
            ({"room": [(1.0, b"x")]}, {}),
            ({}, {"orphan": "token"}),
            ({"room": [(1.0, b"x")]}, {"room": ""}),
            ({"room": [(1.0, b"x")]}, {"room": "tökën"}),
            (
                {"room": [(1.0, b"x")]},
                {"room": "t" * (relay._MAX_ROOM_TOKEN_CHARS + 1)},
            ),
            ({"room": [(float("nan"), b"x")]}, {"room": "token"}),
            ({"room": [(1e20, b"x")]}, {"room": "token"}),
            ({"room": [(1.0, b"")]}, {"room": "token"}),
        ]
        for rooms, tokens in invalid_states:
            with pytest.raises(ValueError):
                RelayStore(rooms=rooms, tokens=tokens)

        valid = RelayStore(rooms={"room": [(1.0, b"x")]}, tokens={"room": "token"})
        assert set(valid.tokens) == set(valid.rooms) == {"room"}

    def test_explicit_state_caps_fail_before_iterating_message_records(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class ExplodingQueue(list[tuple[float, bytes]]):
            def __iter__(self) -> Iterator[tuple[float, bytes]]:
                raise AssertionError("message records were iterated before count admission")

        queue = ExplodingQueue([(1.0, b"a"), (2.0, b"b")])
        monkeypatch.setattr(relay, "_MAX_LIVE_ROOMS", 0)
        with pytest.raises(ValueError, match="room/token limit"):
            RelayStore(rooms={"room": queue}, tokens={"room": "token"})

        monkeypatch.setattr(relay, "_MAX_LIVE_ROOMS", 10)
        monkeypatch.setattr(relay, "_MAX_MESSAGES_PER_ROOM", 1)
        with pytest.raises(ValueError, match="message limit"):
            RelayStore(rooms={"room": queue}, tokens={"room": "token"})

    def test_post_fetch_round_trip_and_metrics(self) -> None:
        store = RelayStore()
        store.post("room", b"ciphertext-1", token=_TOKEN)
        store.post("room", b"ciphertext-2", token=_TOKEN)
        assert store.fetch("room") == [b"ciphertext-1", b"ciphertext-2"]
        metrics = store.metrics()
        assert metrics["posted"] == 2 and metrics["rooms"] == 1
        assert metrics["bytes_relayed"] == len(b"ciphertext-1") + len(b"ciphertext-2")

    def test_direct_post_rejects_mutable_or_wrongly_typed_inputs_without_state(self) -> None:
        store = RelayStore()
        with pytest.raises(RoomAuthError, match="invalid room"):
            store.post(cast(str, 123), b"x", token=_TOKEN)
        with pytest.raises(RoomAuthError, match="invalid room token"):
            store.post("room", b"x", token=cast(str, b"token"))
        with pytest.raises(TypeError, match="immutable bytes"):
            store.post("room", cast(bytes, bytearray(b"mutable")), token=_TOKEN)
        assert store.rooms == {} and store.tokens == {}

    def test_empty_room(self) -> None:
        assert RelayStore().fetch("nobody") == []

    def test_post_requires_a_token(self) -> None:
        store = RelayStore()
        with pytest.raises(RoomAuthError):
            store.post("room", b"x", token=None)
        with pytest.raises(RoomAuthError):
            store.post("room", b"x", token="")

    def test_first_token_binds_and_mismatch_is_rejected(self) -> None:
        """Trust-on-first-use: the first token claims the room; others are rejected."""
        store = RelayStore()
        store.post("room", b"one", token=_TOKEN)
        store.post("room", b"two", token=_TOKEN)  # same token: fine
        with pytest.raises(RoomAuthError):
            store.post("room", b"evil", token="a-different-token")
        # The rejected write did not land.
        assert store.fetch("room") == [b"one", b"two"]

    @pytest.mark.parametrize("token", ["tökën", "contains space", "plus+", "dot."])
    def test_token_grammar_rejects_non_ascii_or_non_base64url_without_crashing(
        self, token: str
    ) -> None:
        store = RelayStore()
        store.post("room", b"accepted", token=_TOKEN)
        with pytest.raises(RoomAuthError, match="invalid room token"):
            store.post("room", b"must-not-land", token=token)
        assert store.fetch("room") == [b"accepted"]

    def test_room_full_raises_instead_of_silent_eviction(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay, "_MAX_MESSAGES_PER_ROOM", 2)
        store = RelayStore()
        store.post("room", b"1", token=_TOKEN)
        store.post("room", b"2", token=_TOKEN)
        with pytest.raises(RoomFullError):
            store.post("room", b"3", token=_TOKEN)
        # The earlier messages are intact — no silent pop(0) displacement.
        assert store.fetch("room") == [b"1", b"2"]

    def test_ttl_expires_stale_messages_lazily(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(relay, "_MESSAGE_TTL_SECONDS", 10.0)
        now = {"t": 1_000.0}
        store = RelayStore(clock=lambda: now["t"])
        store.post("room", b"fresh", token=_TOKEN)
        assert store.fetch("room") == [b"fresh"]
        now["t"] += 11.0  # advance past the TTL
        assert store.fetch("room") == []  # expired lazily on fetch
        # A subsequent post starts a clean queue (expiry also runs on post).
        store.post("room", b"new", token=_TOKEN)
        assert store.fetch("room") == [b"new"]

    def test_ttl_zero_disables_expiry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(relay, "_MESSAGE_TTL_SECONDS", 0.0)
        now = {"t": 1_000.0}
        store = RelayStore(clock=lambda: now["t"])
        store.post("room", b"keep", token=_TOKEN)
        now["t"] += 10_000_000.0
        assert store.fetch("room") == [b"keep"]

    def test_global_room_message_and_byte_caps_reject_without_eviction(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay, "_MAX_LIVE_ROOMS", 2)
        monkeypatch.setattr(relay, "_MAX_LIVE_MESSAGES", 2)
        monkeypatch.setattr(relay, "_MAX_LIVE_CIPHERTEXT_BYTES", 4)
        monkeypatch.setattr(relay, "_MAX_CIPHERTEXT_BYTES_PER_ROOM", 10)
        store = RelayStore()
        store.post("one", b"aa", token="token-one")
        store.post("two", b"bb", token="token-two")

        with pytest.raises(RoomFullError, match="relay full"):
            store.post("three", b"c", token="token-three")
        with pytest.raises(RoomFullError, match="relay full"):
            store.post("one", b"c", token="token-one")

        assert store.fetch("one") == [b"aa"]
        assert store.fetch("two") == [b"bb"]
        assert "three" not in store.rooms and "three" not in store.tokens
        metrics = store.metrics()
        assert metrics["rooms"] == 2
        assert metrics["live_messages"] == 2
        assert metrics["live_ciphertext_bytes"] == 4
        assert metrics["capacity_rejections"] == 2

    def test_per_room_byte_cap_bounds_non_destructive_fetch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay, "_MAX_CIPHERTEXT_BYTES_PER_ROOM", 5)
        store = RelayStore()
        store.post("room", b"abc", token=_TOKEN)
        with pytest.raises(RoomFullError, match="room full"):
            store.post("room", b"def", token=_TOKEN)
        assert store.fetch("room") == [b"abc"]
        assert store.fetch("room") == [b"abc"]  # GET/fetch never drains the room
        assert store.metrics()["live_ciphertext_bytes"] == 3

    def test_size_and_capacity_rejections_do_not_bind_or_mutate_tofu_state(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay, "_MAX_BODY", 2)
        empty = RelayStore()
        with pytest.raises(RoomFullError, match="message too large"):
            empty.post("new-room", b"abc", token="claimant")
        assert empty.rooms == {} and empty.tokens == {}

        monkeypatch.setattr(relay, "_MAX_BODY", 10)
        monkeypatch.setattr(relay, "_MESSAGE_TTL_SECONDS", 1.0)
        now = {"t": 1_000.0}
        store = RelayStore(clock=lambda: now["t"])
        store.post("existing", b"old", token="bound-token")
        before_rooms = {room: list(queue) for room, queue in store.rooms.items()}
        before_tokens = dict(store.tokens)
        now["t"] += 2.0
        monkeypatch.setattr(relay, "_MAX_LIVE_CIPHERTEXT_BYTES", 0)
        with pytest.raises(RoomFullError, match="relay full"):
            store.post("new-room", b"x", token="new-token")

        # The bounded global TTL sweep may remove expired state, but the rejected
        # candidate must never claim a token or create a room/message.
        assert "new-room" not in store.rooms and "new-room" not in store.tokens
        assert before_rooms["existing"][0][1] == b"old"
        assert before_tokens["existing"] == "bound-token"
        assert store.rooms == {} and store.tokens == {}

    def test_global_capacity_check_sweeps_expired_unknown_rooms(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay, "_MAX_LIVE_ROOMS", 1)
        monkeypatch.setattr(relay, "_MESSAGE_TTL_SECONDS", 1.0)
        now = {"t": 1_000.0}
        store = RelayStore(clock=lambda: now["t"])
        store.post("forgotten", b"old", token="old-token")
        now["t"] += 2.0

        # No caller has to know/touch the stale room before capacity is reclaimed.
        store.post("new-room", b"new", token="new-token")
        assert store.fetch("new-room") == [b"new"]
        assert "forgotten" not in store.rooms and "forgotten" not in store.tokens

    def test_ttl_churn_bounds_tokens_and_allows_expired_room_rebinding(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay, "_MAX_LIVE_ROOMS", 2)
        monkeypatch.setattr(relay, "_MESSAGE_TTL_SECONDS", 1.0)
        now = {"t": 1_000.0}
        store = RelayStore(clock=lambda: now["t"])
        for index in range(10):
            store.post(f"room-{index}", b"x", token=f"token-{index}")
            now["t"] += 2.0
            assert len(store.rooms) <= 2
            assert len(store.tokens) <= 2

        # Fetch-triggered expiry removes the final message and its binding, so the
        # same now-empty room may be claimed afresh.
        last_room = "room-9"
        assert store.fetch(last_room) == []
        assert last_room not in store.tokens
        store.post(last_room, b"new", token="replacement-token")
        assert store.tokens[last_room] == "replacement-token"

    def test_ttl_disabled_retains_bounded_binding_and_rejects_rebind(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay, "_MAX_LIVE_ROOMS", 1)
        monkeypatch.setattr(relay, "_MESSAGE_TTL_SECONDS", 0.0)
        now = {"t": 1_000.0}
        store = RelayStore(clock=lambda: now["t"])
        store.post("room", b"keep", token="original-token")
        now["t"] += 10_000_000.0
        with pytest.raises(RoomAuthError, match="mismatch"):
            store.post("room", b"wrong", token="replacement-token")
        with pytest.raises(RoomFullError, match="relay full"):
            store.post("other", b"other", token="other-token")
        assert store.tokens == {"room": "original-token"}
        assert store.fetch("room") == [b"keep"]

    def test_parallel_posts_cannot_overshoot_global_caps(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        workers = 16
        monkeypatch.setattr(relay, "_MAX_LIVE_ROOMS", workers)
        monkeypatch.setattr(relay, "_MAX_LIVE_MESSAGES", 1)
        monkeypatch.setattr(relay, "_MAX_LIVE_CIPHERTEXT_BYTES", 1)
        monkeypatch.setattr(relay, "_MAX_CIPHERTEXT_BYTES_PER_ROOM", 1)
        store = RelayStore()
        barrier = threading.Barrier(workers)

        def attempt(index: int) -> bool:
            barrier.wait()
            try:
                store.post(f"room-{index}", b"x", token=f"token-{index}")
            except RoomFullError:
                return False
            return True

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            accepted = list(executor.map(attempt, range(workers)))

        assert sum(accepted) == 1
        assert len(store.rooms) == len(store.tokens) == 1
        metrics = store.metrics()
        assert metrics["live_messages"] == metrics["live_ciphertext_bytes"] == 1
        assert metrics["capacity_rejections"] == workers - 1


def _journal_path(root: Path, room: str) -> Path:
    return root / f"{hashlib.sha256(room.encode()).hexdigest()}.jsonl"


def _journal_record(
    room: str,
    *,
    token: str = _TOKEN,
    timestamp: float = 1_000.0,
    blob: bytes = b"ciphertext",
) -> bytes:
    return (RelayStore._journal_line(room, token, timestamp, blob) + "\n").encode()


class TestPersistence:
    def test_round_trip_across_a_new_store_instance(self, tmp_path: Path) -> None:
        store = RelayStore(persist_dir=tmp_path)
        store.post("room", b"cipher-1", token=_TOKEN)
        store.post("room", b"cipher-2", token=_TOKEN)

        # A fresh instance (simulating a relay restart) reloads undelivered messages.
        reborn = RelayStore(persist_dir=tmp_path)
        assert reborn.fetch("room") == [b"cipher-1", b"cipher-2"]
        # The trust-on-first-use token binding also survives the restart.
        with pytest.raises(RoomAuthError):
            reborn.post("room", b"x", token="wrong-token")
        reborn.post("room", b"cipher-3", token=_TOKEN)
        assert reborn.fetch("room") == [b"cipher-1", b"cipher-2", b"cipher-3"]

    def test_repeated_restart_prunes_stale_lines_before_line_cap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay, "_MESSAGE_TTL_SECONDS", 1.0)
        monkeypatch.setattr(relay, "_MAX_JOURNAL_LINES_PER_ROOM", 2)
        now = {"t": 1_000.0}
        store = RelayStore(persist_dir=tmp_path, clock=lambda: now["t"])
        store.post("room", b"message-0", token=_TOKEN)

        for index in range(1, 6):
            now["t"] += 2.0
            store = RelayStore(persist_dir=tmp_path, clock=lambda: now["t"])
            assert store.fetch("room") == []
            store.post("room", f"message-{index}".encode(), token=_TOKEN)
            assert len(_journal_path(tmp_path, "room").read_bytes().splitlines()) == 1

        # The newest non-expired append remains loadable after repeated restarts;
        # old lines never get a chance to strand it behind the physical-line cap.
        reborn = RelayStore(persist_dir=tmp_path, clock=lambda: now["t"])
        assert reborn.fetch("room") == [b"message-5"]

    def test_empty_and_blank_only_canonical_journals_are_removed(self, tmp_path: Path) -> None:
        empty = tmp_path / ("0" * 64 + ".jsonl")
        blank = tmp_path / ("f" * 64 + ".jsonl")
        empty.write_bytes(b"")
        blank.write_bytes(b"\n\n")

        store = RelayStore(persist_dir=tmp_path, clock=lambda: 1_000.0)
        assert store.rooms == {} and store.tokens == {}
        assert not empty.exists() and not blank.exists()

    def test_startup_cleans_only_exact_owned_compaction_crash_temps(self, tmp_path: Path) -> None:
        orphan = tmp_path / f".habitable-relay-{'a' * 32}.tmp"
        near_match = tmp_path / ".habitable-relay-not-owned.tmp"
        orphan.write_bytes(b"room-token-timestamp-ciphertext-remnant")
        near_match.write_bytes(b"operator-file")
        room = "temp-cleanup-room"
        _journal_path(tmp_path, room).write_bytes(_journal_record(room, blob=b"load-me"))

        loaded = RelayStore(persist_dir=tmp_path, clock=lambda: 1_000.0)
        assert loaded.fetch(room) == [b"load-me"]
        assert not orphan.exists()
        assert near_match.read_bytes() == b"operator-file"

    def test_created_compaction_temp_uses_the_exact_cleanup_grammar(self, tmp_path: Path) -> None:
        store = RelayStore(persist_dir=tmp_path, clock=lambda: 1_000.0)
        descriptor, temp = store._new_compaction_temp()
        os.close(descriptor)
        try:
            assert relay._COMPACTION_TEMP_RE.fullmatch(temp.name) is not None
            if os.name == "posix":
                assert stat.S_IMODE(temp.stat().st_mode) == 0o600
        finally:
            temp.unlink(missing_ok=True)

    @pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
    def test_temp_cleanup_never_follows_an_exact_name_symlink(self, tmp_path: Path) -> None:
        target = tmp_path / "outside-target"
        target.write_bytes(b"must-survive")
        linked = tmp_path / f".habitable-relay-{'e' * 32}.tmp"
        linked.symlink_to(target)
        room = "temp-symlink-room"
        _journal_path(tmp_path, room).write_bytes(_journal_record(room, blob=b"load-me"))

        loaded = RelayStore(persist_dir=tmp_path, clock=lambda: 1_000.0)
        assert loaded.fetch(room) == [b"load-me"]
        assert linked.is_symlink()
        assert target.read_bytes() == b"must-survive"

    def test_temp_cleanup_has_separate_non_temp_and_owned_temp_allowances(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay, "_MAX_COMPACTION_NON_TEMP_SCAN_ENTRIES", 2)
        (tmp_path / "unrelated").write_bytes(b"operator-file")
        room = "separate-temp-budget-room"
        _journal_path(tmp_path, room).write_bytes(_journal_record(room, blob=b"load-me"))
        orphan = tmp_path / f".habitable-relay-{'b' * 32}.tmp"
        orphan.write_bytes(b"crash-remnant")

        loaded = RelayStore(persist_dir=tmp_path, clock=lambda: 1_000.0)
        assert loaded.fetch(room) == [b"load-me"]
        assert not orphan.exists()

    def test_over_allowance_compaction_temps_refuse_journal_admission(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay, "_MAX_COMPACTION_TEMP_FILES", 1)
        orphans = [tmp_path / f".habitable-relay-{value * 32}.tmp" for value in ("c", "d")]
        for orphan in orphans:
            orphan.write_bytes(b"bounded-crash-remnant")
        room = "over-temp-allowance-room"
        _journal_path(tmp_path, room).write_bytes(_journal_record(room, blob=b"do-not-load"))

        refused = RelayStore(persist_dir=tmp_path, clock=lambda: 1_000.0)
        assert refused.rooms == {} and refused.tokens == {}
        assert all(orphan.exists() for orphan in orphans)
        assert refused.metrics()["journal_load_rejections"] == 1

    def test_expired_messages_are_not_resurrected_on_load(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay, "_MESSAGE_TTL_SECONDS", 10.0)
        now = {"t": 1_000.0}
        store = RelayStore(persist_dir=tmp_path, clock=lambda: now["t"])
        store.post("room", b"stale", token=_TOKEN)
        now["t"] += 11.0  # let it age past the TTL
        reborn = RelayStore(persist_dir=tmp_path, clock=lambda: now["t"])
        assert reborn.fetch("room") == []

    def test_transient_ttl_cleanup_failure_allows_rebind_and_restart(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay, "_MESSAGE_TTL_SECONDS", 1.0)
        now = {"t": 1_000.0}
        room = "cleanup-rebind-room"
        path = _journal_path(tmp_path, room)
        store = RelayStore(persist_dir=tmp_path, clock=lambda: now["t"])
        store.post(room, b"stale", token="token-a")

        now["t"] = 1_002.0

        def fail_unlink(
            _path: Path,
            _expected: relay._JournalCandidate | None = None,
        ) -> None:
            raise OSError("transient cleanup failure")

        with monkeypatch.context() as cleanup_failure:
            cleanup_failure.setattr(
                RelayStore,
                "_unlink_empty_journal",
                staticmethod(fail_unlink),
            )
            with pytest.raises(OSError, match="transient cleanup failure"):
                store.fetch(room)

        assert room not in store.rooms and room not in store.tokens
        assert len(path.read_bytes().splitlines()) == 1

        store.post(room, b"fresh", token="token-b")
        assert len(path.read_bytes().splitlines()) == 2

        restarted = RelayStore(persist_dir=tmp_path, clock=lambda: now["t"])
        assert restarted.fetch(room) == [b"fresh"]
        assert restarted.tokens[room] == "token-b"
        compacted = path.read_bytes().splitlines()
        assert len(compacted) == 1
        assert json.loads(compacted[0])["token"] == "token-b"

    def test_far_future_record_cannot_pin_token_or_ttl_capacity(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay, "_MESSAGE_TTL_SECONDS", 10.0)
        now = {"t": 1_000.0}
        room = "future-clock-room"
        path = _journal_path(tmp_path, room)
        path.write_bytes(
            _journal_record(
                room,
                token="attacker-token",
                timestamp=1e20,
                blob=b"must-not-pin",
            )
            + _journal_record(
                room,
                token="safe-token",
                timestamp=now["t"] + relay._MAX_FUTURE_CLOCK_SKEW_SECONDS,
                blob=b"bounded-skew",
            )
        )

        loaded = RelayStore(persist_dir=tmp_path, clock=lambda: now["t"])
        assert loaded.fetch(room) == [b"bounded-skew"]
        assert loaded.tokens[room] == "safe-token"
        assert loaded.metrics()["journal_load_rejections"] == 1

        now["t"] += relay._MAX_FUTURE_CLOCK_SKEW_SECONDS + 11
        expired = RelayStore(persist_dir=tmp_path, clock=lambda: now["t"])
        assert expired.fetch(room) == []
        assert room not in expired.tokens
        assert path.exists()  # mixed invalid/valid source is never destructively rewritten

    def test_raw_room_id_never_becomes_a_filename(self, tmp_path: Path) -> None:
        room = "room-SECRETNAME-123"
        store = RelayStore(persist_dir=tmp_path)
        store.post(room, b"SECRET-CIPHERTEXT-PAYLOAD", token=_TOKEN)
        names = [p.name for p in tmp_path.iterdir()]
        assert names
        for name in names:
            assert "SECRETNAME" not in name  # no raw room id in any filename
        expected = f"{hashlib.sha256(room.encode()).hexdigest()}.jsonl"
        assert expected in names

    def test_startup_streams_and_strictly_validates_journal_records(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        room = "strict-room"
        invalid_base64 = json.dumps(
            {"room": room, "token": _TOKEN, "ts": 1_000.0, "blob": "YQ==junk"}
        ).encode()
        non_finite = json.dumps(
            {"room": room, "token": _TOKEN, "ts": float("nan"), "blob": "YQ=="}
        ).encode()
        oversized_token = json.dumps(
            {
                "room": room,
                "token": "t" * (relay._MAX_ROOM_TOKEN_CHARS + 1),
                "ts": 1_000.0,
                "blob": "YQ==",
            }
        ).encode()
        non_ascii_token = json.dumps(
            {"room": room, "token": "tökën", "ts": 1_000.0, "blob": "YQ=="}
        ).encode()
        invalid_room = "bad/room"
        _journal_path(tmp_path, invalid_room).write_bytes(
            _journal_record(invalid_room, blob=b"must-not-load")
        )
        _journal_path(tmp_path, room).write_bytes(
            b"\n".join(
                [
                    invalid_base64,
                    non_finite,
                    oversized_token,
                    non_ascii_token,
                    _journal_record(room, blob=b"accepted").rstrip(b"\n"),
                ]
            )
            + b"\n"
        )

        def forbid_read_text(*_args: object, **_kwargs: object) -> str:
            raise AssertionError("startup must stream bounded binary lines")

        monkeypatch.setattr(Path, "read_text", forbid_read_text)
        store = RelayStore(persist_dir=tmp_path, clock=lambda: 1_000.0)
        assert store.fetch(room) == [b"accepted"]
        assert store.metrics()["journal_load_rejections"] == 5

    def test_startup_rejection_warning_is_aggregate_metadata_only(self, tmp_path: Path) -> None:
        secret_name = "SECRET-ROOM-TOKEN-PAYLOAD.jsonl"
        (tmp_path / secret_name).write_bytes(b"SECRET-BODY")
        buffer = io.StringIO()
        configure_logging(buffer)
        try:
            store = RelayStore(persist_dir=tmp_path, clock=lambda: 1_000.0)
        finally:
            configure_logging()

        record = json.loads(buffer.getvalue())
        assert record["msg"] == "relay journal records rejected during bounded startup"
        assert record["journal_load_rejections"] == 1
        assert set(record) == {"ts", "level", "msg", "journal_load_rejections"}
        rendered = buffer.getvalue()
        assert secret_name not in rendered and "SECRET-BODY" not in rendered
        assert store.rooms == {} and store.tokens == {}

    def test_conflicting_tokens_in_one_journal_are_rejected_without_binding(
        self, tmp_path: Path
    ) -> None:
        room = "conflict-room"
        _journal_path(tmp_path, room).write_bytes(
            _journal_record(room, token="token-a", blob=b"a")
            + _journal_record(room, token="token-b", blob=b"b")
        )
        store = RelayStore(persist_dir=tmp_path, clock=lambda: 1_000.0)
        assert room not in store.rooms and room not in store.tokens
        assert store.metrics()["journal_load_rejections"] == 1

    def test_noncanonical_duplicate_journal_cannot_override_tofu_token(
        self, tmp_path: Path
    ) -> None:
        room = "canonical-room"
        canonical = _journal_path(tmp_path, room)
        canonical.write_bytes(_journal_record(room, token="token-a", blob=b"accepted"))
        alternate_name = "0" * 64 + ".jsonl"
        if alternate_name == canonical.name:
            alternate_name = "f" * 64 + ".jsonl"
        (tmp_path / alternate_name).write_bytes(
            _journal_record(room, token="token-b", blob=b"must-not-load")
        )

        store = RelayStore(persist_dir=tmp_path, clock=lambda: 1_000.0)
        assert store.fetch(room) == [b"accepted"]
        assert store.tokens[room] == "token-a"
        with pytest.raises(RoomAuthError, match="mismatch"):
            store.post(room, b"wrong", token="token-b")

    def test_startup_enforces_per_room_and_global_caps(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        per_room = tmp_path / "per-room"
        per_room.mkdir()
        room = "over-room-cap"
        _journal_path(per_room, room).write_bytes(
            _journal_record(room, blob=b"aa") + _journal_record(room, blob=b"bb")
        )
        monkeypatch.setattr(relay, "_MAX_CIPHERTEXT_BYTES_PER_ROOM", 3)
        rejected = RelayStore(persist_dir=per_room, clock=lambda: 1_000.0)
        assert rejected.rooms == {} and rejected.tokens == {}
        assert rejected.metrics()["capacity_rejections"] == 1

        global_dir = tmp_path / "global"
        global_dir.mkdir()
        for index in range(2):
            current = f"global-room-{index}"
            _journal_path(global_dir, current).write_bytes(
                _journal_record(current, token=f"token-{index}", blob=b"x")
            )
        monkeypatch.setattr(relay, "_MAX_CIPHERTEXT_BYTES_PER_ROOM", 10)
        monkeypatch.setattr(relay, "_MAX_LIVE_ROOMS", 10)
        monkeypatch.setattr(relay, "_MAX_LIVE_MESSAGES", 1)
        monkeypatch.setattr(relay, "_MAX_LIVE_CIPHERTEXT_BYTES", 1)
        bounded = RelayStore(persist_dir=global_dir, clock=lambda: 1_000.0)
        assert len(bounded.rooms) == len(bounded.tokens) == 1
        assert bounded.metrics()["capacity_rejections"] == 1

    def test_oversized_journal_and_line_are_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay, "_MAX_PERSIST_BYTES_PER_ROOM", 80)
        oversized_file_room = "oversized-file"
        _journal_path(tmp_path, oversized_file_room).write_bytes(b"x" * 81)

        monkeypatch.setattr(relay, "_MAX_JOURNAL_LINE_BYTES", 40)
        oversized_line_room = "oversized-line"
        line_path = _journal_path(tmp_path, oversized_line_room)
        line_path.write_bytes(b"{" + b"x" * 40 + b"}\n")

        store = RelayStore(persist_dir=tmp_path, clock=lambda: 1_000.0)
        assert store.rooms == {} and store.tokens == {}
        assert store.metrics()["journal_load_rejections"] == 2

    def test_startup_total_journal_read_budget_is_enforced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        room = "startup-budget"
        record = _journal_record(room, blob=b"bounded")
        _journal_path(tmp_path, room).write_bytes(record)
        monkeypatch.setattr(relay, "_MAX_STARTUP_JOURNAL_BYTES", len(record) - 1)

        store = RelayStore(persist_dir=tmp_path, clock=lambda: 1_000.0)
        assert store.rooms == {} and store.tokens == {}
        assert store.metrics()["journal_load_rejections"] == 1

    def test_startup_per_journal_and_global_line_budgets_are_enforced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        room = "line-budget"
        _journal_path(tmp_path, room).write_bytes(
            b"".join(_journal_record(room, blob=str(index).encode()) for index in range(3))
        )
        monkeypatch.setattr(relay, "_MAX_JOURNAL_LINES_PER_ROOM", 2)
        store = RelayStore(persist_dir=tmp_path, clock=lambda: 1_000.0)
        assert store.rooms == {} and store.tokens == {}
        assert store.metrics()["journal_load_rejections"] == 1

        global_dir = tmp_path / "global-lines"
        global_dir.mkdir()
        for index in range(2):
            current = f"global-line-{index}"
            _journal_path(global_dir, current).write_bytes(
                _journal_record(current, token=f"token-{index}", blob=b"x")
            )
        monkeypatch.setattr(relay, "_MAX_JOURNAL_LINES_PER_ROOM", 2)
        monkeypatch.setattr(relay, "_MAX_STARTUP_JOURNAL_LINES", 1)
        globally_bounded = RelayStore(persist_dir=global_dir, clock=lambda: 1_000.0)
        assert len(globally_bounded.rooms) == len(globally_bounded.tokens) == 1
        assert globally_bounded.metrics()["journal_load_rejections"] == 1

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO requires POSIX")
    def test_startup_skips_symlink_and_fifo_without_following_or_blocking(
        self, tmp_path: Path
    ) -> None:
        symlink_room = "symlink-room"
        target = tmp_path / "outside-target"
        target.write_bytes(_journal_record(symlink_room, blob=b"must-not-follow"))
        _journal_path(tmp_path, symlink_room).symlink_to(target)

        fifo_room = "fifo-room"
        fifo = _journal_path(tmp_path, fifo_room)
        os.mkfifo(fifo)
        result: dict[str, RelayStore] = {}

        def construct() -> None:
            result["store"] = RelayStore(persist_dir=tmp_path, clock=lambda: 1_000.0)

        thread = threading.Thread(target=construct, daemon=True)
        thread.start()
        thread.join(timeout=1.0)
        blocked = thread.is_alive()
        if blocked:  # unblock the vulnerable implementation so teardown stays safe
            descriptor = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
            os.write(descriptor, b"\n")
            os.close(descriptor)
            thread.join(timeout=1.0)

        assert not blocked, "journal startup blocked while opening a FIFO"
        assert result["store"].rooms == {}
        assert target.read_bytes() == _journal_record(symlink_room, blob=b"must-not-follow")

    def test_compaction_happens_before_journal_exceeds_its_cap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay, "_MESSAGE_TTL_SECONDS", 1.0)
        now = {"t": 1_000.0}
        sample_size = len(_journal_record("room", blob=b"old"))
        monkeypatch.setattr(relay, "_MAX_PERSIST_BYTES_PER_ROOM", sample_size + 5)
        store = RelayStore(persist_dir=tmp_path, clock=lambda: now["t"])
        store.post("room", b"old", token=_TOKEN)
        now["t"] += 2.0
        store.post("room", b"new", token=_TOKEN)

        path = _journal_path(tmp_path, "room")
        assert path.stat().st_size <= relay._MAX_PERSIST_BYTES_PER_ROOM
        assert len(path.read_bytes().splitlines()) == 1
        reborn = RelayStore(persist_dir=tmp_path, clock=lambda: now["t"])
        assert reborn.fetch("room") == [b"new"]

    def test_retry_repairs_unterminated_partial_append_before_acknowledgement(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = RelayStore(persist_dir=tmp_path, clock=lambda: 1_000.0)
        real_write = os.write
        writes = 0

        def partial_then_fail(descriptor: int, payload: bytes | memoryview) -> int:
            nonlocal writes
            writes += 1
            if writes == 1:
                partial = bytes(payload[: max(1, len(payload) // 2)])
                return real_write(descriptor, partial)
            raise OSError("simulated interrupted append")

        monkeypatch.setattr(os, "write", partial_then_fail)
        with pytest.raises(OSError, match="interrupted append"):
            store.post("partial-room", b"first-attempt", token=_TOKEN)

        path = _journal_path(tmp_path, "partial-room")
        assert path.read_bytes() and not path.read_bytes().endswith(b"\n")

        monkeypatch.setattr(os, "write", real_write)
        store.post("partial-room", b"acknowledged-retry", token=_TOKEN)
        assert path.read_bytes().endswith(b"\n")
        assert len(path.read_bytes().splitlines()) == 2

        restarted = RelayStore(persist_dir=tmp_path, clock=lambda: 1_000.0)
        assert restarted.fetch("partial-room") == [
            b"first-attempt",
            b"acknowledged-retry",
        ]

    def test_persistent_ttl_churn_bounds_journal_files_and_allows_rebind(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay, "_MAX_LIVE_ROOMS", 2)
        monkeypatch.setattr(relay, "_MESSAGE_TTL_SECONDS", 1.0)
        now = {"t": 1_000.0}
        store = RelayStore(persist_dir=tmp_path, clock=lambda: now["t"])
        for index in range(10):
            store.post(f"room-{index}", b"x", token=f"token-{index}")
            now["t"] += 2.0
            assert len(list(tmp_path.glob("*.jsonl"))) <= 2
            assert len(store.tokens) <= 2

        assert store.fetch("room-9") == []
        assert not _journal_path(tmp_path, "room-9").exists()
        assert len(list(tmp_path.glob("*.jsonl"))) <= 1
        store.post("room-9", b"new", token="replacement-token")
        assert store.tokens["room-9"] == "replacement-token"
        assert len(list(tmp_path.glob("*.jsonl"))) <= 2

    def test_journal_identity_swap_is_rejected_before_read_or_append(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        room = "identity-room"
        path = _journal_path(tmp_path, room)
        original = _journal_record(room, token="token-a", blob=b"original")
        replacement = _journal_record(
            room,
            token="token-b",
            blob=b"replacement-with-a-distinct-size",
        )
        # Regression: Linux can immediately reuse the unlinked inode. Generation
        # checks must still notice the changed size/mtime instead of loading or
        # appending to the replacement.
        assert len(original) != len(replacement)
        path.write_bytes(original)
        real_open = os.open
        swapped = False

        def swap_then_open(
            candidate: str | os.PathLike[str],
            flags: int,
            mode: int = 0o600,
        ) -> int:
            nonlocal swapped
            if Path(candidate) == path and not swapped:
                swapped = True
                path.unlink()
                path.write_bytes(replacement)
            return real_open(candidate, flags, mode)

        monkeypatch.setattr(os, "open", swap_then_open)
        loaded = RelayStore(persist_dir=tmp_path, clock=lambda: 1_000.0)
        assert loaded.rooms == {} and loaded.tokens == {}
        assert path.read_bytes() == replacement

        monkeypatch.setattr(os, "open", real_open)
        writer = RelayStore(persist_dir=tmp_path, clock=lambda: 1_000.0)
        path.write_bytes(original)
        swapped = False
        monkeypatch.setattr(os, "open", swap_then_open)
        with pytest.raises(OSError, match="regular file"):
            writer.post(room, b"must-not-append", token="token-b")
        assert path.read_bytes() == replacement

        monkeypatch.setattr(os, "open", real_open)
        path.write_bytes(b"")
        swapped = False
        monkeypatch.setattr(os, "open", swap_then_open)
        with pytest.raises(OSError, match="identity changed"):
            RelayStore._unlink_empty_journal(path)
        assert path.read_bytes() == replacement

    def test_generation_snapshot_rejects_reused_inode_metadata(self, tmp_path: Path) -> None:
        def snapshot(*, size: int, modified_ns: int, changed_ns: int) -> os.stat_result:
            return cast(
                os.stat_result,
                SimpleNamespace(
                    st_dev=7,
                    st_ino=11,
                    st_size=size,
                    st_mtime_ns=modified_ns,
                    st_ctime_ns=changed_ns,
                ),
            )

        candidate = relay._JournalCandidate(tmp_path / "journal", 7, 11, 13, 17, 19)
        original = snapshot(size=13, modified_ns=17, changed_ns=19)
        reused_with_new_size = snapshot(size=14, modified_ns=17, changed_ns=19)
        reused_with_new_mtime = snapshot(size=13, modified_ns=18, changed_ns=19)
        reused_with_new_ctime = snapshot(size=13, modified_ns=17, changed_ns=20)

        assert candidate.matches(original)
        assert not candidate.matches(reused_with_new_size)
        assert not candidate.matches(reused_with_new_mtime)
        assert not candidate.matches(reused_with_new_ctime)
        assert not relay._same_journal_generation(original, reused_with_new_size)
        assert not relay._same_journal_generation(original, reused_with_new_mtime)
        assert not relay._same_journal_generation(original, reused_with_new_ctime)

    def test_windows_unlink_fallback_closes_then_rechecks_generation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "windows-cleanup.jsonl"
        path.write_bytes(b"")
        real_lstat = Path.lstat
        lstat_calls = 0

        def swap_before_final_check(candidate: Path) -> os.stat_result:
            nonlocal lstat_calls
            if candidate == path:
                lstat_calls += 1
                if lstat_calls == 3:
                    candidate.unlink()
                    candidate.write_bytes(b"replacement-generation")
            return real_lstat(candidate)

        monkeypatch.setattr(relay, "_CLOSE_BEFORE_UNLINK", True)
        monkeypatch.setattr(Path, "lstat", swap_before_final_check)
        with pytest.raises(OSError, match="identity changed"):
            RelayStore._unlink_empty_journal(path)
        assert path.read_bytes() == b"replacement-generation"


@pytest.fixture
def server_url() -> Iterator[str]:
    server = make_server("127.0.0.1", 0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _get(url: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        body = exc.read()
        exc.close()
        return exc.code, body


def _post(url: str, data: bytes, *, token: str | None = _TOKEN) -> tuple[int, bytes]:
    headers = {} if token is None else {_TOKEN_HEADER: token}
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        body = exc.read()
        exc.close()
        return exc.code, body


def _raw_post(
    server_url: str,
    headers: list[tuple[str, str]],
    body: bytes = b"",
    *,
    close_write: bool = False,
) -> tuple[int, bytes]:
    authority = server_url.removeprefix("http://")
    host, raw_port = authority.rsplit(":", 1)
    connection = http.client.HTTPConnection(host, int(raw_port), timeout=5)
    connection.putrequest("POST", "/rooms/framing", skip_host=True, skip_accept_encoding=True)
    connection.putheader("Host", authority)
    connection.putheader(_TOKEN_HEADER, _TOKEN)
    for name, value in headers:
        connection.putheader(name, value)
    connection.endheaders(body)
    if close_write:
        assert connection.sock is not None
        connection.sock.shutdown(socket.SHUT_WR)
    response = connection.getresponse()
    try:
        return response.status, response.read()
    finally:
        response.close()
        connection.close()


def _literal_content_length_post(server_url: str, raw_value: bytes) -> tuple[int, bytes]:
    """Send an unnormalized Content-Length field over a literal TCP request."""
    authority = server_url.removeprefix("http://")
    host, raw_port = authority.rsplit(":", 1)
    with socket.create_connection((host, int(raw_port)), timeout=5) as connection:
        connection.sendall(
            b"POST /rooms/framing HTTP/1.1\r\n"
            + f"Host: {authority}\r\n".encode("ascii")
            + f"{_TOKEN_HEADER}: {_TOKEN}\r\n".encode("ascii")
            + b"Content-Length: "
            + raw_value
            + b"\r\nConnection: close\r\n\r\n"
        )
        response = http.client.HTTPResponse(connection)
        response.begin()
        try:
            return response.status, response.read()
        finally:
            response.close()


def test_healthz(server_url: str) -> None:
    status, body = _get(f"{server_url}/healthz")
    assert status == 200
    assert json.loads(body)["status"] == "ok"


def test_unknown_path_is_404(server_url: str) -> None:
    status, _ = _get(f"{server_url}/nope")
    assert status == 404


def test_http_post_then_get(server_url: str) -> None:
    status, _ = _post(f"{server_url}/rooms/abc", b"sealed-bytes")
    assert status == 200
    status, body = _get(f"{server_url}/rooms/abc")
    assert status == 200
    assert json.loads(body)["messages"]  # one base64 message present


def test_http_post_without_token_is_403(server_url: str) -> None:
    status, body = _post(f"{server_url}/rooms/abc", b"sealed-bytes", token=None)
    assert status == 403
    assert "token" in json.loads(body)["error"]


def test_http_post_with_mismatched_token_is_403(server_url: str) -> None:
    assert _post(f"{server_url}/rooms/abc", b"first", token="claimant")[0] == 200
    status, body = _post(f"{server_url}/rooms/abc", b"second", token="impostor")
    assert status == 403
    assert json.loads(body)["error"] == "room token mismatch"


def test_http_room_full_is_413(server_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(relay, "_MAX_MESSAGES_PER_ROOM", 1)
    assert _post(f"{server_url}/rooms/full", b"1")[0] == 200
    status, body = _post(f"{server_url}/rooms/full", b"2")
    assert status == 413
    assert json.loads(body)["error"] == "room full"


def test_http_global_capacity_is_loud_and_does_not_claim_rejected_room(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(relay, "_MAX_LIVE_ROOMS", 1)
    store = RelayStore()
    server = make_server("127.0.0.1", 0, store)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}"
    try:
        assert _post(f"{url}/rooms/one", b"accepted", token="token-one")[0] == 200
        status, body = _post(f"{url}/rooms/two", b"rejected", token="token-two")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert status == 413
    assert json.loads(body) == {"error": "relay full"}
    assert "two" not in store.rooms and "two" not in store.tokens


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ([("Content-Length", "not-a-number")], 400),
        ([("Content-Length", "1"), ("Content-Length", "1")], 400),
        ([("Content-Length", "1"), ("Transfer-Encoding", "chunked")], 400),
        ([("Content-Length", "0")], 400),
        ([("Content-Length", str(relay._MAX_BODY + 1))], 413),
    ],
)
def test_http_invalid_or_oversized_request_framing_is_controlled(
    server_url: str,
    headers: list[tuple[str, str]],
    expected: int,
) -> None:
    status, body = _raw_post(server_url, headers)
    assert status == expected
    assert "error" in json.loads(body)


@pytest.mark.parametrize(
    "raw_value",
    [
        b"1_0",
        b"+10",
        b"1 ",
        b"1\t",
        b"\xb2",
        b"9" * (relay._MAX_CONTENT_LENGTH_DIGITS + 1),
    ],
)
def test_http_content_length_requires_bounded_ascii_digits_on_the_wire(
    server_url: str, raw_value: bytes
) -> None:
    status, body = _literal_content_length_post(server_url, raw_value)
    assert status == 400
    assert json.loads(body) == {"error": "invalid request framing"}


def test_http_short_body_is_rejected_before_store_mutation(server_url: str) -> None:
    status, body = _raw_post(
        server_url,
        [("Content-Length", "5")],
        b"x",
        close_write=True,
    )
    assert status == 400
    assert json.loads(body) == {"error": "incomplete body"}
    status, fetched = _get(f"{server_url}/rooms/framing")
    assert status == 200 and json.loads(fetched) == {"messages": []}


def test_get_streams_bounded_json_and_remains_non_destructive(
    server_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(relay, "_MAX_CIPHERTEXT_BYTES_PER_ROOM", 12)
    monkeypatch.setattr(relay, "_BASE64_CHUNK_BYTES", 3)
    real_encode = base64.b64encode
    encoded_chunk_sizes: list[int] = []

    def track_encode(payload: bytes | memoryview) -> bytes:
        encoded_chunk_sizes.append(len(payload))
        return real_encode(payload)

    monkeypatch.setattr(base64, "b64encode", track_encode)
    assert _post(f"{server_url}/rooms/bounded", b"abc")[0] == 200
    assert _post(f"{server_url}/rooms/bounded", b"defgh")[0] == 200

    first_status, first = _get(f"{server_url}/rooms/bounded")
    second_status, second = _get(f"{server_url}/rooms/bounded")
    assert first_status == second_status == 200
    assert first == second
    assert len(first) <= relay._max_get_json_bytes()
    assert [base64.b64decode(item) for item in json.loads(first)["messages"]] == [
        b"abc",
        b"defgh",
    ]
    assert encoded_chunk_sizes and max(encoded_chunk_sizes) <= relay._BASE64_CHUNK_BYTES


def test_healthz_exposes_only_aggregate_counts(server_url: str) -> None:
    """The relay must leak no room names or message contents — only counts."""
    room = "room-SECRETNAME-123"
    blob = b"SECRET-CIPHERTEXT-PAYLOAD"
    assert _post(f"{server_url}/rooms/{room}", blob)[0] == 200
    status, body = _get(f"{server_url}/healthz")
    assert status == 200
    payload = json.loads(body)
    assert set(payload) <= {
        "status",
        "rooms",
        "live_messages",
        "live_ciphertext_bytes",
        "posted",
        "fetched",
        "bytes_relayed",
        "capacity_rejections",
        "journal_load_rejections",
    }
    text = body.decode("utf-8")
    assert "SECRETNAME" not in text  # no room identifiers
    assert "SECRET-CIPHERTEXT" not in text  # no message contents
    assert payload["rooms"] == 1 and payload["posted"] == 1


# --- Health & readiness endpoints (OBSERVABILITY-STANDARD §6) -----------------


def test_livez_is_ok(server_url: str) -> None:
    status, body = _get(f"{server_url}/livez")
    assert status == 200
    assert json.loads(body) == {"status": "ok"}


def test_readyz_ready_when_store_healthy(server_url: str) -> None:
    status, body = _get(f"{server_url}/readyz")
    assert status == 200
    payload = json.loads(body)
    assert payload["status"] == "ok"
    assert payload["checks"]["store"] == "ok"


def test_readyz_fails_closed_when_dependency_down() -> None:
    """A failing critical dependency must yield 503 (fail-closed), not 200."""
    server = make_server("127.0.0.1", 0, ready_check=lambda: False)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, body = _get(f"http://127.0.0.1:{port}/readyz")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert status == 503
    payload = json.loads(body)
    assert payload["status"] == "unavailable"
    assert payload["checks"]["store"] == "down"


def test_readyz_fails_closed_when_probe_raises() -> None:
    def boom() -> bool:
        raise RuntimeError("dependency exploded")

    server = make_server("127.0.0.1", 0, ready_check=boom)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _ = _get(f"http://127.0.0.1:{port}/readyz")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert status == 503


# --- Structured JSON access logging (metadata-only) ---------------------------


def test_route_label_redacts() -> None:
    """The route label redacts room ids and never echoes arbitrary client input."""
    assert _route_label("/livez") == "/livez"
    assert _route_label("/readyz") == "/readyz"
    assert _route_label("/healthz") == "/healthz"
    assert _route_label("/rooms/room-SECRETNAME-123") == "/rooms/{room}"
    assert _route_label("/anything/else") == "/<other>"


@pytest.fixture
def logging_relay() -> Iterator[tuple[str, io.StringIO]]:
    """A relay with access logging on, capturing JSON lines to an in-memory buffer."""
    buffer = io.StringIO()
    configure_logging(buffer)
    server = make_server("127.0.0.1", 0, access_log=True)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", buffer
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        configure_logging()  # reset the module logger back to stderr


def _wait_for_lines(buffer: io.StringIO, count: int, timeout: float = 3.0) -> list[str]:
    """Poll until the buffer holds >= ``count`` non-empty lines (avoids a race with
    the server thread emitting the log line after the client's response returns)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lines = [ln for ln in buffer.getvalue().splitlines() if ln.strip()]
        if len(lines) >= count:
            return lines
        time.sleep(0.02)
    return [ln for ln in buffer.getvalue().splitlines() if ln.strip()]


def test_access_log_line_is_valid_json_with_expected_fields(
    logging_relay: tuple[str, io.StringIO],
) -> None:
    url, buffer = logging_relay
    assert _post(f"{url}/rooms/abc", b"sealed-bytes")[0] == 200
    _get(f"{url}/rooms/abc")

    lines = _wait_for_lines(buffer, 2)
    assert len(lines) >= 2
    for line in lines:
        record = json.loads(line)  # must be valid JSON (non-JSON raises here)
        assert set(record) >= _REQUIRED_LOG_FIELDS, f"missing fields in {record}"
        assert record["msg"] == "request"
        assert record["method"] in {"GET", "POST"}
        assert record["path"] == "/rooms/{room}"  # redacted route, never the room id
        assert record["status"] == 200
        assert isinstance(record["latency_ms"], (int, float))
        assert len(record["request_id"]) >= 8


def test_access_log_never_leaks_room_id_key_or_payload(
    logging_relay: tuple[str, io.StringIO],
) -> None:
    """Reinforce the threat model: no room id, no ciphertext, no key material in logs."""
    url, buffer = logging_relay
    room = "room-SECRETNAME-123"
    blob = b"SECRET-CIPHERTEXT-PAYLOAD"
    assert _post(f"{url}/rooms/{room}", blob)[0] == 200

    lines = _wait_for_lines(buffer, 1)
    assert lines, "expected an access-log line"
    text = "\n".join(lines)
    assert "SECRETNAME" not in text  # no room identifier
    assert "SECRET-CIPHERTEXT" not in text  # no ciphertext/payload
    assert "sealed-bytes" not in text
    record = json.loads(lines[0])
    assert record["path"] == "/rooms/{room}"


def test_access_log_never_leaks_the_room_write_token(
    logging_relay: tuple[str, io.StringIO],
) -> None:
    """The write-capability token is a header, compared only via hmac — never logged."""
    url, buffer = logging_relay
    token = "ROOMTOKEN-SENTINEL-must-not-appear-in-logs"
    assert _post(f"{url}/rooms/tokenroom", b"sealed", token=token)[0] == 200

    lines = _wait_for_lines(buffer, 1)
    assert lines, "expected an access-log line"
    text = "\n".join(lines)
    assert token not in text  # the token never reaches the log stream
    assert "tokenroom" not in text  # nor the raw room id
    assert json.loads(lines[0])["path"] == "/rooms/{room}"


def test_health_probes_excluded_from_access_log(
    logging_relay: tuple[str, io.StringIO],
) -> None:
    url, buffer = logging_relay
    for route in ("/livez", "/readyz", "/healthz"):
        _get(f"{url}{route}")
    # A room request DOES log; use it as a synchronization point, then assert the
    # only logged lines are the room request — health probes emit nothing.
    _get(f"{url}/rooms/xyz")
    lines = _wait_for_lines(buffer, 1)
    assert lines
    for line in lines:
        record = json.loads(line)
        assert record["path"] == "/rooms/{room}"
        assert record["path"] not in {"/livez", "/readyz", "/healthz"}


def test_access_log_is_off_by_default() -> None:
    """Default deployments write no request lines (threat-model default preserved)."""
    buffer = io.StringIO()
    configure_logging(buffer)
    server = make_server("127.0.0.1", 0)  # access_log defaults to False
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{port}"
        for _ in range(3):
            _get(f"{url}/rooms/silent")
        time.sleep(0.2)  # give the server thread time to (not) log
        assert buffer.getvalue().strip() == ""
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        configure_logging()


def test_server_handle_error_emits_fixed_metadata_without_peer_or_traceback() -> None:
    buffer = io.StringIO()
    stderr = io.StringIO()
    configure_logging(buffer)
    server = make_server("127.0.0.1", 0, access_log=False)
    try:
        with contextlib.redirect_stderr(stderr):
            try:
                raise RuntimeError("TRACEBACK-BODY-TOKEN-ROOM-SENTINEL")
            except RuntimeError:
                server.handle_error(object(), ("203.0.113.77", 45678))
    finally:
        server.server_close()
        configure_logging()

    record = json.loads(buffer.getvalue())
    assert set(record) == {"ts", "level", "msg"}
    assert record["level"] == "error"
    assert record["msg"] == "relay request handler failed"
    rendered = (buffer.getvalue() + stderr.getvalue()).replace(record["ts"], "")
    for sentinel in (
        "203.0.113.77",
        "45678",
        "Traceback",
        "RuntimeError",
        "TRACEBACK-BODY-TOKEN-ROOM-SENTINEL",
    ):
        assert sentinel not in rendered


def test_server_handle_error_silences_expected_connection_reset() -> None:
    buffer = io.StringIO()
    stderr = io.StringIO()
    configure_logging(buffer)
    server = make_server("127.0.0.1", 0, access_log=False)
    try:
        with contextlib.redirect_stderr(stderr):
            try:
                raise ConnectionResetError("RESET-BODY-TOKEN-ROOM-SENTINEL")
            except ConnectionResetError:
                server.handle_error(object(), ("203.0.113.88", 45679))
    finally:
        server.server_close()
        configure_logging()

    assert buffer.getvalue() == ""
    assert stderr.getvalue() == ""


def test_unauthenticated_rst_error_path_never_leaks_peer_or_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    buffer = io.StringIO()
    stderr = io.StringIO()
    handled = threading.Event()
    addresses: list[tuple[str, int]] = []
    configure_logging(buffer)
    server = make_server("127.0.0.1", 0, access_log=False)
    original_handle_error = server.handle_error

    def track_error(request: object, client_address: tuple[str, int]) -> None:
        addresses.append(client_address)
        try:
            original_handle_error(request, client_address)
        finally:
            handled.set()

    monkeypatch.setattr(server, "handle_error", track_error)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    sentinels: list[str] = []
    try:
        with contextlib.redirect_stderr(stderr):
            for attempt in range(3):
                handled.clear()
                room = f"ROOM_SENTINEL_RST_{attempt}"
                token = f"TOKEN_SENTINEL_RST_{attempt}"
                body = f"BODY-SENTINEL-RST-{attempt}".encode()
                connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    connection.connect(server.server_address)
                    peer_ip, peer_port = connection.getsockname()
                    sentinels.extend((peer_ip, str(peer_port), room, token, body.decode()))
                    connection.sendall(
                        f"POST /rooms/{room} HTTP/1.1\r\n".encode()
                        + b"Host: relay.invalid\r\n"
                        + f"{_TOKEN_HEADER}: {token}\r\n".encode()
                        + b"Content-Length: 1000000\r\nConnection: close\r\n\r\n"
                        + body
                    )
                    connection.setsockopt(
                        socket.SOL_SOCKET,
                        socket.SO_LINGER,
                        struct.pack("HH" if os.name == "nt" else "ii", 1, 0),
                    )
                finally:
                    connection.close()
                assert handled.wait(timeout=5), "RST did not reach the threaded error path"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        configure_logging()

    assert len(addresses) == 3
    rendered = buffer.getvalue() + stderr.getvalue()
    assert rendered == ""
    for sentinel in (*sentinels, "Traceback", "ConnectionResetError"):
        assert sentinel not in rendered
