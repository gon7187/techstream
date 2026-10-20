"""Authored literal TY frames; original-image checks run only with private evidence."""

from __future__ import annotations

import hashlib
import json
import unittest
from collections import deque
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from scripts import utility_ex_ty_retained_04 as m
from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import (
    SHA_12_TY,
    SHA_18_TY,
    SHA_PLUS_TY,
    TYContext,
    TYSourceError,
)


class Comm:
    def __init__(self, replies=()):
        self.replies = deque(replies)
        self.events = []
        self.snapshots = deque()
        self.dtc_reply: tuple[int, bytes] = (0, b"\x81\x00")
        self.initial_status = 0
        self.callback: Callable[[bytes], None] | None = None

    def exchange(self, request):
        self.events.append(request)
        if self.callback:
            self.callback(request)
        if not self.replies:
            raise AssertionError(f"Unexpected frame: {request.hex()}")
        value = self.replies.popleft()
        if isinstance(value, BaseException):
            raise value
        return value

    def initialize(self, mode=0):
        self.events.append(("initialize", mode))
        return self.initial_status

    def finalize(self):
        self.events.append("finalize")

    def session(self, mode, keepalive=1, *, normal_first=False, stop_on_error=False):
        self.events.append(("session", mode, normal_first))
        return 0

    def configure(self, field, value):
        self.events.append(("configure", field, value))

    def read_field(self, field):
        self.events.append(("read", field))
        return 19

    def select_target(self, first, second=0):
        self.events.append(("target", first, second))

    def support_snapshot(self, kind):
        self.events.append(("snapshot", kind))
        return self.snapshots.popleft()

    def read_dtcs(self, mode=0x80, capacity=0x1000):
        self.events.append(("dtcs", mode, capacity))
        return self.dtc_reply


class Context:
    def __init__(self, comm, sha):
        self.module_sha256 = sha
        self.module_bytes = b"authored retained TY test image"
        self.controller = comm
        self.mode = 4
        self.state = {}
        self.events = []
        self.clock = 0xFFFFFF00
        self.cancelled = False
        self.cancel_on_sleep = False

    def comm(self, selector):
        self.events.append(selector)
        return self.controller

    def is_cancelled(self):
        return self.cancelled

    def sleep(self, duration):
        self.clock += duration
        self.events.append(("sleep", duration))
        if self.cancel_on_sleep:
            self.cancelled = True

    def native_sleep(self, duration):
        self.sleep(duration)

    def ticks(self):
        return self.clock & 0xFFFFFFFF


def words(*values):
    return bytearray(b"".join(v.to_bytes(4, "little") for v in values))


def snapshot(records):
    raw = bytearray(0x1020)
    offsets = [0x1020] * 256
    at = 0
    for pid, values in records.items():
        offsets[pid] = at
        raw[at : at + len(values) + 2] = bytes((pid, len(values))) + values
        at += len(values) + 2
    return 0, bytes(raw), tuple(offsets)


class RetainedTests(unittest.TestCase):
    def setUp(self):
        self.sha = hashlib.sha256(b"authored retained TY test image").hexdigest()
        for name, mapping in (
            ("_EXPORTS", m._EXPORTS),
            ("_CLASSIC", m._CLASSIC),
            ("_RESULT", m._RESULT),
        ):
            self.enterContext(patch.dict(mapping, {self.sha: mapping[SHA_18_TY]}))
        self.enterContext(patch.object(m, "SHA_18_TY", self.sha))

    def ctx(self, replies=(), *, plus=False):
        comm = Comm(replies)
        context = Context(comm, self.sha)
        if plus:
            self.enterContext(patch.object(m, "SHA_18_TY", SHA_18_TY))
            self.enterContext(patch.object(m, "SHA_PLUS_TY", self.sha))
        return context, comm

    def run_body(self, context, export, data):
        return m.run_body(export, (data,), context)

    def test_exact_pair_universe_and_reject_unassigned(self):
        self.assertEqual(
            tuple(
                map(
                    len,
                    (
                        m.supported_exports(SHA_12_TY),
                        m.supported_exports(SHA_18_TY),
                        m.supported_exports(SHA_PLUS_TY),
                    ),
                )
            ),
            (9, 13, 13),
        )
        self.assertEqual(m.supported_exports("f" * 64), ())
        self.assertNotIn(m._IVM, m.supported_exports(SHA_12_TY))
        context, _ = self.ctx()
        with self.assertRaises(TYSourceError):
            self.run_body(context, "Ex2AHS_99_NameAlias", bytearray(32))

    def test_identity_and_mutability_boundary_before_resources(self):
        context, comm = self.ctx()
        context.module_bytes += b"tampered"
        with self.assertRaises(TYSourceError):
            self.run_body(context, m._AHS[0], bytearray(16))
        self.assertEqual(comm.events, [])
        context.module_bytes = b"authored retained TY test image"
        for data in (bytes(16), bytearray(15)):
            with self.assertRaises(ValueError):
                self.run_body(context, m._AHS[0], data)
        context.mode = 20
        self.assertEqual(self.run_body(context, m._AHS[0], bytearray()), 99)
        self.assertEqual(comm.events, [])

    def test_ahs_support_mutates_same_sparse_native_buffer(self):
        context, comm = self.ctx()
        comm.snapshots.extend(
            (snapshot({8: b"\xff\xff", 9: b"\x00\x01\x80"}), snapshot({4: b"\x80"}))
        )
        data = bytearray(16)
        self.assertEqual(self.run_body(context, m._AHS[2], data), 0)
        self.assertEqual(data, words(2, 2, 1, 3))
        self.assertEqual(
            comm.events,
            [
                ("target", 0x750, 0x7C),
                ("initialize", 0),
                ("configure", "native_rva:12180", 150),
                ("snapshot", 1),
                ("snapshot", 2),
                "finalize",
            ],
        )

    def test_ahs_missing_support_and_bad_offsets_fail(self):
        context, comm = self.ctx()
        comm.snapshots.append(snapshot({}))
        self.assertEqual(self.run_body(context, m._AHS[2], bytearray(16)), 22)
        self.assertEqual(comm.events[-1], "finalize")
        context, comm = self.ctx()
        comm.snapshots.append((0, b"", (0,) * 255))
        with self.assertRaises(ValueError):
            self.run_body(context, m._AHS[4], bytearray(4))
        self.assertEqual(comm.events[-1], "finalize")

    def test_confirmation_echo_output_error_and_busy_restore(self):
        for status, reply, expected in (
            (0, b"\x61\x08\xaa\xbb", 0),
            (0, b"\x61\x07\xaa\xbb", 3),
            (7, b"\x7f\x21\x24", 1001),
            (7, b"\x7f\x21\x22", 26),
        ):
            with self.subTest(reply=reply):
                context, comm = self.ctx(((status, reply),))
                data = words(2, 0, 0, 0) + bytearray(2)
                self.assertEqual(self.run_body(context, m._AHS[1], data), expected)
                if expected == 0:
                    self.assertEqual(data[16:18], b"\xaa\xbb")
                self.assertEqual(
                    comm.events[-2:],
                    [("configure", "native_rva:121d0", 19), "finalize"],
                )

    def test_ahs_adjustment_literal_frames_poll_and_timeout(self):
        context, comm = self.ctx(
            ((0, b"\x70\x04"), (0, b"\x61\x09\x00"), (0, b"\x61\x09\x80"))
        )
        self.assertEqual(self.run_body(context, m._AHS[0], words(0, 1, 1, 2)), 0)
        self.assertEqual(
            [e for e in comm.events if isinstance(e, bytes)],
            [b"\x30\x04\x00\x80", b"\x21\x09", b"\x21\x09"],
        )
        context, comm = self.ctx(((0, b"\x70\x04"),) + ((0, b"\x61\x09\x00"),) * 5)
        self.assertEqual(self.run_body(context, m._AHS[0], words(0, 1, 1, 2)), 1000)
        self.assertEqual(len([x for x in comm.events if x == b"\x21\x09"]), 5)

    def test_ahs_swivel_delay_and_dtc(self):
        for angle, delay in ((0, 1000), (0x10, 7000), (1, 0)):
            context, comm = self.ctx(((0, b"\x99\x0c"),))
            comm.dtc_reply = (0, b"\x81\x01\xa4\x20")
            self.assertEqual(
                self.run_body(context, m._AHS[3], words(5) + bytearray((angle, 0x42))),
                9999,
            )
            self.assertIn(b"\x30\x0c\x00" + bytes((angle, 0x42)), comm.events)
            self.assertEqual(
                [x for x in context.events if isinstance(x, tuple)],
                [("sleep", delay)] if delay else [],
            )

    def test_ahs_height_success_and_failed_request_fallback(self):
        context, comm = self.ctx(((0, b"\x70\x04"),))
        self.assertEqual(self.run_body(context, m._AHS[5], words(2, 2)), 0)
        self.assertIn(b"\x30\x04\x00\x80\x06", comm.events)
        context, comm = self.ctx(((25, b""),))
        self.assertEqual(self.run_body(context, m._AHS[5], words(2, 9)), 1001)
        self.assertIn(("sleep", 1500), context.events)
        self.assertIn(("dtcs", 0x81, 0x1000), comm.events)

    def test_ahs_support03_and_dtc_priority(self):
        context, comm = self.ctx(((0, b"\xe8\x12\x04\x03\x80\xff\x00"),))
        data = bytearray(4)
        self.assertEqual(self.run_body(context, m._AHS[6], data), 0)
        self.assertEqual(data, words(2))
        for code, expected in ((0xC100, 1004), (0xA42D, 1000), (0xA451, 0), (0, 1003)):
            context, comm = self.ctx()
            comm.snapshots.extend(
                (snapshot({1: b"\x40"}), snapshot({3: bytes(8) + b"\xff\xff"}))
            )
            comm.dtc_reply = (0, b"\x81\x01" + code.to_bytes(2, "big"))
            data = bytearray(8)
            self.assertEqual(self.run_body(context, m._AHS[7], data), expected)
            self.assertEqual(data, words(1, 1))

    def test_ahs_sync_dtc_order_and_sleep(self):
        for code, expected in ((0xA420, 1000), (0xA451, 1001), (0xA453, 1002), (0, 0)):
            context, comm = self.ctx(((0, b"\x7b\x01"),))
            comm.dtc_reply = (0, b"\x81\x01" + code.to_bytes(2, "big"))
            self.assertEqual(self.run_body(context, m._AHS[8], words(1, 1)), expected)
            self.assertIn(b"\x3b\x01\x40", comm.events)
            self.assertIn(("sleep", 12000), context.events)

    def test_cancel_and_host_exception_cleanup(self):
        for exception in (Cancelled("host cancel"), RuntimeError("host fault")):
            context, comm = self.ctx((exception,))
            with self.assertRaises(type(exception)):
                self.run_body(context, m._AHS[1], words(2, 0, 0, 0) + bytearray(2))
            self.assertEqual(
                comm.events[-2:], [("configure", "native_rva:121d0", 19), "finalize"]
            )
        context, comm = self.ctx(((0, b"\x70\x04"),))
        context.cancel_on_sleep = True
        with self.assertRaises(Cancelled):
            self.run_body(context, m._AHS[0], words(0, 1, 1, 2))
        self.assertEqual(comm.events[-1], "finalize")

    def test_pseat_retention_followup_and_plus_poll(self):
        for export, rid in zip(m._PSEAT, (1, 5, 6), strict=True):
            context, comm = self.ctx(
                ((0, bytes((0x71, 1, 0x11, rid))), (0, bytes((0x71, 3, 0x11, rid, 2))))
            )
            context.mode = 20
            data = words(0, 0)
            self.assertEqual(self.run_body(context, export, data), 0)
            self.assertNotIn("finalize", comm.events)
            data[:4] = (1).to_bytes(4, "little")
            self.assertEqual(self.run_body(context, export, data), 0)
            self.assertEqual(comm.events[-1], "finalize")
        context, comm = self.ctx(
            ((0, b"\x71\x03\x11\x01\x01"), (0, b"\x71\x03\x11\x01\x02")), plus=True
        )
        context.mode = 21
        self.assertEqual(self.run_body(context, m._PSEAT[0], words(1, 0)), 0)
        self.assertEqual(
            [x for x in comm.events if isinstance(x, bytes)], [b"\x31\x03\x11\x01"] * 2
        )

    def test_pseat_mutable_cancel_and_native_error(self):
        context, comm = self.ctx(((0, b"\x71\x03\x11\x01\x01"),), plus=True)
        context.mode = 20
        data = words(1, 0)
        comm.callback = lambda request: data.__setitem__(
            slice(4, 8), (1).to_bytes(4, "little")
        )
        self.assertEqual(self.run_body(context, m._PSEAT[0], data), 0)
        context, comm = self.ctx(((9, b"\x7f\x31\x22"),))
        context.mode = 20
        self.assertEqual(self.run_body(context, m._PSEAT[0], words(0, 0)), 9)
        self.assertEqual(comm.events[-2:], [("session", 1, False), "finalize"])

    def test_ivm_native_sequence_and_caller_buffer(self):
        replies = (
            (0, b"\x62\x02\x04\x12\x00"),
            (0, b"\x6e\x02\x04"),
            (0, b"\x71\x01\x11\x01"),
            (0, b"\x71\x03\x11\x01\x02"),
            (0, b"\x71\x01\x11\x02"),
            (0, b"\x71\x03\x11\x02\x02"),
            (0, b"\x6e\x02\x04"),
        )
        context, comm = self.ctx(replies)
        context.mode = 20
        data = bytearray(0x204C)
        self.assertEqual(self.run_body(context, m._IVM, data), 0)
        self.assertEqual(data[0x1020:0x1022], b"\x12\x00")
        self.assertEqual(data[0x2040:0x2044], words(2))
        self.assertEqual(data[0x2048:0x204C], words(1))
        self.assertEqual(
            [x for x in comm.events if isinstance(x, bytes)],
            [
                b"\x22\x02\x04",
                b"\x2e\x02\x04\x12\x80",
                b"\x31\x01\x11\x01\x00",
                b"\x31\x03\x11\x01",
                b"\x31\x01\x11\x02\x00",
                b"\x31\x03\x11\x02",
                b"\x2e\x02\x04\x12\x00",
            ],
        )
        self.assertEqual(comm.events[-1], "finalize")

    def test_ivm_1005_and_1007_retain_then_action2_restores(self):
        replies = (
            (0, b"\x62\x02\x04\x12\x80"),
            (0, b"\x71\x01\x11\x01"),
            (0, b"\x71\x03\x11\x01\x03"),
            (0, b"\x62\x10\x11ABCD"),
            (8, b""),
            (0, b"\x6e\x02\x04"),
        )
        context, comm = self.ctx(replies)
        context.mode = 20
        data = bytearray(0x204C)
        self.assertEqual(self.run_body(context, m._IVM, data), 1005)
        self.assertEqual(data[:4], b"ABCD")
        self.assertNotIn("finalize", comm.events)
        m._put(data, 0x2044, 2)
        self.assertEqual(self.run_body(context, m._IVM, data), 1007)
        self.assertNotIn("finalize", comm.events)
        self.assertEqual(self.run_body(context, m._IVM, data), 0)
        self.assertEqual(comm.events[-1], "finalize")

    def test_ivm_followup_recovered_asm_success_both_versions_and_oversize(self):
        for plus, expected, result in ((False, 0, 2), (True, 0, 2)):
            replies = [(0, b"\x71\x01\x11\x02"), (0, b"\x71\x03\x11\x02\x02")]
            replies.append((0, b"\x6e\x02\x04"))
            context, comm = self.ctx(replies, plus=plus)
            context.mode = 20
            data = bytearray(0x204C)
            m._put(data, 0x2044, 1)
            self.assertEqual(self.run_body(context, m._IVM, data), expected)
            self.assertEqual(m._u32(data, 0x2048), result)
            self.assertEqual(comm.events[-1], "finalize")
        context, comm = self.ctx()
        context.mode = 20
        data = bytearray(0x204C)
        m._put(data, 0x2044, 2)
        m._put(data, 0x2040, 0x101E)
        with self.assertRaises(ValueError):
            self.run_body(context, m._IVM, data)
        self.assertEqual(comm.events, ["finalize"])

    def test_actual97_aggregator_preserves_buffer_and_literal_primitive_trace(self):
        from scripts import utility_ex_ty

        context, comm = self.ctx(((0, b"\x61\x08\x21\x43"),))
        data = words(2, 0, 0, 0) + bytearray(2)
        self.assertIn(m._AHS[1], utility_ex_ty.supported_exports(context.module_sha256))
        self.assertEqual(
            utility_ex_ty.run_body(m._AHS[1], (data,), cast(TYContext, context)), 0
        )
        self.assertEqual(data[16:18], b"\x21\x43")
        self.assertEqual(context.events, ["selected"])
        self.assertIn(b"\x21\x08", comm.events)
        self.assertEqual(comm.events[-1], "finalize")

    def test_private35_pairs_through_actual83_selected_engine_and97(self):
        from scripts.utility_ex import UtilityExContext, UtilityExEngine
        from tests.test_utility_ex import Host

        root = Path(__file__).resolve().parents[1]
        path = root / "analysis/evidence/no-car-123/source-packet.json"
        if not path.exists():
            self.skipTest("Private original source images absent")
        packet = json.loads(path.read_text())
        images = {
            entry["source_sha256"]: (root / entry["path"]).read_bytes()
            for entry in packet["modules"]
        }
        # Undo the authored branch key patch for exact original-image admission.
        with patch.object(m, "SHA_18_TY", SHA_18_TY):
            for pair in packet["wrappers"]:
                export, sha = pair["export"], pair["source_sha256"]
                with self.subTest(export=export, sha=sha):
                    host = Host()
                    host.values[0x6F] = 4 if export in m._AHS else 20
                    context = UtilityExContext(images[sha], host, None, None)
                    comm = Comm()
                    expected = 0
                    if export == m._AHS[0]:
                        data = words(0, 1, 1, 2)
                        comm.replies.extend(((0, b"\x70\x04"), (0, b"\x61\x09\x80")))
                    elif export == m._AHS[1]:
                        data = words(2, 0, 0, 0) + bytearray(2)
                        comm.replies.append((0, b"\x61\x08\x01\x02"))
                    elif export == m._AHS[2]:
                        data = bytearray(16)
                        comm.snapshots.extend(
                            (
                                snapshot({8: b"\xff\xff", 9: b"\x00\x01\x80"}),
                                snapshot({4: b"\x80"}),
                            )
                        )
                    elif export == m._AHS[3]:
                        data = words(5) + bytearray(2)
                        comm.replies.append((0, b"\x70\x0c"))
                    elif export == m._AHS[4]:
                        data = bytearray(4)
                        comm.snapshots.append(snapshot({12: b"\xf0\x80"}))
                    elif export == m._AHS[5]:
                        data = words(2, 1)
                        comm.replies.append((0, b"\x70\x04"))
                    elif export == m._AHS[6]:
                        data = bytearray(4)
                        comm.replies.append((0, b"\xe8\x12\x04\x02\x80\xff"))
                    elif export == m._AHS[7]:
                        data = bytearray(8)
                        comm.snapshots.extend(
                            (
                                snapshot({1: b"\x40"}),
                                snapshot({3: bytes(8) + b"\xff\xff"}),
                            )
                        )
                        expected = 1003
                    elif export == m._AHS[8]:
                        data = words(1, 0)
                        comm.replies.append((0, b"\x7b\x01"))
                    elif export in m._PSEAT:
                        data = words(0, 0)
                        rid = (1, 5, 6)[m._PSEAT.index(export)]
                        comm.replies.append((0, bytes((0x71, 1, 0x11, rid))))
                    else:
                        data = bytearray(0x204C)
                        m._put(data, 0x2044, 2)
                        comm.replies.append((0, b"\x6e\x02\x04"))
                    selector = (
                        "selected"
                        if export in m._AHS
                        else (
                            "native:1011d4f0" if sha == SHA_18_TY else "native:101392d0"
                        )
                    )
                    context._communication[selector] = cast(Any, comm)
                    engine = UtilityExEngine(context)
                    self.assertIn(export, engine.supported_bodies())
                    self.assertEqual(engine.run_body(export, (data,)), expected)
                    self.assertEqual(context.module_sha256, sha)
                    self.assertEqual(comm.replies, deque())
                    self.assertEqual(
                        context.state[f"native_global:{m._RESULT[sha]:x}"], expected
                    )
                    if export in m._PSEAT:
                        m._put(data, 0, 1)
                        m._put(data, 4, 1)
                        self.assertEqual(engine.run_body(export, (data,)), 0)
                    self.assertEqual(comm.events[-1], "finalize")

    def test_private_source_packet_bytes_hashes_and_pair_set(self):
        root = Path(__file__).resolve().parents[1]
        packet_path = root / "analysis/evidence/no-car-123/source-packet.json"
        if not packet_path.exists():
            self.skipTest("Private source packet absent")
        packet = json.loads(packet_path.read_text())
        assigned = json.loads(
            (
                root / "analysis/evidence/no-car-123/assigned-source-pairs.json"
            ).read_text()
        )
        self.assertEqual(
            {(x["source_sha256"], x["export"]) for x in packet["wrappers"]},
            {(x["source_sha256"], x["export"]) for x in assigned["pairs"]},
        )
        for entry in packet["source_files"]:
            for kind in ("c", "asm"):
                self.assertEqual(
                    hashlib.sha256(
                        (root / entry[f"{kind}_path"]).read_bytes()
                    ).hexdigest(),
                    entry[f"{kind}_sha256"],
                )
            self.assertTrue(entry["assembly_bytes_match_original"])
        self.assertEqual(len(packet["modules"]), 3)
        for entry in packet["modules"]:
            blob = (root / entry["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(blob).hexdigest(), entry["source_sha256"])


if __name__ == "__main__":
    unittest.main()
