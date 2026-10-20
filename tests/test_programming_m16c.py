"""Independent authored raw-bootloader vectors; no vendor execution."""

import unittest
from collections import deque
from dataclasses import replace

from scripts.programming_m16c import (
    M16CControls,
    M16CError,
    M16COptions,
    M16CReadError,
    M16CSegment,
    M16CWriter,
    VForestPolicy,
    bind_m16c_context,
    m16c_address_frame,
    m16c_password_frames,
    m16c_prepare_retry,
    m16c_segments,
    m16c_write,
    new_password,
    parent_cpu,
    retry_password,
    security_vforest_write,
)
from scripts.programming_vendor import VendorCAN


class RawPeer:
    def __init__(
        self,
        replies=(),
        *,
        fail_at=0,
        cancel_at=0,
        late_at=0,
        failure: BaseException | None = None,
    ):
        self.replies = deque(replies)
        self.events = []
        self.writes = []
        self.now = 100.0
        self.interrupted = False
        self.fail_at, self.cancel_at, self.late_at = fail_at, cancel_at, late_at
        self.failure = failure

    def event(self, name, value=None):
        self.events.append((name, value))
        index = len(self.events)
        if index == self.cancel_at:
            self.interrupted = True
        if index == self.late_at:
            self.now += 1000
        if index == self.fail_at:
            raise self.failure or OSError("authored I/O fault")

    def channel(self):
        return VendorCAN(
            self.write,
            self.read,
            timeout=30,
            clock=lambda: self.now,
            cancelled=lambda: self.interrupted,
            wait=self.wait,
        )

    def write(self, payload, timeout):
        self.event("write", payload)
        self.writes.append(payload)
        return 1

    def read(self, timeout):
        self.event("read")
        if not self.replies:
            raise AssertionError("Unscripted native read")
        result = self.replies.popleft()
        if isinstance(result, Exception):
            raise result
        return result

    def wait(self, milliseconds, timeout):
        self.event("wait", milliseconds)

    def controls(self):
        def get_timeout():
            self.event("get_timeout")
            return 123

        def set_timeout(value):
            self.event("set_timeout", value)

        def start_filter():
            self.event("start_filter")
            return 42

        def stop_filter(value):
            self.event("stop_filter", value)

        return M16CControls(get_timeout, set_timeout, start_filter, stop_filter)


class M16CTests(unittest.TestCase):
    def options(self, **kwargs):
        return M16COptions(
            bytes(range(8)),
            0x11223344,
            0x55667788,
            b"\x12\x34\x56",
            b"\xab\xcd\xef",
            777,
            **kwargs,
        )

    def test_exact_password_address_and_parent_selection_vectors(self):
        self.assertEqual(
            m16c_password_frames(b"\x12\x34\x56", 0x11223344, b"abc"),
            (bytes.fromhex("a012345607"), bytes.fromhex("11223344") + b"abc"),
        )
        self.assertEqual(
            m16c_address_frame("erase", 0x12FFFF), bytes.fromhex("a1ff12d0")
        )
        self.assertEqual(m16c_address_frame("write", 0x123400), bytes.fromhex("a23412"))
        self.assertEqual(
            m16c_address_frame("verify", 0xABCD00), bytes.fromhex("a3cdab")
        )
        self.assertEqual(parent_cpu(("child", "P", "P"), ("P",), 0), 1)
        self.assertEqual(parent_cpu(("P", "P"), ("P",), 0), 1)
        with self.assertRaises(ValueError):
            parent_cpu(("child", "parent"), ("P",), 0)
        self.assertTrue(retry_password(False, 7))
        self.assertFalse(retry_password(True, 7))
        self.assertFalse(retry_password(True, 12))
        self.assertTrue(retry_password(False, 12, force=True))

    def test_password_uses_second_status_byte_and_no_common_ack(self):
        peer = RawPeer([b"\0\x0c"])
        writer = M16CWriter(peer.channel())
        writer.password_check(b"abc", 0x11223344, b"def")
        self.assertEqual(peer.writes, [b"\xa0abc\x07", b"\x11\x22\x33\x44def", b"\xa4"])
        peer = RawPeer([b"\x0c\0"])
        with self.assertRaises(M16CError) as caught:
            M16CWriter(peer.channel()).password_check(b"abc", 1, b"def")
        self.assertEqual(caught.exception.code, 7)

    def test_erase_busy_error_mask_and_write_verify_interleave(self):
        peer = RawPeer([b"\0\0", b"\x80\0", b"\0\0", b"\x80\0", b"\xff", b"\0"])
        writer = M16CWriter(peer.channel())
        writer.erase(0x1234FF)
        writer.page(0x123400, b"x" * 256)
        writer.page(0x123400, b"x" * 256, verify=True)
        self.assertEqual(
            peer.writes,
            [
                b"\xa6",
                bytes.fromhex("a13412d0"),
                b"\xa4",
                b"\xa4",
                b"\xa6",
                bytes.fromhex("a23412"),
                b"x" * 256,
                b"\xa4",
                b"\xa4",
                bytes.fromhex("a33412"),
                b"x" * 256,
                b"\xa8",
                b"\xa8",
            ],
        )
        self.assertEqual((writer.written, writer.verified), (256, 256))
        for operation, status, code in (
            ("erase", b"\xb0\0", 12),
            ("write", b"\x80\x02", 13),
            ("verify", b"\x01", 15),
        ):
            peer = RawPeer([status])
            writer = M16CWriter(peer.channel())
            with (
                self.subTest(operation=operation),
                self.assertRaises(M16CError) as caught,
            ):
                if operation == "erase":
                    writer.erase(255)
                else:
                    writer.page(0, b"x" * 256, verify=operation == "verify")
            self.assertEqual(caught.exception.code, code)

    def test_status_read_errors_only9_and16_are_probe_failures(self):
        for code in (9, 16):
            writer = M16CWriter(RawPeer([M16CReadError(code)]).channel())
            self.assertIsNone(writer.status())
        with self.assertRaises(M16CReadError):
            M16CWriter(RawPeer([M16CReadError(7)]).channel()).status()
        for value in (b"", b"x"):
            with self.assertRaises(ValueError):
                M16CWriter(RawPeer([value]).channel()).status()

    def test_prepare_retry_exact_bounded_dummy_sequence(self):
        peer = RawPeer([M16CReadError(9), M16CReadError(16), b"\0\0"])
        result = m16c_prepare_retry(
            peer.channel(), peer.controls(), wait_after_dummy_ms=5
        )
        self.assertEqual(result["state"], "writer_completed")
        self.assertEqual(peer.writes, [b"\xa4", b"\xa8", bytes(256), b"\xa4"])
        self.assertIn(("wait", 5), peer.events)
        self.assertEqual(peer.events[-1], ("stop_filter", 42))
        peer = RawPeer([M16CReadError(9)] * 7)
        result = m16c_prepare_retry(peer.channel(), peer.controls())
        self.assertEqual(result["native_error"], 20)
        self.assertEqual(peer.writes.count(b"\xa4"), 4)
        self.assertEqual(peer.writes.count(bytes(256)), 3)
        peer = RawPeer([M16CReadError(9), b"\xff"])
        M16CWriter(peer.channel()).prepare_retry()
        self.assertEqual(peer.writes, [b"\xa4", b"\xa8"])

    def run_m16c(self, peer, *, security=False, last_cpu=True, recovery=False):
        options = self.options(
            security=security,
            nonce=bytes(16),
            key=bytes(16),
            recovery=recovery,
            initial_timeout_ms=456,
        )
        channel = peer.channel()
        return m16c_write(
            channel,
            peer.controls(),
            (M16CSegment(0x1200, b"x" * 256),),
            options,
            finish_channel=channel,
            last_cpu=last_cpu,
        )

    def replies(self, *, security=False, last_cpu=True, recovery=False):
        result = [] if recovery else [b"\x3c", b"AUTH"]
        if security:
            result.append(b"\x3c")
        if not recovery:
            result.append(b"\0\x0c")
        result.extend((b"\x80\0", b"\x80\0", b"\0"))
        if not last_cpu:
            result.append(b"\x3c")
        return result

    def test_full_plain_and_security_native_flow_cleanup(self):
        for security in (False, True):
            for last_cpu in (False, True):
                peer = RawPeer(self.replies(security=security, last_cpu=last_cpu))
                result = self.run_m16c(peer, security=security, last_cpu=last_cpu)
                self.assertEqual(result["state"], "writer_completed", result)
                self.assertEqual((result["written"], result["verified"]), (256, 256))
                self.assertEqual(peer.writes[-1], b"\x80" if last_cpu else b"\x65")
                self.assertEqual(
                    peer.events[-2:], [("stop_filter", 42), ("set_timeout", 123)]
                )
                self.assertFalse(result["programming_completed"])
                self.assertEqual(peer.writes.count(b"\x37" + bytes(6)), int(security))
                self.assertFalse(peer.replies)

    def test_recovery_gates_authentication_but_security_nonce_stays(self):
        for security in (False, True):
            peer = RawPeer(self.replies(security=security, recovery=True))
            result = self.run_m16c(peer, security=security, recovery=True)
            self.assertEqual(result["state"], "writer_completed", result)
            self.assertFalse(any(p.startswith(b"\xa0") for p in peer.writes))
            self.assertEqual(
                peer.writes[0], b"\x37" + bytes(6) if security else b"\xa6"
            )

    def test_fault_every_consequential_m16c_io_restores_timeout_and_filter(self):
        baseline = RawPeer(self.replies())
        self.run_m16c(baseline)
        for index, (name, _value) in enumerate(baseline.events, 1):
            if name not in ("write", "read", "set_timeout"):
                continue
            peer = RawPeer(self.replies(), fail_at=index)
            result = self.run_m16c(peer)
            with self.subTest(index=index, name=name):
                self.assertNotEqual(result["state"], "writer_completed")
                self.assertIn(("stop_filter", 42), peer.events)
                self.assertEqual(peer.events[-1], ("set_timeout", 123))
                self.assertEqual(result["progress_bytes"], 0)

    def test_cancel_and_deadline_every_m16c_wire_boundary(self):
        baseline = RawPeer(self.replies())
        self.run_m16c(baseline)
        for index, (name, _value) in enumerate(baseline.events, 1):
            if name not in ("write", "read"):
                continue
            for interrupt in ("cancel_at", "late_at"):
                peer = RawPeer(self.replies())
                setattr(peer, interrupt, index)
                result = self.run_m16c(peer)
                with self.subTest(index=index, interrupt=interrupt):
                    self.assertEqual(result["state"], "recovery_required")
                    self.assertEqual(
                        peer.events[-2:], [("stop_filter", 42), ("set_timeout", 123)]
                    )

    def test_invalid_pages_context_and_partial_write_fail_before_more_io(self):
        for address, data in ((1, b"x" * 256), (0, b"x"), (0x1000000, b"x" * 256)):
            with self.assertRaises(ValueError):
                M16CSegment(address, data)
        peer = RawPeer()
        writer = M16CWriter(peer.channel())
        with self.assertRaises(ValueError):
            writer.erase(255, wait_ms=-1)
        self.assertFalse(peer.events)
        with self.assertRaises(ValueError):
            replace(self.options(), security=True)
        channel = VendorCAN(lambda payload, timeout: 0, lambda timeout: b"\0\0")
        with self.assertRaises(OSError):
            M16CWriter(channel).erase(255)

    def test_native_block_metadata_pairs_concatenated_image_and_kib_sizes(self):
        segments = m16c_segments(b"a" * 1024 + b"b" * 2048, (0x1200, 0x8000), (1, 2))
        self.assertEqual(
            segments,
            (M16CSegment(0x1200, b"a" * 1024), M16CSegment(0x8000, b"b" * 2048)),
        )
        for starts, sizes in (((0,), ()), ((0,), (0,)), ((0,), (2,))):
            with self.assertRaises(ValueError):
                m16c_segments(b"x" * 1024, starts, sizes)

    def test_igoff_retriable_and_optional_watch_memory_native_branches(self):
        # Recovery+IGOffRetriable still performs both parentCheckID and childA0.
        peer = RawPeer(
            [
                b"\x3c",
                b"AUTH",
                b"\x3c",
                bytes.fromhex("001000001fff010100"),
                b"\x3c",
                b"\0\x0c",
                b"\x80\0",
                b"\x80\0",
                b"\0",
            ]
        )
        channel = peer.channel()
        options = self.options(
            recovery=True, igoff_retriable=True, get_memory=True, wait_after_write_ms=17
        )
        result = m16c_write(
            channel,
            peer.controls(),
            (M16CSegment(0, b"x" * 256),),
            options,
            finish_channel=channel,
        )
        self.assertEqual(result["state"], "writer_completed", result)
        self.assertIn("memory_info", result)
        self.assertIn(b"\x76", peer.writes)
        self.assertIn(("wait", 17), peer.events)
        self.assertTrue(any(value.startswith(b"\xa0") for value in peer.writes))

    def test_cleanup_failures_remain_visible_and_both_cleanups_are_attempted(self):
        peer = RawPeer(self.replies())
        controls = peer.controls()

        def broken_stop(token):
            peer.event("stop_filter", token)
            raise OSError("filter cleanup failed")

        def broken_timeout(value):
            peer.event("set_timeout", value)
            if value == 123:
                raise OSError("timeout restore failed")

        result = m16c_write(
            peer.channel(),
            replace(controls, stop_filter=broken_stop, set_timeout=broken_timeout),
            (M16CSegment(0, b"x" * 256),),
            self.options(),
            finish_channel=peer.channel(),
        )
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(len(result["cleanup_errors"]), 2)
        self.assertEqual(peer.events[-2:], [("stop_filter", 42), ("set_timeout", 123)])

    def test_password_failure_retry_toggle_and_forced_retry_selection(self):
        for previous, force, expected in (
            (False, False, True),
            (True, False, False),
            (False, True, True),
        ):
            peer = RawPeer([b"\x3c", b"AUTH", b"\0\0"])
            channel = peer.channel()
            options = self.options(
                previous_retry_password=previous, force_retry_password=force
            )
            result = m16c_write(
                channel,
                peer.controls(),
                (M16CSegment(0, b"x" * 256),),
                options,
                finish_channel=channel,
            )
            self.assertEqual(result["native_error"], 7)
            self.assertEqual(result["retry_password"], expected)

    def test_host_status_poll_bound_and_missing_status_native_error(self):
        with self.assertRaisesRegex(TimeoutError, "poll budget"):
            M16CWriter(RawPeer([b"\0\0"] * 4096).channel()).erase(255)
        with self.assertRaises(M16CError) as error:
            M16CWriter(RawPeer([M16CReadError(9)]).channel()).erase(255)
        self.assertEqual(error.exception.code, 12)

    def vforest_replies(self, descriptor=0x01):
        # CheckID ACK+result; combined authenticationACK; extended memoryACK/data/ACK.
        # Each groupheaderACK/chunkACK/query50ACK/status/queryACK, then falsify47.
        return (
            [
                b"\x3c",
                b"AUTH",
                b"\x3c",
                b"\x3c",
                bytes.fromhex("001000001fff01") + bytes((descriptor, 0)),
                b"\x3c",
            ]
            + [b"\x3c", b"\x3c", b"\x3c", b"\0", b"\x3c"] * 2
            + [b"\x3c", b"\x3c", b"\0", b"\x3c"]
        )

    def run_vforest(self, peer, **kwargs):
        channel = peer.channel()
        return security_vforest_write(
            channel,
            peer.controls(),
            b"ZV\0\0\x01x",
            location_id=bytes(range(8)),
            password=1,
            nonce=bytes(16),
            key=bytes(16),
            policy=VForestPolicy(1, True),
            finish_channel=channel,
            **kwargs,
        )

    def test_security_vforest_actual_auth_memory_write_verify_detect_finish(self):
        peer = RawPeer(self.vforest_replies())
        result = self.run_vforest(peer)
        self.assertEqual(result["state"], "writer_completed", result)
        self.assertIn(b"\x42\0\0\0\0\xff", peer.writes)
        self.assertIn(b"\x17\0\0\0\0\xff", peer.writes)
        self.assertEqual(peer.writes[-3:], [b"\x47", b"\x50", b"\x80"])
        self.assertEqual(result["written"], 6)
        self.assertFalse(peer.replies)
        self.assertEqual(peer.events[-1], ("stop_filter", 42))

    def test_security_vforest_alternate_cpu_and_mismatch_no_data_writes(self):
        peer = RawPeer(self.vforest_replies(2))
        result = self.run_vforest(peer)
        self.assertEqual(result["native_error"], 10)
        self.assertFalse(any(p.startswith(b"\x42") for p in peer.writes))
        peer = RawPeer(self.vforest_replies(2))
        result = self.run_vforest(peer, alternate_policy=lambda: VForestPolicy(2, True))
        self.assertEqual(result["state"], "writer_completed", result)
        self.assertTrue(result["alternate_parameters_loaded"])

    def test_fault_every_security_vforest_wire_operation(self):
        baseline = RawPeer(self.vforest_replies())
        self.run_vforest(baseline)
        for index, (name, _value) in enumerate(baseline.events, 1):
            if name not in ("write", "read"):
                continue
            peer = RawPeer(self.vforest_replies(), fail_at=index)
            result = self.run_vforest(peer)
            with self.subTest(index=index, name=name):
                if result["state"] == "writer_completed":
                    previous_writes = [
                        value
                        for tag, value in baseline.events[:index]
                        if tag == "write"
                    ]
                    self.assertEqual(previous_writes[-1], b"\x50")
                    self.assertEqual(peer.writes.count(b"ZV\0\0\x01x"), 2)
                self.assertEqual(peer.events[-1], ("stop_filter", 42))

    def test_cancel_and_deadline_every_security_vforest_wire_boundary(self):
        baseline = RawPeer(self.vforest_replies())
        self.run_vforest(baseline)
        for index, (name, _value) in enumerate(baseline.events, 1):
            if name not in ("write", "read"):
                continue
            for interruption in ("cancel_at", "late_at"):
                peer = RawPeer(self.vforest_replies())
                setattr(peer, interruption, index)
                result = self.run_vforest(peer)
                with self.subTest(index=index, interruption=interruption):
                    self.assertEqual(result["state"], "recovery_required")
                    self.assertEqual(peer.events[-1], ("stop_filter", 42))

    def test_security_vforest_native_phase_error_codes(self):
        for response_index, code in ((9, 29), (14, 30), (18, 73)):
            replies = self.vforest_replies()
            replies[response_index] = b"\x01"
            peer = RawPeer(replies)
            result = self.run_vforest(peer)
            self.assertEqual(result["native_error"], code, result)

    def test_pre_cancelled_full_writer_has_no_implicit_control_or_data_io(self):
        peer = RawPeer()
        peer.interrupted = True
        result = self.run_m16c(peer)
        self.assertEqual(result["state"], "cancelled")
        self.assertFalse(peer.events)

    def test_native_progress_callbacks_and_versioned_failure_cleanup_order(self):
        for version in ("12", "18"):
            observed = []
            peer = RawPeer([b"\x3c", b"AUTH", b"\0\x0c", b"\x80\0", b"\x80\x02"])
            channel = peer.channel()

            def progress(count, percent, observed=observed, peer=peer):
                observed.append((count, percent))
                peer.events.append(("progress", (count, percent)))

            result = m16c_write(
                channel,
                peer.controls(),
                (M16CSegment(0, b"x" * 256),),
                self.options(version=version),
                finish_channel=channel,
                progress=progress,
            )
            self.assertEqual(result["native_error"], 13)
            self.assertEqual(
                observed,
                [(256, 0), (256, 50)] + ([(0, 50), (0, 0)] if version == "18" else []),
            )
            if version == "18":
                self.assertLess(
                    peer.events.index(("progress", (0, 0))),
                    peer.events.index(("stop_filter", 42)),
                )
        observed = []
        peer = RawPeer(self.replies())
        channel = peer.channel()
        result = m16c_write(
            channel,
            peer.controls(),
            (M16CSegment(0, b"x" * 256),),
            self.options(),
            finish_channel=channel,
            progress=lambda count, percent: observed.append((count, percent)),
        )
        self.assertEqual(result["state"], "writer_completed")
        self.assertEqual(observed, [(256, 0), (256, 50), (512, 50), (512, 100)])
        with self.assertRaises(ValueError):
            self.options(version="12", security=True, nonce=bytes(16), key=bytes(16))

    def test_security_vforest_progress_is_published_before_chunk_ack(self):
        peer = RawPeer(self.vforest_replies())
        observed = []

        def progress(count, percent):
            observed.append((count, percent))
            peer.events.append(("progress", (count, percent)))

        result = self.run_vforest(peer, progress=progress)
        self.assertEqual(result["state"], "writer_completed", result)
        self.assertEqual(observed, [(6, 0), (6, 50), (12, 50), (12, 100)])
        first = peer.events.index(("progress", (6, 0)))
        self.assertEqual(peer.events[first - 1], ("write", b"ZV\0\0\x01x"))
        self.assertEqual(peer.events[first + 2], ("read", None))
        with self.assertRaises(ValueError):
            self.run_vforest(RawPeer(), version="12")

    def test_actual_calibration_new_password_getter_and_retry_branch(self):
        image = bytes.fromhex("aabb11223344cc")
        self.assertEqual(new_password(image, 2, 0), 0x44332211)
        self.assertEqual(new_password(image, 2, 1), 0x11223344)
        self.assertEqual(new_password(image, 2, 65536), 0x44332211)
        self.assertEqual(new_password(None, 0, 0, explicit=0x55667788), 0x55667788)
        with self.assertRaises(ValueError):
            new_password(image, 4, 0)
        peer = RawPeer(self.vforest_replies())
        result = self.run_vforest(
            peer,
            previous_retry_password=True,
            replacement_password=new_password(image, 2, 1),
        )
        self.assertEqual(result["state"], "writer_completed", result)
        self.assertEqual(peer.writes[4], bytes.fromhex("44332211"))
        peer = RawPeer()
        with self.assertRaises(ValueError):
            self.run_vforest(peer, previous_retry_password=True)
        self.assertFalse(peer.events)

    def test_keyboard_interrupt_preserves_uncertainty_and_all_cleanup(self):
        baseline = RawPeer(self.replies())
        self.run_m16c(baseline)
        first_write = next(
            index
            for index, (name, _value) in enumerate(baseline.events, 1)
            if name == "write"
        )
        peer = RawPeer(self.replies(), fail_at=first_write, failure=KeyboardInterrupt())
        result = self.run_m16c(peer)
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(result["error"], "KeyboardInterrupt")
        self.assertEqual(result["progress_bytes"], 0)
        self.assertEqual(peer.events[-2:], [("stop_filter", 42), ("set_timeout", 123)])
        peer = RawPeer(self.replies())
        controls = peer.controls()

        def interrupted_stop(token):
            peer.event("stop_filter", token)
            raise KeyboardInterrupt()

        channel = peer.channel()
        result = m16c_write(
            channel,
            replace(controls, stop_filter=interrupted_stop),
            (M16CSegment(0, b"x" * 256),),
            self.options(),
            finish_channel=channel,
        )
        self.assertEqual(result["cleanup_errors"], ["KeyboardInterrupt"])
        self.assertEqual(peer.events[-1], ("set_timeout", 123))

    def test_simultaneous_io_failure_and_interruption_retains_observed_error(self):
        baseline = RawPeer(self.replies())
        self.run_m16c(baseline)
        for phase in ("write", "read"):
            index = next(
                index
                for index, (name, _value) in enumerate(baseline.events, 1)
                if name == phase
            )
            for kind in ("cancel_at", "late_at"):
                peer = RawPeer(self.replies(), fail_at=index)
                setattr(peer, kind, index)
                result = self.run_m16c(peer)
                with self.subTest(phase=phase, kind=kind):
                    self.assertEqual(result["state"], "recovery_required")
                    self.assertEqual(result["observed_error"], "authored I/O fault")


def authored_m16c_input(
    module="TCUWCanM16CFlashWriter.dll",
    *,
    build=18,
    child_last=False,
    parameters=None,
    metadata_extra="",
    payload=None,
):
    from scripts.calibration import parse_cuw
    from scripts.calibration_catalog import CalibrationCatalog, parse_parameter_table
    from scripts.demo_calibration import table
    from scripts.native_modules import _BUILDS, identify_native_module
    from tests.test_calibration import metadata_container

    vforest = "VFOREST" in module
    child = (
        "CPUType=M16C\nCPUImageName=child.vbf\nLocationID=0108010000000720\n"
        "NumberOfTargets=1\n01_TargetCalibration=CHILD-OLD\n01_TargetData=A1B2C3D4\n"
        + ("" if "NewPassword=" in metadata_extra else "NewPassword=11223344\n")
        + "Nonce="
        + bytes(16).hex()
        + "\nSeedKey="
        + bytes(range(16)).hex()
        + "\n"
        + metadata_extra
    )
    parent = (
        "CPUType=WATCH\nCPUImageName=parent.vbf\nLocationID=0208020000000720\n"
        "NumberOfTargets=1\n01_TargetCalibration=PARENT-OLD\n01_TargetData=12345678\n"
    )
    cpus = [child] if vforest else [parent, child] if child_last else [child, parent]
    metadata = (
        "[Format]\nVersion=6\n[Vehicle]\nNumberOfCalibration="
        + str(len(cpus))
        + "\nKindOfECU=1\nContactType=CAN\n"
        + "".join(f"[CPU{i:02}]\n{cpu}" for i, cpu in enumerate(cpus, 1))
    )
    image = (
        (b"ZV\0\0\x01x" if vforest else bytes(range(256)) * 4)
        if payload is None
        else payload
    )
    records = (
        [(b"child", image)]
        if vforest
        else (
            [(b"parent", bytes(1024)), (b"child", image)]
            if child_last
            else [(b"child", image), (b"parent", bytes(1024))]
        )
    )
    container = parse_cuw(metadata_container(metadata, records, len(records)))
    data = {
        "DLLFileNameForFlashWrite": module,
        "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromLocationIDForWrite",
        "ParentCPUTypeList": "WATCH",
        "BlockSizeInfo": "0:1x1",
        "StartAddress": "00010000",
        "PasswordCheckIDAddress": "12\n34\n56",
        "PasswordCheckPassword": "ab\ncd\nef",
        "ReceiveTimeoutBeforeFlashWrite": "777",
        "CPUIDNo": "01",
        "ShrinkFlag": "1",
        "WaitTimeAfterSendDummyData": "17",
    }
    data.update(parameters or {})
    headers = ("ParamFileKeySystemProtocolMicon", *data)
    catalog = CalibrationCatalog(
        [
            parse_parameter_table(
                name + ".ini",
                table(
                    headers,
                    [("1CANM16C", *data.values()), ("1CANWATCH", *data.values())],
                ),
                encoded=False,
            )
            for name in ("1CANM16C", "1CANWATCH")
        ]
    )
    digest = next(
        digest
        for digest, (builds, name) in _BUILDS.items()
        if name == module and str(build) in builds
    )
    return (
        container,
        catalog.select("1CANWATCH" if child_last else "1CANM16C"),
        identify_native_module(digest, module),
    )


class ImportedM16CTests(unittest.TestCase):
    cids = ("CHILD-OLD", "PARENT-OLD")

    def test_native_password_parameters_copy_first_cbytes_byte(self):
        inputs = authored_m16c_input(
            parameters={
                "PasswordCheckIDAddress": "1200\n34ff\n56ab",
                "PasswordCheckPassword": "ab00\ncdff\nef12",
            }
        )
        bound = bind_m16c_context(inputs[0], 1, self.cids, *inputs[1:])
        assert bound.options is not None
        self.assertEqual(bound.options.id_address, bytes.fromhex("123456"))
        self.assertEqual(bound.options.password_suffix, bytes.fromhex("abcdef"))
        for value in ("1\n34\n56", "12 00\n34\n56", "12\n34", "12" * 130 + "\n34\n56"):
            invalid = authored_m16c_input(parameters={"PasswordCheckIDAddress": value})
            with self.assertRaises(ValueError):
                bind_m16c_context(invalid[0], 1, self.cids, *invalid[1:])

    def test_imported_cuw_catalog_all_native_builds_actual_raw_exchange(self):
        for module, build in (
            ("TCUWCanM16CFlashWriter.dll", 12),
            ("TCUWCanM16CFlashWriter.dll", 18),
            ("TCUWCanSecurityM16CFlashWriter.dll", 18),
        ):
            for child_last in (False, True):
                with self.subTest(module=module, build=build, child_last=child_last):
                    inputs = authored_m16c_input(
                        module, build=build, child_last=child_last
                    )
                    bound = bind_m16c_context(
                        *inputs[:1],
                        1,
                        self.cids,
                        *inputs[1:],
                        observations={"cpu_index": int(child_last)},
                    )
                    assert bound.options is not None
                    self.assertEqual(bound.parent_index, int(not child_last))
                    self.assertEqual(
                        bound.options.location_id, bytes.fromhex("0208020000000720")
                    )
                    self.assertEqual(bound.options.parent_password, 0x12345678)
                    self.assertEqual(bound.options.password, 0xA1B2C3D4)
                    self.assertEqual(bound.target_metadata[0].request, b"\x02\0")
                    self.assertEqual(bound.segments[0].address, 0x10000)
                    security = "Security" in module
                    replies = [b"\x3c", b"AUTH"] + ([b"\x3c"] if security else [])
                    replies += [b"\0\x0c", b"\x80\0"] + [b"\x80\0", b"\0"] * 4
                    replies += [] if child_last else [b"\x3c"]
                    peer = RawPeer(replies)
                    channel = peer.channel()
                    result = m16c_write(
                        channel,
                        peer.controls(),
                        bound.segments,
                        bound.options,
                        last_cpu=bound.last_cpu,
                        finish_channel=channel if child_last else None,
                    )
                    self.assertEqual(result["state"], "writer_completed", result)
                    self.assertFalse(peer.replies)
                    self.assertEqual(
                        peer.writes[-1], b"\x80" if child_last else b"\x65"
                    )
                    self.assertIn(bytes.fromhex("a1b2c3d4abcdef"), peer.writes)
                    self.assertEqual(bound.segments[0].data, bytes(range(256)) * 4)

    def test_imported_security_vforest_native_auth_and_groups(self):
        inputs = authored_m16c_input("TCUWCanSecurityVFORESTFlashWriter.dll")
        bound = bind_m16c_context(inputs[0], 1, self.cids, *inputs[1:])
        peer = RawPeer(M16CTests().vforest_replies())
        channel = peer.channel()
        result = security_vforest_write(
            channel,
            peer.controls(),
            bound.image,
            finish_channel=channel,
            **bound.vforest_options,
        )
        self.assertEqual(result["state"], "writer_completed", result)
        self.assertFalse(peer.replies)
        self.assertEqual(bound.vforest_options["password"], 0xA1B2C3D4)
        self.assertEqual(bound.vforest_options["key"], bytes(range(16)))
        self.assertEqual(bound.target_metadata[1].request, bytes.fromhex("0720"))

    def test_prepare_retry_needs_no_password_observation_and_uses_native_wait(self):
        inputs = authored_m16c_input()
        bound = bind_m16c_context(
            inputs[0], 1, (), *inputs[1:], observations={"stage": "prepare_retry"}
        )
        self.assertEqual(bound.stage, "prepare_retry")
        self.assertEqual(bound.wait_after_dummy_ms, 17)
        self.assertIsNone(bound.options)
        self.assertFalse(bound.segments)
        peer = RawPeer([M16CReadError(9), M16CReadError(16), b"\x80\0"])
        result = m16c_prepare_retry(
            peer.channel(),
            peer.controls(),
            wait_after_dummy_ms=bound.wait_after_dummy_ms,
        )
        self.assertEqual(result["state"], "writer_completed", result)
        self.assertEqual(peer.writes, [b"\xa4", b"\xa8", bytes(256), b"\xa4"])
        self.assertIn(("wait", 17), peer.events)
        for module in (
            "TCUWCanSecurityM16CFlashWriter.dll",
            "TCUWCanSecurityVFORESTFlashWriter.dll",
        ):
            inputs = authored_m16c_input(module)
            with self.assertRaises(ValueError):
                bind_m16c_context(
                    inputs[0],
                    1,
                    (),
                    *inputs[1:],
                    observations={"stage": "prepare_retry"},
                )

    def test_unused_new_password_metadata_does_not_change_m16c_old_password(self):
        for module in (
            "TCUWCanM16CFlashWriter.dll",
            "TCUWCanSecurityM16CFlashWriter.dll",
        ):
            inputs = authored_m16c_input(
                module,
                metadata_extra="NewPassword=not-a-password\nPasswordAddress=invalid\n",
            )
            bound = bind_m16c_context(inputs[0], 1, self.cids, *inputs[1:])
            assert bound.options is not None
            self.assertEqual(bound.options.password, 0xA1B2C3D4)

    def test_vforest_resolves_new_password_only_for_observed_retry_branch(self):
        inputs = authored_m16c_input("TCUWCanSecurityVFORESTFlashWriter.dll")
        bound = bind_m16c_context(
            inputs[0],
            1,
            self.cids,
            *inputs[1:],
            observations={"previous_retry_password": True},
        )
        self.assertEqual(bound.vforest_options["replacement_password"], 0x11223344)
        peer = RawPeer(M16CTests().vforest_replies())
        channel = peer.channel()
        result = security_vforest_write(
            channel,
            peer.controls(),
            bound.image,
            finish_channel=channel,
            **bound.vforest_options,
        )
        self.assertEqual(result["state"], "writer_completed", result)
        self.assertIn(bytes.fromhex("44332211"), peer.writes)
        malformed = authored_m16c_input(
            "TCUWCanSecurityVFORESTFlashWriter.dll",
            metadata_extra="NewPassword=invalid\n",
        )
        self.assertIsNone(
            bind_m16c_context(
                malformed[0], 1, self.cids, *malformed[1:]
            ).vforest_options["replacement_password"]
        )
        with self.assertRaises(ValueError):
            bind_m16c_context(
                malformed[0],
                1,
                self.cids,
                *malformed[1:],
                observations={"previous_retry_password": True},
            )

    def test_vforest_alternate_catalog_lookup_is_native_lazy_branch(self):
        inputs = authored_m16c_input(
            "TCUWCanSecurityVFORESTFlashWriter.dll",
            parameters={"AlternateCPUType": "UNAVAILABLE"},
        )
        bound = bind_m16c_context(inputs[0], 1, self.cids, *inputs[1:])
        for descriptor, expected in ((1, "writer_completed"), (2, "recovery_required")):
            peer = RawPeer(M16CTests().vforest_replies(descriptor))
            channel = peer.channel()
            result = security_vforest_write(
                channel,
                peer.controls(),
                bound.image,
                finish_channel=channel,
                **bound.vforest_options,
            )
            self.assertEqual(result["state"], expected, result)
            if descriptor == 2:
                self.assertFalse(any(p.startswith(b"\x42") for p in peer.writes))

    def test_raw_native_addresses_strip_only_extended_protocol_byte(self):
        inputs = authored_m16c_input(
            child_last=True,
            parameters={
                "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromLocationIDForWrite"
            },
        )
        # A non-0720 functional selector is native 0740fe; raw M16C uses first2.
        from scripts.calibration import CalibrationRecord, parse_cuw
        from tests.test_calibration import metadata_container

        metadata = (
            inputs[0].attached.data.decode("cp1252").replace("00000720", "00000721")
        )
        records = [(record.header, record.data) for record in inputs[0].records]
        container = parse_cuw(metadata_container(metadata, records, 2))
        self.assertIsInstance(container.attached, CalibrationRecord)
        bound = bind_m16c_context(
            container, 1, self.cids, *inputs[1:], observations={"cpu_index": 1}
        )
        self.assertEqual(bound.target_metadata[1].request, bytes.fromhex("0740"))
        self.assertFalse(bound.target_metadata[1].extended)

    def test_context_rejects_operator_geometry_identity_and_auth_contradictions(self):
        inputs = authored_m16c_input("TCUWCanSecurityM16CFlashWriter.dll")
        for observations in (
            {"StartAddress": 1},
            {"recovery": 1},
            {"cpu_index": True},
            {"stage": "erase"},
        ):
            with (
                self.subTest(observations=observations),
                self.assertRaises((ValueError, TypeError)),
            ):
                bind_m16c_context(
                    inputs[0], 1, self.cids, *inputs[1:], observations=observations
                )
        for attachments in (
            {"authorized_key": b"x" * 16},
            {"password": bytes(16)},
            {"nonce": bytes(15)},
        ):
            with self.subTest(attachments=attachments), self.assertRaises(ValueError):
                bind_m16c_context(
                    inputs[0], 1, self.cids, *inputs[1:], attachments=attachments
                )
        with self.assertRaises(ValueError):
            bind_m16c_context(
                inputs[0], 1, self.cids, inputs[1], replace(inputs[2], cuw_build="12")
            )
        with self.assertRaises(ValueError):
            bind_m16c_context(inputs[0], 1, (), *inputs[1:])
        for params in (
            {"ParentCPUTypeList": "MISSING"},
            {"BlockSizeInfo": "0:2x1"},
            {"StartAddress": "100000000"},
        ):
            malformed = authored_m16c_input(parameters=params)
            with self.subTest(params=params), self.assertRaises(ValueError):
                bind_m16c_context(malformed[0], 1, self.cids, *malformed[1:])


if __name__ == "__main__":
    unittest.main()
