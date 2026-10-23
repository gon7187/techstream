"""Authored CUW2026 persistence checks; no vendor data or devices."""

import dataclasses
import hashlib
import stat
import struct
import tempfile
import tracemalloc
import unittest
import zlib
from pathlib import Path
from typing import Any

from scripts.cuw_large import MIN_SIZE, LargeSource2026, native_large_cuw_2026
from scripts.cuw_persistence import (
    CUWPersistence,
    ProgrammingLogInfo,
    RecoveryCalibration,
    RecoveryDocument,
    ReproInfoState,
    RequestedAddress,
    build_programming_log_info,
    calibration_source_identity,
    decode_nibble_text,
    encode_nibble_text,
    encode_recovery_info,
    load_recovery_state,
    parse_recovery_info,
)
from scripts.programming_2026_common import NotificationBool


def state(multi=False):
    calibrations = tuple(
        RecoveryCalibration(
            f"C:\\authored\\file{i}.cuw",
            f"authored-source-{i}".encode(),
            ("AUTHORED-CID",),
            (RequestedAddress("750", False),),
            ("AUTHORED-ASSY",),
            (True, False),
            (False, True),
        )
        for i in range(1, 3 if multi else 2)
    )
    return ReproInfoState(
        calibrations,
        multi_calibration_file_num=2 if multi else 0,
        selected_j2534_device="authored-device",
        vin="AUTHORED-VIN",
        is_suzuki_repro_security_supported=True,
    )


class PersistenceTests(unittest.TestCase):
    def test_engine_owner_is_associated_before_loaded_source_validation(self):
        from scripts.cuw_2026 import CUWEngine2026

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        with tempfile.TemporaryDirectory() as root:
            persistence = CUWPersistence(Path(root), state())
            with CUWEngine2026(image.read_bytes()) as engine:
                engine.bind_persistence(persistence)
                self.assertIs(engine.persistence, persistence)
                self.assertIs(persistence._engine, engine)
                with self.assertRaisesRegex(
                    ValueError, "Load CUW before validating persistence source"
                ):
                    persistence.bind_engine_source(engine)
                self.assertIs(persistence._engine, engine)

    def test_file_source_association_separates_original_index_from_live_flow(self):
        from scripts.cuw_file_services import admit_file_sources_2026
        from tests.test_cuw_engine_worker import EngineWorker2026Tests, calibration

        raw = calibration(cpus=2)
        fixture = EngineWorker2026Tests("runTest")
        engine = fixture.engine(raw)
        self.addCleanup(engine.close)
        with tempfile.TemporaryDirectory() as root:
            info = ReproInfoState(
                (RecoveryCalibration("direct.cuw", raw),),
            )
            persistence = CUWPersistence(Path(root), info)
            engine.bind_persistence(persistence)
            sources = admit_file_sources_2026(engine, "direct.cuw", raw, region=0)
            engine.bind_file_sources(sources)
            self.assertEqual(
                sources.recovery_index_for_metadata(engine.native_metadata), 0
            )

            info.calibration_file_index = 1
            with self.assertRaisesRegex(ValueError, "Recovery file index"):
                persistence.validate_file_source_association(
                    sources, engine.native_metadata
                )
            self.assertEqual(
                persistence._validate_file_source_membership(
                    sources, engine.native_metadata
                ),
                0,
            )

    def test_codec_sorted_crlf_source_preserving_and_all_noise(self):
        raw = b"[RecoveryInfo]\r\nWriting=1"
        for value in range(4):
            encoded = encode_nibble_text(raw, lambda value=value: value)
            self.assertEqual(decode_nibble_text(encoded), raw)
            document = parse_recovery_info(encoded)
            self.assertEqual(document.to_bytes(), encoded)
        info = state(True)
        for calibration in info.calibrations:
            calibration.saved_path = "Save/" + Path(calibration.source_path).name
        encoded = encode_recovery_info(info)
        plain = decode_nibble_text(encoded)
        self.assertTrue(plain.startswith(b"[InfoInStorage]\r\n"))
        self.assertFalse(plain.endswith(b"\r\n"))
        parsed = parse_recovery_info(encoded)
        self.assertEqual(
            parsed.sections["RecoveryInfo"]["MultiCalibrationFileNum"], "2"
        )
        self.assertEqual(parsed.sections["RecoveryInfo2"]["CID1"], "AUTHORED-CID")
        self.assertNotIn("CIDNodeNum", parsed.sections["RecoveryInfo"])

    def test_actual_shared_notification_files_and_cpu_updates(self):
        with tempfile.TemporaryDirectory() as root:
            info = state(True)
            persistence = CUWPersistence(Path(root), info)
            self.assertIsInstance(persistence.notification, NotificationBool)
            self.assertFalse(list(Path(root).iterdir()))
            persistence.notification.assign(False)
            self.assertFalse(list(Path(root).iterdir()))
            persistence.notification.assign(True)
            self.assertTrue(info.writing)
            self.assertTrue(info.logged)
            for i, calibration in enumerate(info.calibrations, 1):
                path = Path(root) / "Save" / f"{i}_file{i}.cuw"
                self.assertEqual(path.read_bytes(), calibration.source_bytes)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            recovery = Path(root) / "Save" / "RecoveryInfo.ini"
            self.assertEqual(stat.S_IMODE(recovery.stat().st_mode), 0o600)
            self.assertEqual(
                parse_recovery_info(recovery.read_bytes()).sections["InfoInStorage"][
                    "IsSuzukiReproSecuritySupported"
                ],
                "1",
            )
            count = len(persistence.events)
            persistence.notification.assign(True)
            self.assertGreater(len(persistence.events), count)
            persistence.update_cpu(3)
            self.assertEqual(
                parse_recovery_info(recovery.read_bytes()).sections["RecoveryInfo"][
                    "WriteCpuIndex"
                ],
                "3",
            )
            persistence.notification.assign(False)
            self.assertTrue(info.writing)  # native309d0 false does nothing
            self.assertNotIn("AUTHORED-VIN", str(persistence.report()))

    def test_unrelated_outputs_and_symlinks_are_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root) / "Save"
            folder.mkdir()
            other = folder / "unrelated"
            other.write_bytes(b"keep")
            (folder / "RecoveryInfo.ini").write_bytes(b"not-owned")
            persistence = CUWPersistence(Path(root), state())
            with self.assertRaises(FileExistsError):
                persistence.notification.assign(True)
            self.assertEqual(other.read_bytes(), b"keep")
            self.assertEqual((folder / "RecoveryInfo.ini").read_bytes(), b"not-owned")
            self.assertFalse((folder / "file1.cuw").exists())
        with (
            tempfile.TemporaryDirectory() as root,
            tempfile.TemporaryDirectory() as outside,
        ):
            (Path(root) / "Save").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(OSError):
                CUWPersistence(Path(root), state()).notification.assign(True)
            self.assertFalse(list(Path(outside).iterdir()))

    def test_replaced_save_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            persistence = CUWPersistence(Path(root), state())
            persistence.notification.assign(True)
            saved = Path(root) / "Save"
            saved.rename(Path(root) / "preserved")
            saved.mkdir()
            with self.assertRaises(ValueError):
                persistence.update_cpu(2)
            self.assertFalse(list(saved.iterdir()))
            self.assertTrue((Path(root) / "preserved/RecoveryInfo.ini").exists())

    def test_every_file_boundary_fault_cancel_deadline_is_uncertain(self):
        with tempfile.TemporaryDirectory() as root:
            successful = CUWPersistence(Path(root), state())
            successful.notification.assign(True)
            total = len(successful.events)
        for kind in ("fault", "cancel", "deadline"):
            for failure in range(total):
                with (
                    self.subTest(kind=kind, failure=failure),
                    tempfile.TemporaryDirectory() as root,
                ):
                    now, cancelled = [0.0], [False]

                    def hook(
                        operation,
                        index,
                        failure=failure,
                        kind=kind,
                        cancelled=cancelled,
                        now=now,
                    ):
                        if index == failure:
                            if kind == "fault":
                                raise OSError("authored I/O fault")
                            if kind == "cancel":
                                cancelled[0] = True
                            else:
                                now[0] = 31

                    info = state()
                    persistence = CUWPersistence(
                        Path(root),
                        info,
                        clock=lambda now=now: now[0],
                        cancelled=lambda cancelled=cancelled: cancelled[0],
                        fault_hook=hook,
                    )
                    with self.assertRaises((OSError, InterruptedError, TimeoutError)):
                        persistence.notification.assign(True)
                    self.assertTrue(persistence.notification.value)
                    self.assertFalse(info.logged)
                    self.assertFalse(list(Path(root).rglob(".cuw-*.tmp")))
                    for path in Path(root).rglob("*"):
                        if path.is_file():
                            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_divided_image_callback_uses_same_state_and_logged_gate(self):
        with tempfile.TemporaryDirectory() as root:
            persistence = CUWPersistence(Path(root), state())
            persistence.update_divided_image(3)
            self.assertFalse((Path(root) / "Save").exists())
            persistence.notification.assign(True)
            persistence.update_divided_image(4)
            document = parse_recovery_info(
                (Path(root) / "Save/RecoveryInfo.ini").read_bytes()
            )
            self.assertEqual(
                document.sections["RecoveryInfo"]["WriteTargetDividedCPUImageIndex"],
                "4",
            )

    def test_restore_capacity_relocation_replacement_and_delete(self):
        info = state()
        info.calibrations[0].saved_path = r"C:\old\Save\file1.cuw"
        document = parse_recovery_info(encode_recovery_info(info))
        attached = {info.calibrations[0].saved_path: info.calibrations[0].source_bytes}
        loaded = load_recovery_state(document, attached, cpu_capacity=3)
        self.assertEqual(loaded.calibrations[0].update_available, (True, False, False))
        self.assertEqual(
            loaded.calibrations[0].assembly_numbers, ("AUTHORED-ASSY", "", "")
        )
        self.assertFalse(loaded.loaded)
        with tempfile.TemporaryDirectory() as root:
            persistence = CUWPersistence.import_recovery(
                Path(root), document, attached, cpu_capacity=3
            )
            self.assertTrue(persistence.state.loaded)
            self.assertEqual(
                (Path(root) / "Save/RecoveryInfo.ini").read_bytes(), document.to_bytes()
            )
            persistence.notification.assign(True)
            original = persistence.state.calibrations[0]
            persistence.replace_calibration(
                0, RecoveryCalibration("new.cuw", b"new authored source")
            )
            replacement = persistence.state.calibrations[0]
            self.assertEqual(replacement.cids, original.cids)
            self.assertEqual(replacement.update_available, original.update_available)
            self.assertTrue(replacement.whole_repro)
            self.assertFalse((Path(root) / "Save/file1.cuw").exists())
            self.assertEqual(
                (Path(root) / "Save/1_new.cuw").read_bytes(), b"new authored source"
            )
            persistence.delete_recovery()
            self.assertEqual(persistence.state.calibrations, ())
            self.assertFalse(persistence.state.logged)
            self.assertFalse(list((Path(root) / "Save").iterdir()))
        with self.assertRaises(ValueError):
            load_recovery_state(document, {}, cpu_capacity=3)

    def test_actual_programming_log_buffer_and_error_flags(self):
        arguments: dict[str, Any] = {
            "calibration_path": r"C:\authored\file.cuw",
            "receiving_status": 0x138C,
            "reprogramming_status": 0,
            "current_cpu": 1,
            "cpu_offset": 2,
            "progress_base": 0,
            "complete": False,
            "controller_present": True,
            "percentages": (7, 42),
            "error_code": 0,
            "exchange_data": bytes.fromhex("07587f2231"),
            "address_size": 2,
            "connected": True,
            "voltage": 12.5,
        }
        info = build_programming_log_info(**arguments)
        self.assertIsNotNone(info)
        assert info is not None
        self.assertEqual((info.error_flag, info.nrc, info.percent), (4, "31", 42))
        self.assertEqual(info.error_text, "0758 SID7F2231")
        raw = info.to_bytes(b"X" * 0x2160)
        self.assertEqual(raw[:9], b"file.cuw\x00")
        self.assertEqual(raw[0x104:0x108], b"\xff" * 4)
        self.assertEqual(raw[0x2151:0x2154], b"XXX")
        self.assertEqual(raw[-1:], b"X")
        for code, voltage, flag in (
            (0, 1.0, 6),
            (8, 12.0, 5),
            (9, 12.0, 2),
            (16, 12.0, 2),
            (23, 12.0, 1),
        ):
            result = build_programming_log_info(
                **(arguments | {"error_code": code, "voltage": voltage})
            )
            assert result is not None
            self.assertEqual(result.error_flag, flag)
        unavailable: dict[str, Any] = arguments | {"receiving_status": 0}
        self.assertIsNone(build_programming_log_info(**unavailable))
        with self.assertRaises(ValueError):
            ProgrammingLogInfo("bad\x00name", 0, 0, "-", 1, 0, "")

    def test_alternate_progress_keeps_regular_percentage_cpu(self):
        result = build_programming_log_info(
            calibration_path="authored.cuw",
            receiving_status=0x138C,
            reprogramming_status=0,
            current_cpu=1,
            cpu_offset=0,
            progress_base=0,
            complete=False,
            controller_present=True,
            percentages=(10, 20, 30),
            error_code=0,
            exchange_data=b"",
            address_size=0,
            connected=False,
            voltage=None,
            alternate_progress_active=True,
            alternate_current_cpu=2,
            alternate_cpu_offset=0,
            alternate_progress_base=5,
        )
        assert result is not None
        self.assertEqual((result.cpu_progress_index, result.percent), (7, 20))

    def test_regular_file_replaced_during_atomic_commit_is_preserved(self):
        with tempfile.TemporaryDirectory() as root:

            def hook(operation, index):
                if operation == "atomic_replace":
                    (Path(root) / "Save/file1.cuw").write_bytes(
                        b"unrelated replacement"
                    )

            persistence = CUWPersistence(Path(root), state(), fault_hook=hook)
            with self.assertRaises(FileExistsError):
                persistence.notification.assign(True)
            self.assertEqual(
                (Path(root) / "Save/file1.cuw").read_bytes(), b"unrelated replacement"
            )
            self.assertFalse(list(Path(root).rglob(".cuw-*.tmp")))

    def test_restore_replace_delete_every_boundary_fault_cancel_deadline(self):
        for operation in ("import", "replace", "delete", "last_block"):

            def run(root, kind=None, failure=None, operation=operation):
                now, cancelled, calls = [0.0], [False], [0]

                def hook(event, index):
                    count = calls[0]
                    calls[0] += 1
                    if count == failure:
                        if kind == "fault":
                            raise OSError("authored boundary")
                        if kind == "cancel":
                            cancelled[0] = True
                        else:
                            now[0] = 31

                options = {"clock": lambda: now[0], "cancelled": lambda: cancelled[0]}
                if operation == "import":
                    info = state()
                    info.calibrations[0].saved_path = "Save/file1.cuw"
                    document = parse_recovery_info(encode_recovery_info(info))
                    CUWPersistence.import_recovery(
                        Path(root),
                        document,
                        {"Save/file1.cuw": b"authored source"},
                        cpu_capacity=2,
                        fault_hook=hook,
                        **options,
                    )
                else:
                    persistence = CUWPersistence(Path(root), state(), **options)
                    persistence.notification.assign(True)
                    persistence.fault_hook = hook
                    if operation == "replace":
                        persistence.replace_calibration(
                            0, RecoveryCalibration("new.cuw", b"authored replacement")
                        )
                    elif operation == "last_block":
                        persistence.last_block_notification.assign(True)
                    else:
                        persistence.delete_recovery()
                return calls[0]

            with tempfile.TemporaryDirectory() as root:
                boundaries = run(root)
            for kind in ("fault", "cancel", "deadline"):
                for failure in range(boundaries):
                    with (
                        self.subTest(operation=operation, kind=kind, failure=failure),
                        tempfile.TemporaryDirectory() as root,
                    ):
                        unrelated = Path(root) / "unrelated"
                        unrelated.write_bytes(b"preserve")
                        with self.assertRaises(
                            (OSError, InterruptedError, TimeoutError)
                        ):
                            run(root, kind, failure)
                        self.assertEqual(unrelated.read_bytes(), b"preserve")
                        self.assertFalse(list(Path(root).rglob(".cuw-*.tmp")))

    def test_nonfinite_clock_rejected_at_constructor_and_boundary(self):
        for invalid in (float("nan"), float("inf"), float("-inf"), True):
            with tempfile.TemporaryDirectory() as root:
                with self.assertRaises(ValueError):
                    CUWPersistence(
                        Path(root), state(), clock=lambda invalid=invalid: invalid
                    )
                now = [0.0]
                persistence = CUWPersistence(
                    Path(root), state(), clock=lambda now=now: now[0]
                )
                now[0] = invalid
                with self.assertRaises(ValueError):
                    persistence.notification.assign(True)
                self.assertFalse((Path(root) / "Save").exists())

    def test_externally_changed_owned_files_are_never_overwritten_or_deleted(self):
        for name in ("file1.cuw", "RecoveryInfo.ini"):
            for delete in (False, True):
                with tempfile.TemporaryDirectory() as root:
                    persistence = CUWPersistence(Path(root), state())
                    persistence.notification.assign(True)
                    target = Path(root) / "Save" / name
                    target.write_bytes(b"external content")
                    with self.assertRaises(OSError):
                        if delete:
                            persistence.delete_recovery()
                        elif name == "RecoveryInfo.ini":
                            persistence.update_cpu(2)
                        else:
                            persistence.replace_calibration(
                                0, RecoveryCalibration("new.cuw", b"new authored data")
                            )
                    self.assertEqual(target.read_bytes(), b"external content")

    def test_identical_existing_multiple_cache_files_are_adopted_per_file(self):
        with tempfile.TemporaryDirectory() as root:
            info = state(True)
            saved = Path(root) / "Save"
            saved.mkdir()
            for index, calibration in enumerate(info.calibrations, 1):
                assert isinstance(calibration.source_bytes, bytes)
                (saved / f"{index}_file{index}.cuw").write_bytes(
                    calibration.source_bytes
                )
            persistence = CUWPersistence(Path(root), info)
            persistence.notification.assign(True)
            persistence.update_cpu(1)
            self.assertTrue(info.logged)
            persistence.delete_recovery()
            self.assertFalse(list(saved.iterdir()))

    def test_loader_truncates_native_requested_address_after_selecting_type(self):
        info = state()
        info.calibrations[0].saved_path = "Save/file1.cuw"
        raw = decode_nibble_text(encode_recovery_info(info)).replace(
            b"CIDRequestedCanID1=750",
            b"CIDRequestedCanID1=123456789\r\nCIDRequestedLogicalAddress1=ABCDEF0123",
        )
        loaded = load_recovery_state(
            parse_recovery_info(raw, encoded=False),
            {"Save/file1.cuw": b"authored"},
            cpu_capacity=2,
        )
        self.assertEqual(
            loaded.calibrations[0].requested_addresses,
            (RequestedAddress("ABCDEF", True),),
        )

    def test_detached_save_is_rejected_before_atomic_commit(self):
        with (
            tempfile.TemporaryDirectory() as root,
            tempfile.TemporaryDirectory() as outside,
        ):

            def hook(operation, index):
                if operation == "atomic_replace":
                    (Path(root) / "Save").rename(Path(outside) / "detached")
                    (Path(root) / "Save").mkdir()

            persistence = CUWPersistence(Path(root), state(), fault_hook=hook)
            with self.assertRaises(ValueError):
                persistence.notification.assign(True)
            self.assertFalse(list((Path(root) / "Save").iterdir()))
            self.assertFalse(list((Path(outside) / "detached").iterdir()))

    def test_native_byte_strings_preserve_all_high_bytes_without_guessed_locale(self):
        values = bytes(range(128, 256))
        info = state()
        info.vin = values.decode("latin1")
        info.calibrations[0].saved_path = "Save/file1.cuw"
        encoded = encode_recovery_info(info)
        document = parse_recovery_info(encoded)
        self.assertEqual(
            document.sections["RecoveryInfo"]["VIN"].encode("latin1"), values
        )
        self.assertEqual(document.to_bytes(), encoded)
        loaded = load_recovery_state(
            document, {"Save/file1.cuw": b"authored source"}, cpu_capacity=2
        )
        self.assertEqual(loaded.vin.encode("latin1"), values)

    def test_forged_document_fields_or_encoding_fail_before_import_side_effects(self):
        info = state()
        info.calibrations[0].saved_path = "Save/file1.cuw"
        document = parse_recovery_info(encode_recovery_info(info))
        fields = {section: dict(rows) for section, rows in document.sections.items()}
        fields["RecoveryInfo"]["VIN"] = "forged"
        attached = {"Save/file1.cuw": b"authored source"}
        for forged in (
            RecoveryDocument(fields, document.original_bytes, True),
            RecoveryDocument(document.sections, document.original_bytes, False),
        ):
            with tempfile.TemporaryDirectory() as root:
                with self.assertRaises(ValueError):
                    CUWPersistence.import_recovery(
                        Path(root), forged, attached, cpu_capacity=2
                    )
                self.assertFalse(list(Path(root).iterdir()))

    def test_final_read_callback_cannot_detach_directory_or_replace_target(self):
        for detach in (False, True):
            with (
                tempfile.TemporaryDirectory() as root,
                tempfile.TemporaryDirectory() as outside,
            ):
                persistence = CUWPersistence(Path(root), state())
                persistence.notification.assign(True)
                armed = [False]

                def hook(operation, index, armed=armed, detach=detach):
                    if operation == "atomic_replace":
                        armed[0] = True
                    elif operation == "read_existing" and armed[0]:
                        armed[0] = False
                        if detach:
                            (Path(root) / "Save").rename(Path(outside) / "detached")
                            (Path(root) / "Save").mkdir()
                        else:
                            target = Path(root) / "Save/RecoveryInfo.ini"
                            target.rename(target.with_suffix(".previous"))
                            target.write_bytes(b"foreign replacement")

                persistence.fault_hook = hook
                with self.assertRaises((OSError, ValueError)):
                    persistence.update_cpu(1)
                if detach:
                    document = parse_recovery_info(
                        (Path(outside) / "detached/RecoveryInfo.ini").read_bytes()
                    )
                    self.assertEqual(
                        document.sections["RecoveryInfo"]["WriteCpuIndex"], "0"
                    )
                else:
                    self.assertEqual(
                        (Path(root) / "Save/RecoveryInfo.ini").read_bytes(),
                        b"foreign replacement",
                    )

    def test_actual_last_block_notification_handler_writes_both_boolean_values(self):
        with tempfile.TemporaryDirectory() as root:
            persistence = CUWPersistence(Path(root), state())
            notification = persistence.last_block_notification
            self.assertIsInstance(notification, NotificationBool)
            notification.assign(True)
            self.assertTrue(persistence.state.writing_end_block)
            self.assertFalse((Path(root) / "Save").exists())
            persistence.notification.assign(True)
            for value in (False, True, True, False):
                notification.assign(value)
                self.assertIs(notification, persistence.last_block_notification)
                document = parse_recovery_info(
                    (Path(root) / "Save/RecoveryInfo.ini").read_bytes()
                )
                self.assertEqual(
                    document.sections["RecoveryInfo"]["WritingEndBlock"],
                    str(int(value)),
                )

    def test_global_blank_flag_fallback_and_actual_secondary_owner_value(self):
        info = state()
        info.calibrations[0].saved_path = "Save/file1.cuw"
        raw = (
            decode_nibble_text(encode_recovery_info(info))
            .replace(b"BlankECUFlag1=0", b"BlankECUFlag=1")
            .replace(b"BlankECUFlag2=1", b"BlankECUFlag2=0")
        )
        loaded = load_recovery_state(
            parse_recovery_info(raw, encoded=False),
            {"Save/file1.cuw": b"authored"},
            cpu_capacity=3,
        )
        self.assertEqual(loaded.calibrations[0].blank_ecu_flags, (True, False, True))
        with tempfile.TemporaryDirectory() as root:
            persistence = CUWPersistence(Path(root), state())
            copied = NotificationBool().assign(persistence.last_block_notification)
            copied.assign(True)
            self.assertFalse(persistence.state.writing_end_block)

    def test_final_eof_in_place_target_modification_is_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            persistence = CUWPersistence(Path(root), state())
            persistence.notification.assign(True)
            armed, reads = [False], [0]

            def hook(operation, index):
                if operation == "atomic_replace":
                    armed[0] = True
                elif operation == "read_existing" and armed[0]:
                    reads[0] += 1
                    if reads[0] == 2:
                        (Path(root) / "Save/RecoveryInfo.ini").write_bytes(
                            b"foreign in-place"
                        )

            persistence.fault_hook = hook
            with self.assertRaises(FileExistsError):
                persistence.update_cpu(1)
            self.assertEqual(
                (Path(root) / "Save/RecoveryInfo.ini").read_bytes(), b"foreign in-place"
            )

    def test_oversized_recovery_document_rejected_before_cache_io(self):
        info = state()
        info.calibrations[0].cids = ("A" * 256,) * 4096
        info.calibrations[0].requested_addresses = (RequestedAddress("750"),) * 4096
        with tempfile.TemporaryDirectory() as root:
            persistence = CUWPersistence(Path(root), info)
            with self.assertRaises(ValueError):
                persistence.notification.assign(True)
            self.assertFalse(list(Path(root).iterdir()))

    def test_malformed_codec_counts_and_inputs(self):
        for data in (b"!", b"\x00\x00", b"aa", b" " * (2 * 1024 * 1024 + 2)):
            with self.assertRaises(ValueError):
                parse_recovery_info(data)
        for raw in (
            b"[DEFAULT]\nX=y\n[RecoveryInfo]\n",
            b"[RecoveryInfo]\nCIDNum=1\n",
            b"[RecoveryInfo]\nWriting=2\n",
            b"[RecoveryInfo]\nMultiCalibrationFileNum=2\n",
            b"[RecoveryInfo]\nVIN=first\nVIN=second\n",
        ):
            with self.assertRaises(ValueError):
                parse_recovery_info(raw, encoded=False)
        with self.assertRaises(ValueError):
            CUWPersistence(Path("../unsafe"), state())
        with tempfile.TemporaryDirectory() as root:
            persistence = CUWPersistence(Path(root), state())
            for operation in (
                persistence.validate_engine_owner,
                persistence.bind_engine_source,
            ):
                with self.assertRaises(TypeError):
                    operation(object())
            self.assertFalse(list(Path(root).iterdir()))


class LargePersistenceTests(unittest.TestCase):
    def test_source_issued_300mib_cache_restore_cleanup_and_bounded_memory(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "original.cuw"
            metadata = b"[Format]\nVersion=500\n[Vehicle]\nProtocol=02\nNumberOfNode=1\n[Node01]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n[CPU11]\n"
            prefix = b"\0CALIBRATION\0\x0c" + bytes(4) + struct.pack(">I", MIN_SIZE)
            prefix += (
                struct.pack(">H", 3)
                + b"INI"
                + struct.pack(">II", len(metadata), zlib.crc32(metadata))
                + metadata
            )
            prefix += b"\x01"
            size = MIN_SIZE - len(prefix) - 10
            zeros = bytes(65536)
            crc = 0
            for offset in range(0, size, len(zeros)):
                crc = zlib.crc32(zeros[: min(len(zeros), size - offset)], crc)
            prefix += struct.pack(">HII", 0, size, crc)
            with path.open("wb") as output:
                output.write(prefix)
                output.truncate(MIN_SIZE)
            crc = 0
            with path.open("rb") as source:
                source.seek(18)
                while chunk := source.read(65536):
                    crc = zlib.crc32(chunk, crc)
            with path.open("r+b") as output:
                output.seek(14)
                output.write(struct.pack(">I", crc))
            with native_large_cuw_2026(path) as container:
                view = LargeSource2026(container)
                original = calibration_source_identity(view)
                info = state()
                info.calibrations[0].source_path = str(path)
                info.calibrations[0].source_bytes = view
                target = Path(root) / "cache"
                persistence = CUWPersistence(target, info)
                primary, secondary = (
                    persistence.notification,
                    persistence.last_block_notification,
                )
                tracemalloc.start()
                try:
                    primary.assign(True)
                    _, peak = tracemalloc.get_traced_memory()
                finally:
                    tracemalloc.stop()
                self.assertLess(peak, 4 * 1024 * 1024)
                cache = Path(info.calibrations[0].saved_path)
                self.assertEqual(cache.stat().st_size, MIN_SIZE)
                with cache.open("rb") as source:
                    self.assertEqual(
                        hashlib.file_digest(source, "sha256").hexdigest(), original[1]
                    )
                self.assertIs(primary, persistence.notification)
                self.assertIs(secondary, persistence.last_block_notification)
                document = parse_recovery_info(
                    (target / "Save/RecoveryInfo.ini").read_bytes()
                )
                imported = CUWPersistence.import_recovery(
                    Path(root) / "restore", document, {str(cache): view}, cpu_capacity=2
                )
                self.assertTrue(imported.state.loaded)
                imported.notification.assign(True)
                imported.delete_recovery()
                persistence.delete_recovery()
                self.assertEqual(calibration_source_identity(view), original)
                self.assertEqual(list((target / "Save").iterdir()), [])
                # Each failure happens after streaming begins and must remove its temporary.
                for operation in ("write_chunk", "atomic_replace"):

                    def fail(event, index, operation=operation):
                        if event == operation:
                            raise InterruptedError("authored cancellation")

                    failed = CUWPersistence(
                        Path(root) / operation, info := state(), fault_hook=fail
                    )
                    info.calibrations[0].source_bytes = view
                    with self.assertRaises(InterruptedError):
                        failed.notification.assign(True)
                    self.assertFalse(info.logged)
                    self.assertFalse(
                        list((Path(root) / operation / "Save").glob(".cuw-*"))
                    )
                    self.assertEqual(calibration_source_identity(view), original)
                forged = LargeSource2026(dataclasses.replace(container))
                with self.assertRaises(ValueError):
                    calibration_source_identity(forged)

                def mutate(event, index):
                    if event == "atomic_replace":
                        with path.open("r+b") as output:
                            output.seek(MIN_SIZE - 1)
                            output.write(b"X")

                info = state()
                info.calibrations[0].source_bytes = view
                failed = CUWPersistence(Path(root) / "mutated", info, fault_hook=mutate)
                with self.assertRaises(ValueError):
                    failed.notification.assign(True)
                self.assertFalse(info.logged)
                self.assertEqual(list((Path(root) / "mutated/Save").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
