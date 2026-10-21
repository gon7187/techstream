"""Original12/18 source-bound recovery codec and shared-RAM lifecycle checks."""

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from scripts.calibration import decode_cuw_text
from scripts.cuw_legacy_engine import (
    ExecutableIO,
    apply_recovery_password_state,
    set_executable_error_code,
)
from scripts.cuw_legacy_recovery import (
    LegacyRecoveryStore,
    encode_recovery_text,
    write_recovery_file,
)
from scripts.programming import inspect_recovery_info
from tests.private_evidence import read_private_text
from tests.test_cuw_legacy_engine import imported_context


def context(build=18):
    return replace(
        imported_context(),
        build=build,
        observations={
            "recovery_executable_path": r"C:\Toyota\Cuw.exe",
            "recovery_user_enabled": False,
        },
    )


def store(build=18, data=None):
    return LegacyRecoveryStore.from_context(
        context(build), r"D:\actual.cuw", "Actual J2534", data
    )


def buffer(build=18):
    s = store(build)
    s.fields.update(
        CIDNum="2",
        CID1="OLD1",
        CID2="OLD2",
        VIN="VIN123",
        CIDNodeNum="2",
        CIDNode1="1",
        CIDNode2="255",
        ReproCheckResult="4",
        IsCentralGWExist="1",
    )
    if build == 18:
        s.fields.update(
            AssyNoNum="1",
            AssyNo1="ASSY",
            VehicleInfoForUpdateAvailableFlagNum="2",
            VehicleInfoForUpdateAvailableFlag1="0",
            VehicleInfoForUpdateAvailableFlag2="1",
        )
    return s._plain()


class RecoveryCodecTests(unittest.TestCase):
    def test_both_original_full_field_roundtrip_and_byte_order(self):
        for build in (12, 18):
            raw = buffer(build)
            for encoded in (False, True):
                data = encode_recovery_text(raw) if encoded else raw
                s = store(build, data)
                self.assertEqual(s.to_bytes(), data)
                self.assertEqual(s.state.pass_thru_error_code, 99)
                self.assertIn(b"CIDNum=2\r\nCID1=OLD1\r\nCID2=OLD2\r\nVIN=", raw)
                self.assertEqual(b"AssyNoNum=" in raw, build == 18)
                self.assertEqual(
                    b"VehicleInfoForUpdateAvailableFlagNum=" in raw, build == 18
                )

    def test_field_order_matches_version_specific_static_initializer(self):
        evidence = json.loads(
            read_private_text(
                Path(__file__).resolve().parents[1]
                / "analysis/evidence/no-car-112/source-map.json"
            )
        )
        for build in (12, 18):
            names = [
                item["text"]
                for item in evidence[str(build)]["strings"]
                if item["text"] not in ("RecoveryInfo", "RecoveryInfo.ini")
                and "%d" not in item["text"]
            ]
            actual = [
                line.split("=", 1)[0]
                for line in store(build)._plain().decode("cp1252").splitlines()[1:]
            ]
            self.assertEqual(actual, names)

    def test_native_default_schema_and_encoding(self):
        for build in (12, 18):
            s = store(build)
            raw = decode_cuw_text(s.to_bytes())
            self.assertIn(
                b"Writing=0\r\nUseNewSoftwarePassword=0\r\nWritingEndBlock=0\r\nPassThruErrorCode=99",
                raw,
            )
            self.assertEqual(inspect_recovery_info(s.to_bytes())["fields"]["cidnum"], 0)

    def test_unmapped_sections_keys_comments_survive_changed_save(self):
        raw = buffer() + b"; keep\r\nFutureField=opaque=12\r\n[Other]\r\nRaw=abc\r\n"
        s = store(data=raw)
        s.set_field(ExecutableIO(lambda *_: None), "WritingEndBlock", True)
        changed = s.to_bytes()
        self.assertTrue(
            changed.endswith(
                b"; keep\r\nFutureField=opaque=12\r\n[Other]\r\nRaw=abc\r\n"
            )
        )
        self.assertIn(b"WritingEndBlock=1\r\n", changed)

    def test_random_native_noise_bits_preserved_when_unchanged(self):
        raw = bytes(c | (i % 4) for i, c in enumerate(encode_recovery_text(buffer())))
        self.assertEqual(store(data=raw).to_bytes(), raw)

    def test_source_device_mismatch_never_mutates_context(self):
        for old, new in (
            (b"actual.cuw", b"foreign.cuw"),
            (b"Actual J2534", b"Other J2534"),
        ):
            ctx = context()
            with self.assertRaises(ValueError):
                LegacyRecoveryStore.from_context(
                    ctx, r"D:\actual.cuw", "Actual J2534", buffer().replace(old, new)
                )
            self.assertFalse(ctx.state.writing)

    def test_malformed_scalar_and_vector_rejected(self):
        raw = buffer()
        for old, new in (
            (b"Writing=0", b"Writing=2"),
            (b"WriteCpuIndex=0", b"WriteCpuIndex=1"),
            (b"CIDNum=2", b"CIDNum=3"),
            (b"CIDNum=2", b"CIDNum=1"),
            (b"CIDNode2=255", b"CIDNode2=256"),
            (b"AvailableFlag2=1", b"AvailableFlag2=2"),
            (b"PassThruErrorCode=99", b"PassThruErrorCode=-1"),
        ):
            with self.subTest(new=new), self.assertRaises(ValueError):
                store(data=raw.replace(old, new))

    def test_original12_retains_unknown18_fields_without_aliasing_schema(self):
        s = store(12, buffer(12) + b"AssyNoNum=1\r\nAssyNo1=foreign\r\n")
        self.assertIn(b"AssyNoNum=1\r\nAssyNo1=foreign\r\n", s.to_bytes())


class RecoveryLifecycleTests(unittest.TestCase):
    def io(self, events, fail=None):
        def primitive(event, remaining):
            events.append(event)
            if fail == event["operation"]:
                raise OSError("injected failure")
            return False if event["operation"] == "recovery_path_exists" else None

        return ExecutableIO(primitive)

    def test_begin_directory_copy_writing_fullsave_then_activate(self):
        for build in (12, 18):
            s = store(build)
            events = []
            s.begin_writing(self.io(events))
            self.assertEqual(
                [e["operation"] for e in events],
                [
                    "recovery_path_exists",
                    "create_recovery_directory",
                    "copy_recovery_source",
                    "write_recovery_bytes",
                ],
            )
            saved = inspect_recovery_info(events[-1]["data"])["fields"]
            self.assertEqual(
                saved["savedcalibrationfilepath"], r"C:\Toyota\Save\actual.cuw"
            )
            self.assertEqual(saved["writing"], 1)
            self.assertTrue(s.state.recovery_persistence_active)

    def test_save_fault_retains_writing_without_activating(self):
        for build in (12, 18):
            s = store(build)
            with self.assertRaises(OSError):
                s.begin_writing(self.io([], "write_recovery_bytes"))
            self.assertTrue(s.state.writing)
            self.assertFalse(s.state.recovery_persistence_active)

    def test_path_fault_precedes_writing_mutation(self):
        s = store()
        with self.assertRaises(OSError):
            s.begin_writing(self.io([], "create_recovery_directory"))
        self.assertFalse(s.state.writing)

    def test_imported_writing_is_not_active(self):
        s = store(data=buffer().replace(b"Writing=0", b"Writing=1"))
        self.assertTrue(s.state.writing)
        self.assertFalse(s.state.recovery_persistence_active)
        events = []
        s.set_field(self.io(events), "PassThruErrorCode", 7)
        self.assertEqual(events, [])
        self.assertEqual(s.state.pass_thru_error_code, 7)

    def test_all_active_setters_mutate_before_fullsave_failure(self):
        for build in (12, 18):
            for key, value, attr in (
                ("WriteCpuIndex", 0, "write_cpu_index"),
                ("Writing", False, "writing"),
                ("UseNewSoftwarePassword", True, "use_new_software_password"),
                ("WritingEndBlock", True, "writing_end_block"),
                ("PassThruErrorCode", 7, "pass_thru_error_code"),
            ):
                s = store(build)
                s.state.recovery_persistence_active = True
                events = []
                with self.assertRaises(OSError):
                    s.set_field(self.io(events, "write_recovery_bytes"), key, value)
                self.assertEqual(getattr(s.state, attr), value)
                self.assertEqual(len(events), 1)
                saved = inspect_recovery_info(events[0]["data"])["fields"]
                self.assertEqual(saved[key.casefold()], int(value))
                self.assertEqual("assynonum" in saved, build == 18)

    def test_cancellation_after_mutation_retains_ram(self):
        s = store()
        s.state.recovery_persistence_active = True
        with self.assertRaises(InterruptedError):
            s.set_field(
                ExecutableIO(lambda *_: None, cancelled=lambda: True),
                "WritingEndBlock",
                True,
            )
        self.assertTrue(s.state.writing_end_block)

    def test_save_rejects_changed_source_device_association(self):
        for key in ("SavedCalibrationFilePath", "SelectedJ2534Device"):
            s = store()
            s.fields[key] = "unbound"
            with self.assertRaises(ValueError):
                s.save(self.io([]))

    def test_setter_rejects_cpu_outside_source_before_ram_mutation(self):
        s = store()
        with self.assertRaises(ValueError):
            s.set_field(self.io([]), "WriteCpuIndex", 2)
        self.assertEqual(s.state.write_cpu_index, 0)

    def test_cancel_after_bytes_written_does_not_prematurely_activate(self):
        s = store()
        cancelled = False
        written = []

        def primitive(event, remaining):
            nonlocal cancelled
            if event["operation"] == "write_recovery_bytes":
                written.append(event["data"])
                cancelled = True
            return False if event["operation"] == "recovery_path_exists" else None

        with self.assertRaises(InterruptedError):
            s.begin_writing(ExecutableIO(primitive, cancelled=lambda: cancelled))
        self.assertEqual(len(written), 1)
        self.assertTrue(s.state.writing)
        self.assertFalse(s.state.recovery_persistence_active)

    def test_retry_inputs_do_not_save_or_alias_manager_retry(self):
        s = store()
        s.state.recovery_persistence_active = True
        events = []
        for key in ("RetryInput", "RetryMode"):
            s.set_field(self.io(events), key, True)
        self.assertEqual(events, [])
        self.assertTrue(s.state.recovery_retry)
        self.assertTrue(s.state.retry_input)
        self.assertFalse(s.state.retry_mode)

    def test_profile_directory_is_explicit_source_input(self):
        ctx = replace(
            context(),
            observations={
                "recovery_executable_path": r"C:\Toyota\Cuw.exe",
                "recovery_user_enabled": True,
                "recovery_user_name": "First_Last",
            },
        )
        s = LegacyRecoveryStore.from_context(ctx, r"D:\actual.cuw", "Actual J2534")
        events = []
        s.begin_writing(self.io(events))
        self.assertEqual(events[0]["path"], r"C:\Toyota\Save\First_Last")

    def test_actual_executable_controller_uses_shared_store_full_saves(self):
        for build in (12, 18):
            ctx = context(build)
            s = LegacyRecoveryStore.from_context(ctx, r"D:\actual.cuw", "Actual J2534")
            ctx = replace(ctx, recovery_store=s)
            self.assertIs(ctx.state, s.state)
            events = []
            io = self.io(events)
            apply_recovery_password_state(ctx, io, False, 7)
            self.assertTrue(ctx.state.use_new_software_password)
            self.assertEqual(events, [])
            s.begin_writing(io)
            apply_recovery_password_state(ctx, io, False, 7)
            set_executable_error_code(ctx, io, 7)
            writes = [e for e in events if e["operation"] == "write_recovery_bytes"]
            self.assertEqual(len(writes), 3)
            saved = inspect_recovery_info(writes[-1]["data"])["fields"]
            self.assertEqual(saved["passthruerrorcode"], 7)
            self.assertEqual(saved["usenewsoftwarepassword"], 0)
            self.assertFalse(
                any(
                    e["operation"] in ("write_recovery_bool", "write_recovery_int")
                    for e in events
                )
            )
            with self.assertRaises(OSError):
                set_executable_error_code(ctx, self.io([], "write_recovery_bytes"), 8)
            self.assertEqual(ctx.state.pass_thru_error_code, 8)
            self.assertTrue(ctx.state.recovery_persistence_active)

    def test_terminal_cursor_persists_but_cannot_be_imported_as_selected_cpu(self):
        for build in (12, 18):
            s = store(build)
            s.state.recovery_persistence_active = True
            events = []
            s.set_field(self.io(events), "Writing", False)
            s.set_field(self.io(events), "WriteCpuIndex", 1)
            self.assertEqual(s.state.write_cpu_index, 1)
            self.assertEqual(
                inspect_recovery_info(events[-1]["data"])["fields"]["writecpuindex"], 1
            )
            with self.assertRaises(ValueError):
                store(build, events[-1]["data"])

    def test_finish_ignores_delete_false_resets_all_recovery_fields_only(self):
        for build in (12, 18):
            s = store(build, encode_recovery_text(buffer(build)))
            s.begin_writing(self.io([]))
            s.state.retry_mode = True
            s.state.recovery_retry = True
            s.state.retry_input = True
            s.state.writing_end_block = True
            s.state.use_new_software_password = True
            s.state.pass_thru_error_code = 7
            path = s.recovery_path
            events = []
            s.finish(
                ExecutableIO(
                    lambda e, remaining, events=events: events.append(e) or False
                )
            )
            self.assertEqual(
                [e["path"] for e in events], [r"C:\Toyota\Save\actual.cuw", path]
            )
            self.assertTrue(all(e["owned_output"] for e in events))
            self.assertEqual(
                [e["operation"] for e in events], ["delete_recovery_file"] * 2
            )
            self.assertTrue(s.state.retry_mode)
            self.assertFalse(s.state.recovery_retry)
            self.assertFalse(s.state.retry_input)
            self.assertFalse(s.state.recovery_persistence_active)
            self.assertFalse(s.state.writing)
            self.assertFalse(s.state.writing_end_block)
            self.assertFalse(s.state.use_new_software_password)
            self.assertEqual(s.state.write_cpu_index, 0)
            self.assertEqual(s.state.pass_thru_error_code, 99)
            self.assertEqual(s.fields["SavedCalibrationFilePath"], "")
            self.assertEqual(s.fields["SelectedJ2534Device"], "")
            self.assertEqual(s.fields["VIN"], "")
            self.assertEqual(s.fields["CIDNum"], "0")
            self.assertEqual(s.fields["CIDNodeNum"], "0")
            self.assertNotIn("CID1", s.fields)
            if build == 18:
                self.assertEqual(s.fields["AssyNoNum"], "0")
                self.assertEqual(s.fields["VehicleInfoForUpdateAvailableFlagNum"], "0")
                self.assertNotIn("AssyNo1", s.fields)
            self.assertEqual(s.source_path, r"D:\actual.cuw")
            self.assertEqual(s.recovery_path, path)
            self.assertEqual(s.raw_unmapped, "")
            self.assertIsNone(s.original_data)
            self.assertEqual(
                inspect_recovery_info(s.to_bytes())["fields"]["passthruerrorcode"], 99
            )

    def test_import_restore_retains_ini_path_without_owning_originals(self):
        for build in (12, 18):
            s = store(build, encode_recovery_text(buffer(build)))
            self.assertEqual(s.recovery_path, r"C:\Toyota\Save\RecoveryInfo.ini")
            self.assertEqual(s.fields["SavedCalibrationFilePath"], r"D:\actual.cuw")
            events = []
            s.finish(
                ExecutableIO(
                    lambda e, remaining, events=events: events.append(e) or False
                )
            )
            self.assertEqual(
                [e["path"] for e in events],
                [r"D:\actual.cuw", r"C:\Toyota\Save\RecoveryInfo.ini"],
            )
            self.assertTrue(all(not e["owned_output"] for e in events))

    def test_finish_first_or_second_delete_exception_keeps_ram_and_order(self):
        for failed_call in (1, 2):
            s = store()
            s.begin_writing(self.io([]))
            events = []
            deleted = []

            def primitive(
                event,
                remaining,
                events=events,
                failed_call=failed_call,
                deleted=deleted,
            ):
                events.append(event)
                if len(events) == failed_call:
                    raise OSError("native host delete fault")
                deleted.append(event["path"])
                return True

            with self.assertRaises(OSError):
                s.finish(ExecutableIO(primitive))
            self.assertEqual(len(events), failed_call)
            self.assertEqual(len(deleted), failed_call - 1)
            self.assertTrue(s.state.writing)
            self.assertTrue(s.state.recovery_persistence_active)
            self.assertEqual(
                s.fields["SavedCalibrationFilePath"], r"C:\Toyota\Save\actual.cuw"
            )

    def test_finish_cancel_after_first_delete_preserves_partial_state(self):
        s = store()
        s.begin_writing(self.io([]))
        cancelled = False
        deleted = []

        def primitive(event, remaining):
            nonlocal cancelled
            deleted.append(event["path"])
            cancelled = True
            return True

        with self.assertRaises(InterruptedError):
            s.finish(ExecutableIO(primitive, cancelled=lambda: cancelled))
        self.assertEqual(deleted, [r"C:\Toyota\Save\actual.cuw"])
        self.assertTrue(s.state.writing)
        self.assertTrue(s.state.recovery_persistence_active)

    def test_finish_does_not_mark_original_alias_as_owned_output(self):
        ctx = context()
        s = LegacyRecoveryStore.from_context(
            ctx, r"C:\Toyota\Save\actual.cuw", "Actual J2534"
        )
        s.begin_writing(self.io([]))
        events = []
        s.finish(
            ExecutableIO(lambda e, remaining, events=events: events.append(e) or False)
        )
        self.assertFalse(events[0]["owned_output"])
        self.assertTrue(events[1]["owned_output"])

    def test_linux_atomic_byte_adapter_preserves_existing_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "RecoveryInfo.ini"
            path.write_bytes(b"previous")
            with (
                patch(
                    "scripts.cuw_legacy_recovery.os.replace",
                    side_effect=OSError("fault"),
                ),
                self.assertRaises(OSError),
            ):
                write_recovery_file(path, b"new")
            self.assertEqual(path.read_bytes(), b"previous")
            self.assertEqual(list(Path(directory).iterdir()), [path])
            write_recovery_file(path, b"complete")
            self.assertEqual(path.read_bytes(), b"complete")


if __name__ == "__main__":
    unittest.main()
