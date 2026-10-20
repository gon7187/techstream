"""Source-reconciled state controls for original CUW executable writers."""

import unittest
from dataclasses import replace
from typing import Any, cast

from scripts.cuw_legacy_engine import (
    ExecutableContext,
    ExecutableImage,
    ExecutableIO,
    ExecutableJ2534Error,
    ExecutableState,
    apply_recovery_password_state,
    bind_context,
    executable_constructor_timeout,
    executable_cpu_type,
    executable_j2534_call,
    executable_new_password,
    executable_parameters,
    executable_retry_requested,
    executable_start_filter,
    executable_stop_filter,
    executable_sync,
    legacy_indication,
    legacy_messages,
    legacy_recovery_password_state,
    select_executable_controller,
    set_executable_cpu_type,
    set_executable_error_code,
)
from scripts.j2534_2026 import NativeMessage


class NativeImageOrderTests(unittest.TestCase):
    def test_manager_connect_rejects_unidentified_source_before_io(self):
        from scripts.cuw_legacy_engine import connect_executable_context

        calls = []
        with self.assertRaises(ValueError):
            connect_executable_context(
                authored_compaction_context(),
                ExecutableIO(lambda event, remaining: calls.append(event)),
            )
        self.assertEqual(calls, [])
        for value in (True, -1, 0x100000000):
            with self.assertRaises(ValueError):
                ExecutableState(native_value_e60=value)

    def test_indexed_factory_requires_the_actual_original_source(self):
        from scripts.cuw_legacy_engine import select_executable_cpu

        with self.assertRaises(ValueError):
            select_executable_cpu(authored_compaction_context(), 1)

    def test_terminal_cpu_counter_is_not_an_eligible_selected_cpu(self):
        from scripts.cuw_legacy_engine import executable_selected_password

        ExecutableState(write_cpu_index=128).validate()
        with self.assertRaises(ValueError):
            ExecutableState(write_cpu_index=129).validate()
        with self.assertRaises(ValueError):
            executable_selected_password(imported_context(), 128)

    def test_serial_getter_uses_catalog_switch_and_its_own_factory(self):
        from scripts.cuw_legacy_engine import require_executable_standard_getter

        context = imported_context()
        base = dict(context.native.base_metadata, contact_type="SIL", kind_of_ecu="0")

        def candidate(*, kind="0", cpu="1", switch=""):
            native = replace(
                context.native,
                base_metadata=dict(base, kind_of_ecu=kind),
                base_parameters={"FlagToUseCIDGetterAndFlashWriterDLL": switch},
            )
            return replace(context, native=native, cpus=(native,), cpu_types=(cpu,))

        for switch in ("", "0", "+00", " -0"):
            require_executable_standard_getter(
                candidate(switch=switch), "CSilCIDGetter"
            )
        for switch in ("1", "-1", "2", "true", "0garbage", "2147483648"):
            with self.assertRaises(ValueError):
                require_executable_standard_getter(
                    candidate(switch=switch), "CSilCIDGetter"
                )
        for kind in ("11", "37", "30", "8", "63"):
            with self.assertRaises(ValueError):
                require_executable_standard_getter(
                    candidate(kind=kind), "CSilCIDGetter"
                )
        for cpu in ("57", "58", "59", "60"):
            with self.assertRaises(ValueError):
                require_executable_standard_getter(candidate(cpu=cpu), "CSilCIDGetter")
        with self.assertRaises(ValueError):
            require_executable_standard_getter(context, "CSilCIDGetter")

    def test_imported_srecord_password_consumes_native_sorted_overlap(self):
        from scripts.programming_legacy import bind_native_cpu_context
        from tests.test_calibration import srecord
        from tests.test_programming_legacy import authored_legacy_input

        payload = b"\n".join(
            (srecord(1, 0x1002, b"XY"), srecord(1, 0x1000, b"abcd"), srecord(9, 0))
        )
        container, selection, _, _ = authored_legacy_input(
            "TCUWCanCommonFlashWriter.dll",
            "write",
            payload=payload,
            parameters={"PasswordAddress": "00000000", "ByteOrder": "1"},
        )
        native = bind_native_cpu_context(
            container, 1, ("DEMO-OLD",), selection, stage="write"
        )
        self.assertEqual(executable_new_password(native), 0x61625859)

    def test_reverse_address_records_copy_in_native_unsigned_sorted_order(self):
        from scripts.programming_legacy import materialize_legacy_image
        from tests.test_calibration import srecord

        raw = b"\n".join(
            (srecord(1, 0x1002, b"XY"), srecord(1, 0x1000, b"abcd"), srecord(9, 0))
        )
        image = materialize_legacy_image(raw)
        self.assertEqual(image.data, b"abXY")
        self.assertEqual((image.base_address, image.flash_size), (0x1000, 6))

    def test_last_sorted_record_end_bounds_containing_earlier_record(self):
        from scripts.programming_legacy import materialize_legacy_image
        from tests.test_calibration import srecord

        raw = b"\n".join(
            (srecord(1, 0x1000, b"abcdef"), srecord(1, 0x1002, b"XY"), srecord(9, 0))
        )
        with self.assertRaises(ValueError):
            materialize_legacy_image(raw)


def authored_compaction_context(
    build=18,
    version=6,
    new_cids=("NEW-A", "NEW-B", "NEW-C"),
    target_count=1,
    vbf=False,
    hardware_targets=(),
    target_data: str | None = "12345678",
):
    from scripts.calibration import parse_cuw
    from scripts.programming_legacy import bind_native_cpu_context
    from tests.test_calibration import metadata_container, srecord
    from tests.test_programming_legacy import authored_legacy_input

    _, selection, _, _ = authored_legacy_input(
        "TCUWCanCommonFlashWriter.dll",
        "write",
        build=build,
        parameters={"PasswordAddress": "00000000", "ByteOrder": "1"},
    )
    metadata = (
        f"[Format]\nVersion={version}\n[Vehicle]\nNumberOfCalibration=3\n"
        "KindOfECU=1\nContactType=CAN\n"
    )
    for index, cid in enumerate(new_cids, 1):
        metadata += (
            f"[CPU{index:02}]\nCPUType=1\nNewCID={cid}\nCPUImageName=cpu{index}.{'vbf' if vbf else 'srec'}\n"
            f"LocationID=0108010000000720\nNumberOfTargets={target_count}\n"
        )
        metadata += f"NumberOfTargetHardwares={len(hardware_targets)}\n"
        for hardware_index, hardware in enumerate(hardware_targets, 1):
            metadata += f"{hardware_index:02}_TargetHardware={hardware}\n"
        for target in range(1, target_count + 1):
            metadata += f"{target:02}_TargetCalibration=DEMO-OLD\n"
            if target_data is not None:
                metadata += f"{target:02}_TargetData={target_data}\n"
        if version == 9:
            metadata += (
                f"NumberOfFiles=1\n[File{index}001]\nFileName=cpu{index}.vbf\n"
                "DataFormat=00\nDownloadAddress=00000000\nDownloadMemsize=00000008\nALFID=44\n"
            )
    container = parse_cuw(
        metadata_container(
            metadata,
            [
                (
                    b"cpu",
                    bytes((index,)) * 8
                    if version == 9 or vbf
                    else b"\n".join(
                        (srecord(1, 0x1000, bytes((index,)) * 8), srecord(9, 0))
                    ),
                )
                for index in range(3)
            ],
            3,
            2 if version == 9 else 1,
        )
    )
    cpus = tuple(
        bind_native_cpu_context(
            container, 1, ("DEMO-OLD",), selection, stage="write", cpu_index=index
        )
        for index in range(3)
    )
    return ExecutableContext(
        build,
        "CCanFlashWriter",
        cpus[0],
        cpus,
        container.digest,
        cpu_types=("1", "1", "1"),
        catalog=selection.catalog,
    )


class ExecutableCompactionTests(unittest.TestCase):
    def test_vbf_initial_targets_use_actual_hardware_string_and_native_bypass(self):
        from scripts.cuw_legacy_engine import (
            ExecutableStringContext,
            complete_executable_targets,
            initialize_executable_targets,
        )

        for build in (12, 18):
            context = replace(
                authored_compaction_context(
                    build, vbf=True, hardware_targets=("HW-A",)
                ),
                observations={"observed_cids": (), "native_hardware_98": "HW-A"},
            )
            context.state.native_flag_2c = True
            strings = ExecutableStringContext(1252, 0x409, False)
            result = initialize_executable_targets(context, strings=strings)
            self.assertTrue(result.native_result)
            self.assertEqual(
                context.state.target_indices, (0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
            )
            self.assertEqual(result.excluded_cids, ())
            context = replace(
                context,
                observations={
                    "observed_cids": ("DEMO-OLD",) * 3,
                    "native_hardware_98": "hw-a",
                },
            )
            result = initialize_executable_targets(context, strings=strings)
            self.assertFalse(result.native_result)
            self.assertEqual(
                context.state.target_indices, (0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
            )
            context = replace(
                context,
                observations={
                    "observed_cids": ("DEMO-OLD",) * 3,
                    "native_hardware_98": "HW-A",
                },
            )
            self.assertTrue(
                initialize_executable_targets(context, strings=strings).native_result
            )
            self.assertEqual(context.state.target_indices, (0, 0, 0, 0xFFFFFFFF))
            with self.assertRaises(ValueError):
                complete_executable_targets(context)
            context = replace(context, observations={"observed_cids": ("DEMO-OLD",)})
            with self.assertRaises(ValueError):
                initialize_executable_targets(context, strings=strings)
            excess = replace(
                authored_compaction_context(
                    build, vbf=True, hardware_targets=("HW-A",) * 100
                ),
                observations={"observed_cids": (), "native_hardware_98": "HW-A"},
            )
            with self.assertRaises(ValueError):
                initialize_executable_targets(excess, strings=strings)
            self.assertEqual(excess.state.target_indices, (0xFFFFFFFF,) * 4)

    def test_target_fallback_native_capacity_and_version8_ram_password(self):
        from scripts.cuw_legacy_engine import (
            complete_executable_targets,
            executable_selected_password,
        )

        for build in (12, 18):
            full = complete_executable_targets(
                authored_compaction_context(build, target_count=32)
            )
            self.assertEqual(full.state.target_indices, (31, 31, 31, 0xFFFFFFFF))
            self.assertEqual(full.cpus[1].selected.values["numberoftargets"], "32")
            self.assertEqual(full.ram_target_passwords, {})
            self.assertEqual(executable_selected_password(full, 1), 0x12345678)
        version8 = complete_executable_targets(
            authored_compaction_context(18, version=8)
        )
        self.assertEqual(executable_selected_password(version8, 1), 0x01010101)
        with self.assertRaises(ValueError):
            authored_compaction_context(12, version=8)

    def test_initial_target_scc_blank_branch_preserves_separate_manager_flag(self):
        from scripts.cuw_legacy_engine import (
            ExecutableStringContext,
            initialize_executable_targets,
        )

        context = replace(
            authored_compaction_context(),
            observations={"observed_cids": ()},
            kind_of_cal={"iscontrolledbyscc": "+01", "isblankecu": "1"},
        )
        context.state.native_flag_2c = True
        strings = ExecutableStringContext(1252, 0x409, False)
        self.assertFalse(
            initialize_executable_targets(context, strings=strings).native_result
        )
        context.state.native_flag_6e4 = True
        result = initialize_executable_targets(context, strings=strings)
        self.assertTrue(result.native_result)
        self.assertEqual(context.state.target_indices, (0, 0, 0, 0xFFFFFFFF))
        self.assertEqual(result.excluded_cids, ())

    def test_unresolved_target_fallback_appends_image_password_in_native_ram(self):
        from scripts.cuw_legacy_engine import (
            complete_executable_targets,
            executable_selected_password,
            executable_selected_target_calibration,
        )

        for build in (12, 18):
            context = authored_compaction_context(build)
            result = complete_executable_targets(context)
            self.assertEqual(result.state.target_indices, (1, 1, 1, 0xFFFFFFFF))
            self.assertEqual(context.state.target_indices, (0xFFFFFFFF,) * 4)
            self.assertEqual(result.cpus[1].selected.values["numberoftargets"], "2")
            self.assertEqual(executable_selected_password(result, 1), 0x01010101)
            self.assertEqual(executable_selected_target_calibration(result, 1), "NEW-B")
            self.assertEqual(context.cpus[1].selected.values["numberoftargets"], "1")
            self.assertEqual(complete_executable_targets(result), result)

    def test_initial_targets_are_produced_from_actual_imported_rows(self):
        from scripts.cuw_legacy_engine import (
            ExecutableStringContext,
            initialize_executable_targets,
        )

        for build in (12, 18):
            context = replace(
                authored_compaction_context(build),
                observations={"observed_cids": ("demo-old",)},
            )
            result = initialize_executable_targets(
                context, strings=ExecutableStringContext(1252, 0x409, False)
            )
            self.assertEqual(context.state.target_indices, (0, 0, 0, 0xFFFFFFFF))
            self.assertEqual(result.excluded_cids, ())
            self.assertFalse(result.native_result)
            context.state.native_flag_2c = True
            result = initialize_executable_targets(
                context, strings=ExecutableStringContext(1252, 0x409, True)
            )
            self.assertEqual(context.state.target_indices, (0xFFFFFFFF,) * 4)
            self.assertEqual(result.excluded_cids, ("NEW-A", "NEW-B", "NEW-C"))
            self.assertFalse(result.native_result)

    def test_initial_targets_feed_actual_compaction_and_password(self):
        from scripts.cuw_legacy_engine import (
            ExecutableStringContext,
            compact_executable_context,
            executable_selected_password,
            initialize_executable_targets,
            produce_executable_compaction,
        )

        for build in (12, 18):
            context = replace(
                authored_compaction_context(
                    build, new_cids=("DEMO-OLD", "NEW-B", "NEW-C")
                ),
                observations={"observed_cids": ("DEMO-OLD",) * 3},
            )
            context.state.native_flag_2c = True
            strings = ExecutableStringContext(1252, 0x409, False)
            targets = initialize_executable_targets(context, strings=strings)
            self.assertTrue(targets.native_result)
            self.assertEqual(targets.excluded_cids, ("DEMO-OLD",))
            compacted = compact_executable_context(
                context,
                produce_executable_compaction(
                    context, targets.excluded_cids, strings=strings
                ),
            )
            self.assertEqual(compacted.source_cpu_indices, (1, 2))
            self.assertEqual(
                compacted.state.target_indices, (0, 0, 0xFFFFFFFF, 0xFFFFFFFF)
            )
            self.assertEqual(executable_selected_password(compacted), 0x12345678)

    def test_initial_target_inputs_fail_before_native_ram_mutation(self):
        from scripts.cuw_legacy_engine import (
            ExecutableStringContext,
            initialize_executable_targets,
        )

        strings = ExecutableStringContext(1252, 0x409, False)
        context = authored_compaction_context()
        context.state.target_indices = (3, 2, 1, 0)
        with self.assertRaises(ValueError):
            initialize_executable_targets(context, strings=strings)
        self.assertEqual(context.state.target_indices, (3, 2, 1, 0))
        context = replace(context, observations={"observed_cids": ("é",)})
        with self.assertRaises(ValueError):
            initialize_executable_targets(context, strings=strings)
        self.assertEqual(context.state.target_indices, (3, 2, 1, 0))
        other = replace(
            context.cpus[1],
            selected=replace(context.cpus[1].selected, values={"numberoftargets": "0"}),
        )
        inconsistent = replace(
            context,
            cpus=(context.cpus[0], other, context.cpus[2]),
            observations={"observed_cids": ("DEMO-OLD",)},
        )
        with self.assertRaises(ValueError):
            initialize_executable_targets(inconsistent, strings=strings)
        self.assertEqual(context.state.target_indices, (3, 2, 1, 0))

    def test_imported_cpu_and_image_compaction_preserves_source_mapping(self):
        from scripts.cuw_legacy_engine import (
            ExecutableStringContext,
            compact_executable_context,
            produce_executable_compaction,
        )

        for build in (12, 18):
            context = authored_compaction_context(build)
            context.state.target_indices = (7, 8, 9, 0xFFFFFFFF)
            plan = produce_executable_compaction(
                context,
                ("NEW-A", "NEW-C"),
                strings=ExecutableStringContext(1252, 0x409, False),
            )
            result = compact_executable_context(context, plan)
            self.assertEqual(result.source_cpu_indices, (1,))
            self.assertEqual(result.image_source_cpu_indices, (1,))
            self.assertEqual(result.native.selected.index, 0)
            self.assertEqual(result.native.selected.values["newcid"], "NEW-B")
            assert result.native.image is not None
            self.assertEqual(result.native.image.data, bytes((1,)) * 8)
            self.assertIs(result.native.first_image, result.native.image)
            self.assertEqual(result.state.write_cpu_index, 0)
            self.assertEqual(
                result.state.target_indices, (8, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
            )
            self.assertEqual(result.cpu_types, ("1",))
            self.assertEqual(len(result.native.cpus), 1)
            self.assertEqual(len(context.native.cpus), 3)

    def test_version9_duplicate_cids_keep_distinct_metadata_and_first_file_groups(self):
        from scripts.cuw_legacy_engine import (
            ExecutableStringContext,
            compact_executable_context,
            produce_executable_compaction,
        )

        context = authored_compaction_context(
            version=9, new_cids=("NEW-A", "NEW-A", "NEW-C")
        )
        source = context.cpus[0].selected
        context.state.target_indices = (7, 8, 9, 0xFFFFFFFF)
        plan = produce_executable_compaction(
            context, ("NEW-C",), strings=ExecutableStringContext(1252, 0x409, False)
        )
        result = compact_executable_context(context, plan)
        self.assertEqual(result.source_cpu_indices, (0, 1))
        self.assertEqual(result.image_source_cpu_indices, (0, 0))
        self.assertEqual(result.cpus[1].selected.section, "CPU02")
        self.assertEqual(result.cpus[1].selected.files, source.files)
        self.assertEqual(
            result.state.target_indices, (8, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
        )

    def test_case_policy_is_explicit_and_unsupported_collation_fails_closed(self):
        from scripts.cuw_legacy_engine import (
            ExecutableStringContext,
            produce_executable_compaction,
        )

        context = authored_compaction_context()
        folded = produce_executable_compaction(
            context, ("new-a",), strings=ExecutableStringContext(1252, 0x409, False)
        )
        literal = produce_executable_compaction(
            context, ("new-a",), strings=ExecutableStringContext(1252, 0x409, True)
        )
        self.assertEqual(folded.source_cpu_indices, (1, 2))
        self.assertEqual(literal.source_cpu_indices, (0, 1, 2))
        for excluded in (("é",), ("NEW A",)):
            with self.subTest(excluded=excluded), self.assertRaises(ValueError):
                produce_executable_compaction(
                    context,
                    excluded,
                    strings=ExecutableStringContext(1252, 0x409, False),
                )
        for fields in ((1254, 0x409, False), (1252, 0x41F, False), (1252, 0x409, 0)):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                ExecutableStringContext(*cast(Any, fields))

    def test_plan_is_bound_to_original_context_and_ram_cpu_type_snapshot(self):
        from scripts.cuw_legacy_engine import (
            ExecutableStringContext,
            compact_executable_context,
            produce_executable_compaction,
        )

        context = authored_compaction_context()
        plan = produce_executable_compaction(
            context, ("NEW-A",), strings=ExecutableStringContext(1252, 0x409, False)
        )
        with self.assertRaises(ValueError):
            compact_executable_context(replace(context), plan)
        with self.assertRaises(ValueError):
            compact_executable_context(
                context, replace(plan, source_cpu_indices=(0, 2))
            )
        context.state.cpu_type_overrides[1] = "54"
        with self.assertRaises(ValueError):
            compact_executable_context(context, plan)
        context.state.cpu_type_overrides.clear()
        compacted = compact_executable_context(context, plan)
        with self.assertRaises(ValueError):
            produce_executable_compaction(
                compacted, (), strings=ExecutableStringContext(1252, 0x409, False)
            )
        with self.assertRaises(ValueError):
            produce_executable_compaction(
                context,
                ("NEW-A", "NEW-B", "NEW-C"),
                strings=ExecutableStringContext(1252, 0x409, False),
            )

    def test_original12_unadmitted_formats_and_active_recovery_fail_closed(self):
        from scripts.cuw_legacy_engine import (
            ExecutableStringContext,
            produce_executable_compaction,
        )

        with self.assertRaises(ValueError):
            authored_compaction_context(build=12, version=9)
        for context in (
            replace(authored_compaction_context(), state=ExecutableState(writing=True)),
            replace(
                authored_compaction_context(),
                state=ExecutableState(recovery_persistence_active=True),
            ),
            replace(
                authored_compaction_context(), state=ExecutableState(retry_mode=True)
            ),
            replace(
                authored_compaction_context(),
                state=ExecutableState(native_flag_6e4=True),
            ),
            replace(imported_context(), cpu_types=("1",)),
        ):
            with (
                self.subTest(
                    build=context.build, version=context.native.metadata_version
                ),
                self.assertRaises(ValueError),
            ):
                produce_executable_compaction(
                    context, (), strings=ExecutableStringContext(1252, 0x409, False)
                )


class RecoveryPasswordStateTests(unittest.TestCase):
    def test_true_argument_sets_all_native_modes(self):
        for mode in (0, 1, 7, 0xFFFFFFFF):
            for previous in (False, True):
                with self.subTest(mode=mode, previous=previous):
                    self.assertIs(
                        legacy_recovery_password_state(True, mode, previous), True
                    )

    def test_false_argument_toggles_only_mode_seven(self):
        self.assertIs(legacy_recovery_password_state(False, 7, False), True)
        self.assertIs(legacy_recovery_password_state(False, 7, True), False)
        for mode in (0, 1, 6, 8, 0xFFFFFFFF):
            for previous in (False, True):
                with self.subTest(mode=mode, previous=previous):
                    self.assertIs(
                        legacy_recovery_password_state(False, mode, previous), False
                    )

    def test_bools_are_not_integer_cursors(self):
        for supplied in (0, 1, -1, None, "true"):
            with self.subTest(supplied=supplied):
                with self.assertRaises(ValueError):
                    legacy_recovery_password_state(cast(Any, supplied), 7, False)
                with self.assertRaises(ValueError):
                    legacy_recovery_password_state(False, 7, cast(Any, supplied))

    def test_native_mode_requires_unsigned_dword(self):
        for mode in (True, False, -1, 1 << 32, 7.0, "7", None):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                legacy_recovery_password_state(False, cast(Any, mode), False)


class ControllerSelectionTests(unittest.TestCase):
    def test_can_router_preserves_composite_result_and_factory_selection(self):
        from unittest.mock import patch

        from scripts.cuw_legacy_engine import execute

        for contact, name in (
            ("CAN", "CCanFlashWriter"),
            ("P5-CAN", "CP5CanFlashWriter"),
        ):
            context = authored_compaction_context()
            rows = tuple(
                replace(
                    row, base_metadata=dict(row.base_metadata, contact_type=contact)
                )
                for row in context.cpus
            )
            context = replace(context, native=rows[0], cpus=rows, controller=name)
            result = {
                "native_success": True,
                "success": False,
                "host_cleanup_errors": ["authored cleanup fault"],
            }
            io = ExecutableIO(lambda event, remaining: None)
            with patch("scripts.cuw_legacy_can.execute", return_value=result) as target:
                self.assertIs(execute(context, io), result)
                target.assert_called_once_with(context, io)
            context.state.recovery_retry = True
            with self.assertRaises(NotImplementedError):
                execute(context, io)

    def test_execute_rejects_unimplemented_or_spoofed_factory_before_io(self):
        from scripts.cuw_legacy_engine import execute

        calls = []
        io = ExecutableIO(lambda event, remaining: calls.append(event))
        context = authored_compaction_context()
        with self.assertRaises(ValueError):
            execute(context, io)
        with self.assertRaises(ValueError):
            execute(replace(context, controller="CSilFlashWriter"), io)
        with self.assertRaises(TypeError):
            cast(Any, execute)(context, io, native_delay=True)
        self.assertEqual(calls, [])

    def test_native_standard_flow_reaches_all_twenty_concrete_classes(self):
        cases = (
            ("SIL", "8", "1", "17", "CSilDCMPRLFlashWriter"),
            ("SIL", "1", "1", "17", "CSilM16CFlashWriter"),
            ("SIL", "1", "57", "1", "CSilEMPS_V850E_PS1_2FlashWriter"),
            ("SIL", "37", "1", "1", "CSilOccupantDetectionFlashWriter"),
            ("SIL", "1", "1", "1", "CSilFlashWriter"),
            ("P5-CAN", "8", "57", "17", "CP5CanFlashWriter"),
            ("CAN", "13", "56", "1", "CCanEMPS_V850E_PS2FlashWriter"),
            ("CAN", "5", "1", "1", "CCanFCFlashWriter"),
            ("CAN", "4", "1", "1", "CCanOldSpecECBFlashWriter"),
            ("CAN", "7", "27", "1", "CCanEPBFlashWriter"),
            ("CAN", "14", "1", "1", "CCanChassisShrinkFlashWriter"),
            ("CAN", "17", "1", "1", "CCanDHFlashWriter"),
            ("CAN", "19", "1", "1", "CCanAirbagFlashWriter"),
            ("CAN", "24", "1", "1", "CCanBodyFlashWriter"),
            ("CAN", "29", "1", "1", "CCanClearanceSonarFlashWriter"),
            ("CAN", "31", "1", "1", "CCanFHIFlashWriter"),
            ("CAN", "35", "1", "1", "CCanDSS1FlashWriter"),
            ("CAN", "8", "1", "1", "CCanDCMPRLFlashWriter"),
            ("CAN", "45", "1", "1", "CCanElectricPowerControlFlashWriter"),
            ("CAN", "1", "1", "1", "CCanFlashWriter"),
        )
        observed = set()
        for protocol, kind, first, selected, expected in cases:
            with self.subTest(expected=expected):
                actual = select_executable_controller(
                    protocol, kind, first, selected, native_flag_ed4=True
                )
                self.assertEqual(actual, expected)
                observed.add(actual)
        self.assertEqual(len(observed), 20)

    def test_selected_cpu_and_first_cpu_have_distinct_native_roles(self):
        select = select_executable_controller
        self.assertEqual(select("SIL", "37", "57", "17"), "CSilM16CFlashWriter")
        self.assertEqual(
            select("SIL", "37", "57", "1"), "CSilEMPS_V850E_PS1_2FlashWriter"
        )
        self.assertEqual(
            select("SIL", "37", "1", "57"), "CSilOccupantDetectionFlashWriter"
        )
        self.assertEqual(select("CAN", "7", "1", "27"), "CCanChassisShrinkFlashWriter")
        self.assertEqual(select("CAN", "13", "1", "56"), "CCanChassisShrinkFlashWriter")

    def test_literal_metadata_is_not_normalized_into_another_native_branch(self):
        self.assertEqual(
            select_executable_controller("CAN", "04", "27", "17"), "CCanFlashWriter"
        )
        for protocol in ("can", "CAN ", "P5-Unified", "Ethernet", ""):
            with self.subTest(protocol=protocol), self.assertRaises(ValueError):
                select_executable_controller(protocol, "1", "1", "1")
        with self.assertRaises(ValueError):
            select_executable_controller("CAN", "4", "1", "1")
        self.assertEqual(
            select_executable_controller("CAN", "4", "1", "1", native_flag_ed4=False),
            "CCanChassisShrinkFlashWriter",
        )


class NativeMessageTests(unittest.TestCase):
    def test_raw_rx_status_and_metadata_survive_provider_boundary(self):
        fields = {
            "protocol_id": 6,
            "data": b"\x00\x00\x07\x00\x3c",
            "rx_status": 16,
            "tx_flags": 128,
            "timestamp": 42,
            "extra_data_index": 5,
        }
        messages = legacy_messages([fields])
        self.assertEqual(
            messages, (NativeMessage(6, b"\x00\x00\x07\x00\x3c", 16, 128, 42, 5),)
        )
        self.assertEqual(legacy_indication(messages[0].rx_status, False), 3)
        self.assertEqual(legacy_indication(messages[0].rx_status, True), 2)
        self.assertEqual(legacy_messages(messages), messages)

    def test_bytes_or_partial_structs_cannot_silently_assume_status_zero(self):
        for result in (
            b"payload",
            [b"payload"],
            [{"data": b"payload"}],
            [
                {
                    "protocol_id": 6,
                    "data": b"x",
                    "rx_status": True,
                    "tx_flags": 0,
                    "timestamp": 0,
                    "extra_data_index": 0,
                }
            ],
        ):
            with self.subTest(result=result), self.assertRaises(ValueError):
                legacy_messages(result)

    def test_classification_ignores_only_native_high_status_bits(self):
        for low, expected in ((0, 3), (2, 1), (9, 0), (16, 3), (1, 4), (31, 4)):
            with self.subTest(low=low):
                self.assertEqual(legacy_indication(low | 0x100, False), expected)


def imported_context(parameters=None):
    from scripts.programming_legacy import bind_native_cpu_context
    from tests.test_programming_legacy import authored_legacy_input

    container, selection, _, _ = authored_legacy_input(
        "TCUWCanCommonFlashWriter.dll",
        "write",
        payload=b"AB\x12\x34\x56\x78" + bytes(1018),
        parameters={
            "PasswordAddress": "00000002",
            "ByteOrder": "0",
            **(parameters or {}),
        },
    )
    native = bind_native_cpu_context(
        container, 1, ("DEMO-OLD",), selection, stage="write"
    )
    return ExecutableContext(18, "CCanFlashWriter", native, (native,), container.digest)


class ImportedPasswordAndRecoveryTests(unittest.TestCase):
    def test_original_location_id_uses_native_zero_padded_array(self):
        from scripts.cuw_legacy_engine import executable_selected_location_id

        for build in (12, 18):
            context = authored_compaction_context(build)
            rows = []
            for row, value in zip(context.cpus, ("", "1234", "0102030405060708")):
                selected = replace(
                    row.selected, values=dict(row.selected.values, locationid=value)
                )
                rows.append(replace(row, selected=selected, location_id=None))
            context = replace(context, native=rows[1], cpus=tuple(rows))
            self.assertEqual(
                executable_selected_location_id(context), b"\x12\x34" + bytes(6)
            )
            self.assertEqual(executable_selected_location_id(context, 0), bytes(8))
            self.assertEqual(
                executable_selected_location_id(context, 2), bytes(range(1, 9))
            )
            sparse = replace(rows[2], selected=replace(rows[2].selected, index=127))
            context = replace(context, cpus=(*context.cpus, sparse))
            self.assertEqual(
                executable_selected_location_id(context, 127), bytes(range(1, 9))
            )
            for index in (True, -1, 128, 3):
                with self.assertRaises(ValueError):
                    executable_selected_location_id(context, index)

    def test_missing_targetdata_uses_native_zero_default(self):
        from scripts.cuw_legacy_engine import executable_selected_password

        for build in (12, 18):
            context = authored_compaction_context(build, target_data=None)
            context.state.target_indices = (0, 0, 0, 0xFFFFFFFF)
            self.assertEqual(executable_selected_password(context), 0)
            empty = authored_compaction_context(build, target_data="")
            empty.state.target_indices = (0, 0, 0, 0xFFFFFFFF)
            self.assertEqual(executable_selected_password(empty), 0)
            for value in ("0x1", "+1", "G", "123456789"):
                malformed = authored_compaction_context(build, target_data=value)
                malformed.state.target_indices = (0, 0, 0, 0xFFFFFFFF)
                with self.assertRaises(ValueError):
                    executable_selected_password(malformed)

    def test_selected_password_requires_native_index_and_keeps_cpu_rows_distinct(self):
        from scripts.cuw_legacy_engine import executable_selected_password

        context = authored_compaction_context()
        with self.assertRaises(LookupError):
            executable_selected_password(context)
        context.state.target_indices = (0, 0, 0, 0xFFFFFFFF)
        self.assertEqual(executable_selected_password(context, 1), 0x12345678)
        context.state.target_indices = (1, 0, 0, 0xFFFFFFFF)
        with self.assertRaises(LookupError):
            executable_selected_password(context)
        for index in (True, -1, 3):
            with self.subTest(index=index), self.assertRaises(ValueError):
                executable_selected_password(context, index)

    def test_concrete_store_controls_active_full_save_for_password_and_error(self):
        from scripts.cuw_legacy_recovery import LegacyRecoveryStore
        from scripts.programming import inspect_recovery_info

        context = replace(
            imported_context(),
            observations={
                "recovery_executable_path": "C:\\CUW\\Cuw.exe",
                "recovery_user_enabled": False,
            },
        )
        self.assertIsNone(getattr(context, "recovery_store", "missing"))
        store = LegacyRecoveryStore.from_context(
            context, "D:\\authored.cuw", "AuthoredDriver"
        )
        context = replace(context, recovery_store=store)
        calls = []

        def action(event, remaining):
            calls.append(event)
            return False if event["operation"] == "recovery_path_exists" else None

        io = ExecutableIO(action)
        apply_recovery_password_state(context, io, True, 0)
        self.assertEqual(calls, [])
        store.begin_writing(io)
        apply_recovery_password_state(context, io, False, 0)
        set_executable_error_code(context, io, 13)
        saved = [
            inspect_recovery_info(event["data"])["fields"]
            for event in calls
            if event["operation"] == "write_recovery_bytes"
        ]
        self.assertEqual(len(saved), 3)
        self.assertTrue(saved[0]["usenewsoftwarepassword"])
        self.assertFalse(saved[1]["usenewsoftwarepassword"])
        self.assertEqual(saved[2]["passthruerrorcode"], 13)
        self.assertIs(store.state, context.state)
        self.assertTrue(context.state.recovery_persistence_active)
        before = len(calls)
        store.set_field(io, "RetryMode", True)
        self.assertTrue(executable_retry_requested(context))
        store.set_field(io, "RetryInput", True)
        self.assertFalse(executable_retry_requested(context))
        self.assertFalse(context.state.retry_mode)
        self.assertEqual(len(calls), before)

    def test_normalized_cpu_types_preserve_imported_order(self):
        context = replace(imported_context(), cpu_types=("17",))
        self.assertEqual(executable_cpu_type(context), "17")
        self.assertEqual(executable_cpu_type(context, 0), "17")
        for index in (True, -1, 1):
            with self.subTest(index=index), self.assertRaises(ValueError):
                executable_cpu_type(context, index)
        with self.assertRaises(ValueError):
            executable_cpu_type(imported_context())
        with self.assertRaises(ValueError):
            replace(context, cpu_types=("17", "18"))

    def test_detected_cpu_type_updates_ram_without_changing_imported_metadata(self):
        context = replace(imported_context(), cpu_types=("17",))
        original = dict(context.native.selected.values)
        set_executable_cpu_type(context, 0, "54")
        self.assertEqual(executable_cpu_type(context), "54")
        self.assertEqual(context.cpu_types, ("17",))
        self.assertEqual(dict(context.native.selected.values), original)
        for value in ("bad\0type", "あ", "1" * 129):
            with self.subTest(value=value), self.assertRaises(ValueError):
                set_executable_cpu_type(context, 0, value)
        with self.assertRaises(ValueError):
            set_executable_cpu_type(context, 1, "1")
        self.assertEqual(executable_cpu_type(context), "54")

    def test_cpu_type_mutation_reselects_password_parameters_from_actual_catalog(self):
        from scripts.calibration_catalog import (
            CalibrationCatalog,
            parse_parameter_table,
        )
        from scripts.demo_calibration import table
        from tests.test_programming_legacy import authored_legacy_input

        _, selection, _, _ = authored_legacy_input(
            "TCUWCanCommonFlashWriter.dll", "write"
        )
        extra = parse_parameter_table(
            "1CAN54.ini",
            table(
                ("ParamFileKeySystemProtocolMicon", "PasswordAddress", "ByteOrder"),
                [("1CAN54", "00000000", "1")],
            ),
            encoded=False,
        )
        context = replace(
            imported_context(),
            cpu_types=("1",),
            catalog=CalibrationCatalog((*selection.catalog.tables, extra)),
        )
        self.assertEqual(executable_new_password(context), 0x78563412)
        set_executable_cpu_type(context, 0, "54")
        self.assertEqual(executable_parameters(context)["PasswordAddress"], "00000000")
        self.assertEqual(executable_new_password(context), 0x41421234)
        set_executable_cpu_type(context, 0, "UNKNOWN")
        with self.assertRaises(LookupError):
            executable_new_password(context)

    def test_import_binder_requires_actual_source_and_typed_observations(self):
        from tests.test_programming_legacy import authored_legacy_input

        container, selection, _, _ = authored_legacy_input(
            "TCUWCanCommonFlashWriter.dll", "write"
        )
        for build, observations in (
            (18, {}),
            (18, {"channel_padding": 1}),
            (12, {"channel_flag_67": True}),
            (18, {"channel_flag_67": True, "channel_padding": False}),
            (18, {"observed_cids": ("OTHER-CID",)}),
        ):
            with (
                self.subTest(build=build, observations=observations),
                self.assertRaises(ValueError),
            ):
                bind_context(
                    container,
                    1,
                    ("DEMO-OLD",),
                    selection,
                    build=build,
                    observations=observations,
                )

    def test_actual_authored_cuw_image_and_catalog_produce_password(self):
        context = imported_context()
        self.assertEqual(executable_new_password(context.native), 0x78563412)
        self.assertEqual(
            executable_new_password(imported_context({"ByteOrder": "1"}).native),
            0x12345678,
        )
        # The executable compares the whole signed long, not its low WORD.
        self.assertEqual(
            executable_new_password(imported_context({"ByteOrder": "65536"}).native),
            0x12345678,
        )
        self.assertEqual(
            executable_new_password(imported_context({"ByteOrder": "-1"}).native),
            0x12345678,
        )
        # NewPassword in the imported CPU is11223344; this helper reads the image.
        self.assertNotEqual(executable_new_password(context.native), 0x11223344)

    def test_image_pointer_and_native_parameter_boundaries(self):
        context = imported_context()
        for parameters in (
            {"PasswordAddress": "00000400"},
            {"PasswordAddress": "2"},
            {"PasswordAddress": "zz"},
            {"ByteOrder": "2147483648"},
        ):
            with self.subTest(parameters=parameters), self.assertRaises(ValueError):
                executable_new_password(imported_context(parameters).native)
        with self.assertRaises(ValueError):
            executable_new_password(replace(context.native, image=None))

    def test_end_block_argument_updates_password_field_then_persists(self):
        context = imported_context()
        calls = []
        io = ExecutableIO(lambda event, remaining: calls.append(event))
        self.assertTrue(
            apply_recovery_password_state(context, io, True, 0, persist=True)
        )
        self.assertTrue(context.state.use_new_software_password)
        self.assertFalse(context.state.writing_end_block)
        self.assertEqual(
            calls,
            [
                {
                    "operation": "write_recovery_bool",
                    "key": "UseNewSoftwarePassword",
                    "value": True,
                }
            ],
        )
        self.assertFalse(
            apply_recovery_password_state(context, io, False, 7, persist=False)
        )
        self.assertEqual(len(calls), 1)

    def test_persistence_fault_retains_native_memory_mutation(self):
        context = imported_context()

        def fault(event, remaining):
            raise OSError("authored persistence failure")

        with self.assertRaises(OSError):
            apply_recovery_password_state(
                context, ExecutableIO(fault), True, 0, persist=True
            )
        self.assertTrue(context.state.use_new_software_password)

    def test_cancelled_persistence_is_bounded_and_does_not_become_success(self):
        context = imported_context()
        calls = []
        io = ExecutableIO(
            lambda event, remaining: calls.append(event), cancelled=lambda: True
        )
        with self.assertRaises(InterruptedError):
            apply_recovery_password_state(context, io, True, 0, persist=True)
        self.assertEqual(calls, [])
        self.assertTrue(context.state.use_new_software_password)

    def test_native_retry_predicate_uses_both_runtime_flags(self):
        for first in (False, True):
            for second in (False, True):
                io = ExecutableIO(
                    lambda event, remaining, first=first, second=second: {
                        "native_flag_5b": first,
                        "native_flag_5c": second,
                    }
                )
                self.assertIs(executable_retry_requested(io), first and not second)
        for result in (
            True,
            {"native_flag_5b": True},
            {"native_flag_5b": 1, "native_flag_5c": False},
        ):
            with self.subTest(result=result), self.assertRaises(ValueError):
                executable_retry_requested(
                    ExecutableIO(lambda event, remaining, result=result: result)
                )

    def test_context_and_state_reject_unbound_or_malformed_selections(self):
        context = imported_context()
        with self.assertRaises(ValueError):
            replace(context, native=replace(context.native))
        with self.assertRaises(ValueError):
            replace(context, cpus=(context.native, context.native))
        with self.assertRaises(ValueError):
            replace(context, state=ExecutableState(write_cpu_index=1))
        for build in (True, 2026, "18"):
            with self.subTest(build=build), self.assertRaises(ValueError):
                replace(context, build=build)


class ConcreteBoundaryTests(unittest.TestCase):
    def test_constructor_timeout_snapshot_and_retry_bool_keep_native_types(self):
        from scripts.cuw_legacy_engine import executable_constructor_send_timeout

        context = replace(
            imported_context(),
            constructor_read_timeout=137,
            constructor_send_timeout=927,
        )
        self.assertEqual(executable_constructor_timeout(context), 137)
        self.assertEqual(executable_constructor_send_timeout(context), 927)
        self.assertFalse(context.state.retry_mode)
        self.assertFalse(context.state.recovery_retry)
        self.assertFalse(context.state.retry_input)
        self.assertFalse(context.state.native_flag_ed6)
        self.assertFalse(context.state.native_flag_ed7)
        self.assertFalse(context.state.native_flag_ed8)
        self.assertFalse(context.state.recovery_persistence_active)
        context.state.retry_mode = True
        context.state.validate()
        self.assertFalse(context.state.recovery_retry)
        self.assertFalse(context.state.retry_input)
        for value in (True, -1, 1 << 32):
            with self.subTest(value=value), self.assertRaises(ValueError):
                replace(context, constructor_read_timeout=value)
            with self.subTest(send_value=value), self.assertRaises(ValueError):
                replace(context, constructor_send_timeout=value)
        with self.assertRaises(ValueError):
            executable_constructor_timeout(imported_context())
        with self.assertRaises(ValueError):
            executable_constructor_send_timeout(imported_context())
        with self.assertRaises(ValueError):
            ExecutableState(retry_mode=cast(Any, 1))
        with self.assertRaises(ValueError):
            ExecutableState(recovery_retry=cast(Any, 1))
        with self.assertRaises(ValueError):
            ExecutableState(retry_input=cast(Any, 1))
        for key in (
            "native_flag_ed5",
            "native_flag_ed6",
            "native_flag_ed7",
            "native_flag_ed8",
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                ExecutableState(**{key: cast(Any, 1)})

    def test_native_exception_domain_does_not_admit_host_faults(self):
        from scripts.cuw_legacy_engine import (
            ExecutableForeignNativeError,
            ExecutableNativeError,
        )

        foreign = ExecutableForeignNativeError("authored native exception")
        self.assertIsInstance(foreign, ExecutableNativeError)
        self.assertIsInstance(ExecutableJ2534Error(1, 7), ExecutableNativeError)
        self.assertNotIsInstance(foreign, ExecutableJ2534Error)
        for error in (
            ValueError("host validation"),
            OSError("host I/O"),
            InterruptedError(),
        ):
            self.assertNotIsInstance(error, ExecutableNativeError)

    def test_literal_filter_messages_and_owned_release(self):
        for width, padding, flags in ((4, False, 0), (4, True, 0x40), (5, True, 0xC0)):
            calls = []

            def action(event, remaining, calls=calls):
                calls.append(event)
                return 41 if event["operation"] == "start_filter" else None

            io = ExecutableIO(action)
            request, response = bytes(range(width)), bytes(range(8, 8 + width))
            handle = executable_start_filter(io, request, response, padding=padding)
            self.assertEqual(handle, 41)
            self.assertEqual(
                calls[0],
                {
                    "operation": "start_filter",
                    "filter_type": 3,
                    "mask": NativeMessage(6, b"\xff" * width, tx_flags=flags),
                    "pattern": NativeMessage(6, response, tx_flags=flags),
                    "flow_control": NativeMessage(6, request, tx_flags=flags),
                },
            )
            self.assertTrue(io.owns_resource("stop_filter", filter_id=41))
            executable_stop_filter(io, handle)
            self.assertEqual(calls[-1], {"operation": "stop_filter", "filter_id": 41})
            self.assertFalse(io.owns_resource("stop_filter", filter_id=41))

    def test_filter_acquisition_cancel_rolls_back_returned_handle(self):
        cancelled = False
        calls = []

        def action(event, remaining):
            nonlocal cancelled
            calls.append(event["operation"])
            if event["operation"] == "start_filter":
                cancelled = True
                return 0

        io = ExecutableIO(action, cancelled=lambda: cancelled)
        with self.assertRaises(InterruptedError):
            executable_start_filter(io, bytes(4), bytes(4), padding=True)
        self.assertEqual(calls, ["start_filter", "stop_filter"])
        self.assertFalse(io.owns_resource("stop_filter", filter_id=0))

    def test_failed_native_filter_stop_retains_resource_for_host_cleanup(self):
        from scripts.programming import NativeTransportError

        fail_stop = True

        def action(event, remaining):
            if event["operation"] == "start_filter":
                return 6
            if fail_stop:
                raise NativeTransportError(16)

        io = ExecutableIO(action)
        executable_start_filter(io, bytes(4), bytes(4), padding=False)
        with self.assertRaises(ExecutableJ2534Error) as raised:
            executable_stop_filter(io, 6)
        self.assertEqual(
            (raised.exception.native_code, raised.exception.driver_status), (1, 16)
        )
        self.assertTrue(io.owns_resource("stop_filter", filter_id=6))
        fail_stop = False
        self.assertEqual(io.close(), [])

    def test_j2534_category_and_driver_status_are_distinct_and_remappable(self):
        from scripts.programming import NativeTransportError

        def failed(event, remaining):
            raise NativeTransportError(16)

        with self.assertRaises(ExecutableJ2534Error) as raised:
            executable_j2534_call(
                ExecutableIO(failed), "read_messages", protocol_id=6, count=1
            )
        error = raised.exception
        self.assertEqual(
            (error.native_code, error.driver_status, error.code), (1, 16, 16)
        )
        error.native_code = 13
        self.assertEqual(
            (error.native_code, error.driver_status, error.code), (13, 16, 16)
        )
        for malformed in (True, -129, 128, 256):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                error.native_code = malformed

    def test_typed_native_error_and_host_faults_keep_original_identity(self):
        native = ExecutableJ2534Error(13, 9)
        for error in (
            native,
            OSError("authored host failure"),
            InterruptedError("authored cancellation"),
        ):

            def fail(event, remaining, error=error):
                raise error

            with self.assertRaises(type(error)) as raised:
                executable_j2534_call(
                    ExecutableIO(fail), "write_messages", data=b"abc", count=1
                )
            self.assertIs(raised.exception, error)
        with self.assertRaises(ValueError):
            executable_j2534_call(
                ExecutableIO(lambda event, remaining: None), "wait", milliseconds=1
            )

    def test_synchronized_callback_copies_exact_fields_and_typed_read(self):
        calls = []
        io = ExecutableIO(lambda event, remaining: calls.append(event))
        executable_sync(io, "values_78_80", value_78=13, value_80=9)
        executable_sync(io, "completion", outcome="failure")
        self.assertEqual(
            calls,
            [
                {
                    "operation": "controller_callback",
                    "callback": "values_78_80",
                    "value_78": 13,
                    "value_80": 9,
                },
                {
                    "operation": "controller_callback",
                    "callback": "completion",
                    "outcome": "failure",
                },
            ],
        )
        self.assertIs(
            executable_sync(
                ExecutableIO(lambda event, remaining: True), "read_flag_88"
            ),
            True,
        )
        for callback, values in (
            ("unknown", {}),
            ("flag_68", {"value": 1}),
            ("value_70", {"value": True}),
            ("completion", {"outcome": "native_pointer"}),
        ):
            with self.subTest(callback=callback), self.assertRaises(ValueError):
                executable_sync(io, callback, **values)
        for callback, result in (
            ("read_flag_88", 1),
            ("owner_clear", True),
            ("completion", False),
        ):
            with self.subTest(callback=callback), self.assertRaises(ValueError):
                executable_sync(
                    ExecutableIO(lambda event, remaining, result=result: result),
                    callback,
                    **({"outcome": "success"} if callback == "completion" else {}),
                )

    def test_phase_error_code_is_mutated_before_persist_and_not_rolled_back(self):
        context = imported_context()
        self.assertEqual(context.state.pass_thru_error_code, 99)
        calls = []
        io = ExecutableIO(lambda event, remaining: calls.append(event))
        set_executable_error_code(context, io, 13, persist=True)
        self.assertEqual(context.state.pass_thru_error_code, 13)
        self.assertEqual(
            calls,
            [
                {
                    "operation": "write_recovery_int",
                    "key": "PassThruErrorCode",
                    "value": 13,
                }
            ],
        )

        def fault(event, remaining):
            raise OSError("authored persistence failure")

        with self.assertRaises(OSError):
            set_executable_error_code(context, ExecutableIO(fault), 15, persist=True)
        self.assertEqual(context.state.pass_thru_error_code, 15)

    def test_static_image_requires_actual_matching_original_identity(self):
        context = imported_context()
        for attachments in ({}, {"legacy_executable": b"MZ" + bytes(100)}):
            with self.subTest(attachments=attachments), self.assertRaises(ValueError):
                ExecutableImage(replace(context, attachments=attachments))


if __name__ == "__main__":
    unittest.main()
