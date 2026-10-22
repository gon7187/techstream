"""Authored controls for the concrete, source-issued native CParameter array."""

import struct
import unittest
from pathlib import Path
from typing import cast

from scripts.calibration_2026 import native2026_with_cpu_type
from scripts.cuw_2026 import CUWEngine2026
from scripts.cuw_parameter_pool import (
    ControlParameterPool2026,
    _binding_state2026,
)
from scripts.demo_calibration import table
from scripts.programming_2026_common import (
    NativeGeneralParameters2026,
    NativePassThruException2026,
    NativeRuntime2026,
)
from tests.private_evidence import read_private_bytes
from tests.test_calibration_2026 import cuw
from tests.test_cuw_engine_worker import make_controller

RUNTIME = Path("runtime/no-car-21/recovered")


def classic_source() -> bytes:
    return cuw(
        "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=2\n"
        "KindOfECU=K\nContactType=SIL\n"
        "[CPU01]\nCPUImageName=a.bin\nCPUType=311\nNewCID=A\n"
        "[CPU02]\nCPUImageName=b.bin\nCPUType=312\nNewCID=B\n",
        (b"a", b"b"),
    )


def modern_logical_source() -> bytes:
    return cuw(
        "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=2\n"
        "KindOfECU=149\nContactType=P5-Unified\n"
        "[Node01]\nRequiredSpecReproVer=02\nProtocol=09\nNumberOfCalibration=1\n"
        "[CPU11]\nCPUImageName=ordinary.bin\nCPUType=311\nNewCID=ORDINARY\n"
        "[Node02]\nRequiredSpecReproVer=03\nNumberOfLogicalBlock=1\n"
        "[LogicalBlock201]\nNewCID=LOGICAL\nNumberOfTargets=1\n"
        "01_TargetCalibration=OLD\nReproMethod=00\n"
        "[ReproData201]\nStartAddress=00001000\nLength=00000004\n",
        (b"a", b"b"),
    )


def modern_cpu_source(cpus: int = 1, *, required: str | None = "02") -> bytes:
    cpu_text = (
        "[CPU11]\nCPUImageName=a.bin\nCPUType=311\nNewCID=NEW1\n"
        "StartAddress=0100001000\nSizeOfUncompressedDownloadData=00000020\n"
        "SizeOfDownloadData=00000004\nNumberOfTargets=2\n"
        "01_TargetCalibration=OLD\n02_TargetCalibration=LATEST\n"
    )
    payloads = [b"a"]
    if cpus == 2:
        cpu_text += (
            "[CPU12]\nCPUImageName=b.bin\nCPUType=312\nNewCID=NEW2\n"
            "StartAddress=0100002000\nSizeOfUncompressedDownloadData=00000020\n"
            "SizeOfDownloadData=00000004\nNumberOfTargets=2\n"
            "01_TargetCalibration=SECOND-OLD\n02_TargetCalibration=SECOND-LATEST\n"
        )
        payloads.append(b"b")
    required_line = f"RequiredSpecReproVer={required}\n" if required is not None else ""
    text = (
        "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=1\n"
        "ContactType=P5-Unified\nKindOfECU=149\n"
        f"[Node01]\n{required_line}NumberOfCalibration={cpus}\n"
        f"{cpu_text}"
    )
    return cuw(text, tuple(payloads))


def parameter_file(rows: tuple[tuple[str, str], ...]) -> bytes:
    return (
        "ParamFileKeySystemProtocolMicon,Value\r\n"
        + "".join(f"{key},{value}\r\n" for key, value in rows)
    ).encode("ascii")


def encode_parameter_file(data: bytes) -> bytes:
    return bytes(
        value
        for byte in data
        for value in (((byte >> 4) + 8) << 2, ((byte & 0x0F) + 8) << 2)
    )


class ControlParameterPool2026Tests(unittest.TestCase):
    def setUp(self):
        required = (RUNTIME / "CUW.dll", RUNTIME / "TCUWControlCommPhase.dll")
        if any(not path.is_file() for path in required):
            self.skipTest("Authenticated static CUW2026 pipeline is absent")

    def make_engine(self, source: bytes) -> CUWEngine2026:
        general = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": table(
                    (
                        "ParamFileKeySystemProtocolMicon",
                        "M16CTypeFlag",
                        "FORESTTypeFlag",
                        "PasswordAddress",
                        "ByteOrder",
                        "FlagToDoIGOFFONAtCPUTypeChange",
                        "FlagToChangeToReprogGWModeForCentralGW",
                    ),
                    tuple(
                        (key, "0", "0", "00", "1", "0", "0")
                        for key in (
                            "KSIL",
                            "KSIL311",
                            "KSIL312",
                            "149P5-Unified",
                            "149P5-Unified311",
                            "149P5-Unified312",
                        )
                    ),
                )
            },
            encoded=False,
        )
        engine = CUWEngine2026(
            read_private_bytes(RUNTIME / "CUW.dll"), general_parameters=general
        )
        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        engine.load_cuw(source)
        self.addCleanup(engine.close)
        return engine

    def run_control(self, engine, controller, callback):
        with engine.controller_execution(controller, 1):
            callback(engine.worker)

    def controller(self):
        return make_controller(NativeRuntime2026(lambda *_: None))

    def test_constructor_slots_are_issued_empty_and_reject_copies(self):
        import copy

        engine = self.make_engine(classic_source())
        controller = self.controller()
        engine.bind_worker(controller)
        result = []

        def check(_worker):
            pool = ControlParameterPool2026.issue(engine, controller, {}, encoded=False)
            self.addCleanup(pool.close)
            self.assertEqual(pool.capacity, engine.common_definitions.num_cpu_maxnum)
            self.assertIs(
                ControlParameterPool2026.issue(engine, controller, {}, encoded=False),
                pool,
            )
            empty = pool.slot(0)
            self.assertFalse(empty.loaded)
            self.assertIsNone(empty.filename)
            self.assertEqual((empty.row_index, empty.value("Absent")), (0, ""))
            snapshot = empty.parameter
            snapshot.row_index = 3
            snapshot.headers = ("mutated",)
            self.assertEqual(
                (empty.parameter.row_index, empty.parameter.headers), (0, ())
            )
            with self.assertRaises(TypeError):
                cast(dict[str, bytes], pool.catalog_sources)["injected.ini"] = (
                    b"K,V\r\nkey,value\r\n"
                )
            with self.assertRaises(ValueError):
                pool._slot_state(copy.copy(empty), engine, controller)
            result.append(pool)

        self.run_control(engine, controller, check)
        self.assertEqual(len(result), 1)

    def test_classic_prepare_loads_distinct_rows_in_slot_order(self):
        engine = self.make_engine(classic_source())
        controller = self.controller()
        engine.bind_worker(controller)
        sources = {
            "KSIL311.ini": parameter_file((("KSIL311", "first"),)),
            "KSIL312.ini": parameter_file((("KSIL312", "second"),)),
        }

        def check(_worker):
            pool = ControlParameterPool2026.issue(
                engine, controller, sources, encoded=False
            )
            self.addCleanup(pool.close)
            self.assertEqual(pool.load_for(engine, controller, "prepare"), (0, 1))
            first, second = pool.slot(0), pool.slot(1)
            self.assertEqual(
                (first.value("Value"), second.value("Value")), ("first", "second")
            )
            self.assertEqual(
                (first.filename, second.filename), ("KSIL311.ini", "KSIL312.ini")
            )
            self.assertEqual((first.revision, second.revision), (2, 2))
            pool.load_for(engine, controller, "prepare")
            self.assertEqual((first.revision, second.revision), (4, 4))
            slot, metadata = _binding_state2026(engine, controller, 1)
            self.assertIs(slot, second)
            self.assertIs(
                metadata.source_container, engine.native_metadata.source_container
            )
            binding = pool.selected_binding(engine, controller, 1, "prepare")
            self.assertEqual(binding.value("Value"), "second")
            module_binding = binding.module_binding
            assert module_binding is not None
            self.assertEqual(module_binding.value("Value"), "first")
            self.assertIs(
                binding.validate_against(
                    metadata.source_container, operation="prepare"
                ),
                binding,
            )
            with self.assertRaisesRegex(ValueError, "catalog"):
                ControlParameterPool2026.issue(
                    engine,
                    controller,
                    {
                        **sources,
                        "KSIL311.ini": parameter_file((("KSIL311", "changed"),)),
                    },
                    encoded=False,
                )

        self.run_control(engine, controller, check)

    def test_missing_second_file_keeps_first_slot_mutation_and_native_error_location(
        self,
    ):
        engine = self.make_engine(classic_source())
        controller = self.controller()
        engine.bind_worker(controller)
        sources = {"KSIL311.ini": parameter_file((("KSIL311", "first"),))}

        def check(_worker):
            pool = ControlParameterPool2026.issue(
                engine, controller, sources, encoded=False
            )
            self.addCleanup(pool.close)
            with self.assertRaises(NativePassThruException2026) as raised:
                pool.load_for(engine, controller, "write")
            self.assertEqual(
                (raised.exception.error, raised.exception.line), (9999, 0x8DC)
            )
            self.assertEqual(
                raised.exception.source, "TCUWControlCommPhase.dll:RVA4c10"
            )
            self.assertEqual(pool.slot(0).value("Value"), "first")
            self.assertFalse(pool.slot(1).loaded)

        self.run_control(engine, controller, check)

    def test_load_iterator_leaves_next_slot_untouched_on_consumer_exception(self):
        engine = self.make_engine(classic_source())
        controller = self.controller()
        engine.bind_worker(controller)
        sources = {
            "KSIL311.ini": parameter_file((("KSIL311", "first"),)),
            "KSIL312.ini": parameter_file((("KSIL312", "second"),)),
        }

        def check(_worker):
            pool = ControlParameterPool2026.issue(
                engine, controller, sources, encoded=False
            )
            self.addCleanup(pool.close)
            steps = pool.load_steps_for(engine, controller, "write")
            self.assertEqual(next(steps), 0)
            original = LookupError("interleaved preflight fault")
            try:
                raise original
            except LookupError as caught:
                self.assertIs(caught, original)
            self.assertTrue(pool.slot(0).loaded)
            self.assertFalse(pool.slot(1).loaded)

        self.run_control(engine, controller, check)

    def test_gateway_plan_overwrites_slot_zero_with_empty_dll_value(self):
        engine = self.make_engine(classic_source())
        controller = self.controller()
        engine.bind_worker(controller)
        sources = {
            "KSIL311.ini": (
                "ParamFileKeySystemProtocolMicon,DLLFileNameForChangeGateway,Value\r\n"
                "KSIL311,,gateway\r\n"
            ).encode("ascii")
        }

        def check(_worker):
            pool = ControlParameterPool2026.issue(
                engine, controller, sources, encoded=False
            )
            self.addCleanup(pool.close)
            pool.load_for(engine, controller, "get_cid")
            self.assertEqual(pool.slot(0).revision, 2)
            self.assertEqual(pool.load_for(engine, controller, "change_gateway"), (0,))
            self.assertEqual(pool.slot(0).revision, 4)
            self.assertEqual(pool.slot(0).value("DLLFileNameForChangeGateway"), "")
            self.assertEqual(pool.slot(0).value("Value"), "gateway")
            self.assertFalse(pool.slot(1).loaded)

        self.run_control(engine, controller, check)

    def test_capacity_zero_and_one_are_read_from_common_definitions(self):
        for capacity in (0, 1):
            with self.subTest(capacity=capacity):
                engine = self.make_engine(classic_source())
                engine.common_definitions.num_cpu_maxnum = capacity
                controller = self.controller()
                engine.bind_worker(controller)

                def check(
                    _worker, capacity=capacity, engine=engine, controller=controller
                ):
                    pool = ControlParameterPool2026.issue(
                        engine, controller, {}, encoded=False
                    )
                    self.addCleanup(pool.close)
                    self.assertEqual(pool.capacity, capacity)
                    if capacity == 0:
                        with self.assertRaises(IndexError):
                            pool.slot(0)
                    else:
                        self.assertEqual(pool.slot(0).index, 0)
                        with self.assertRaises(ValueError):
                            pool.load_for(engine, controller, "prepare")
                        self.assertFalse(pool.slot(0).loaded)

                self.run_control(engine, controller, check)

    def test_slot_read_requires_active_owner_and_close_invalidates_idempotently(self):
        engine = self.make_engine(classic_source())
        controller = self.controller()
        engine.bind_worker(controller)
        pool_holder = []

        def check(_worker):
            pool = ControlParameterPool2026.issue(engine, controller, {}, encoded=False)
            slot = pool.slot(0)
            self.assertEqual(slot.parameter.key_column, 0)
            pool_holder.append((pool, slot))

        self.run_control(engine, controller, check)
        pool, slot = pool_holder[0]
        pool.close()
        pool.close()
        with self.assertRaisesRegex(ValueError, "pool"):
            _ = slot.loaded

    def test_inactive_pool_detach_after_worker_close_preserves_active_and_foreign_guards(
        self,
    ):
        engine = self.make_engine(classic_source())
        controller = self.controller()
        worker = engine.bind_worker(controller)
        issued = []

        def issue(_worker):
            pool = ControlParameterPool2026.issue(engine, controller, {}, encoded=False)
            controller._control_parameter_pool2026 = pool
            issued.append(pool)
            with self.assertRaisesRegex(ValueError, "Active CONTROL module array"):
                pool.close()
            self.assertEqual(pool.capacity, engine.common_definitions.num_cpu_maxnum)

        self.run_control(engine, controller, issue)
        pool = issued[0]
        foreign_engine = self.make_engine(classic_source())
        foreign_controller = self.controller()
        foreign_engine.bind_worker(foreign_controller)
        with self.assertRaisesRegex(ValueError, "owners"):
            pool._require_state(
                foreign_engine,
                foreign_controller,
                active=False,
                check_capacity=False,
            )
        foreign_engine.close()

        worker.close()
        with self.assertRaisesRegex(ValueError, "Engine worker is closed"):
            ControlParameterPool2026.issue(engine, controller, {}, encoded=False)
        engine.close()
        self.assertTrue(pool._state.closed)
        pool.close()

    def test_getter_missing_file_is_native_error_and_capacity_cannot_drift(self):
        engine = self.make_engine(classic_source())
        controller = self.controller()
        engine.bind_worker(controller)

        def check(_worker):
            pool = ControlParameterPool2026.issue(engine, controller, {}, encoded=False)
            self.addCleanup(pool.close)
            with self.assertRaises(NativePassThruException2026) as raised:
                pool.load_for(engine, controller, "get_cid")
            self.assertEqual(
                (raised.exception.source, raised.exception.line),
                ("TCUWControlCommPhase.dll:RVA6f20", 0x6AB),
            )
            engine.common_definitions.num_cpu_maxnum += 1
            with self.assertRaisesRegex(ValueError, "capacity changed"):
                pool.validate(engine, controller)

        self.run_control(engine, controller, check)

    def test_absent_required_spec_is_not_forced_to_native_02(self):
        engine = self.make_engine(modern_cpu_source(required=None))
        controller = self.controller()
        engine.bind_worker(controller)

        def check(_worker):
            pool = ControlParameterPool2026.issue(engine, controller, {}, encoded=False)
            self.addCleanup(pool.close)
            with self.assertRaises(NativePassThruException2026) as raised:
                pool.load_for(engine, controller, "prepare")
            self.assertEqual(
                (raised.exception.source, raised.exception.line),
                ("TCUWControlCommPhase.dll:RVA9370", 0xA22),
            )

        self.run_control(engine, controller, check)

    def test_modern_logical_node_starts_after_prior_ordinary_cpu_slots(self):
        source = modern_logical_source()
        engine = self.make_engine(source)
        engine.load_cuw(source, node=2, cpu_index=0)
        controller = self.controller()
        worker = engine.bind_worker(controller)
        engine._select_worker_metadata(
            native2026_with_cpu_type(engine.native_metadata, 0, "311"),
            controller=controller,
            worker=worker,
        )
        sources = {
            "149P5-Unified03311.ini": parameter_file((("149P5-Unified03311", "same"),))
        }

        def check(_worker):
            pool = ControlParameterPool2026.issue(
                engine, controller, sources, encoded=False
            )
            self.addCleanup(pool.close)
            self.assertEqual(pool.load_for(engine, controller, "write"), (1,))
            self.assertFalse(pool.slot(0).loaded)
            self.assertEqual(pool.slot(1).value("Value"), "same")

        self.run_control(engine, controller, check)

    def test_getter_protocol_and_modern_prepare_required_suffix_are_distinct(self):
        source = modern_logical_source()
        engine = self.make_engine(source)
        engine.load_cuw(source, node=2, cpu_index=0)
        controller = self.controller()
        worker = engine.bind_worker(controller)
        engine._select_worker_metadata(
            native2026_with_cpu_type(engine.native_metadata, 0, "311"),
            controller=controller,
            worker=worker,
        )
        sources = {
            "149P5-Unified09311.ini": parameter_file(
                (("149P5-Unified09311", "getter"),)
            ),
            "149P5-Unified03311.ini": parameter_file(
                (("149P5-Unified03311", "prepare"),)
            ),
        }

        def check(_worker):
            pool = ControlParameterPool2026.issue(
                engine, controller, sources, encoded=False
            )
            self.addCleanup(pool.close)
            self.assertEqual(pool.load_for(engine, controller, "get_cid"), (0,))
            self.assertEqual(pool.slot(0).value("Value"), "getter")
            self.assertEqual(pool.load_for(engine, controller, "prepare"), (0,))
            self.assertEqual(pool.slot(0).filename, "149P5-Unified03311.ini")
            self.assertEqual(pool.slot(0).value("Value"), "prepare")

        self.run_control(engine, controller, check)

    def test_setkeys_failure_retains_replaced_matrix_and_failed_row(self):
        source = modern_logical_source()
        engine = self.make_engine(source)
        controller = self.controller()
        worker = engine.bind_worker(controller)
        engine._select_worker_metadata(
            native2026_with_cpu_type(engine.native_metadata, 0, "311"),
            controller=controller,
            worker=worker,
        )
        sources = {
            "149P5-Unified09311.ini": parameter_file(
                (("149P5-Unified09311", "getter"),)
            ),
            "149P5-Unified311.ini": parameter_file((("wrong-key", "new matrix"),)),
        }

        def check(_worker):
            pool = ControlParameterPool2026.issue(
                engine, controller, sources, encoded=False
            )
            self.addCleanup(pool.close)
            pool.load_for(engine, controller, "get_cid")
            with self.assertRaises(NativePassThruException2026) as raised:
                pool.load_for(engine, controller, "prepare")
            self.assertEqual(
                (raised.exception.source, raised.exception.line),
                ("TCUWControlCommPhase.dll:RVA9370", 0xA49),
            )
            slot = pool.slot(0)
            self.assertEqual(slot.filename, "149P5-Unified311.ini")
            self.assertEqual((slot.row_index, slot.value("Value")), (-1, ""))
            self.assertEqual(slot.revision, 4)

        self.run_control(engine, controller, check)

    def test_missing_key_column_replaces_matrix_but_preserves_old_row(self):
        source = modern_logical_source()
        engine = self.make_engine(source)
        controller = self.controller()
        worker = engine.bind_worker(controller)
        engine._select_worker_metadata(
            native2026_with_cpu_type(engine.native_metadata, 0, "311"),
            controller=controller,
            worker=worker,
        )
        sources = {
            "149P5-Unified09311.ini": parameter_file(
                (("149P5-Unified09311", "getter"),)
            ),
            "149P5-Unified311.ini": b"Other,Value\r\nother,new matrix\r\n",
        }

        def check(_worker):
            pool = ControlParameterPool2026.issue(
                engine, controller, sources, encoded=False
            )
            self.addCleanup(pool.close)
            pool.load_for(engine, controller, "get_cid")
            with self.assertRaises(NativePassThruException2026) as raised:
                pool.load_for(engine, controller, "prepare")
            self.assertEqual(raised.exception.line, 0xA42)
            slot = pool.slot(0)
            self.assertEqual(slot.parameter.headers, ("Other", "Value"))
            self.assertEqual(slot.parameter.key_column, -1)
            self.assertEqual(slot.row_index, 1)
            self.assertEqual(slot.revision, 3)

        self.run_control(engine, controller, check)

    def test_modern_ordinary_write_resumes_at_live_cpu_cursor(self):
        source = modern_cpu_source(cpus=2)
        engine = self.make_engine(source)
        engine.load_cuw(source, cpu_index=1)
        controller = self.controller()
        worker = engine.bind_worker(controller)
        engine._select_worker_metadata(
            native2026_with_cpu_type(engine.native_metadata, 0, "311"),
            controller=controller,
            worker=worker,
        )
        sources = {
            "149P5-Unified311.ini": parameter_file((("149P5-Unified311", "cpu0-key"),))
        }

        def check(_worker):
            pool = ControlParameterPool2026.issue(
                engine, controller, sources, encoded=False
            )
            self.addCleanup(pool.close)
            self.assertEqual(pool.load_for(engine, controller, "write"), (1,))
            self.assertFalse(pool.slot(0).loaded)
            self.assertEqual(pool.slot(1).value("Value"), "cpu0-key")

        self.run_control(engine, controller, check)

    def test_encoded_catalog_and_foreign_owner_are_authenticated(self):
        engine = self.make_engine(classic_source())
        controller = self.controller()
        engine.bind_worker(controller)
        encoded = encode_parameter_file(parameter_file((("KSIL311", "decoded"),)))

        def check(_worker):
            pool = ControlParameterPool2026.issue(
                engine, controller, {"KSIL311.ini": encoded}
            )
            self.addCleanup(pool.close)
            self.assertEqual(pool.load_for(engine, controller, "get_cid"), (0,))
            self.assertEqual(pool.slot(0).value("Value"), "decoded")
            foreign_engine = self.make_engine(classic_source())
            foreign_controller = self.controller()
            foreign_engine.bind_worker(foreign_controller)
            with self.assertRaisesRegex(ValueError, "owners"):
                pool.validate(foreign_engine, foreign_controller)
            foreign_engine.close()

        self.run_control(engine, controller, check)


if __name__ == "__main__":
    unittest.main()
