import copy

"""Authored primitive vectors; private integration separately uses actual images."""

import hashlib
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import cast

from scripts.cuw_2026 import rks_data_from_native
from scripts.cuw_engine_worker import EngineWorker2026
from scripts.cuw_online import (
    ENGINE_SHA256,
    SCHEMA,
    OnlineKey2026,
    OnlineKeyController2026,
    OnlineReplay2026,
    _configuration,
    _request_buffer,
)
from scripts.cuw_persistence import encode_nibble_text
from scripts.cuw_services import rks_xml


def configuration(**overrides):
    fields = {
        "IFVersion": "1",
        "SoftwareID": "authored-tester",
        "SoftwareVersion": "1.0",
        "LicenseKey": "authored-default",
        "SUBARU_LicenseKey": "authored-subaru",
        "SUZUKI_LicenseKey": "authored-suzuki",
        "DAIHATSU_LicenseKey": "authored-daihatsu",
        "VehicleIdentificationNumber": "unused",
        "RequesterKind": "1",
        "KeypairID": "1",
        "DAIHATSU_KeypairID": "2",
    }
    fields.update(overrides)
    return encode_nibble_text(
        (
            "[ReproKeyRequest]\n" + "".join(f"{k}={v}\n" for k, v in fields.items())
        ).encode()
    )


def step(method, result=None, *, args=None, fault=None, elapsed_ms=0):
    return {
        "method": method,
        "args": {} if args is None else args,
        "result": result,
        "fault": fault,
        "elapsed_ms": elapsed_ms,
    }


def controller(
    *, region=0, vin=b"AUTHOREDVIN123456", kind="1", daihatsu=False, format_version=10
):
    # Unit-only controller memory fixture; source-issued worker integration is separate.
    instance = object.__new__(OnlineKeyController2026)
    context = SimpleNamespace(
        engine_sha256=ENGINE_SHA256,
        source_sha256="1" * 64,
        vin=vin,
        region=region,
        kind_of_ecu=kind,
        is_daihatsu=daihatsu,
    )
    engine = SimpleNamespace(
        online_modal_state=0,
        native_metadata=SimpleNamespace(format_version=format_version),
    )
    engine._publish_online_modal = lambda _owner, state: setattr(
        engine, "online_modal_state", state
    )
    instance.worker = cast(
        EngineWorker2026, SimpleNamespace(online_context=lambda: context, engine=engine)
    )
    instance._rks_store = None
    instance._config = _configuration(configuration())
    instance.configuration_sha256 = hashlib.sha256(configuration()).hexdigest()
    instance._request = instance._key = b""
    instance._result = instance._request_status = instance._watch_status = 0
    instance._modal_history = []
    instance._started = instance._closed = False
    instance._capture_sha256 = ""
    instance._access = None
    instance._exported_path = None
    return instance


def capture(instance, seed, steps):
    return OnlineReplay2026(
        {
            "schema": SCHEMA,
            "provenance": "authored",
            "engine_sha256": ENGINE_SHA256,
            "source_sha256": instance.worker.online_context().source_sha256,
            "configuration_sha256": instance.configuration_sha256,
            "seed_sha256": hashlib.sha256(seed).hexdigest(),
            "steps": steps,
        }
    )


class OnlineControllerTests(unittest.TestCase):
    def test_same_rks_store_retains_native_strings_and_failed_import_state(self):
        import struct

        from scripts.cuw_2026 import CUWEngine2026

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image absent")
        engine = CUWEngine2026(image.read_bytes())
        self.addCleanup(engine.close)
        store = engine.rks_configuration
        initial = store.software_identity
        self.assertEqual(
            initial.software_id32, bytes(16) + struct.pack("<II", 0, 15) + bytes(8)
        )
        self.assertTrue(all(value == "" for value in store.fields_snapshot().values()))
        self.assertFalse(store.load(encode_nibble_text(b"not INI")))
        self.assertIs(store.software_identity, initial)
        first = configuration(
            SoftwareID="ABC", SoftwareVersion="1.0", LicenseKey="first-license"
        )
        retained = engine.load_rks_configuration(first)
        expected = b"ABC" + bytes(13) + struct.pack("<II", 3, 15) + b"1.0" + bytes(5)
        self.assertEqual(retained.software_id32, expected)
        second = configuration(
            SoftwareID="XYZ",
            SoftwareVersion="9.9",
            LicenseKey="second-license",
            KeypairID="2",
        )
        self.assertIs(engine.load_rks_configuration(second), retained)
        values = store.fields_snapshot()
        self.assertEqual(
            (
                values["SoftwareID"],
                values["SoftwareVersion"],
                values["LicenseKey"],
                values["KeypairID"],
            ),
            ("ABC", "1.0", "second-license", "2"),
        )
        self.assertEqual(store.source_sha256, hashlib.sha256(second).hexdigest())
        for bad in (
            b"",
            encode_nibble_text(b"not INI"),
            configuration(LicenseKey=""),
            encode_nibble_text(b"[ReproKeyRequest]\nSoftwareID=NO_RESET\n"),
        ):
            self.assertFalse(store.load(bad))
            self.assertEqual(store.fields_snapshot(), values)
            self.assertIs(engine.rks_software_identity, retained)
            self.assertEqual(store.source_sha256, hashlib.sha256(second).hexdigest())
            self.assertEqual(store.last_source_sha256, hashlib.sha256(bad).hexdigest())
        # 1c420 accepts these high-byte pairs; RecoveryInfo's narrower codec does not.
        alternate = bytes(
            byte + 64 if index % 2 == 0 else byte for index, byte in enumerate(second)
        )
        self.assertEqual(_configuration(alternate), _configuration(second))
        self.assertTrue(store.load(alternate))
        self.assertIs(store.software_identity, retained)
        self.assertEqual(retained.software_id32, expected)
        # DataFile input has a trailing NUL;5c7d0 stops at the first decoded NUL.
        terminated = second + b"  " + b"A"
        self.assertTrue(store.load(terminated))
        self.assertEqual(store.fields_snapshot(), values)
        self.assertIs(store.software_identity, retained)
        before = store.fields_snapshot()
        completed_source = store.last_source_sha256
        for _ in range(2):
            with self.assertRaises(NotImplementedError):
                store.load(second + b"A")
            self.assertEqual(store.last_source_sha256, completed_source)
        self.assertEqual(store.fields_snapshot(), before)
        self.assertIs(store.software_identity, retained)

    def test_same_rks_store_does_not_invent_heap_bytes_or_reset_on_reload(self):
        from scripts.cuw_2026 import CUWEngine2026

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image absent")
        for first_id in ("H" * 16, "H" * 30, "H" * 31, "H" * 32):
            with self.subTest(first_id_length=len(first_id)):
                engine = CUWEngine2026(image.read_bytes())
                try:
                    retained = engine.load_rks_configuration(
                        configuration(SoftwareID=first_id)
                    )
                    self.assertIs(
                        engine.load_rks_configuration(
                            configuration(
                                SoftwareID="ABC",
                                SoftwareVersion="new",
                                LicenseKey="reload",
                            )
                        ),
                        retained,
                    )
                    self.assertEqual(
                        engine.rks_configuration.fields_snapshot()["SoftwareID"],
                        first_id,
                    )
                    if len(first_id) < 31:
                        with self.assertRaises(NotImplementedError):
                            _ = retained.software_id32
                    else:
                        self.assertEqual(
                            retained.software_id32, (first_id.encode() + b"\0")[:32]
                        )
                finally:
                    engine.close()

    def test_repeated_rks_imports_reach_actual_online_request_and_native_key(self):
        import struct

        from scripts.cuw_2026 import CUWEngine2026, identity_2026
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeRuntime2026,
        )
        from tests.test_calibration_2026 import cpu_text, cuw

        root = Path("runtime/no-car-21/recovered")
        if not all(
            (root / name).is_file() for name in ("CUW.dll", "TCUWControlCommPhase.dll")
        ):
            self.skipTest("Authenticated static CUW2026 images absent")
        engine = CUWEngine2026((root / "CUW.dll").read_bytes())
        self.addCleanup(engine.close)
        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        engine.load_cuw(cuw(cpu_text()))
        control = ControlCommPhase2026(
            identity_2026(
                (root / "TCUWControlCommPhase.dll").read_bytes(),
                "TCUWControlCommPhase.dll",
            ),
            NativeRuntime2026(lambda *_: None),
        )
        worker = engine.bind_worker(control)
        engine.set_vin(b"JT123456789012345")
        initial = configuration(
            SoftwareID="ABC", SoftwareVersion="1.0", LicenseKey="first-license"
        )
        identity = engine.load_rks_configuration(initial)
        first = OnlineKeyController2026(worker, initial)
        first.start(bytes(16))
        self.assertEqual(
            rks_data_from_native(first.request_buffer, encoding="latin1").software_id,
            "ABC",
        )
        first.close()
        self.assertTrue(first.closed)
        reload = configuration(
            SoftwareID="XYZ",
            SoftwareVersion="9.9",
            LicenseKey="second-license",
            KeypairID="2",
        )
        engine.load_rks_configuration(reload)
        self.assertIs(engine.rks_software_identity, identity)
        current = OnlineKeyController2026(worker, reload)
        seed = bytes(16)
        replay = capture(
            current, seed, [step("online.SetReprogrammingKey", (b"ab" * 256).hex())]
        )
        result = current.calculate(seed, replay)
        assert result is not None
        expected = _request_buffer(
            (
                "1",
                "ABC",
                "1.0",
                "second-license",
                "JT123456789012345",
                "1",
                "2",
                "00" * 16,
            )
        )
        self.assertEqual(result.request_sha256, hashlib.sha256(expected).hexdigest())
        self.assertEqual(result.value, b"\xab" * 256)
        self.assertIs(engine.rks_software_identity, identity)
        self.assertEqual(
            engine.rks_configuration.fields_snapshot()["LicenseKey"], "second-license"
        )
        self.assertTrue(current.closed)
        self.assertNotEqual(
            current.configuration_sha256, hashlib.sha256(reload).hexdigest()
        )
        # The same last file in a fresh singleton has different native strings.
        fresh = CUWEngine2026((root / "CUW.dll").read_bytes())
        self.addCleanup(fresh.close)
        fresh.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        fresh.load_cuw(cuw(cpu_text()))
        fresh_control = ControlCommPhase2026(
            control.identity, NativeRuntime2026(lambda *_: None)
        )
        fresh_worker = fresh.bind_worker(fresh_control)
        fresh.set_vin(b"JT123456789012345")
        fresh.load_rks_configuration(reload)
        wrong_instance = OnlineKeyController2026(fresh_worker, reload)
        wrong_replay = OnlineReplay2026(copy.deepcopy(replay._data))
        with self.assertRaisesRegex(ValueError, "binding mismatch"):
            wrong_instance.calculate(seed, wrong_replay)
        self.assertFalse(wrong_replay.used)
        wrong_instance.close()
        delayed = OnlineKeyController2026(worker)
        old_capture = capture(
            delayed, seed, [step("online.SetReprogrammingKey", (b"ab" * 256).hex())]
        )
        third = configuration(
            SoftwareID="NEW", SoftwareVersion="10.0", LicenseKey="third-license"
        )
        engine.load_rks_configuration(third)
        with self.assertRaisesRegex(ValueError, "binding mismatch"):
            delayed.calculate(seed, old_capture)
        self.assertFalse(old_capture.used)
        delayed.start(seed)
        observed = rks_data_from_native(delayed.request_buffer, encoding="latin1")
        self.assertEqual(
            (observed.software_id, observed.software_version, observed.license_key),
            ("ABC", "1.0", "third-license"),
        )
        delayed.close()
        self.assertIs(engine.rks_software_identity, identity)
        completed_source = engine.rks_configuration.last_source_sha256
        for _ in range(2):
            with self.assertRaises(NotImplementedError):
                OnlineKeyController2026(worker, third + b"A")
            self.assertEqual(
                engine.rks_configuration.last_source_sha256, completed_source
            )

    def test_source_issued_worker_to_online_key(self):
        import struct

        from scripts.cuw_2026 import CUWEngine2026, identity_2026
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeRuntime2026,
        )
        from tests.test_calibration_2026 import cpu_text, cuw

        root = Path("runtime/no-car-21/recovered")
        if not all(
            (root / name).is_file() for name in ("CUW.dll", "TCUWControlCommPhase.dll")
        ):
            self.skipTest("Authenticated static CUW2026 images absent")
        source = cuw(cpu_text() + "NumberOfTargets=1\n01_TargetCalibration=0751\n")
        engine = CUWEngine2026((root / "CUW.dll").read_bytes())
        self.addCleanup(engine.close)
        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        engine.load_cuw(source)
        control = ControlCommPhase2026(
            identity_2026(
                (root / "TCUWControlCommPhase.dll").read_bytes(),
                "TCUWControlCommPhase.dll",
            ),
            NativeRuntime2026(lambda *_: None),
        )
        worker = engine.bind_worker(control)
        engine.set_vin(b"JT123456789012345")
        obj = OnlineKeyController2026(worker, configuration())
        seed = bytes(range(16))
        replay = capture(
            obj, seed, [step("online.SetReprogrammingKey", (b"aB" * 256).hex())]
        )
        result = obj.calculate(seed, replay)
        assert result is not None
        self.assertEqual(result.value, b"\xab" * 256)
        self.assertEqual(obj.modal_history, (1, 0))
        self.assertEqual(engine.online_modal_state, 0)
        self.assertEqual(worker.online_context().vin, b"JT123456789012345")
        self.assertFalse(worker.online_context().is_daihatsu)
        with self.assertRaises(TypeError):
            OnlineKeyController2026(cast(EngineWorker2026, object()), configuration())

    def test_source_worker_reissue_preserves_online_globals_and_rolls_back(self):
        import struct

        from scripts.cuw_2026 import CUWEngine2026, RKSAccess2026, identity_2026
        from scripts.cuw_engine_worker import (
            _finalize_engine_worker_replacement,
            _replace_engine_worker,
            _rollback_engine_worker_replacement,
        )
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeRuntime2026,
        )
        from tests.test_calibration_2026 import cpu_text, cuw

        root = Path("runtime/no-car-21/recovered")
        if not all(
            (root / name).is_file() for name in ("CUW.dll", "TCUWControlCommPhase.dll")
        ):
            self.skipTest("Authenticated static CUW2026 images absent")
        for state in ("unused", "modal", "key", "closed"):
            with self.subTest(state=state):
                engine = CUWEngine2026((root / "CUW.dll").read_bytes())
                self.addCleanup(engine.close)
                engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
                engine.load_cuw(cuw(cpu_text()))
                runtime = NativeRuntime2026(lambda *_: None)
                control = ControlCommPhase2026(
                    identity_2026(
                        (root / "TCUWControlCommPhase.dll").read_bytes(),
                        "TCUWControlCommPhase.dll",
                    ),
                    runtime,
                )
                old = engine.bind_worker(control)
                engine.set_vin(b"JT123456789012345")
                obj = OnlineKeyController2026(old, configuration())
                seed, elapsed = bytes(range(16)), []
                recording = capture(
                    obj,
                    seed,
                    [
                        step(
                            "online.SetReprogrammingKey",
                            (b"ab" * 256).hex(),
                            elapsed_ms=125,
                        )
                    ],
                )
                runtime.bind_p5_online(obj, recording, advance_clock=elapsed.append)
                self.assertIsNone(engine._online_controller)
                if state != "unused":
                    obj.start(seed)
                    self.assertIsNotNone(obj.request_parameters())
                    access = RKSAccess2026()
                    access.set_data(
                        rks_data_from_native(obj.request_buffer, encoding="latin1")
                    )
                    obj._access = access
                    if state == "key":
                        obj._native_input(b"ab" * 256)
                    elif state == "closed":
                        obj.close()
                snapshot = {k: v for k, v in vars(obj).items() if k != "worker"}
                binding, modal = runtime._p5_online, engine.online_modal_state
                with self.assertRaises(TypeError):
                    obj.rebind_worker(cast(EngineWorker2026, object()), old)
                with self.assertRaises(ValueError):
                    obj.rebind_worker(old, old)
                new = _replace_engine_worker(engine, control, old)
                self.assertTrue(old._closed)
                obj.rebind_worker(old, new)
                self.assertIs(obj.worker, new)
                self.assertIs(runtime.bound_online_controller2026(), obj)
                self.assertIs(runtime._p5_online, binding)
                self.assertEqual(
                    snapshot, {k: v for k, v in vars(obj).items() if k != "worker"}
                )
                self.assertEqual(engine.online_modal_state, modal)
                self.assertFalse(recording.used)
                with self.assertRaises(ValueError):
                    obj.rebind_worker(old, new)
                _rollback_engine_worker_replacement(engine, old, new)
                obj.rebind_worker(new, old)
                self.assertIs(obj.worker, old)
                self.assertEqual(
                    snapshot, {k: v for k, v in vars(obj).items() if k != "worker"}
                )
                new = _replace_engine_worker(engine, control, old)
                obj.rebind_worker(old, new)
                _finalize_engine_worker_replacement(engine, old, new)
                obj.validate_source()
                if state == "unused":
                    self.assertEqual(
                        runtime.call("calculate_p5_gateway_key", seed=seed),
                        b"\xab" * 256,
                    )
                    self.assertEqual(elapsed, [0.125])
                    self.assertTrue(recording.used)
                elif state == "key":
                    self.assertEqual(obj._key, b"\xab" * 256)
                obj.close()

    def test_public_cid_stop_rebinds_runtime_only_and_live_online_controller(self):
        from unittest.mock import patch

        from tests.test_cuw_engine_threads import ThreadOwnershipTests

        for live in (False, True):
            with self.subTest(live=live):
                fixture = ThreadOwnershipTests()
                self.addCleanup(fixture.doCleanups)
                engine, control, job, root, _pair, _rows, _sdk, _sources = (
                    fixture.authored_two_file_getter_job()
                )
                fixture.complete_two_file_getter_roots(engine, control, job, root)
                session = root.next_session2026("get_cid", node=1, cpu_index=0)
                session.bind_runtime2026(control.runtime)
                session.bind_engine2026(engine)
                session.bind_controller2026(control)
                engine.set_vin(b"JT123456789012345")
                old = engine.worker
                obj = OnlineKeyController2026(old, configuration())
                seed, elapsed = bytes(range(16)), []
                replay = capture(
                    obj,
                    seed,
                    [
                        step(
                            "online.SetReprogrammingKey",
                            (b"ab" * 256).hex(),
                            elapsed_ms=125,
                        )
                    ],
                )
                control.runtime.bind_p5_online(
                    obj, replay, advance_clock=elapsed.append
                )
                if live:
                    obj.start(seed)
                    obj.request_parameters()
                    self.assertIs(engine._online_controller, obj)
                else:
                    self.assertIsNone(engine._online_controller)
                snapshot = {k: v for k, v in vars(obj).items() if k != "worker"}
                fault = ValueError("authored native clock boundary")

                def clock_fault(error=fault):
                    raise error

                session.trace.native_local_milliseconds_of_day = clock_fault
                control.runtime.local_milliseconds_of_day = clock_fault
                job.start(session)
                with self.assertRaises(ValueError) as caught:
                    job.result(2)
                self.assertIs(caught.exception, fault)
                self.assertEqual(engine.stop_receiving_cid(timeout=2), 0)
                failure = ValueError("authored new native job boundary")
                with (
                    patch(
                        "scripts.cuw_engine_threads._issue_engine_thread_job",
                        side_effect=failure,
                    ),
                    self.assertRaises(ValueError) as caught,
                ):
                    engine.bind_thread_job(control)
                self.assertIs(caught.exception, failure)
                self.assertIs(engine.worker, old)
                self.assertIs(obj.worker, old)
                obj.validate_source()
                self.assertEqual(
                    snapshot, {k: v for k, v in vars(obj).items() if k != "worker"}
                )
                replacement_job = engine.bind_thread_job(control)
                self.addCleanup(replacement_job.stop)
                self.assertIsNot(engine.worker, old)
                self.assertIs(obj.worker, engine.worker)
                self.assertIs(control.runtime.bound_online_controller2026(), obj)
                self.assertFalse(replay.used)
                self.assertEqual(
                    snapshot, {k: v for k, v in vars(obj).items() if k != "worker"}
                )
                if not live:
                    self.assertEqual(
                        control.runtime.call("calculate_p5_gateway_key", seed=seed),
                        b"\xab" * 256,
                    )
                    self.assertEqual(elapsed, [0.125])
                else:
                    self.assertEqual(engine.online_modal_state, 5)
                    obj._native_input(b"ab" * 256)
                    self.assertEqual(obj._key, b"\xab" * 256)
                    self.assertEqual(engine.online_modal_state, 0)
                obj.close()

    def test_source_subaru_selector_is_format9_not_vehicle_kind9(self):
        import struct

        from scripts.cuw_2026 import CUWEngine2026, identity_2026
        from scripts.demo_calibration import table
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeGeneralParameters2026,
            NativeRuntime2026,
        )
        from tests.test_calibration_2026 import cpu_text, cuw

        root = Path("runtime/no-car-21/recovered")
        if not all(
            (root / name).is_file() for name in ("CUW.dll", "TCUWControlCommPhase.dll")
        ):
            self.skipTest("Authenticated static CUW2026 images absent")
        for version, kind, license_key in (
            (9, "1", "authored-subaru"),
            (10, "9", "authored-default"),
        ):
            with self.subTest(format_version=version, kind_of_ecu=kind):
                text = cpu_text(version).replace("KindOfECU=149", "KindOfECU=" + kind)
                if version == 9:
                    text += "NumberOfFiles=1\n[File1001]\nFileName=authored\nALFID=44\nDownloadAddress=0\nDownloadMemsize=4\n"
                source = cuw(text)
                general = NativeGeneralParameters2026.from_sources(
                    {
                        "Parameter.ini": table(
                            (
                                "ParamFileKeySystemProtocolMicon",
                                "M16CTypeFlag",
                                "FORESTTypeFlag",
                            ),
                            (
                                (kind + "P5-Unified311", "0", "0"),
                                (kind + "P5-Unified", "0", "0"),
                            ),
                        )
                    },
                    encoded=False,
                )
                engine = CUWEngine2026(
                    (root / "CUW.dll").read_bytes(), general_parameters=general
                )
                try:
                    engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
                    engine.load_cuw(source)
                    control = ControlCommPhase2026(
                        identity_2026(
                            (root / "TCUWControlCommPhase.dll").read_bytes(),
                            "TCUWControlCommPhase.dll",
                        ),
                        NativeRuntime2026(lambda *_: None),
                    )
                    worker = engine.bind_worker(control)
                    engine.set_vin(b"JT123456789012345")
                    obj = OnlineKeyController2026(worker, configuration())
                    obj.start(bytes(16))
                    self.assertEqual(
                        rks_data_from_native(
                            obj.request_buffer, encoding="latin1"
                        ).license_key,
                        license_key,
                    )
                    obj.close()
                finally:
                    engine.close()

    def test_source_multifile_selection_is_not_current_kind(self):
        import struct

        from scripts.cuw_2026 import CUWEngine2026, identity_2026
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeRuntime2026,
        )
        from tests.test_calibration_2026 import cpu_text, cuw

        root = Path("runtime/no-car-21/recovered")
        if not all(
            (root / name).is_file() for name in ("CUW.dll", "TCUWControlCommPhase.dll")
        ):
            self.skipTest("Authenticated static CUW2026 images absent")
        current = cuw(cpu_text().replace("KindOfECU=149", "KindOfECU=9"))
        other = cuw(
            cpu_text()
            .replace("KindOfECU=149", "KindOfECU=12")
            .replace("ContactType=P5-Unified", "ContactType=CAN")
        )
        with tempfile.TemporaryDirectory() as directory:
            state = ReproInfoState(
                (
                    RecoveryCalibration("current.cuw", current),
                    RecoveryCalibration("other.cuw", other),
                ),
                multi_calibration_file_num=2,
            )
            engine = CUWEngine2026(
                (root / "CUW.dll").read_bytes(),
                persistence=CUWPersistence(Path(directory), state),
            )
            try:
                engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
                engine.load_cuw(current)
                control = ControlCommPhase2026(
                    identity_2026(
                        (root / "TCUWControlCommPhase.dll").read_bytes(),
                        "TCUWControlCommPhase.dll",
                    ),
                    NativeRuntime2026(lambda *_: None),
                )
                worker = engine.bind_worker(control)
                engine.set_vin(b"JT123456789012345")
                self.assertEqual(worker.online_context().kind_of_ecu, "9")
                self.assertEqual(len(worker.online_context().all_loaded_metadata), 2)
                self.assertTrue(worker.online_context().is_daihatsu)
                obj = OnlineKeyController2026(worker, configuration())
                seed = bytes(16)
                replay = capture(
                    obj, seed, [step("online.SetReprogrammingKey", (b"ab" * 256).hex())]
                )
                result = obj.calculate(seed, replay)
                assert result is not None
                expected = _request_buffer(
                    (
                        "1",
                        "authored-tester",
                        "1.0",
                        "authored-daihatsu",
                        "JT123456789012345",
                        "1",
                        "1",
                        "00" * 16,
                    )
                )
                self.assertEqual(
                    result.request_sha256, hashlib.sha256(expected).hexdigest()
                )
            finally:
                engine.close()

    def test_native_request_selectors_and_inline_offsets(self):
        for region, kind, version, dh, license_key, seed_size, keypair in (
            (0, "1", 10, False, "authored-default", 16, "1"),
            (0, "9", 10, False, "authored-default", 16, "1"),
            (0, "1", 9, False, "authored-subaru", 16, "1"),
            (2, "1", 10, False, "authored-suzuki", 8, "2"),
            (2, "1", 9, False, "authored-subaru", 8, "2"),
            (2, "1", 9, True, "authored-daihatsu", 8, "2"),
        ):
            with self.subTest(region=region, kind=kind, version=version, dh=dh):
                obj = controller(
                    region=region, kind=kind, daihatsu=dh, format_version=version
                )
                seed = bytes(range(seed_size))
                obj.start(seed)
                data = rks_data_from_native(obj.request_buffer, encoding="latin1")
                self.assertEqual(data.license_key, license_key)
                self.assertEqual(data.keypair_id, keypair)
                self.assertEqual(data.seed, seed.hex().upper())
                self.assertEqual(len(obj.request_buffer), 160)
                self.assertEqual(obj.modal_history, (1,))

    def test_vin_short_padding_and_no_vin(self):
        obj = controller(vin=b"ABC")
        obj.start(bytes(16))
        self.assertEqual(
            rks_data_from_native(obj.request_buffer, encoding="latin1").vin,
            "ABC" + " " * 14,
        )
        missing = controller(vin=b"")
        missing.start(bytes(16))
        self.assertEqual(
            (missing.modal_state, missing.request_status, missing.request_buffer),
            (6, 0x1B63, b""),
        )

    def test_callback_mapping_and_status_reset(self):
        for status, modal in ((0, 4), (13, 9), (12, 10), (11, 10)):
            obj = controller()
            obj._watch_status = status
            obj._callback("watch")
            self.assertEqual(obj.modal_state, modal)
            self.assertEqual((obj._request_status, obj._watch_status), (0, 0))
        for status, modal in ((3, 7), (5, 9)):
            obj = controller()
            obj._request_status = status
            obj._callback("request")
            self.assertEqual(obj.modal_state, modal)

    def test_captured_native_input_issues_key_and_wipes_controller(self):
        obj = controller()
        seed = bytes(range(16))
        raw = bytes(range(256))
        replay = capture(
            obj,
            seed,
            [
                step(
                    "online.SetReprogrammingKey",
                    (raw.hex().encode() + b"\0ignored").hex(),
                ),
                step("online.finish", elapsed_ms=125),
            ],
        )
        result = obj.calculate(seed, replay, clock=lambda: 10)
        self.assertIsInstance(result, OnlineKey2026)
        assert result is not None
        self.assertEqual(result.value, raw)
        self.assertEqual(replay.consumed_elapsed_seconds, 0.125)
        self.assertTrue(obj._closed)
        self.assertEqual(obj._key, b"")
        with self.assertRaises(ValueError):
            obj.calculate(seed, replay)

    def test_suzuki_key64_and_wrong_lengths(self):
        obj = controller(region=2)
        seed = bytes(8)
        replay = capture(
            obj, seed, [step("online.SetReprogrammingKey", (b"ab" * 64).hex())]
        )
        result = obj.calculate(seed, replay)
        assert result is not None
        self.assertEqual(result.value, b"\xab" * 64)
        for raw in (b"a" * 511, b"g" * 512):
            obj = controller()
            replay = capture(
                obj, bytes(16), [step("online.SetReprogrammingKey", raw.hex())]
            )
            with self.assertRaises(ValueError):
                obj.calculate(bytes(16), replay)
            self.assertTrue(obj._closed)

    def test_browser_approval_does_not_issue_key(self):
        obj = controller()
        obj.start(bytes(16))
        xml = rks_xml(
            rks_data_from_native(obj.request_buffer, encoding="latin1")
        ).decode()
        obj = controller()
        window, url = "authored-window", "https://offline.invalid/repro"

        def snapshot(elements):
            return {
                "window": window,
                "url": url,
                "busy": False,
                "ready_state": 4,
                "closed": False,
                "elements": elements,
            }

        field = {
            "tag": "textarea",
            "name": "ReproKeyRequest",
            "element_id": "",
            "value": "",
            "kind": "",
        }
        pasted = dict(field, value=xml)
        approval = {
            "tag": "input",
            "name": "",
            "element_id": "result_code",
            "value": "0",
            "kind": "hidden",
        }
        replay = capture(
            obj,
            bytes(16),
            [
                step("online.request", {"url": url, "allowed_origins": []}),
                step(
                    "registry.open",
                    0,
                    args={
                        "root": "HKLM",
                        "key": r"SOFTWARE\Microsoft\Internet Explorer",
                        "access": 0x20019,
                    },
                ),
                step("registry.read", "11.0.0", args={"name": "svcVersion"}),
                step("registry.close"),
                step("browser.create", window),
                step("browser.navigate", args={"window": window, "url": url}),
                step("browser.snapshot", snapshot([field]), args={"window": window}),
                step(
                    "browser.set",
                    args={
                        "window": window,
                        "tag": "textarea",
                        "name": "ReproKeyRequest",
                        "value": xml,
                    },
                ),
                step("browser.snapshot", snapshot([pasted]), args={"window": window}),
                step("online.watch"),
                step("browser.snapshot", snapshot([approval]), args={"window": window}),
                step("online.finish"),
                step("browser.close", args={"window": window}),
            ],
        )
        for value, modal in (("0", 4), ("2", 10)):
            data = copy.deepcopy(replay._data)
            data["steps"][10]["result"]["elements"][0]["value"] = value
            current = controller()
            self.assertIsNone(current.calculate(bytes(16), OnlineReplay2026(data)))
            self.assertEqual(current.modal_history, (1, 2, modal))
            self.assertTrue(current._closed)
        # A closed owned browser is native13 and must reach415b0 state9.
        data = copy.deepcopy(replay._data)
        data["steps"][10]["result"]["closed"] = True
        data["steps"][11], data["steps"][12] = data["steps"][12], data["steps"][11]
        current = controller()
        self.assertIsNone(current.calculate(bytes(16), OnlineReplay2026(data)))
        self.assertEqual(current.modal_history, (1, 2, 9))
        # Native11 repeats;12 must finish the watcher rather than being retried.
        data = copy.deepcopy(replay._data)
        data["steps"][10]["result"]["elements"][0]["value"] = None
        data["steps"][11:11] = copy.deepcopy(replay._data["steps"][9:11])
        current = controller()
        self.assertIsNone(current.calculate(bytes(16), OnlineReplay2026(data)))
        self.assertEqual(current.modal_history, (1, 2, 4))

    def test_native_browser_preflight_and_query_launch(self):
        registry = {
            "root": "HKLM",
            "key": r"SOFTWARE\Microsoft\Internet Explorer",
            "access": 0x20019,
        }
        for version in (None, "10.0"):
            obj = controller()
            steps = [
                step(
                    "online.request",
                    {"url": "https://offline.invalid/", "allowed_origins": []},
                ),
                step("registry.open", 2 if version is None else 0, args=registry),
            ]
            if version is not None:
                steps += [
                    step("registry.read", version, args={"name": "svcVersion"}),
                    step("registry.close"),
                ]
            steps.append(step("online.finish"))
            self.assertIsNone(obj.calculate(bytes(16), capture(obj, bytes(16), steps)))
            self.assertEqual(obj.modal_history, (1, 7))
        utc = datetime(2026, 10, 20, 1, 2, 3, 456000, tzinfo=UTC)
        obj = controller(vin=b"A B")
        obj.start(bytes(16))
        query = obj.query_string(utc, 1234)
        self.assertIn(
            "&vin=A+B++++++++++++++&timestamp=2026.10.20.01%3A02%3A03%3A4561234", query
        )
        for result, modal in ((32, 8), (33, 5)):
            obj = controller(vin=b"A B")
            steps = [
                step(
                    "online.start_query",
                    {
                        "url": "https://offline.invalid/?",
                        "utc_time": utc.isoformat(),
                        "filetime_remainder": 1234,
                    },
                ),
                step(
                    "shell.open",
                    result,
                    args={"url": "https://offline.invalid/?" + query},
                ),
                step("online.finish"),
            ]
            self.assertIsNone(obj.calculate(bytes(16), capture(obj, bytes(16), steps)))
            self.assertEqual(obj.modal_history, (1, modal))

    def test_export_native_filename_parameters_and_import_wrapper(self):
        obj = controller(vin=b"SHORT")
        obj.start(bytes(16))
        params = obj.request_parameters()
        self.assertEqual(params, b"0" * 32 + b"\0" + b"1\0\0\0\0\0\0")
        self.assertEqual(obj.modal_state, 5)
        with tempfile.TemporaryDirectory() as directory:
            path = obj.export_data(
                directory, datetime(2026, 10, 20, 1, 2, 3, tzinfo=UTC)
            )
            assert path is not None
            self.assertEqual(path.name, "SHORT            _20261020010203.xml")
            self.assertEqual(
                path.read_bytes(),
                rks_xml(rks_data_from_native(obj.request_buffer, encoding="latin1")),
            )
            second = obj.export_data(
                directory, datetime(2026, 10, 20, 1, 2, 4, tzinfo=UTC)
            )
            self.assertFalse(path.exists())
            assert second is not None
            self.assertTrue(Path(second).is_file())
        for region, size in ((0, 256), (2, 64)):
            obj = controller(region=region)
            seed = bytes(8 if region else 16)
            xml = b"<Signature>" + b"aB" * 256 + b"</Signature>"
            replay = capture(
                obj, seed, [step("online.LoadXMLFileForReprogrammingKey", xml.hex())]
            )
            result = obj.calculate(seed, replay)
            assert result is not None
            self.assertEqual(result.value, b"\xab" * size)

    def test_host_fault_and_cancel_propagate_and_cleanup(self):
        for fault, error_type in (
            ("io", OSError),
            ("timeout", TimeoutError),
            ("cancel", InterruptedError),
        ):
            obj = controller()
            replay = capture(obj, bytes(16), [step("online.finish", fault=fault)])
            with self.assertRaises(error_type):
                obj.calculate(bytes(16), replay)
            self.assertTrue(obj._closed)
            if fault == "cancel":
                self.assertEqual(obj.modal_history, (1, 1))

    def test_boundaries_and_no_result_injection(self):
        with self.assertRaises(TypeError):
            OnlineKey2026(bytes(256), ENGINE_SHA256, "", "", object())
        with self.assertRaises(ValueError):
            _configuration(configuration(LicenseKey=""))
        with self.assertRaises(ValueError):
            _request_buffer(("1", "x" * 35, "1", "1", "1", "1", "1", "1"))
        obj = controller()
        replay = capture(obj, bytes(16), [step("online.finish")])
        with self.assertRaises(ValueError):
            obj.calculate(bytes([1]) * 16, replay)
        self.assertFalse(replay.used)
        replay = capture(
            obj, bytes(16), [step("calculate_p5_gateway_key", bytes(256).hex())]
        )
        with self.assertRaises(ValueError):
            obj.calculate(bytes(16), replay)


if __name__ == "__main__":
    unittest.main()
