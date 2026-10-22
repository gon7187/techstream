"""Authored synthetic native-utility fixtures; no OEM images or private evidence."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.text_resources import (
    UtilityTextResources,
    create_utility_group_text_examples,
)
from scripts.utility_authored import (
    AUTHORED_CALLER_SHA256,
    AUTHORED_MODULE_BYTES,
    DCM_COMMON_IDENTIFIERS,
    DCM_TEXT_IDENTIFIERS,
    DCM_UTILITY_GROUP,
    AuthoredNativeUtility,
)


class AuthoredNativeUtilityTests(unittest.TestCase):
    def test_dcm_business_stage_uses_the_real_controller_and_worker(self):
        from scripts.utility_ex import SOURCES

        digest = hashlib.sha256(AUTHORED_MODULE_BYTES).hexdigest()
        self.assertNotIn(digest, SOURCES)
        fixture = AuthoredNativeUtility(dcm_value=0)
        try:
            self.assertEqual(SOURCES[digest], "TY18")
            runtime = fixture.runtime
            screen = runtime.start(0x13723)
            self.assertEqual(
                (screen["title_id"], screen["message_id"]), (0x948B, 0x9490)
            )
            self.assertEqual(
                screen["progress"], {"PROGRESSTIME": 10000, "UPDATETIME": 1000}
            )
            runtime.progress(1000)
            self.assertEqual((runtime.result, runtime.status), (0, "completed"))
            self.assertEqual(runtime.current, 0x13724)
            self.assertEqual(runtime.receiver, bytes(4))
            runtime.key("acknowledge")
            self.assertTrue(runtime.done)
            report = runtime.report()
            self.assertEqual(report["status"], "completed")
            self.assertEqual(report["utility_group"], DCM_UTILITY_GROUP)
            self.assertEqual(report["caller_sha256"], AUTHORED_CALLER_SHA256)
            self.assertIn("finalize", fixture.events)
        finally:
            fixture.close()
        self.assertNotIn(digest, SOURCES)
        self.assertIsNone(runtime.libraries.engine.worker._thread)

    def test_native_readback_warning_keeps_the_source_result(self):
        fixture = AuthoredNativeUtility(dcm_value=7)
        try:
            runtime = fixture.runtime
            runtime.start(0x13723)
            runtime.progress(1000)
            self.assertEqual((runtime.result, runtime.status), (2005, "native-result"))
            screen = runtime.screen()
            self.assertEqual(
                (screen["title_id"], screen["message_id"]), (0x948C, 0x9492)
            )
        finally:
            fixture.close()

    def test_close_releases_the_worker_and_restores_every_global(self):
        from scripts import utility_ex_ty_body
        from scripts.utility_ex import SOURCES

        digest = hashlib.sha256(AUTHORED_MODULE_BYTES).hexdigest()
        previous_body = utility_ex_ty_body.SHA_18_TY
        fixture = AuthoredNativeUtility(dcm_value=0)
        runtime = fixture.runtime
        runtime.start(0x13723)
        fixture.close()
        fixture.close()
        self.assertNotIn(digest, SOURCES)
        self.assertEqual(utility_ex_ty_body.SHA_18_TY, previous_body)
        self.assertIsNone(runtime.libraries.engine.worker._thread)

    def test_close_after_acknowledgement_is_safe(self):
        fixture = AuthoredNativeUtility(dcm_value=0)
        runtime = fixture.runtime
        runtime.start(0x13723)
        runtime.progress(1000)
        runtime.key("acknowledge")
        self.assertTrue(runtime.done)
        fixture.close()
        self.assertIsNone(runtime.libraries.engine.worker._thread)

    def test_authored_pair_is_not_a_production_source_pair(self):
        from scripts.utility import open_native_utility

        digest = hashlib.sha256(AUTHORED_MODULE_BYTES).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            caller = root / "caller.bin"
            engine = root / "engine.bin"
            recording = root / "recording.json"
            caller.write_bytes(b"authored caller image")
            engine.write_bytes(AUTHORED_MODULE_BYTES)
            recording.write_text(
                json.dumps(
                    {
                        "schema": "techstream-native-utility-v1",
                        "source": "authored_synthetic",
                        "caller_sha256": hashlib.sha256(
                            caller.read_bytes()
                        ).hexdigest(),
                        "engine_sha256": digest,
                        "broker": {"111": 20},
                        "events": [],
                    }
                )
            )
            with self.assertRaisesRegex(ValueError, "Unregistered original"):
                open_native_utility(caller, engine, recording, function_id=0x13723)

    def test_authored_readback_value_must_be_one_byte(self):
        with self.assertRaisesRegex(ValueError, "one byte"):
            AuthoredNativeUtility(dcm_value=256)


class AuthoredFixtureOwnershipTests(unittest.TestCase):
    def test_overlapping_fixture_is_rejected_without_disturbing_first(self):
        first = AuthoredNativeUtility(dcm_value=0)
        try:
            with self.assertRaisesRegex(RuntimeError, "fixture is already active"):
                AuthoredNativeUtility(dcm_value=7)
            runtime = first.runtime
            runtime.start(0x13723)
            runtime.progress(1000)
            self.assertEqual((runtime.result, runtime.status), (0, "completed"))
        finally:
            first.close()

    def test_close_restores_preexisting_registry_and_body_values(self):
        from scripts import utility_ex_ty_body
        from scripts.utility_ex import SOURCES

        digest = hashlib.sha256(AUTHORED_MODULE_BYTES).hexdigest()
        prior_source = SOURCES.get(digest)
        prior_body = utility_ex_ty_body.SHA_18_TY
        SOURCES[digest] = "preexisting"
        utility_ex_ty_body.SHA_18_TY = "preexisting-body"
        try:
            fixture = AuthoredNativeUtility(dcm_value=0)
            fixture.close()
            fixture.close()
            self.assertEqual(SOURCES[digest], "preexisting")
            self.assertEqual(utility_ex_ty_body.SHA_18_TY, "preexisting-body")
        finally:
            if prior_source is None:
                SOURCES.pop(digest, None)
            else:
                SOURCES[digest] = prior_source
            utility_ex_ty_body.SHA_18_TY = prior_body

    def test_constructor_failure_releases_fixture_ownership(self):
        from unittest.mock import patch

        from scripts import utility_ex_ty_body
        from scripts.utility_ex import SOURCES

        digest = hashlib.sha256(AUTHORED_MODULE_BYTES).hexdigest()
        prior_source = SOURCES.get(digest)
        prior_body = utility_ex_ty_body.SHA_18_TY
        with (
            patch(
                "scripts.utility.NativeUtilityRuntime",
                side_effect=RuntimeError("runtime construction failed"),
            ),
            self.assertRaisesRegex(RuntimeError, "construction failed"),
        ):
            AuthoredNativeUtility(dcm_value=0)
        self.assertEqual(SOURCES.get(digest), prior_source)
        self.assertEqual(utility_ex_ty_body.SHA_18_TY, prior_body)
        fixture = AuthoredNativeUtility(dcm_value=0)
        fixture.close()

    def test_failed_worker_stop_retains_fixture_ownership_for_retry(self):
        from unittest.mock import patch

        from scripts.utility_ex import SOURCES

        digest = hashlib.sha256(AUTHORED_MODULE_BYTES).hexdigest()
        fixture = AuthoredNativeUtility(hold=True)
        runtime = fixture.runtime
        runtime.start(0x1381D)
        self.assertTrue(fixture.entered.wait(1))
        try:
            with (
                patch.object(
                    runtime.libraries.engine.worker,
                    "stop",
                    side_effect=TimeoutError("injected stop timeout"),
                ),
                self.assertRaisesRegex(TimeoutError, "injected stop timeout"),
            ):
                fixture.close()
            self.assertIsNotNone(runtime.libraries.engine.worker._thread)
            self.assertEqual(SOURCES[digest], "TY18")
            with self.assertRaisesRegex(RuntimeError, "fixture is already active"):
                AuthoredNativeUtility()
        finally:
            fixture.close()
        self.assertIsNone(runtime.libraries.engine.worker._thread)
        self.assertNotIn(digest, SOURCES)

    def test_worker_failure_releases_fixture_after_join_and_propagates(self):
        from scripts.utility_ex import SOURCES

        digest = hashlib.sha256(AUTHORED_MODULE_BYTES).hexdigest()
        fixture = AuthoredNativeUtility(fault=True)
        runtime = fixture.runtime
        runtime.start(0x1381D)
        worker = runtime.libraries.engine.worker
        thread = worker._thread
        assert thread is not None
        thread.join(1)
        self.assertFalse(thread.is_alive())
        with self.assertRaisesRegex(OSError, "authored exchange fault"):
            fixture.close()
        self.assertTrue(fixture.closed)
        self.assertIsNone(worker._thread)
        self.assertNotIn(digest, SOURCES)
        replacement = AuthoredNativeUtility()
        replacement.close()


class AuthoredUtilityGroupTextTests(unittest.TestCase):
    def test_selected_and_common_identifiers_resolve_in_their_own_groups(self):
        files = create_utility_group_text_examples(
            DCM_UTILITY_GROUP,
            DCM_TEXT_IDENTIFIERS,
            common=DCM_COMMON_IDENTIFIERS,
        )
        texts = UtilityTextResources(
            files["U_Example.ddb"],
            files["UtilityResID_NK.rsd"],
            utility_group=DCM_UTILITY_GROUP,
        )
        for identifier in DCM_TEXT_IDENTIFIERS:
            with self.subTest(identifier=identifier):
                entry = texts.resolve(identifier)
                self.assertEqual(entry["status"], "resolved")
                self.assertEqual(entry["symbol_group"], DCM_UTILITY_GROUP)
        for identifier in DCM_COMMON_IDENTIFIERS:
            with self.subTest(identifier=identifier):
                entry = texts.resolve(identifier)
                self.assertEqual(entry["status"], "resolved")
                self.assertEqual(entry["symbol_group"], 20000)
        self.assertEqual(texts.resolve(0x9488)["status"], "missing_symbol")

    def test_malformed_authored_groups_are_rejected(self):
        for arguments in (
            (0x1352, ()),
            (0x1352, (0x948A, 0x948A)),
            (-1, (0x948A,)),
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                create_utility_group_text_examples(*arguments)
        with self.assertRaisesRegex(ValueError, "distinct"):
            create_utility_group_text_examples(0x1352, (0x948A,), common=(0x948A,))
        with self.assertRaisesRegex(ValueError, "match the identifiers"):
            create_utility_group_text_examples(0x1352, (0x948A,), texts=("a", "b"))


if __name__ == "__main__":
    unittest.main()
