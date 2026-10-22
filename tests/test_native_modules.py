import unittest
from dataclasses import FrozenInstanceError

from scripts.native_modules import identify_native_module

MMC12 = "337471cdd200e6d1a3fd561d1374c1e5e999ad5f426054189aa03350f0438d4c"
MMC18 = "28598b23787ce67d63620a267ec1e0897b2cd5abf8a3319609a3cb4a5fccca9b"
NAME = "TCUWCanMMCFlashWriter.dll"
HMAC2026 = "e1e6cc8a531e8a3f3c899e3f11a48d4e0556e0903bc15cb944ef289c2f79eeef"


class NativeModuleTests(unittest.TestCase):
    def test_plain2026_dependency_has_its_actual_source_identity(self):
        identity = identify_native_module(HMAC2026, "CalculationHmacAPI.dll")
        self.assertEqual(identity.cuw_build, "2026")
        self.assertEqual(identity.cuw_builds, ("2026",))
        self.assertEqual(identity.callable_exports, ("MakeSendKeyCGWHmac",))
        self.assertEqual(identity.artifact_form, "original")
        self.assertIsNone(identity.engine_sha256)
        self.assertIsNone(identity.companion_sha256)
        for digest, name in (
            (HMAC2026, "TCUWUnifiedUtils.dll"),
            (HMAC2026, "calculationhmacapi.dll"),
            (HMAC2026, "./CalculationHmacAPI.dll"),
            ("0" * 64, "CalculationHmacAPI.dll"),
            (HMAC2026.upper(), "CalculationHmacAPI.dll"),
        ):
            with self.subTest(digest=digest, name=name), self.assertRaises(ValueError):
                identify_native_module(digest, name)

    def test_exact_build_identity_and_export(self):
        old = identify_native_module(MMC12, NAME)
        new = identify_native_module(MMC18, NAME)
        self.assertEqual((old.cuw_build, new.cuw_build), ("12", "18"))
        self.assertEqual(new.module_name, NAME)
        self.assertEqual(new.callable_exports, ("StartFlashWrite",))
        with self.assertRaises(FrozenInstanceError):
            new.cuw_build = "12"  # pyright: ignore[reportAttributeAccessIssue]

    def test_known_hash_cannot_impersonate_another_module_or_path(self):
        for name in (
            "TCUWCanM16CFlashWriter.dll",
            "renamed.dll",
            "./" + NAME,
            NAME.lower(),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                identify_native_module(MMC18, name)

    def test_unknown_and_malformed_digest_fail(self):
        for value in ("0" * 64, "", MMC18.upper(), MMC18 + "0", None, b"00"):
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                identify_native_module(value, NAME)  # pyright: ignore[reportArgumentType]

    def test_identical_shared_helper_does_not_invent_build(self):
        shared = identify_native_module(
            "2088b7066c749eab0bf60278afaf15fdf2acc65e7e033f07121bbba524e0a7e4",
            "TCUWParameterForBCB.dll",
        )
        self.assertIsNone(shared.cuw_build)
        self.assertEqual(shared.cuw_builds, ("12", "18"))

    def test_recovered2026_identity_records_provenance_without_equivalence(self):
        outer = identify_native_module(
            "0feb1c9dfc8a8867d90f6fe662ded7047ea3efecbd32622c822e5aa932024edf",
            "TCUWCanPowerTrainFlashWriter.dll",
        )
        self.assertEqual(outer.cuw_build, "2026")
        self.assertEqual(outer.artifact_form, "protected-original")
        self.assertEqual(
            outer.engine_sha256,
            "0a11170ac1b6b14bf387164ada2f5f2f6ab93e084a341affa5794164d79e3a82",
        )
        self.assertEqual(
            outer.companion_sha256,
            "2aabf6c0db0047bcb9b1a252574c7fe49f4e4d1741636deffb608c6ad910c5f5",
        )
        self.assertEqual(outer.callable_exports, ("PrepareRetry", "StartFlashWrite"))
        assert outer.engine_sha256 is not None
        recovered = identify_native_module(outer.engine_sha256, outer.module_name)
        self.assertEqual(recovered.artifact_form, "reconstructed-inspection")
        self.assertEqual(recovered.callable_exports, outer.callable_exports)
        with self.assertRaises(ValueError):
            identify_native_module(outer.sha256, "TCUWCanMMCFlashWriter.dll")
        assert outer.companion_sha256 is not None
        with self.assertRaises(ValueError):
            identify_native_module(outer.companion_sha256, outer.module_name)

    def test_data_exports_are_not_callable(self):
        crc = identify_native_module(
            "c8f921bd80b51a700e5171008a37a44d7803576be918dc8b5edce9497e4ad3c5",
            "TCUWCRC.dll",
        )
        self.assertEqual(crc.callable_exports, ("?CalcCRC16@@YAGPAEH@Z",))
        calibration = identify_native_module(
            "8ea3d0e516056040456a79c700a2b46e9ba2273e42c415cdf285f6232e839a96",
            "TCUWCalibrationFile.dll",
        )
        self.assertFalse(any("glptr" in name for name in calibration.callable_exports))
        self.assertIn(
            "?GetP4ServerMaxTime@CalibrationFile@@QAE?BIH@Z",
            calibration.callable_exports,
        )


if __name__ == "__main__":
    unittest.main()
