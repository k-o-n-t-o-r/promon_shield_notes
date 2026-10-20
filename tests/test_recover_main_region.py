from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from recover_main_region import (
    ELF_HEADER,
    PROGRAM_HEADER,
    Profile,
    chacha8_block,
    encode_checksum,
    fletcher64_words,
    load_profile,
    recover,
    virtual_range_to_file_offset,
)


class RecoveryPrimitiveTests(unittest.TestCase):
    def test_chacha8_all_zero_regression_vector(self) -> None:
        self.assertEqual(
            chacha8_block(bytes(32), bytes(8), 0).hex(),
            "3e00ef2f895f40d67f5bb8e81f09a5a1"
            "2c840ec3ce9a7f3b181be188ef711a1e"
            "984ce172b9216f419f445367456d5619"
            "314a42a3da86b001387bfdb80e0cfe42",
        )

    def test_checksum_primitives(self) -> None:
        self.assertEqual(fletcher64_words(b"\0" * 8), 0)
        self.assertEqual(
            encode_checksum(0x0123456789ABCDEF).hex(),
            "afabf5f7116fce914dab25135865f309" * 2,
        )

    def test_virtual_range_must_fit_one_file_backed_segment(self) -> None:
        data = bytearray(0x200)
        data[: ELF_HEADER.size] = ELF_HEADER.pack(
            b"\x7fELF\x02\x01" + bytes(10),
            3,
            183,
            1,
            0,
            ELF_HEADER.size,
            0,
            0,
            ELF_HEADER.size,
            PROGRAM_HEADER.size,
            1,
            64,
            0,
            0,
        )
        data[ELF_HEADER.size : ELF_HEADER.size + PROGRAM_HEADER.size] = (
            PROGRAM_HEADER.pack(1, 5, 0x100, 0x4000, 0, 0x80, 0x80, 0x1000)
        )
        self.assertEqual(
            virtual_range_to_file_offset(bytes(data), 0x4010, 0x20),
            0x110,
        )
        with self.assertRaisesRegex(ValueError, "not fully file-backed"):
            virtual_range_to_file_offset(bytes(data), 0x4070, 0x20)

    def test_profile_validation(self) -> None:
        profile = {
            "format": 1,
            "input_sha256": "00" * 32,
            "plaintext_sha256": "11" * 32,
            "checksum_virtual_address": "0x1000",
            "checksum_length": "0x100",
            "key_mask_virtual_address": "0x2000",
            "protected_virtual_address": "0x3000",
            "protected_length": "0x1000",
            "nonce": "00" * 8,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            path.write_text(json.dumps(profile))
            parsed = load_profile(path)
            self.assertEqual(parsed.protected_length, 0x1000)

            profile["nonce"] = "00"
            path.write_text(json.dumps(profile))
            with self.assertRaisesRegex(ValueError, "exactly 8 bytes"):
                load_profile(path)

    def test_recovery_refuses_unprofiled_input(self) -> None:
        profile = Profile(
            input_sha256="00" * 32,
            plaintext_sha256="11" * 32,
            checksum_virtual_address=0,
            checksum_length=4,
            key_mask_virtual_address=0,
            protected_virtual_address=0,
            protected_length=4,
            nonce=bytes(8),
        )
        with self.assertRaisesRegex(ValueError, "wrong encrypted build"):
            recover(b"not the profiled ELF", profile)


if __name__ == "__main__":
    unittest.main()
