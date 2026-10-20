from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from elf_symbolize_eh_frame import (
    ELF_HEADER,
    PROGRAM_HEADER,
    SECTION_HEADER,
    symbolize,
)
from merge_runtime_image import merge


def synthetic_elf() -> bytes:
    data = bytearray(0x3C0)
    program_offset = ELF_HEADER.size
    section_offset = 0x300
    data[: ELF_HEADER.size] = ELF_HEADER.pack(
        b"\x7fELF\x02\x01" + bytes(10),
        3,
        183,
        1,
        0x400020,
        program_offset,
        section_offset,
        0,
        ELF_HEADER.size,
        PROGRAM_HEADER.size,
        2,
        SECTION_HEADER.size,
        3,
        2,
    )
    programs = [
        PROGRAM_HEADER.pack(
            1, 5, 0x100, 0x400000, 0x400000, 0x180, 0x180, 0x1000
        ),
        PROGRAM_HEADER.pack(
            0x6474E550,
            4,
            0x180,
            0x400080,
            0x400080,
            20,
            20,
            4,
        ),
    ]
    for index, program in enumerate(programs):
        start = program_offset + index * PROGRAM_HEADER.size
        data[start : start + PROGRAM_HEADER.size] = program

    names = b"\0.text\0.shstrtab\0"
    data[0x280 : 0x280 + len(names)] = names
    sections = [
        bytes(SECTION_HEADER.size),
        SECTION_HEADER.pack(1, 1, 6, 0x400000, 0x100, 0x80, 0, 0, 4, 0),
        SECTION_HEADER.pack(7, 3, 0, 0, 0x280, len(names), 0, 0, 1, 0),
    ]
    for index, section in enumerate(sections):
        start = section_offset + index * SECTION_HEADER.size
        data[start : start + SECTION_HEADER.size] = section

    # version=1, eh_frame_ptr=pcrel-sdata4, count=udata4,
    # table=datarel-sdata4. The file offset differs from the virtual address.
    struct.pack_into(
        "<4siIii",
        data,
        0x180,
        b"\x01\x1b\x03\x3b",
        0x3C,
        1,
        -0x60,
        0x40,
    )
    struct.pack_into("<I", data, 0x1C0, 0)
    return bytes(data)


class ElfToolTests(unittest.TestCase):
    def test_merge_uses_virtual_runtime_coordinates(self) -> None:
        original = synthetic_elf()
        runtime = bytes(index & 0xFF for index in range(0x180))
        output, segments, copied, skipped = merge(
            original,
            runtime,
            runtime_base=0x400000,
            extend_text=False,
        )
        self.assertEqual(segments, 1)
        self.assertEqual(skipped, 0)
        self.assertEqual(copied, 0x180)
        self.assertEqual(output[0x100:0x280], runtime)

    def test_merge_reports_load_segment_missing_from_dump(self) -> None:
        original = bytearray(synthetic_elf())
        second_program = ELF_HEADER.size + PROGRAM_HEADER.size
        original[
            second_program : second_program + PROGRAM_HEADER.size
        ] = PROGRAM_HEADER.pack(
            1,
            6,
            0x280,
            0x500000,
            0x500000,
            0x10,
            0x10,
            0x1000,
        )
        runtime = bytes(0x180)
        _output, segments, _copied, skipped = merge(
            bytes(original),
            runtime,
            runtime_base=0x400000,
            extend_text=False,
        )
        self.assertEqual(segments, 1)
        self.assertEqual(skipped, 1)

    def test_symbolizer_handles_nonidentity_file_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.so"
            output = Path(directory) / "output.so"
            source.write_bytes(synthetic_elf())
            self.assertEqual(symbolize(source, output), 1)
            result = output.read_bytes()
            header = ELF_HEADER.unpack_from(result)
            self.assertEqual(header[12], 7)
            self.assertIn(b"fde_00400020\0", result)


if __name__ == "__main__":
    unittest.main()
