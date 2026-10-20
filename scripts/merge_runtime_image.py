#!/usr/bin/env python3
"""Merge file-backed PT_LOAD bytes from a flat runtime image into an ELF.

The output is analysis-only. Program headers and mapped addresses are left
unchanged. By default, a deliberately short ``.text`` section is extended to
the end of its executable file-backed segment so analysis tools can discover
runtime-unpacked functions.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
PT_LOAD = 1
PF_X = 1


def integer(value: str) -> int:
    return int(value, 0)


def c_string(data: bytes, offset: int) -> bytes:
    if not 0 <= offset < len(data):
        raise ValueError("section name offset is outside the string table")
    end = data.find(b"\0", offset)
    if end < 0:
        raise ValueError("unterminated section name")
    return data[offset:end]


def parse_elf(data: bytes) -> tuple[list[int | bytes], list[list[int]], list[list[int]]]:
    if len(data) < ELF_HEADER.size:
        raise ValueError("input is shorter than an ELF header")
    header = list(ELF_HEADER.unpack_from(data))
    if header[0][:6] != b"\x7fELF\x02\x01":
        raise ValueError("only little-endian ELF64 input is supported")
    if header[9] != PROGRAM_HEADER.size:
        raise ValueError("unexpected ELF64 program-header size")
    if header[11] != SECTION_HEADER.size:
        raise ValueError("unexpected ELF64 section-header size")

    program_end = header[5] + header[9] * header[10]
    section_end = header[6] + header[11] * header[12]
    if program_end > len(data) or section_end > len(data):
        raise ValueError("truncated ELF header table")

    programs = [
        list(PROGRAM_HEADER.unpack_from(data, header[5] + index * header[9]))
        for index in range(header[10])
    ]
    sections = [
        list(SECTION_HEADER.unpack_from(data, header[6] + index * header[11]))
        for index in range(header[12])
    ]
    return header, programs, sections


def merge(
    original: bytes,
    runtime: bytes,
    *,
    runtime_base: int = 0,
    extend_text: bool = True,
) -> tuple[bytes, int, int, int]:
    header, programs, sections = parse_elf(original)
    output = bytearray(original)
    copied_segments = 0
    copied_bytes = 0
    skipped_segments = 0

    for program in programs:
        kind, _flags, file_offset, virtual, _physical, file_size, *_ = program
        if kind != PT_LOAD or not file_size:
            continue
        runtime_offset = virtual - runtime_base
        if runtime_offset < 0 or runtime_offset + file_size > len(runtime):
            skipped_segments += 1
            continue
        if file_offset + file_size > len(output):
            raise ValueError(
                f"ELF PT_LOAD at file offset 0x{file_offset:x} is truncated"
            )
        output[file_offset : file_offset + file_size] = runtime[
            runtime_offset : runtime_offset + file_size
        ]
        copied_segments += 1
        copied_bytes += file_size

    if not copied_segments:
        raise ValueError("runtime image does not contain any complete PT_LOAD")

    if extend_text and sections:
        section_names_index = header[13]
        if section_names_index >= len(sections):
            raise ValueError("invalid section-name-table index")
        names_header = sections[section_names_index]
        names = original[names_header[4] : names_header[4] + names_header[5]]
        text = next(
            (
                section
                for section in sections
                if c_string(names, section[0]) == b".text"
            ),
            None,
        )
        if text is None:
            raise ValueError("input has no .text section")
        executable = next(
            (
                program
                for program in programs
                if program[0] == PT_LOAD
                and program[1] & PF_X
                and program[3] <= text[3] < program[3] + program[5]
            ),
            None,
        )
        if executable is None:
            raise ValueError(".text is not inside a file-backed executable PT_LOAD")
        expanded_size = executable[3] + executable[5] - text[3]
        if expanded_size > text[5]:
            text[5] = expanded_size
            for index, section in enumerate(sections):
                offset = header[6] + index * header[11]
                output[offset : offset + SECTION_HEADER.size] = SECTION_HEADER.pack(
                    *section
                )

    return bytes(output), copied_segments, copied_bytes, skipped_segments


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("runtime", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--runtime-base",
        type=integer,
        default=0,
        help="virtual address represented by runtime byte zero",
    )
    parser.add_argument(
        "--no-extend-text",
        action="store_true",
        help="do not extend .text to its executable PT_LOAD boundary",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output, segments, size, skipped = merge(
        args.original.read_bytes(),
        args.runtime.read_bytes(),
        runtime_base=args.runtime_base,
        extend_text=not args.no_extend_text,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    print(
        f"OUTPUT={args.output} SEGMENTS={segments} "
        f"SKIPPED={skipped} BYTES={size}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"ERROR={error}", file=sys.stderr)
        raise SystemExit(1)
