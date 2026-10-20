#!/usr/bin/env python3
"""Add function symbols from a stripped ELF64 binary's GNU EH-frame table.

Some protected binaries retain a PT_GNU_EH_FRAME search table while omitting
the corresponding section headers and static symbols. Binary Ninja and other
tools then miss valid runtime-unpacked functions. This creates an analysis-only
ELF with:

* ``.eh_frame_hdr`` and ``.eh_frame`` section headers;
* one ``STT_FUNC`` symbol per FDE start;
* a replacement section-name table and a new static symbol table.

Program headers and mapped bytes are unchanged.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
SYMBOL = struct.Struct("<IBBHQQ")

PT_LOAD = 1
PT_GNU_EH_FRAME = 0x6474E550
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHF_ALLOC = 2
STB_GLOBAL = 1
STT_FUNC = 2


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def append_aligned(output: bytearray, data: bytes, alignment: int) -> int:
    offset = align(len(output), alignment)
    output.extend(b"\0" * (offset - len(output)))
    output.extend(data)
    return offset


def c_string(data: bytes, offset: int) -> bytes:
    if not 0 <= offset < len(data):
        raise ValueError("string-table offset is out of range")
    end = data.find(b"\0", offset)
    if end < 0:
        raise ValueError("unterminated string-table entry")
    return data[offset:end]


def add_string(table: bytearray, value: bytes) -> int:
    offset = len(table)
    table.extend(value)
    table.append(0)
    return offset


def virtual_to_file_offset(
    programs: list[tuple[int, ...]], address: int, length: int = 1
) -> int:
    for program in programs:
        kind, _flags, offset, virtual, _physical, file_size, *_ = program
        if (
            kind == PT_LOAD
            and virtual <= address
            and address + length <= virtual + file_size
        ):
            return offset + address - virtual
    raise ValueError(f"virtual range at 0x{address:x} is not file-backed")


def parse_eh_frame_table(
    data: bytes,
    programs: list[tuple[int, ...]],
    header_offset: int,
    header_virtual: int,
    header_size: int,
) -> tuple[list[tuple[int, int]], int, int, int]:
    if data[header_offset : header_offset + 4] != b"\x01\x1b\x03\x3b":
        raise ValueError(
            "unsupported .eh_frame_hdr encoding; expected "
            "version=1, pcrel-sdata4, udata4, datarel-sdata4"
        )
    eh_frame_relative, count = struct.unpack_from("<iI", data, header_offset + 4)
    expected_size = 12 + count * 8
    if expected_size > header_size:
        raise ValueError("truncated .eh_frame_hdr search table")

    rows: list[tuple[int, int]] = []
    for index in range(count):
        initial_relative, fde_relative = struct.unpack_from(
            "<ii", data, header_offset + 12 + index * 8
        )
        rows.append(
            (
                header_virtual + initial_relative,
                header_virtual + fde_relative,
            )
        )
    if rows != sorted(rows):
        raise ValueError(".eh_frame_hdr function table is not sorted")

    eh_frame_virtual = header_virtual + 4 + eh_frame_relative
    eh_frame_offset = virtual_to_file_offset(programs, eh_frame_virtual)
    cursor = eh_frame_offset
    while cursor + 4 <= len(data):
        length = struct.unpack_from("<I", data, cursor)[0]
        if length == 0:
            cursor += 4
            break
        if length == 0xFFFFFFFF:
            if cursor + 12 > len(data):
                raise ValueError("truncated extended .eh_frame entry")
            extended_length = struct.unpack_from("<Q", data, cursor + 4)[0]
            cursor += 12 + extended_length
        else:
            cursor += 4 + length
        if cursor > len(data):
            raise ValueError("truncated .eh_frame entry")
    else:
        raise ValueError(".eh_frame terminator not found")

    return rows, eh_frame_virtual, eh_frame_offset, cursor - eh_frame_offset


def symbolize(input_path: Path, output_path: Path) -> int:
    data = input_path.read_bytes()
    if len(data) < ELF_HEADER.size:
        raise ValueError("input is shorter than an ELF header")

    header = list(ELF_HEADER.unpack_from(data))
    if header[0][:6] != b"\x7fELF\x02\x01":
        raise ValueError("only little-endian ELF64 input is supported")

    program_offset = header[5]
    section_offset = header[6]
    program_entry_size = header[9]
    program_count = header[10]
    section_entry_size = header[11]
    section_count = header[12]
    section_names_index = header[13]
    if program_entry_size != PROGRAM_HEADER.size:
        raise ValueError("unexpected ELF64 program-header size")
    if section_entry_size != SECTION_HEADER.size:
        raise ValueError("unexpected ELF64 section-header size")
    if section_names_index >= section_count:
        raise ValueError("invalid section-name-table index")
    if program_offset + program_entry_size * program_count > len(data):
        raise ValueError("truncated program-header table")
    if section_offset + section_entry_size * section_count > len(data):
        raise ValueError("truncated section-header table")

    programs = [
        PROGRAM_HEADER.unpack_from(
            data, program_offset + index * program_entry_size
        )
        for index in range(program_count)
    ]
    eh_frame_header = next(
        (program for program in programs if program[0] == PT_GNU_EH_FRAME),
        None,
    )
    if eh_frame_header is None:
        raise ValueError("input has no PT_GNU_EH_FRAME program header")
    eh_frame_header_offset = eh_frame_header[2]
    eh_frame_header_virtual = eh_frame_header[3]
    eh_frame_header_size = eh_frame_header[5]

    sections = [
        list(
            SECTION_HEADER.unpack_from(
                data, section_offset + index * section_entry_size
            )
        )
        for index in range(section_count)
    ]
    old_names_header = sections[section_names_index]
    old_names = data[
        old_names_header[4] : old_names_header[4] + old_names_header[5]
    ]
    text_index = next(
        (
            index
            for index, section in enumerate(sections)
            if c_string(old_names, section[0]) == b".text"
        ),
        None,
    )
    if text_index is None:
        raise ValueError("input has no .text section")

    rows, eh_frame_virtual, eh_frame_offset, eh_frame_size = parse_eh_frame_table(
        data,
        programs,
        eh_frame_header_offset,
        eh_frame_header_virtual,
        eh_frame_header_size,
    )
    text_start = sections[text_index][3]
    text_end = text_start + sections[text_index][5]
    starts = sorted({start for start, _fde in rows})
    if not starts or starts[0] < text_start or starts[-1] >= text_end:
        raise ValueError(
            "FDE function starts fall outside .text; extend the analysis "
            "section first"
        )

    symbol_names = bytearray(b"\0")
    symbols = bytearray(SYMBOL.size)
    for index, start in enumerate(starts):
        name_offset = add_string(symbol_names, f"fde_{start:08x}".encode())
        end = starts[index + 1] if index + 1 < len(starts) else text_end
        symbols.extend(
            SYMBOL.pack(
                name_offset,
                (STB_GLOBAL << 4) | STT_FUNC,
                0,
                text_index,
                start,
                end - start,
            )
        )

    section_names = bytearray(old_names)
    eh_frame_header_name = add_string(section_names, b".eh_frame_hdr")
    eh_frame_name = add_string(section_names, b".eh_frame")
    string_table_name = add_string(section_names, b".strtab")
    symbol_table_name = add_string(section_names, b".symtab")

    output = bytearray(data)
    string_table_offset = append_aligned(output, symbol_names, 1)
    symbol_table_offset = append_aligned(output, symbols, 8)
    section_names_offset = append_aligned(output, section_names, 1)

    sections[section_names_index][4] = section_names_offset
    sections[section_names_index][5] = len(section_names)

    string_table_index = len(sections) + 2
    sections.extend(
        [
            [
                eh_frame_header_name,
                SHT_PROGBITS,
                SHF_ALLOC,
                eh_frame_header_virtual,
                eh_frame_header_offset,
                eh_frame_header_size,
                0,
                0,
                4,
                0,
            ],
            [
                eh_frame_name,
                SHT_PROGBITS,
                SHF_ALLOC,
                eh_frame_virtual,
                eh_frame_offset,
                eh_frame_size,
                0,
                0,
                8,
                0,
            ],
            [
                string_table_name,
                SHT_STRTAB,
                0,
                0,
                string_table_offset,
                len(symbol_names),
                0,
                0,
                1,
                0,
            ],
            [
                symbol_table_name,
                SHT_SYMTAB,
                0,
                0,
                symbol_table_offset,
                len(symbols),
                string_table_index,
                1,
                8,
                SYMBOL.size,
            ],
        ]
    )

    new_section_offset = align(len(output), 8)
    output.extend(b"\0" * (new_section_offset - len(output)))
    for section in sections:
        output.extend(SECTION_HEADER.pack(*section))

    header[6] = new_section_offset
    header[12] = len(sections)
    output[: ELF_HEADER.size] = ELF_HEADER.pack(*header)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(output)
    return len(starts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    count = symbolize(args.input, args.output)
    print(f"OUTPUT={args.output} FUNCTIONS={count}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"ERROR={error}", file=sys.stderr)
        raise SystemExit(1)
