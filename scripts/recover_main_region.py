#!/usr/bin/env python3
"""Recover an observed Promon SHIELD main code region from an ELF.

The build-specific values live in a private JSON profile. The implemented
checksum encoding and ChaCha8 construction are the ones reconstructed from the
studied SHIELD generation; a profile hash prevents accidental use on another
build.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
FLETCHER_MODULUS = 0xFFFFFFFF
HEX_DIGITS = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class Profile:
    input_sha256: str
    plaintext_sha256: str
    checksum_virtual_address: int
    checksum_length: int
    key_mask_virtual_address: int
    protected_virtual_address: int
    protected_length: int
    nonce: bytes
    runtime_virtual_base: int = 0


def parse_integer(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise TypeError(f"{field} must be an integer")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        result = int(value, 0)
    else:
        raise TypeError(f"{field} must be an integer or integer string")
    if result < 0:
        raise ValueError(f"{field} must not be negative")
    return result


def parse_hash(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a hexadecimal string")
    result = value.lower()
    if len(result) != 64 or any(character not in HEX_DIGITS for character in result):
        raise ValueError(f"{field} must contain exactly 64 hexadecimal characters")
    return result


def load_profile(path: Path) -> Profile:
    raw = json.loads(path.read_text())
    if raw.get("format") != 1:
        raise ValueError("unsupported profile format")

    try:
        nonce = bytes.fromhex(raw["nonce"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("nonce must be a hexadecimal string") from error
    if len(nonce) != 8:
        raise ValueError("nonce must contain exactly 8 bytes")

    profile = Profile(
        input_sha256=parse_hash(raw.get("input_sha256"), "input_sha256"),
        plaintext_sha256=parse_hash(
            raw.get("plaintext_sha256"), "plaintext_sha256"
        ),
        checksum_virtual_address=parse_integer(
            raw.get("checksum_virtual_address"), "checksum_virtual_address"
        ),
        checksum_length=parse_integer(
            raw.get("checksum_length"), "checksum_length"
        ),
        key_mask_virtual_address=parse_integer(
            raw.get("key_mask_virtual_address"), "key_mask_virtual_address"
        ),
        protected_virtual_address=parse_integer(
            raw.get("protected_virtual_address"), "protected_virtual_address"
        ),
        protected_length=parse_integer(
            raw.get("protected_length"), "protected_length"
        ),
        nonce=nonce,
        runtime_virtual_base=parse_integer(
            raw.get("runtime_virtual_base", 0), "runtime_virtual_base"
        ),
    )
    if not profile.checksum_length or profile.checksum_length % 4:
        raise ValueError("checksum_length must be a positive multiple of 4")
    if not profile.protected_length:
        raise ValueError("protected_length must be positive")
    return profile


def elf_program_headers(elf: bytes) -> list[tuple[int, ...]]:
    if len(elf) < ELF_HEADER.size:
        raise ValueError("input is shorter than an ELF header")
    header = ELF_HEADER.unpack_from(elf)
    if header[0][:6] != b"\x7fELF\x02\x01":
        raise ValueError("only little-endian ELF64 input is supported")
    program_offset = header[5]
    program_entry_size = header[9]
    program_count = header[10]
    if program_entry_size != PROGRAM_HEADER.size:
        raise ValueError("unexpected ELF64 program-header size")
    end = program_offset + program_entry_size * program_count
    if end > len(elf):
        raise ValueError("truncated program-header table")
    return [
        PROGRAM_HEADER.unpack_from(elf, program_offset + index * program_entry_size)
        for index in range(program_count)
    ]


def virtual_range_to_file_offset(elf: bytes, address: int, length: int) -> int:
    end = address + length
    for fields in elf_program_headers(elf):
        segment_type, _flags, offset, virtual, _physical, file_size, *_ = fields
        if (
            segment_type == 1
            and virtual <= address
            and end <= virtual + file_size
        ):
            file_offset = offset + address - virtual
            if file_offset + length > len(elf):
                break
            return file_offset
    raise ValueError(
        f"virtual range 0x{address:x}..0x{end:x} is not fully file-backed"
    )


def fletcher64_words(data: bytes) -> int:
    if len(data) % 4:
        raise ValueError("Fletcher input length is not uint32-aligned")
    sum1 = FLETCHER_MODULUS
    sum2 = FLETCHER_MODULUS
    for (word,) in struct.iter_unpack("<I", data):
        sum1 = (sum1 + word) % FLETCHER_MODULUS
        sum2 = (sum2 + sum1) % FLETCHER_MODULUS
    return (sum2 << 32) | sum1


def encode_checksum(checksum: int) -> bytes:
    block = bytearray(16)
    block[0] = (checksum >> 14) & 0xFF
    block[1] = 0xAB
    block[2] = ((checksum >> 9) + 0x0F) & 0xFF
    block[3] = (checksum >> 1) & 0xFF
    block[4] = 0x11
    block[5] = (checksum >> 5) & 0xFF
    shifted = checksum >> 20
    block[6] = ((0x54 & ~shifted) | (shifted & 0xAB)) & 0xFF
    block[7] = 0x91
    block[8] = (checksum >> 21) & 0xFF
    block[9] = ((checksum >> 15) + 0x54) & 0xFF
    block[10] = 0x25
    block[11] = (checksum >> 23) & 0xFF
    shifted = checksum >> 12
    block[12] = (((~shifted & 0xE3) | (shifted & 0x1C)) ^ 7) & 0xFF
    block[13] = 0x65
    block[14] = (checksum >> 10) & 0xFF
    block[15] = 9
    return bytes(block * 2)


def rotate_left32(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def quarter_round(words: list[int], a: int, b: int, c: int, d: int) -> None:
    words[a] = (words[a] + words[b]) & 0xFFFFFFFF
    words[d] = rotate_left32(words[d] ^ words[a], 16)
    words[c] = (words[c] + words[d]) & 0xFFFFFFFF
    words[b] = rotate_left32(words[b] ^ words[c], 12)
    words[a] = (words[a] + words[b]) & 0xFFFFFFFF
    words[d] = rotate_left32(words[d] ^ words[a], 8)
    words[c] = (words[c] + words[d]) & 0xFFFFFFFF
    words[b] = rotate_left32(words[b] ^ words[c], 7)


def chacha8_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    if len(key) != 32 or len(nonce) != 8:
        raise ValueError("ChaCha8 requires a 32-byte key and 8-byte nonce")
    initial = (
        list(struct.unpack("<4I", b"expand 32-byte k"))
        + list(struct.unpack("<8I", key))
        + [counter & 0xFFFFFFFF, counter >> 32]
        + list(struct.unpack("<2I", nonce))
    )
    working = initial.copy()
    for _ in range(4):
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)
    return struct.pack(
        "<16I",
        *((left + right) & 0xFFFFFFFF for left, right in zip(working, initial)),
    )


def chacha8_xor(data: bytes, key: bytes, nonce: bytes) -> bytes:
    output = bytearray(len(data))
    for offset in range(0, len(data), 64):
        key_stream = chacha8_block(key, nonce, offset // 64)
        chunk = data[offset : offset + 64]
        output[offset : offset + len(chunk)] = bytes(
            left ^ right for left, right in zip(chunk, key_stream)
        )
    return bytes(output)


def recover(encrypted: bytes, profile: Profile) -> tuple[bytes, dict[str, Any]]:
    input_hash = hashlib.sha256(encrypted).hexdigest()
    if input_hash != profile.input_sha256:
        raise ValueError(
            f"wrong encrypted build: expected {profile.input_sha256}, "
            f"got {input_hash}"
        )

    checksum_offset = virtual_range_to_file_offset(
        encrypted,
        profile.checksum_virtual_address,
        profile.checksum_length,
    )
    checksum_input = encrypted[
        checksum_offset : checksum_offset + profile.checksum_length
    ]
    checksum = fletcher64_words(checksum_input)
    encoded = encode_checksum(checksum)

    mask_offset = virtual_range_to_file_offset(
        encrypted, profile.key_mask_virtual_address, 32
    )
    key_mask = encrypted[mask_offset : mask_offset + 32]
    key = bytes(left ^ right for left, right in zip(encoded, key_mask))

    protected_offset = virtual_range_to_file_offset(
        encrypted,
        profile.protected_virtual_address,
        profile.protected_length,
    )
    ciphertext = encrypted[
        protected_offset : protected_offset + profile.protected_length
    ]
    plaintext = chacha8_xor(ciphertext, key, profile.nonce)
    plaintext_hash = hashlib.sha256(plaintext).hexdigest()
    if plaintext_hash != profile.plaintext_sha256:
        raise ValueError(
            f"plaintext hash mismatch: expected {profile.plaintext_sha256}, "
            f"got {plaintext_hash}"
        )

    output = bytearray(encrypted)
    output[protected_offset : protected_offset + profile.protected_length] = plaintext
    metadata: dict[str, Any] = {
        "input_sha256": input_hash,
        "checksum": f"0x{checksum:016x}",
        "encoded_checksum_sha256": hashlib.sha256(encoded).hexdigest(),
        "derived_key_sha256": hashlib.sha256(key).hexdigest(),
        "protected_virtual_address": f"0x{profile.protected_virtual_address:x}",
        "protected_length": profile.protected_length,
        "plaintext_sha256": plaintext_hash,
        "runtime_verified": False,
    }
    return bytes(output), metadata


def verify_runtime(
    recovered: bytes,
    runtime: bytes,
    profile: Profile,
) -> None:
    recovered_offset = virtual_range_to_file_offset(
        recovered,
        profile.protected_virtual_address,
        profile.protected_length,
    )
    runtime_offset = (
        profile.protected_virtual_address - profile.runtime_virtual_base
    )
    if runtime_offset < 0:
        raise ValueError("protected region begins below runtime_virtual_base")
    runtime_plaintext = runtime[
        runtime_offset : runtime_offset + profile.protected_length
    ]
    if len(runtime_plaintext) != profile.protected_length:
        raise ValueError("runtime image does not contain the protected span")
    recovered_plaintext = recovered[
        recovered_offset : recovered_offset + profile.protected_length
    ]
    if recovered_plaintext != runtime_plaintext:
        differences = sum(
            left != right
            for left, right in zip(recovered_plaintext, runtime_plaintext)
        )
        raise ValueError(
            f"runtime verification failed: {differences} differing byte(s)"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("encrypted", type=Path)
    parser.add_argument("profile", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--runtime",
        type=Path,
        help="optional flat runtime image for byte-for-byte verification",
    )
    parser.add_argument("--metadata", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    profile = load_profile(args.profile)
    recovered, metadata = recover(args.encrypted.read_bytes(), profile)

    if args.runtime:
        verify_runtime(recovered, args.runtime.read_bytes(), profile)
        metadata["runtime_verified"] = True

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(recovered)
    if args.metadata:
        args.metadata.parent.mkdir(parents=True, exist_ok=True)
        args.metadata.write_text(json.dumps(metadata, indent=2) + "\n")

    print(
        f"OUTPUT={args.output} BYTES={profile.protected_length} "
        f"SHA256={metadata['plaintext_sha256']}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR={error}", file=sys.stderr)
        raise SystemExit(1)
