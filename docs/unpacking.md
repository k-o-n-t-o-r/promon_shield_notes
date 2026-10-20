# Recovering a SHIELD-protected native region

## Result

The dominant encrypted code span in the observed ARM64 ELF was reproduced
offline, byte for byte, from:

- the original encrypted ELF;
- a build-specific profile containing addresses, lengths, expected hashes,
  and the bootstrap-recovered nonce.

Build-specific parameters live in a JSON profile. See `profiles/example.json`
for the shape.

![Protected-code recovery pipeline](diagrams/unpacking-pipeline-dark.svg)

![SHIELD main-region unpacking internals](diagrams/unpacking-internals-dark.svg)

## Recovered structures

The relevant logical structures were:

```c
struct shield_secret32 {
    uint8_t initialized;
    uint8_t bytes[32];
};

struct shield_region_descriptor {
    uint64_t back_offset;
    uint64_t length;
    uint8_t key_mask[32];
};

struct shield_region_span {
    uint64_t page_size;
    uint8_t *start;
    uint64_t length;
    uint8_t protection_result;
    uint8_t padding[3];
    uint32_t saved_errno;
};
```

The descriptor table contained one live descriptor followed by an all-zero
sentinel in the studied build.

## Recovered semantic catalog

The final Binary Ninja database assigned these build-independent semantic
names:

```text
shield_get_page_size_cached
shield_fletcher64_words
shield_encode_region_checksum
shield_store_checksum_and_wipe
shield_verify_code_regions
shield_validate_and_activate_regions
shield_build_region_span
shield_xor_32
shield_destroy_checksum
shield_zero_qwords
shield_zero_bytes
shield_flush_icache
shield_raw_mprotect
shield_memset
shield_memcpy
shield_chacha_xor_rounds
shield_chacha8_xor

shield_scan_region_set
shield_scan_memory_window
shield_scan_buffer_init
shield_build_scan_page_span
shield_buffers_differ
shield_scan_buffer_destroy
shield_close_owned_fd
shield_open_thunk
shield_close_thunk
shield_read_thunk
shield_read_chk_thunk
shield_mprotect_thunk
shield_lseek_thunk
```

Store build-specific addresses in an `annotations.json` file using the
provided Binary Ninja schema.

## Algorithm

### 1. Fletcher-64 over the loader

The checksum routine starts both accumulators at `0xffffffff` and processes
little-endian 32-bit words modulo `0xffffffff`:

```c
uint64_t fletcher64_words(const uint32_t *words, size_t count)
{
    uint64_t sum1 = 0xffffffff;
    uint64_t sum2 = 0xffffffff;

    while (count-- != 0) {
        sum1 = (sum1 + *words++) % 0xffffffff;
        sum2 = (sum2 + sum1) % 0xffffffff;
    }
    return (sum2 << 32) | sum1;
}
```

The actual implementation batches reductions to avoid overflow, but the result
is equivalent.

### 2. Encode the checksum

Selected shifted bytes of the checksum are mixed with fixed marker bytes into
a 16-byte block, then repeated to 32 bytes. Some expressions are written as
opaque Boolean combinations. For example, because `0x8c` and `0x73` are
complements:

```c
((0x8c & ~a) | (0x73 & a)) ^
((0x8c & ~b) | (0x73 & b))
```

reduces to `a ^ b`.

The exact encoding recovered from the sample is implemented in
`scripts/recover_main_region.py`.

### 3. Derive the descriptor key

```c
for (size_t i = 0; i < 32; i++)
    key[i] = encoded_checksum[i] ^ descriptor->key_mask[i];
```

The mask remains inside the original binary and is read at the
profile-specified virtual address.

### 4. Activate and decrypt

The page span is aligned down at its start and rounded up until it covers the
requested region. SHIELD makes that span RWX, decrypts each descriptor in
place with original-layout ChaCha8, flushes the ARM64 caches, and restores RX.

The ChaCha construction uses:

- constant `"expand 32-byte k"`;
- 256-bit key;
- 64-bit block counter;
- 64-bit nonce;
- rotations 16, 12, 8, and 7;
- four double rounds, for eight rounds total.

### 5. Integrity coupling

Integrity is coupled into key derivation. The path performs no separate
plaintext comparison: changing the checksummed loader changes the key and
decrypts the main span incorrectly.

The recovery script therefore fails closed on:

- an input ELF hash mismatch;
- an invalid or truncated virtual-address mapping;
- an unexpected recovered-plaintext hash;
- any byte mismatch against an optional runtime oracle.

## Reproduction

Create a private profile from your own authorized sample:

```sh
cp profiles/example.json profiles/local.json
```

Fill in the values recovered from the build, then run:

```sh
python3 scripts/recover_main_region.py \
  original.so profiles/local.json artifacts/recovered.so \
  --metadata artifacts/recovered.json
```

If a flat runtime image is available:

```sh
python3 scripts/recover_main_region.py \
  original.so profiles/local.json artifacts/recovered.so \
  --runtime runtime.bin \
  --metadata artifacts/recovered.json
```

The script uses the runtime image only to verify the recovered bytes.

## Preparing Binary Ninja input

If the complete runtime image is available, merge file-backed runtime bytes
into an analysis-only copy of the ELF:

```sh
python3 scripts/merge_runtime_image.py \
  original.so runtime.bin artifacts/runtime-expanded.so
```

Then recover GNU EH-frame function boundaries:

```sh
python3 scripts/elf_symbolize_eh_frame.py \
  artifacts/runtime-expanded.so artifacts/runtime-symbolized.so
```

Open the symbolized file in Binary Ninja and apply the private annotation JSON
with the repository's `Promon Research > Apply annotations JSON` UI command.
See [binary-ninja-workflow.md](binary-ninja-workflow.md) for installation and
the optional headless CLI.

## Remaining boundary

The observed main nonce was produced by an earlier bootstrap stage. It was
deterministic across independent snapshots, so carrying it in an exact-build
profile was sufficient for reproducible recovery. Fully reconstructing the
earlier descriptor state machines would remove that final runtime-provenance
dependency.

Optional runtime verification matched every byte in the recovered main span.
