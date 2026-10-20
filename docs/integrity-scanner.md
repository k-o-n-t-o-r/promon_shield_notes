# Reconstructed live-vs-file integrity scanner

## Verdict

One SHIELD helper compares a short live executable-memory window with exact
bytes read from an already-open backing-file descriptor. The primitive checks
code bytes directly.

![SHIELD integrity evidence and correlation](diagrams/integrity-oracles-dark.svg)

![SHIELD live-vs-file scanner decision flow](diagrams/scanner-algorithm-dark.svg)

The observed region walker scanned Android runtime code in 4,095-byte chunks.
Because those chunks are usually unaligned, each page-protection span covers
8 KiB on a 4 KiB-page device, and successive spans overlap by one page.

## Recovered types and signature

```c
struct shield_byte_buffer {
    uint8_t *begin;
    uint8_t *end;
    uint8_t *capacity_end;
};

struct shield_scan_result {
    const void *tag;
    uint8_t mismatch;
    uint8_t initialized;
    uint8_t padding[6];
};

struct shield_scan_result shield_scan_memory_window(
    int fd,
    const uint8_t *live_bytes,
    int64_t file_offset,
    uint64_t length,
    bool force_rx);
```

The 16-byte result is returned in `x0:x1`. A successful comparison returns a
success tag plus a mismatch bit and initialized byte. Error paths use an
adjacent error tag. The exact source-language wrapper type is unknown, but its
ABI and consumer tests were unambiguous.

## Pseudo-original implementation

```c
static struct shield_scan_result
shield_scan_memory_window(
    int fd,
    const uint8_t *live_bytes,
    int64_t file_offset,
    uint64_t length,
    bool force_rx)
{
    struct shield_byte_buffer file_bytes = {0};

    if (fd < 1 || file_offset < 0 || length > 0x1000)
        return scan_error();

    if (shield_lseek(fd, file_offset, SEEK_SET) != file_offset)
        return scan_error();

    shield_buffer_init(&file_bytes, length);
    ssize_t amount = shield_read(fd, file_bytes.begin, length);
    if (amount < 1 || (uint64_t)amount != length) {
        shield_buffer_destroy(&file_bytes);
        return scan_error();
    }

    if (force_rx) {
        struct shield_region_span span;
        shield_build_page_span(&span, live_bytes, length, 0);
        errno = 0;
        if (shield_mprotect(
                span.start, span.length, PROT_READ | PROT_EXEC) != 0) {
            shield_buffer_destroy(&file_bytes);
            return scan_error();
        }
    }

    bool mismatch =
        shield_buffers_differ(live_bytes, file_bytes.begin, length) != 0;

    shield_buffer_destroy(&file_bytes);
    return scan_success(mismatch);
}
```

The binary also contains a fortified-read branch selected by a signed-negative
length test. It is unreachable for ordinary valid callers after the upper
bound check but was retained in the reconstruction.

## Region walker

The higher-level caller opens one backing object with `O_CLOEXEC`, orders
live-address/file-offset/length triples, and scans large regions as:

```c
while (length > 0xfff) {
    result = shield_scan_memory_window(
        fd, live, file_offset, 0xfff, true);
    if (result.tag != success_tag || result.mismatch)
        stop;

    live += 0xfff;
    file_offset += 0xfff;
    length -= 0xfff;
}

if (length != 0)
    result = shield_scan_memory_window(
        fd, live, file_offset, length, true);
```

The fd is closed and reset on every terminal path. Other callers use the same
primitive for very short spot checks, so moving a hook a few bytes beyond a
single prologue test is not a general bypass.

## Runtime proof

A runtime observation point on the scanner dispatcher recorded the same
complete flattened path repeatedly. A separate observation point on the
private `mprotect` wrapper showed a long sequence of:

```text
address      next page each call
length       two pages
protection   PROT_READ|PROT_EXEC
chunk        0x0fff bytes
file offset  previous offset + 0x0fff
```

Mapping attribution placed those destination addresses in `libart.so`. The
scanner was walking live ART code against file bytes.

## Consequence

Temporary unhook races and unusually shaped trampolines do not address the
whole mechanism. The build combined:

- short spot checks;
- overlapping whole-region scans;
- module and relocation inspection;
- independent workers;
- self-tracer enforcement.

Installing instrumentation after the observed detector windows avoided those
startup checks in this build. The timing is not portable across releases.
