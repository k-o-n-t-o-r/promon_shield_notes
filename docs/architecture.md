# Observed Promon SHIELD architecture

## Scope

These findings come from an ARM64 Android application protected by Promon
SHIELD 8.2.4. They combine Java decompilation, runtime observation, syscall
traces, and reconstruction of an unpacked native image.

The analysis focused on ARM64 native startup, unpacking, integrity checks,
detector coordination, and enforcement on physical hardware. It did not
characterize Java/DEX/resource integrity, signing-certificate or repackaging
checks, emulator verdict behavior, or UI-layer protections such as screenshot,
overlay, accessibility, and input-abuse defenses.

Policy, offsets, timings, and helper layout vary by build. The architecture
below is the reusable part.

![SHIELD observation and enforcement architecture](diagrams/shield-architecture-dark.svg)

![SHIELD startup and verdict sequence](diagrams/shield-startup-sequence-dark.svg)

## Startup order

The protected Java wrapper loads the native library from
`attachBaseContext()`, before the application's ordinary `onCreate()` path.
The observed order was:

1. load the protected native image;
2. unpack bootstrap and main code regions;
3. initialize environment, root, hook, and native-integrity checks;
4. start a one-thread ptrace helper;
5. wait for detector results;
6. release application initialization only after the relevant workers finish;
7. poison protected services and enter a fatal path if a detector reports a
   violation.

Instrumentation present when the library loads becomes part of SHIELD's
startup evidence. Suppressing the final exception does not undo a detector
result that has already poisoned protected services.

## Runtime code recovery

The on-disk ELF deliberately understates its useful executable extent and
contains encrypted or transformed pages. At runtime, SHIELD:

1. derives a build-bound key from a Fletcher-64 checksum of an unprotected
   loader region;
2. encodes selected checksum bits and constants into a 32-byte value;
3. XORs that value with a descriptor-resident 32-byte mask;
4. makes the protected span writable and executable;
5. decrypts it in place with original-layout ChaCha8;
6. flushes the ARM64 data and instruction caches;
7. restores the pages to read/execute.

The dominant span was deterministic across independent launches. A flat
first-load memory image could therefore be merged into the ELF for analysis,
and the reconstructed key schedule could reproduce that span offline.

The image retained a `PT_GNU_EH_FRAME` search table even though section
headers and static symbols were insufficient. Recovering its FDE starts
exposed more than ten thousand function boundaries to Binary Ninja.

## Control-flow flattening

Large SHIELD functions use integer state dispatchers with:

- opaque state constants;
- dispatcher-local aliases of the primary state variable;
- duplicated cleanup and error states;
- nested dispatchers;
- deliberately redundant Boolean arithmetic;
- transiently decrypted functions which may be encrypted again before a
  later memory snapshot.

Automated deflattening was useful only with a side-effect check. One aggressive
rewrite produced attractive pseudocode while silently deleting a call. The
safe workflow was:

1. export the inferred state graph without mutating IL;
2. rewrite one dispatcher only;
3. compare callsites, stores, syscalls, and cache/protection operations before
   and after;
4. retain unresolved alternatives instead of deleting them;
5. restore the database if any side-effect signature disappears.

## Address and object inspection

The observed build did not rely on `/proc/self/maps` alone. It combined:

- sequential reads of `/proc/self/maps`;
- parsing of the reference C library's ELF metadata and dynamic symbols;
- `dlsym` results for selected libc and linker APIs;
- `dladdr` classification of object bases and symbol addresses;
- dynamically resolved `dl_iterate_phdr`;
- inspection of relocated function pointers;
- live-vs-backing-file byte comparisons;
- short prologue checks;
- module and foreign-mapping classification.

Hiding mapping names failed because a fake maps view must agree with every
other address oracle. Even a consistent pristine libc view did not account
for all detectors.

![SHIELD integrity evidence and correlation](diagrams/integrity-oracles-dark.svg)

See [environment-checks.md](environment-checks.md) and
[detector-signals.md](detector-signals.md) for the observed inputs and the
boundaries isolated for each reason family.

## Live-vs-file scanner

One recovered primitive:

1. validates an open fd, file offset, and length;
2. seeks and reads exact bytes from the backing file;
3. optionally forces the corresponding live pages to `PROT_READ|PROT_EXEC`;
4. compares live and file bytes with a private `bcmp` equivalent;
5. returns a tagged result containing a mismatch bit.

Its region walker uses 4,095-byte chunks. On 4 KiB pages, an unaligned chunk
usually spans 8 KiB, so adjacent checks overlap by one page. Runtime evidence
showed repeated scanning of Android runtime code.

See [integrity-scanner.md](integrity-scanner.md).

## Self-tracer

The parent becomes ptrace-owned by a one-thread child. The child:

- waits with `waitpid(..., __WALL)`;
- handles fork, vfork, clone, exec, seccomp, signal, and syscall stops;
- maintains a registry of traced tasks;
- uses `PTRACE_GETEVENTMSG`, `PTRACE_GETSIGINFO`, `PTRACE_SETOPTIONS`, and
  `PTRACE_CONT`;
- communicates over a nonblocking Unix socketpair integrated with epoll;
- fails closed on unexpected status or state.

The terminal routine uses raw syscalls to kill registered tracees, the parent,
and itself, then calls `exit_group(1)`. Ordinary debugger attachment becomes
fragile, while the child can detect later code mutation independently of the
parent's Java reporting path.

See [self-tracer.md](self-tracer.md).

## Detector races and reporting

Several workers run concurrently. The first completed policy violation can win
the report race, so a single instrumentation configuration may produce
different public reason classes across launches. In the observed build:

- mapping-only instrumentation reached a root/tamper detector;
- process-wide libc entry hooks reached a hooking-framework detector quickly;
- persistent local GOT redirection reached a native-hook detector;
- independent workers remained capable of terminating the process after one
  worker was parked.

![SHIELD concurrent verdict race](diagrams/verdict-race-dark.svg)

The Java exception and process exit are downstream effects. By the time the
fatal callback is visible, protected string decoding and other SHIELD services
may already return invalid values. Bypassing the final abort, exit, or uncaught
exception therefore does not restore a usable application.

See [protected-services.md](protected-services.md) for the observed poison
transition and remaining unknowns.

## Detector lifetime

The observed build had finite startup and mutation-watch windows. Installing
the same full hook set after both windows survived the validation interval.
That survival result is build-specific and does not establish how other SHIELD
deployments behave.
