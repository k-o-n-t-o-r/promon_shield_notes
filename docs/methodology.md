# Experimental method and failure controls

## One variable at a time

The research repeatedly produced plausible but wrong explanations when more
than one state changed between launches. A valid arm needs:

1. an immediately preceding healthy control;
2. the same app data and authorization state;
3. the same network condition unless network timing is the variable;
4. one instrumentation change;
5. process-lifetime, report, signal, and functional observations;
6. immutable logs for both control and arm.

## A PID is not health

`pidof` alone can mistake a crash loop for a stable process. A useful health
check includes:

- stable process start time, not only PID;
- no SHIELD report;
- no native fatal signal;
- resumed/focused activity;
- a drawn and interactive UI or another application-level success oracle.

## Reason classes race

Independent detector workers can race. The first report is not necessarily the
only violated policy. Parking the worker that produced one reason allowed a
second reason to appear.

A reason code records one winning path under the exact launch state;
independent violations may remain.

## State contamination

Security-sensitive Android apps often bind state to:

- UID;
- Android Keystore entries;
- hardware-backed attestation;
- server registrations;
- app data;
- root-hiding policy;
- boot-time mounts.

A clear-data, reinstall, or reboot can alter several of those at once. A
"clean" reinstall is not automatically a valid control. Record each state
transition and verify the control after it.

## Attribution

System-wide probes and syscall traces can collect events from unrelated
processes. One early observation was discarded after TID/TGID and loaded-code
attribution showed that it came from another process.

Positive evidence should join:

- process and thread identity;
- target UID;
- module mapping;
- the triggering action;
- the expected code path;
- process survival and verdict logs.

If any link is missing, call the result unattributed.

## Exact-build binding

A native offset is not reusable across updates. Before applying a private
analysis profile:

1. extract the exact ABI member;
2. hash it;
3. compare package/build metadata if available;
4. refuse a stale profile;
5. resolve the runtime base from the current process's maps;
6. compute addresses from that verified image and profile.

`recover_main_region.py` follows the same rule for offline recovery.

## Private artifact hygiene

Never commit:

- tokens;
- app data;
- APKs or proprietary native images;
- runtime dumps;
- target profiles containing exact hashes and offsets.

## Binary Ninja mutation discipline

Before any deobfuscation plugin changes IL:

1. save and copy the database;
2. export the inferred graph;
3. record call/store/syscall side-effect signatures;
4. run one pass only;
5. compare signatures;
6. reject and restore on any unexplained loss.

Readable pseudocode is not evidence if a transformation deleted behavior.

## Kernel safety

A dynamic kretprobe pretest on a physical handset caused a watchdog reset and
hypervisor-level fault. No further dynamic kprobe experiment was justified.

Prefer, in order:

1. emulator validation;
2. a separately bootable statically instrumented kernel;
3. only then a carefully isolated physical-device kernel experiment.

Never repeat a kernel fault merely to improve a trace.
