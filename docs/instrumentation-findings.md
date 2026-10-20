# Instrumentation and concealment findings

## Summary

The experiments split into three groups:

1. changes that were visible immediately;
2. changes that hid one evidence source but not the whole detector model;
3. approaches that avoided or outlived the detector.

Instrumentation present during SHIELD's detector window exposed mappings,
entry patches, relocation changes, and linker modifications. The same full
hook set survived when installed after the measured startup and mutation
windows.

![SHIELD integrity evidence and correlation](diagrams/integrity-oracles-dark.svg)

## Experimental matrix

| Technique | Observed result | Interpretation |
|---|---|---|
| Instrumentation library mapped, no hooks | detected | Mapping/framework presence alone reached a root/tamper worker. |
| Renamed anonymous mappings | detected | Names were only one signal. |
| Sanitized `/proc/self/maps` | detected | Other address and integrity oracles remained. |
| Deny maps or reference-library reads | explicit fail-closed exit | Missing evidence was itself treated as tampering. |
| Mirror live libc bytes into reference-file reads | detected | The detector parsed metadata and resolved live addresses instead of reading the whole text from disk. |
| Passive pristine libc decoy in maps | detected | Linker APIs still returned the real registered object. |
| Spoof maps, `dlsym`, `dladdr`, `dl_iterate_phdr`, and libc relocations consistently | detected | A consistent libc view was necessary but not sufficient. |
| Process-wide libc inline hooks | fast hook-framework verdict | Live entry points and/or hook machinery were visible. |
| SHIELD-local persistent GOT redirection | native-hook verdict | Local relocation changes were independently checked. |
| Restore transient GOT changes before the final sweep | immediate native-hook verdict removed; another worker remained | Persistence mattered, but other detector families still applied. |
| Park one detector worker | first verdict suppressed; another worker won | Workers were redundant and raced. |
| Park all observed workers | process lived but application UI never initialized | Worker completion was an initialization barrier. |
| Suppress Java report handler | initialization completed, later watchdog/fatal path fired | Reporting was downstream of native enforcement. |
| Patch abort/exit sites | terminal mechanism changed; process still died or services were poisoned | Patching noreturn leaves was the wrong abstraction level. |
| Patch a pre-report code branch | self-tracer killed the parent | Private executable mutation was independently watched. |
| Temporarily substitute mutable callback data | callback was bypassed, but protected string service was already poisoned | The intervention was still too late. |
| Install full hooks after measured detector expiry | survived the observation interval | This build's checks were finite, not continuous. |

![SHIELD concurrent verdict race](diagrams/verdict-race-dark.svg)

See [detector-signals.md](detector-signals.md) for the evidence separating the
mapping/root, hook-framework, native-hook, and code-integrity families.

## Why maps-only hiding failed

The maps experiment was valid: SHIELD consumed a current, address-correct
snapshot with only instrumentation-owned rows removed and then proceeded to
its next checks. The process still reported a hook violation.

Follow-up observations found:

- dynamic symbol resolution into real libc;
- object-base classification with `dladdr`;
- a dynamically obtained `dl_iterate_phdr`;
- imported and relocated API pointers;
- live-vs-file byte comparison;
- short prologue checks.

A believable alternate view has to be consistent across every source.
Sanitizing mapping strings alone cannot do that. Even after making the libc
view consistent, framework mappings, linker modifications, other library
families, and the self-tracer remained.

## Why report suppression failed

The visible exception was not the decision point. Detector workers had already:

- selected a fatal result;
- disabled protected native services;
- released or withheld startup barriers;
- notified independent native enforcement paths.

Parking the reporting thread avoided Android's immediate kill but triggered a
liveness failure. Replacing the uncaught-exception handler removed one exit
path but a native abort followed. Bypassing abort exposed `exit_group`.
Bypassing both produced a null fault or another worker's abort. Clearing a
later result flag still left protected-string methods returning null.

Once protected services return invalid values, move the experiment earlier
instead of suppressing another terminal primitive.

## Finite detector windows

In this one build, instrumentation timing separated two checks:

1. an initialization inspection that caught hooks present almost immediately;
2. a mutation watch that reacted after an install and remained active for
   several seconds.

Early and mid-startup installs died. Installs after the measured watch expiry
survived, including the full hook set, for the longest validation run. An
eight-second delay was the conservative validated value for that sample.

Do not cargo-cult that number. A different protected build may:

- use a longer timeout;
- re-arm on lifecycle or network events;
- perform random periodic checks;
- hash a load vehicle;
- defer checks until a protected feature is exercised.

Determine the window with a clean control and a single changed variable.

## What survived

The build exposed two finite detector periods:

1. startup inspection caught instrumentation already present when SHIELD
   initialized;
2. a mutation watch caught code or relocation changes for several seconds
   afterward.

Early and mid-window installs died. The full hook set survived when installed
after both periods had expired. This does not establish a universal delay:
another build can extend, randomize, or re-arm either check.

## What not to repeat

A dynamic kernel kretprobe experiment on the test handset caused a watchdog
reset with a hypervisor-level fault and no useful kernel backtrace. Do not
repeat dynamic kprobe experiments on production hardware merely to move
observation earlier; use an emulator or a separately bootable instrumented
kernel.
