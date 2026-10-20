# Detector families and isolated signals

## Observed reason families

The build exposed separate workers for mapping/root state, process-wide hook
frameworks, native redirection, and later mutation. Their reports could race;
the first completed violation became the visible reason.

![SHIELD concurrent verdict race](diagrams/verdict-race-dark.svg)

## Signal matrix

| Detector family | Isolated observation | What remains unknown |
|---|---|---|
| Mapping/root/tamper | Instrumentation and its hook runtime mapped with zero entry hooks still reached this worker | The exact mapping, thread, path, property, or environment signature that completed the verdict |
| Hook framework | Process-wide libc entry hooks consistently produced the fast hook-framework reason; crypto-only entry hooks did not | Whether the decisive signature was a patched libc prologue, trampoline shape, framework metadata, or another framework artifact |
| Native hook | With process-wide entry hooks removed, persistent SHIELD-local GOT redirection produced the native-hook reason | The full set of watched relocation slots and whether each slot is checked directly or through a derived table |
| Code integrity | A private-code mutation caused the self-tracer to kill the parent without waiting for Java reporting | The complete baseline schedule and every page covered by the later mutation watch |
| Live-vs-file scanner | Short spot checks and overlapping 4,095-byte region comparisons tested live code against backing bytes | Which scanner callers map to which public reason class |

## Hook-framework boundary

The hook-framework reason was narrower than "any native hook":

- a full process-wide libc hook family reached it quickly
- a crypto-only hook profile did not produce that reason
- hiding instrumentation rows from `/proc/self/maps` did not remove it
- a consistent alternate libc view across maps and linker APIs still left
  other framework artifacts

The exact final fingerprint was not isolated. The evidence identifies the libc
entry-hook family as necessary in the measured configuration, not the one
instruction or metadata field that completed the policy.

## Native-hook boundary

Replacing SHIELD's own relocated function pointers changed the winning reason
from hook-framework to native-hook. Restoring those slots before the later
sweep removed the immediate native-hook report, after which another detector
could still win.

That result separates persistent relocation redirection from process-wide
entry patching, but it does not show that temporary GOT changes are generally
safe.

## Reporting caveat

A visible reason is the winner of a race, not an exhaustive diagnosis.
Suppressing one worker exposed another reason, and suppressing the reporter did
not reverse protected-service poisoning or self-tracer enforcement.
