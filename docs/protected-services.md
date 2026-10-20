# Protected services and the poison transition

## What was observed

The Java layer depends on native SHIELD services during class initialization
and application startup. The clearest service is an indexed protected-string
decoder:

```text
Java callsite -> native decoder(index) -> decoded string
```

Callers treat the returned string as non-null and immediately pass it to
constructors and parsers. Under a healthy launch, those calls return ordinary
configuration strings. After a detector commits a fatal result, the same
service begins returning null before the visible report callback finishes.

Observed failures included:

- a null passed to `StringBuilder(String)`
- a null regular-expression pattern passed to `Pattern.compile`
- application initialization failing while the reporting thread was still
  being intercepted

Those failures appeared after the detector result but before report
suppression could restore control.

![SHIELD concurrent verdict race](diagrams/verdict-race-dark.svg)

## Enforcement order

The observed order was:

1. a detector worker commits a fatal result in shared native state
2. protected native services stop returning valid values
3. the startup barrier and reporting paths consume the committed result
4. Java logs the reason and enters its fatal handler
5. native abort, exit, or self-tracer paths terminate the process

This ordering explains why replacing the Java uncaught-exception handler,
parking the reporting thread, or bypassing one terminal syscall did not restore
a usable application. Those interventions occurred after the protected
services had already changed behavior.

## Initialization barrier

Parking detector workers kept the process alive but prevented the application
from building its UI. Allowing the workers to finish released the startup
barrier, even when the reporting thread was then parked.

The detector result therefore controls at least two downstream actions:

- whether application startup may continue
- whether protected native services remain usable

The visible exception is one consumer of that result, not the enforcement
decision itself.

## What was not recovered

The analysis did not recover:

- the backing format of the protected string table
- the string/key derivation algorithm
- the exact shared-state field that poisons the service
- whether poisoning clears a key, changes a table pointer, flips a gate, or
  selects a null-return implementation
- the complete set of protected services beyond strings and startup-sensitive
  key operations

The evidence supports a state transition before reporting. It does not support
a claim that the mechanism is white-box cryptography or that a particular key
is zeroed.
