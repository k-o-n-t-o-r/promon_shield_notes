# Promon SHIELD research

Some notes from reverse engineering Promon SHIELD 8.2.4 on an ARM64 Android
application.

The repository focuses on:

- SHIELD's native unpacking and control-flow flattening
- Its self-tracer and live-vs-file integrity checks
- The address, mapping, relocation, and code-byte evidence its workers combine
- Why common concealment ideas failed
- The finite startup and mutation windows measured in the observed build

## Quick checks

```sh
ruff check .
python3 -m unittest discover -s tests -v
python3 -m compileall -q scripts binaryninja
```

See [`scripts/README.md`](scripts/README.md) for the offline recovery pipeline.

## Start here

1. [Observed architecture](docs/architecture.md)
2. [Instrumentation and concealment findings](docs/instrumentation-findings.md)
3. [Protected-region recovery](docs/unpacking.md)
4. [Live-vs-file integrity scanner](docs/integrity-scanner.md)
5. [Self-tracer](docs/self-tracer.md)
6. [Binary Ninja workflow](docs/binary-ninja-workflow.md)
7. [Experimental method and failure controls](docs/methodology.md)
8. [Detector families and isolated signals](docs/detector-signals.md)
9. [Root and environment checks](docs/environment-checks.md)
10. [Protected services and poison transition](docs/protected-services.md)

## Diagrams

### SHIELD observation and enforcement

![SHIELD observation and enforcement architecture](docs/diagrams/shield-architecture-dark.svg)

### Startup and verdict sequence

![SHIELD startup and verdict sequence](docs/diagrams/shield-startup-sequence-dark.svg)

### Integrity evidence and correlation

![SHIELD integrity evidence and correlation](docs/diagrams/integrity-oracles-dark.svg)

### Live-vs-file scanner decision flow

![SHIELD live-vs-file scanner decision flow](docs/diagrams/scanner-algorithm-dark.svg)

### Concurrent verdict race

![SHIELD concurrent verdict race](docs/diagrams/verdict-race-dark.svg)

### Self-tracer state machine

![SHIELD self-tracer state machine](docs/diagrams/self-tracer-state-dark.svg)

### Protected-code recovery

![Protected-code recovery pipeline](docs/diagrams/unpacking-pipeline-dark.svg)

### Main-region unpacking internals

![SHIELD main-region unpacking internals](docs/diagrams/unpacking-internals-dark.svg)

## Disclaimer

This project was developed with the assistance of AI tools. AI was used for tasks such as code generation, refactoring, debugging, documentation, reverse engineering and general development support.
