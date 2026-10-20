# Root and environment checks

## Observed inputs

SHIELD read several process, filesystem, property, and linker sources during
startup.

### Process state

- sequential reads of `/proc/self/maps`
- repeated reads of `/proc/self/status`
- object ownership and load-bias classification through linker APIs
- anonymous and unregistered executable-address checks

### Filesystem probes

- common `su` locations
- Magisk and SuperSU paths
- the platform C library as a reference ELF
- extended attributes through `getxattr`
- path existence checks through dynamically resolved `access`

### Android properties

Observed property lookups included:

```text
qemu.hw.mainkeys
qemu.sf.lcd_density
vendor.qemu.sf.fake_camera
vendor.qemu.timezone
ro.boot.serialno
```

Denied lookups generated platform log messages, which made the property sweep
visible even when the protected callsites were transiently decrypted.

### Dynamically resolved APIs

One startup resolver batch requested:

```text
eventfd
prctl
inotify_init
dl_iterate_phdr
fork
dlopen
inotify_add_watch
syscall
__system_property_get
execl
dladdr
killpg
```

Other SHIELD callsites resolved `access`, `getauxval`, and `getxattr`.

## How the inputs combine

The evidence does not support a one-signal model. SHIELD compared or
cross-checked:

- the mapping view
- reference ELF symbols
- linker-resolved addresses
- object names and load biases
- imported and relocated pointers
- live executable bytes

Hiding one mapping name left the remaining views inconsistent.

![SHIELD integrity evidence and correlation](diagrams/integrity-oracles-dark.svg)

## Coverage boundary

Tests ran on physical ARM64 hardware. Emulator-related property probes were
observed, but emulator and virtualization verdict behavior was not tested.

The analysis also did not isolate every input to the root/tamper reason class.
Detector workers raced, so a root/tamper reason records the first completed
path rather than a complete list of failed checks.
