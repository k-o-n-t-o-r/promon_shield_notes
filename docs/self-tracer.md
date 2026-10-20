# SHIELD self-tracer

![SHIELD self-tracer state machine](diagrams/self-tracer-state-dark.svg)

## Process topology

The protected parent was ptrace-owned before a conventional debugger could
attach. Its tracer was a one-thread child with seccomp enabled. The child
blocked in:

```c
waitpid(-1, &status, __WALL);
```

The setup path:

1. creates a nonblocking Unix stream socketpair;
2. creates an epoll instance;
3. toggles `prctl(PR_SET_DUMPABLE, 0)` around the protected fork;
4. restores dumpability after the relationship is established;
5. enters the event dispatcher.

## Event dispatcher

Recovered branches handle:

```text
PTRACE_EVENT_FORK
PTRACE_EVENT_VFORK
PTRACE_EVENT_CLONE
PTRACE_EVENT_EXEC
PTRACE_EVENT_SECCOMP
PTRACE_O_TRACESYSGOOD syscall stops
ordinary signal stops
```

The child uses:

- `PTRACE_GETEVENTMSG`
- `PTRACE_GETSIGINFO`
- `PTRACE_SETOPTIONS`
- `PTRACE_CONT`

It maintains a tracee registry and treats unexpected status, timeout, or
inconsistent state as a fatal condition.

Recovered semantic names included:

```text
PromonShield_self_tracer_wait_loop
PromonShield_dispatch_ptrace_event
PromonShield_ptrace
PromonShield_kill_traced_process_and_self
PromonShield_init_and_self_tracer
raw_ptrace
raw_write
raw_exit_group
```

## Fail-closed path

The terminal routine uses raw syscalls rather than exported libc wrappers:

1. send `SIGKILL` to registered tracees;
2. send `SIGKILL` to the tracer's parent;
3. send `SIGKILL` to the tracer itself;
4. invoke `exit_group(1)`.

Observed consequences:

- disconnecting a debugger from the tracer also removed the parent;
- a private-code mutation could be followed by a silent parent death with no
  Java reason;
- suppressing the parent's public report path did not neutralize enforcement;
- libc write and signal hooks did not necessarily observe tracer control
  traffic.

## Raw syscall wrappers

The unpacked image contained compact wrappers for operations such as:

```text
write
pipe2
ptrace
kill
exit_group
```

The self-tracer used raw `write` for small control records and a separate
parent channel existed for higher-level reporting. Do not infer channel
semantics from fd number or syscall family alone; classify endpoints and copy
payloads before assigning meaning.

## Research implications

- A ptrace debugger competes with the self-tracer and is not a transparent
  observer.
- Patching one parent fatal edge is insufficient.
- Restoring code after SHIELD has baselined it can itself trigger the child.
- Any debugger that needs ptrace ownership competes with the tracer.

A clean process exit does not establish a benign application decision. Always
correlate Java logs, raw signal events, sender PID/TID, and the parent/child
relationship.
