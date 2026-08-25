# Frida Dynamic Instrumentation

RAPTOR wraps the Frida dynamic instrumentation framework into a
lifecycle-managed session runner. It resolves devices (local, USB,
remote frida-server), resolves targets (PID, process name, bundle ID, or
binary path), spawns or attaches, loads JavaScript hook scripts, captures
`send()` messages into `events.jsonl`, and writes structured metadata and
a human-readable report.

The Frida subsystem is both a standalone operator tool (`/frida`) and a
pipeline component that feeds runtime evidence into
[/binary](binary-analysis.md), [/validate](validation.md)
and [/understand](commands.md#understand).

See also: [commands](commands.md), [binary analysis](binary-analysis.md),
[sandbox](sandbox.md).

**Status:** Alpha. Templates and runner are minimal starters.

---

## Setup

### Host Install

```bash
pipx install frida-tools         # recommended (PEP 668-safe)
# or, in a virtualenv:
pip install frida-tools
```

Verify:

```bash
raptor doctor          # confirms frida binary is detected
frida --version        # client version
```

`raptor doctor` only checks the host side. Target reachability is the
operator's responsibility.

### Linux

The kernel `yama.ptrace_scope` sysctl gates who can `ptrace` what:

| Value | Meaning |
|-------|---------|
| 0 | Classic -- any process can ptrace any other process with the same UID. |
| 1 | Default -- only child/explicit-trace targets allowed (most distros). |
| 2 | Admin-only. |
| 3 | Ptrace disabled entirely. |

To attach to a sibling process you own (the common case), drop to 0
temporarily:

```bash
sudo sysctl -w kernel.yama.ptrace_scope=0
```

Spawning a binary you can execute does not need `ptrace_scope=0`:

```bash
raptor frida --target ./vulnerable --template api-trace --duration 60
```

`metadata.json` from each run records the current `ptrace_scope` --
useful for "why did attach fail" forensics.

### macOS

No SIP changes required for processes you own. `task_for_pid` works for
same-UID processes.

**System / Apple-signed processes** are blocked by
`com.apple.private.disable-task_for_pid` even as root. To attach, SIP
must be partially disabled:

```
csrutil disable --without debug
```

This significantly reduces system security. Use a dedicated research VM.
RAPTOR's runner does not require SIP to be off; it only matters for the
targets you can attach to.

Hardened-runtime binaries with `com.apple.security.get-task-allow=false`
(most distributed App Store apps) reject attach. Either use a debug
build or re-sign with `--entitlements` that include
`get-task-allow=true`. Check existing entitlements with
`codesign -d --entitlements - <binary>`.

Frida 17.x ships arm64 builds for Apple Silicon natively.

### Remote frida-server

On the target (typically an embedded device or VM):

```bash
# download the matching frida-server for the target's arch
./frida-server -l 0.0.0.0:27042 &
```

The `-l 0.0.0.0:27042` is critical. Default builds bind to `127.0.0.1`
only, which is unreachable from another host.

From the RAPTOR host:

```bash
raptor frida --target some-process --host 10.10.20.1 --template api-trace
```

Treat the network channel as unauthenticated. Frida-server has no auth
in front of it. On shared networks, prefer SSH-forwarding:

```bash
# On the target: bind to localhost only
./frida-server -l 127.0.0.1:27042 &

# On the host: SSH-forward instead of --host
ssh -L 27042:127.0.0.1:27042 target-user@10.10.20.1
raptor frida --target some-process --host 127.0.0.1 --template api-trace
```

---

## Usage

**Slash command:**

```bash
/frida --target <target> --template <name> --duration <seconds>
```

**CLI entry point:**

```bash
raptor frida --target <target> --template <name> --duration <seconds>
```

### CLI Flags

| Flag | Purpose |
|------|---------|
| `--target <target>` | Required. PID (digits), process name, bundle ID, or path to a binary to spawn. |
| `--template <name>` | Bundled hook template name. Mutually exclusive with `--script` / `--sink-watch`. |
| `--script <path>` | Path to an operator-supplied JS hook file. Mutually exclusive with `--template` / `--sink-watch`. |
| `--sink-watch <file>` | Watch a finding-specific sink list: a sinks JSON or a validation run's `attack-paths.json`. Mutually exclusive with `--template` / `--script`. |
| `--host <host[:port]>` | Connect to a remote frida-server. Default port 27042. Mutually exclusive with `--usb`. |
| `--usb` | Connect to the first USB-attached device. Mutually exclusive with `--host`. |
| `--duration <seconds>` | Seconds to run before detaching. Default 60. |
| `--spawn` | Force spawn-and-attach. Implied when `--target` is an existing file path. |
| `--unsafe-attach` | Required for templates/modes needing `PTRACE_ATTACH` or `task_for_pid`. Logged in metadata. |
| `--list-templates` | Print bundled template names and exit. |

### Examples

```bash
# List bundled templates
raptor frida --list-templates

# Attach to a local process by PID
raptor frida --target 1234 --template api-trace --duration 30

# Spawn a binary and trace for 60 seconds
raptor frida --target ./victim --template api-trace --duration 60

# Bypass SSL pinning on a USB-attached mobile target (spawn by bundle ID)
raptor frida --target com.example.app --template ssl-unpin --usb --spawn --duration 120

# Remote frida-server on the LAN
raptor frida --target target-binary --template api-trace --host 10.10.20.1

# Operator-supplied hook script
raptor frida --target Safari --script ./my-hook.js --duration 30
```

---

## Bundled Templates

Use `--list-templates` to see the current set.

### api-trace

Hooks common input/output APIs (`recv`, `recvfrom`, `read`, `write`,
`send`, `sendto`, etc.) and records call arguments and return values.
The general-purpose starting point for understanding what a binary does
at runtime.

```bash
raptor frida --target ./app --template api-trace --duration 30
```

### ssl-unpin

Bypasses SSL/TLS certificate pinning for common frameworks and
libraries. Useful for intercepting HTTPS traffic from mobile
applications during security assessment.

```bash
raptor frida --target com.example.app --template ssl-unpin --usb --spawn
```

### binary-flow-trace

Records ASLR-relative callsites for input APIs (`recv`, `recvfrom`,
`read`) and high-value parser entry points (`XML_Parse`,
`xmlReadMemory`, `d2i_X509`, `jpeg_read_header`, `inflate`). When a
callsite maps back to a recovered function address, RAPTOR emits
`OBSERVED_CALLSITE` or `OBSERVED_PARSER_CALLSITE` graph edges.

This template is used by `/binary trace-parser` to fold runtime
evidence back into an existing binary investigation. It proves the
function called the API during that run; it does not claim those bytes
reached a later sink.

```bash
raptor frida --target ./app --template binary-flow-trace --duration 20
```

### bb-coverage

Basic-block coverage collection via Frida Stalker. Records which basic
blocks execute during the traced session. Useful for measuring code
coverage of specific inputs or comparing coverage between test cases.

```bash
raptor frida --target ./app --template bb-coverage --duration 30
```

### seed-harvest

Dumps the input buffers the target actually received (`read`, `recv`,
`recvfrom`, `SSL_read`, `fread`, `fgets`, `getline`, ...) and distills
them into a fuzz-ready seed corpus. After the session the CLI writes
one file per unique payload into `<out>/seeds/` plus a
`seeds-manifest.json` sibling with per-function counts.

Observing a network daemon or file parser under real traffic for a
minute yields protocol-realistic seeds — usually the hardest part of
fuzzing a binary-only target.

```bash
raptor frida --target ./daemon --template seed-harvest --duration 60
raptor fuzz --binary ./daemon --corpus out/frida_<ts>/seeds
```

Captures are capped (8 KiB per buffer, 2048 events per hooked
function) and deduplicated in-process; caps are reported in the event
stream and manifest, never applied silently.

Seeds are the raw bytes the target received — decrypted TLS payloads
(`SSL_read`), file contents, anything on its sockets. Treat a
harvested corpus as potentially secret-bearing and review it before
sharing or committing it anywhere.

### exec-and-load

Records command execution (`system`, `popen`, the `exec` family,
`posix_spawn`) with the resolved argv, and dynamic-loader activity
(`dlopen`, `dlmopen`, `android_dlopen_ext`) — each event annotated
with the calling module, offset, and backtrace. Answers "did that
command-injection sink actually fire, and from where?" and enumerates
runtime-loaded libraries/plugins that static import tables miss.

```bash
raptor frida --target ./app --template exec-and-load --duration 60
```

Events are captured on function entry: `execve` does not return on
success, so exit-side hooks would miss exactly the interesting calls.

The session traces one process: a plain `fork()` child is outside it
(child gating is not enabled), so the fork()+exec pattern emits
nothing even though the exec fired. Treat the *absence* of an exec
event as unknown, never as proof the sink did not fire;
`system`/`popen`/`posix_spawn` in the traced process are captured.

### sink-watch

Records every call to a configured list of dangerous sinks with its
arguments and full callsite. Two modes:

- `--template sink-watch` watches the default sink vocabulary from the
  central function taxonomy (memory-copy, string-overflow,
  format-string, and exec sinks).
- `--sink-watch <file>` watches a finding-specific list — either a
  hand-written sinks JSON (`["memcpy", {"fn": "SSL_write", "module":
  "libssl.so.3"}]`) or a validation run's `attack-paths.json`, from
  which every step function is derived mechanically.

Per-sink resolution tries module-scoped exports, global exports, then
`DebugSymbol` — the fallback rescues project-internal sink wrappers on
targets that ship symbols. Unresolved sinks are listed in the `_meta`
event, and hot sinks are capped at 500 events each with a loud cap
marker.

```bash
# Run the PoC input while watching exactly the finding's sinks:
raptor frida --target ./srv --sink-watch out/validate_<ts>/attack-paths.json --duration 60
```

Sink events carry `category=sink` and the function name in `fn` — the
exact shape the validation bridge counts, so the observed arguments
("the tainted length reached the memcpy") flow into `/validate`'s
`runtime_evidence` annotations with no extra wiring.

### jni-trace

Maps the Java↔native boundary on ART (Android) targets by hooking
`RegisterNatives` (every `art::JNI<...>` instantiation, CheckJNI twin
excluded): one event per registered native method with the method
name, JNI signature, and the native implementation's module + offset.
This bridges jadx-level Java analysis to native-code analysis — jadx
shows which class declares a `native` method with that name and
signature; the emitted offset says which native function backs it.

```bash
raptor frida --target com.example.app --template jni-trace --usb --spawn --duration 30
```

On a non-ART process the template loads, reports the miss in a
`_meta` event, and hooks nothing. Class names resolve only when the
Java bridge is present in the agent — Frida 17 unbundled it, and
RAPTOR loads scripts unbundled via `create_script`, so on current
Frida expect the raw `jclass` handle per registration batch (the
method/signature/module mapping is unaffected).

---

## Pipeline Integration

Beyond standalone use, `/binary` and `/agentic` launch Frida
observation themselves when dynamic evidence collection is warranted
(programmatic entry points `observe_target` / `observe_paired` /
`auto_observe` in `packages/frida/`; existing fresh evidence for a
target is reused rather than re-collected). Frida sessions run under
the same [sandbox](sandbox.md) constraints as every other RAPTOR
subprocess, observed callsites and parser boundaries are folded back
into `/understand` context maps, and `/binary map --runtime-dir`
ingests evidence from prior runs.

---

## Custom Scripts

Operator-supplied scripts are loaded verbatim via `--script`. The script
runs in Frida's JavaScript runtime and should use `send()` to emit
structured messages, which RAPTOR captures in `events.jsonl`.

```javascript
// my-hook.js
Interceptor.attach(Module.findExportByName(null, 'open'), {
    onEnter: function(args) {
        send({
            type: 'open',
            path: args[0].readUtf8String(),
            flags: args[1].toInt32()
        });
    }
});
```

```bash
raptor frida --target ./app --script ./my-hook.js --duration 30
```

A copy of the executed script (template or operator-supplied) is saved
as `script.js` in the output directory for reproducibility.

---

## Output

Each run drops into a lifecycle-managed directory:

```
out/projects/<project>/frida-<timestamp>/      # if a /project is active
out/frida_<timestamp>/                         # otherwise
```

Contents:

| File | Purpose |
|------|---------|
| `events.jsonl` | One JSON object per `send(...)` from the script. |
| `metadata.json` | Target, host info, timings, errors, ptrace_scope (Linux). |
| `script.js` | Copy of the hook that executed. |
| `frida-report.md` | Short human-readable summary. |
| `seeds/` + `seeds-manifest.json` | Fuzz-ready corpus distilled from data-carrying events (only when the script emitted `args.data_hex` payloads, e.g. seed-harvest). |

---

## Common Failure Modes

| Symptom | Likely cause |
|---------|-------------|
| `frida: run failed: ptrace denied` (Linux) | `kernel.yama.ptrace_scope` >= 1; relax via `sysctl` or attach as the target's owning user. |
| `frida: run failed: ... task_for_pid` (macOS) | System process or hardened target; needs SIP-disabled or signed binary entitlement. |
| `Failed to enumerate processes: unable to connect to remote frida-server` | frida-server bound to localhost only -- re-launch with `-l 0.0.0.0:27042` or SSH-forward 27042. |
| `failed to enumerate processes: timeout` | Network filter/firewall between host and target. |
| Empty `events.jsonl` | Script did not hook anything that fired during the window; raise `--duration` or check `metadata.json` for an error. |
| frida-server killed by SELinux (Android-flavoured Linux) | Run `setenforce 0` while researching, or label the binary appropriately. |
| No provisioning profile / arch mismatch (macOS) | Old Intel frida-server binary on Apple Silicon; match host and target architectures. |
