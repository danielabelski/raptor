// exec-and-load.js - command execution and library-load evidence.
//
// Hooks the process-execution sinks (system, popen, the exec family,
// posix_spawn) and the dynamic-loader entry points (dlopen family) and
// records what was executed/loaded and WHERE FROM (caller module +
// offset + backtrace). Two questions this answers cheaply:
//   * did a command-injection sink actually fire during the session,
//     and with what argv?
//   * what libraries/plugins does the target pull in at runtime
//     (attack surface that static import tables miss)?
//
// The execution vocabulary is RENDERED from RAPTOR's central function
// taxonomy (EXEC_FUNCS) into the slot below at load time. Per-function
// argument readers stay explicit here; rendered names without a reader
// (the varargs execl family, Windows-only entries on POSIX hosts) are
// hooked with a no-argument reader or skipped when the export does not
// resolve. dlopen/dlmopen/android_dlopen_ext are hooked locally -
// loader entry points, not execution sinks, so outside EXEC_FUNCS.
//
// LIMITATION: by default the session traces ONE process, so a plain
// fork() child is outside it and the fork()+exec pattern emits
// nothing. Run with --follow-children to trace children too (Frida
// child gating); without it, treat the ABSENCE of an exec event as
// unknown, never as "the sink did not fire". system()/popen()/
// posix_spawn() in the traced process are always captured.

'use strict';

var MAX_EVENTS_PER_FN = 500;   // a hostile target looping dlopen/system
                               // must not flood events.jsonl

function findGlobalExport(name) {
  if (typeof Module.findGlobalExportByName === 'function') {
    return Module.findGlobalExportByName(name);
  }
  if (typeof Module.findExportByName === 'function') {
    try { return Module.findExportByName(null, name); } catch (_e) { return null; }
  }
  return null;
}

function safeStr(ptr, maxLen) {
  if (ptr === null || ptr.isNull()) return '<null>';
  var max = maxLen || 512;
  try {
    // NUL-terminated read with output-side truncation. An explicit
    // length argument over-decodes past the terminator on Frida 17
    // (throws on interior NUL bytes), and Memory.readUtf8String was
    // removed in the 17.0 cleanup — probe for the instance method
    // first, fall back for older runtimes.
    var s = (typeof ptr.readUtf8String === 'function')
      ? ptr.readUtf8String()
      : Memory.readUtf8String(ptr);
    if (s === null) return '<null>';
    return s.length > max ? s.slice(0, max) : s;
  } catch (_e) {
    return '<unreadable>';
  }
}

// Walk a NULL-terminated char*[] (argv/envp shape). Bounded: a corrupt
// pointer table must not spin the agent.
function readArgv(ptr, maxEntries) {
  if (ptr === null || ptr.isNull()) return null;
  var out = [];
  var max = maxEntries || 32;
  try {
    for (var i = 0; i < max; i++) {
      var entry = ptr.add(i * Process.pointerSize).readPointer();
      if (entry.isNull()) return out;
      out.push(safeStr(entry, 256));
    }
    out.push('<truncated>');
  } catch (_e) {
    out.push('<unreadable>');
  }
  return out;
}

function callsite(context, returnAddress) {
  let backtrace = [];
  let moduleInfo = {};
  try {
    backtrace = Thread.backtrace(context, Backtracer.ACCURATE)
      .slice(0, 8)
      .map(addr => {
        let frame = { address: addr.toString() };
        try {
          const module = Process.findModuleByAddress(addr);
          if (module !== null) {
            frame = Object.assign(frame, {
              module: module.name,
              module_offset: addr.sub(module.base).toString(),
            });
          }
        } catch (_e) {}
        return frame;
      });
  } catch (_e) {
    backtrace = [];
  }
  try {
    const module = returnAddress ? Process.findModuleByAddress(returnAddress) : null;
    if (module !== null) {
      moduleInfo = {
        caller_module: module.name,
        caller_module_base: module.base.toString(),
        caller_offset: returnAddress.sub(module.base).toString(),
      };
    }
  } catch (_e) {
    moduleInfo = {};
  }
  return {
    caller: returnAddress ? returnAddress.toString() : null,
    backtrace_frames: backtrace,
    ...moduleInfo,
  };
}

const hooks = [];
const emitted = Object.create(null);   // null-proto: cap must be unpoisonable

function hook(name, category, readArgs) {
  const addr = findGlobalExport(name);
  if (addr === null) return;
  try {
    attachHook(name, category, readArgs, addr);
  } catch (_e) {
    // One unhookable address must not kill the remaining hooks; the
    // name is simply absent from the loaded-meta hook list.
    return;
  }
  hooks.push(name);
}

function attachHook(name, category, readArgs, addr) {
  Interceptor.attach(addr, {
    onEnter: function (args) {
      // Capture on ENTER: execve does not return on success, so an
      // onLeave-only emit would miss exactly the interesting calls.
      emitted[name] = (emitted[name] || 0) + 1;
      if (emitted[name] > MAX_EVENTS_PER_FN) {
        if (emitted[name] === MAX_EVENTS_PER_FN + 1) {
          // Never truncate silently: one loud marker per hook.
          send({ _meta: 'exec-and-load cap reached', fn: name, cap: MAX_EVENTS_PER_FN });
        }
        return;
      }
      let captured;
      try {
        captured = readArgs ? readArgs(args) : {};
      } catch (e) {
        captured = { _err: String(e) };
      }
      send(Object.assign({
        category: category,
        fn: name,
        args: captured,
        tid: Process.getCurrentThreadId(),
      }, callsite(this.context, this.returnAddress)));
    },
  });
}

// Explicit argument readers for the POSIX exec surface. Varargs
// entries (execl/execlp/execle) get no reader - stack layouts are
// arch-specific - but the call + callsite is still recorded.
const execArgReaders = {
  'system':       a => ({ command: safeStr(a[0]) }),
  'popen':        a => ({ command: safeStr(a[0]), mode: safeStr(a[1], 8) }),
  'execve':       a => ({ path: safeStr(a[0]), argv: readArgv(a[1]) }),
  'execv':        a => ({ path: safeStr(a[0]), argv: readArgv(a[1]) }),
  'execvp':       a => ({ path: safeStr(a[0]), argv: readArgv(a[1]) }),
  'execvpe':      a => ({ path: safeStr(a[0]), argv: readArgv(a[1]) }),
  'fexecve':      a => ({ fd: a[0].toInt32(), argv: readArgv(a[1]) }),
  'posix_spawn':  a => ({ path: safeStr(a[1]), argv: readArgv(a[4]) }),
  'posix_spawnp': a => ({ path: safeStr(a[1]), argv: readArgv(a[4]) }),
};

const execHookNames = /*__EXEC_HOOKS__*/ [];
execHookNames.forEach(function (name) {
  hook(name, 'exec', execArgReaders[name] || null);
});

// Dynamic loader surface - runtime attack surface the static import
// table cannot show (plugins, lazily-loaded crypto/parsers).
hook('dlopen',  'load', a => ({ path: safeStr(a[0]), flags: a[1].toInt32() }));
hook('dlmopen', 'load', a => ({ path: safeStr(a[1]), flags: a[2].toInt32() }));
hook('android_dlopen_ext', 'load', a => ({ path: safeStr(a[0]), flags: a[1].toInt32() }));

send({ _meta: 'exec-and-load loaded', hooks: hooks });
