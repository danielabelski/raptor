// sink-watch.js - argument-level runtime evidence at dangerous sinks.
//
// Watches a configured list of sink functions and records every call
// with its arguments and full callsite (caller module + offset +
// backtrace). This is the strongest runtime evidence /validate can
// get short of a PoC: "the tainted length reached the memcpy" is a
// sink-watch event, not an inference.
//
// Two ways to configure the slot below:
//   * `--template sink-watch` renders the default sink vocabulary
//     from RAPTOR's central function taxonomy (memory-copy, string-
//     overflow, format-string, and exec sinks).
//   * `--sink-watch <file>` renders a finding-specific list -
//     mechanically derived from a sinks JSON or a validation run's
//     attack-paths.json (packages.frida.sink_watch).
//
// Resolution order per sink: module-scoped export (when the spec
// names a module) → global export → DebugSymbol. The DebugSymbol
// fallback rescues project-internal sink wrappers when the target
// ships symbols. Unresolved sinks are reported in the _meta event -
// never dropped silently.

'use strict';

var MAX_EVENTS_PER_FN = 500;   // memcpy-class sinks are hot

function findGlobalExport(name) {
  if (typeof Module.findGlobalExportByName === 'function') {
    return Module.findGlobalExportByName(name);
  }
  if (typeof Module.findExportByName === 'function') {
    try { return Module.findExportByName(null, name); } catch (_e) { return null; }
  }
  return null;
}

function findModuleExport(moduleName, name) {
  try {
    var m = Process.findModuleByName(moduleName);
    if (m !== null && typeof m.findExportByName === 'function') {
      return m.findExportByName(name);
    }
  } catch (_e) {}
  if (typeof Module.findExportByName === 'function') {
    try { return Module.findExportByName(moduleName, name); } catch (_e) { return null; }
  }
  return null;
}

function resolveSink(spec) {
  var addr = null;
  if (spec.module) {
    addr = findModuleExport(spec.module, spec.fn);
    if (addr !== null && !addr.isNull()) return { addr: addr, via: 'module' };
  }
  addr = findGlobalExport(spec.fn);
  if (addr !== null && !addr.isNull()) {
    // A module-scoped spec resolved globally is watching a DIFFERENT
    // module's function - report that, never hide it.
    return { addr: addr, via: spec.module ? 'global-fallback' : 'global' };
  }
  try {
    var sym = DebugSymbol.fromName(spec.fn);
    if (sym !== null && sym.address && !sym.address.isNull()) {
      return { addr: sym.address, via: 'debug-symbol' };
    }
  } catch (_e) {}
  return null;
}

function safeStr(ptr, maxLen) {
  if (ptr === null || ptr.isNull()) return '<null>';
  var max = maxLen || 256;
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

function callsite(context, returnAddress) {
  let backtrace = [];
  let moduleInfo = {};
  try {
    backtrace = Thread.backtrace(context, Backtracer.ACCURATE)
      .slice(0, 12)
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

// Explicit argument readers for well-known sink shapes. Anything not
// listed gets the generic reader: raw pointer values of the first
// four arguments - honest, if less legible.
const sinkArgReaders = {
  'memcpy':   a => ({ dst: a[0].toString(), src: a[1].toString(), n: a[2].toInt32() }),
  'memmove':  a => ({ dst: a[0].toString(), src: a[1].toString(), n: a[2].toInt32() }),
  'strcpy':   a => ({ dst: a[0].toString(), src: safeStr(a[1]) }),
  'strcat':   a => ({ dst: a[0].toString(), src: safeStr(a[1]) }),
  'strncpy':  a => ({ dst: a[0].toString(), src: safeStr(a[1]), n: a[2].toInt32() }),
  'strncat':  a => ({ dst: a[0].toString(), src: safeStr(a[1]), n: a[2].toInt32() }),
  'sprintf':  a => ({ dst: a[0].toString(), format: safeStr(a[1]) }),
  'vsprintf': a => ({ dst: a[0].toString(), format: safeStr(a[1]) }),
  'snprintf': a => ({ dst: a[0].toString(), n: a[1].toInt32(), format: safeStr(a[2]) }),
  'gets':     a => ({ dst: a[0].toString() }),
  'system':   a => ({ command: safeStr(a[0]) }),
  'popen':    a => ({ command: safeStr(a[0]), mode: safeStr(a[1], 8) }),
  'execve':   a => ({ path: safeStr(a[0]) }),
};

function genericReader(a) {
  return {
    a0: a[0].toString(),
    a1: a[1].toString(),
    a2: a[2].toString(),
    a3: a[3].toString(),
  };
}

// Null-prototype maps: sink names come from attacker-influenced
// findings, and a name like 'constructor' or '__proto__' on a plain
// object would inherit Object.prototype members — silently defeating
// the per-fn cap and reader lookup.
const emitted = Object.create(null);
const attached = Object.create(null);   // addr → alias group (IFUNC aliases)
const hooked = [];
const unresolved = [];
const aliased = [];
const fallbacks = [];
const debugSymbols = [];

const sinkSpecs = /*__SINK_WATCH__*/ [];
sinkSpecs.forEach(function (spec) {
  const resolved = resolveSink(spec);
  if (resolved === null) {
    unresolved.push(spec.fn);
    return;
  }
  if (resolved.via === 'global-fallback') {
    fallbacks.push(spec.fn + '@' + spec.module + '→global');
  }
  if (resolved.via === 'debug-symbol') {
    // Debug-symbol addresses can be stale on rebuilt targets — the
    // operator must be able to tell them from export-resolved hooks.
    debugSymbols.push(spec.fn);
  }
  // glibc IFUNCs resolve aliases (memcpy/memmove) to one shared
  // implementation address. Attaching twice would fire both listeners
  // per call (double-counting), and dropping the later name would
  // silently strip evidence from the exact sink a finding names -
  // the hook cannot know which name the call site used. One attach
  // per address; every event carries the full alias group so
  // downstream evidence credits all names.
  const addrKey = resolved.addr.toString();
  const existing = attached[addrKey];
  if (existing) {
    // Self-alias (the same fn watched plain and module-scoped) must
    // not enter the alias group — evidence would double-count it.
    if (spec.fn !== existing.primary
        && existing.aliases.indexOf(spec.fn) < 0) {
      existing.aliases.push(spec.fn);
    }
    aliased.push(spec.fn + '=' + existing.primary);
    return;
  }
  const group = { primary: spec.fn, aliases: [] };
  attached[addrKey] = group;
  const reader = Object.prototype.hasOwnProperty.call(sinkArgReaders, spec.fn)
    ? sinkArgReaders[spec.fn]
    : genericReader;
  try {
    Interceptor.attach(resolved.addr, {
      onEnter: function (args) {
        // Emit on ENTER: exec-class sinks may not return, and the
        // pre-call argument state is the evidence of interest.
        emitted[group.primary] = (emitted[group.primary] || 0) + 1;
        if (emitted[group.primary] > MAX_EVENTS_PER_FN) {
          if (emitted[group.primary] === MAX_EVENTS_PER_FN + 1) {
            send({ _meta: 'sink-watch cap reached', fn: group.primary, cap: MAX_EVENTS_PER_FN });
          }
          return;
        }
        let captured;
        try {
          captured = reader(args);
        } catch (e) {
          captured = { _err: String(e) };
        }
        const record = Object.assign({
          category: 'sink',
          fn: group.primary,
          args: captured,
          tid: Process.getCurrentThreadId(),
        }, callsite(this.context, this.returnAddress));
        if (group.aliases.length > 0) record.aliases = group.aliases;
        if (spec.module) record.watched_module = spec.module;
        send(record);
      },
    });
  } catch (e) {
    // One bad address (stale DebugSymbol, unhookable thunk) must not
    // kill the remaining hooks - and must not vanish.
    delete attached[addrKey];
    unresolved.push(spec.fn);
    return;
  }
  hooked.push(spec.module ? spec.fn + '@' + spec.module : spec.fn);
});

send({ _meta: 'sink-watch loaded', hooks: hooked, unresolved: unresolved,
       aliased: aliased, fallbacks: fallbacks, debug_symbols: debugSymbols });
