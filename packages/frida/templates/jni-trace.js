// jni-trace.js - map the Java↔native boundary via RegisterNatives.
//
// Hooks art::JNI::RegisterNatives in ART (libart.so) and emits one
// event per registered native method: Java class + method name +
// JNI signature + the native implementation's module and offset.
// This is the bridge between jadx-level Java analysis and native-code
// analysis: the emitted module/offset pairs tell you exactly which
// native function backs which Java-declared native method - a mapping
// nothing in the static import tables provides.
//
// Scope: ART targets (Android; USB or remote frida-server sessions).
// On a non-ART process the template loads, reports the miss in a
// _meta event, and hooks nothing. Class names resolve through the
// Java bridge when it is available; otherwise the raw jclass handle
// is reported so registrations are still attributable per-batch.

'use strict';

var MAX_METHODS_PER_BATCH = 512;    // bound a corrupt count argument
var MAX_METHOD_EVENTS = 4096;       // global bound: a hostile app looping
                                    // RegisterNatives must not flood
                                    // events.jsonl
var methodEvents = 0;

// EVERY send goes through the global budget - including the per-batch
// cap markers, or a loop of oversized batches would emit one marker
// per call forever. One loud marker at the budget boundary, then
// silence.
function sendBudgeted(obj) {
  methodEvents++;
  if (methodEvents > MAX_METHOD_EVENTS) {
    if (methodEvents === MAX_METHOD_EVENTS + 1) {
      send({ _meta: 'jni-trace event cap reached', cap: MAX_METHOD_EVENTS });
    }
    return false;
  }
  send(obj);
  return true;
}

function pointerSize() { return Process.pointerSize; }

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

function moduleInfo(addr) {
  try {
    var m = Process.findModuleByAddress(addr);
    if (m !== null) {
      return { module: m.name, module_offset: addr.sub(m.base).toString() };
    }
  } catch (_e) {}
  return {};
}

function className(clazzHandle) {
  // Java bridge (frida-java-bridge) resolution; degrade to the raw
  // handle when the bridge or a usable JNIEnv is unavailable.
  try {
    if (typeof Java !== 'undefined' && Java.available) {
      var env = Java.vm.tryGetEnv();
      if (env !== null) {
        return env.getClassName(clazzHandle);
      }
    }
  } catch (_e) {}
  return '<jclass ' + clazzHandle.toString() + '>';
}

function findRegisterNatives() {
  // Android 11+ ART instantiates art::JNI<kEnableIndexIds> twice;
  // which instantiation is live depends on runtime flags, so hook
  // EVERY match (deduplicated by address) rather than the first.
  var found = [];
  var seenAddr = Object.create(null);
  var candidates = ['libart.so', 'libartd.so'];
  for (var i = 0; i < candidates.length; i++) {
    var mod = Process.findModuleByName(candidates[i]);
    if (mod === null) continue;
    var symbols;
    try {
      symbols = mod.enumerateSymbols();
    } catch (_e) {
      continue;
    }
    for (var j = 0; j < symbols.length; j++) {
      var sym = symbols[j];
      // art::JNI::RegisterNatives - skip the CheckJNI twin, which
      // delegates to the real one (hooking both double-counts).
      if (sym.name.indexOf('RegisterNatives') >= 0 &&
          sym.name.indexOf('CheckJNI') < 0 &&
          sym.address && !sym.address.isNull() &&
          !seenAddr[sym.address.toString()]) {
        seenAddr[sym.address.toString()] = true;
        found.push({ module: candidates[i], symbol: sym.name, address: sym.address });
      }
    }
  }
  return found;
}

var targets = findRegisterNatives();
if (targets.length === 0) {
  send({ _meta: 'jni-trace: libart RegisterNatives not found - not an ART/Android process?' });
}
var hookedSymbols = [];
targets.forEach(function (target) {
  try {
    Interceptor.attach(target.address, hookCallbacks());
  } catch (_e) {
    // One unhookable instantiation must not kill the others.
    return;
  }
  hookedSymbols.push(target.symbol);
});

function hookCallbacks() {
  return {
    onEnter: function (args) {
      // Budget exhausted: skip ALL work (className() does a JNI
      // round-trip - a post-cap flood must not keep paying it).
      if (methodEvents > MAX_METHOD_EVENTS) return;
      // JNI signature: RegisterNatives(env, jclass, JNINativeMethod*, count)
      var clazz = className(args[1]);
      var methods = args[2];
      var count = args[3].toInt32();
      var bounded = Math.min(count, MAX_METHODS_PER_BATCH);
      if (count > MAX_METHODS_PER_BATCH) {
        if (!sendBudgeted({ _meta: 'jni-trace method-count cap reached',
                            class: clazz, count: count,
                            cap: MAX_METHODS_PER_BATCH })) {
          return;
        }
      }
      for (var i = 0; i < bounded; i++) {
        try {
          // JNINativeMethod: { const char* name; const char* signature; void* fnPtr; }
          var entry = methods.add(i * 3 * pointerSize());
          var namePtr = entry.readPointer();
          var sigPtr = entry.add(pointerSize()).readPointer();
          var fnPtr = entry.add(2 * pointerSize()).readPointer();
          var ok = sendBudgeted(Object.assign({
            category: 'jni',
            fn: 'RegisterNatives',
            args: Object.assign({
              class: clazz,
              method: safeStr(namePtr, 256),
              signature: safeStr(sigPtr, 256),
              address: fnPtr.toString(),
            }, moduleInfo(fnPtr)),
            tid: Process.getCurrentThreadId(),
          }));
          if (!ok) return;
        } catch (e) {
          sendBudgeted({ _meta: 'jni-trace method read failed', class: clazz,
                         index: i, error: String(e) });
          break;
        }
      }
    },
  };
}

if (hookedSymbols.length > 0) {
  send({
    _meta: 'jni-trace loaded',
    hooked: hookedSymbols,
    module: targets[0].module,
  });
} else if (targets.length > 0) {
  send({ _meta: 'jni-trace: RegisterNatives found but every attach failed' });
}
