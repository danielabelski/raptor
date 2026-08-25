// seed-harvest.js - dump ingested input buffers as fuzz-ready seeds.
//
// Hooks buffer-filling ingestion APIs (read/recv family, stream input,
// SSL_read) and emits the bytes the target actually received -
// hex-encoded, capped, deduplicated - so a run directory can be
// distilled into an AFL++ seed corpus. The CLI runs
// packages.frida.seeds.extract_seeds automatically after the session;
// point /fuzz at the resulting directory with --corpus.
//
// Capture happens in onLeave: the buffer contents are only valid after
// the call returns, and the return value is the byte count actually
// written into the buffer.
//
// The ingestion vocabulary is RENDERED from RAPTOR's central function
// taxonomy (NETWORK_INGEST_FUNCS | STREAM_INPUT_FUNCS) into the slot
// below at load time. Only names with an explicit buffer reader are
// hooked - buffer/length argument positions are per-function knowledge
// that lives here, not in the taxonomy. `read` and `fread` are added
// locally: the taxonomy excludes them as ubiquitous (zero fuzz-priority
// signal), but for seed harvesting the ubiquitous input path is exactly
// the point.

'use strict';

var MAX_CAPTURE_BYTES = 8192;   // per-event capture cap
var MAX_EVENTS_PER_FN = 2048;   // per-hook emission cap (post-dedup)

function findGlobalExport(name) {
  if (typeof Module.findGlobalExportByName === 'function') {
    return Module.findGlobalExportByName(name);
  }
  if (typeof Module.findExportByName === 'function') {
    try { return Module.findExportByName(null, name); } catch (_e) { return null; }
  }
  return null;
}

var HEX = '0123456789abcdef';
function toHex(u8) {
  var out = '';
  for (var i = 0; i < u8.length; i++) {
    out += HEX[u8[i] >> 4] + HEX[u8[i] & 15];
  }
  return out;
}

// FNV-1a over the captured bytes - in-script dedup only (a repeated
// identical read must not flood events.jsonl); the Python extractor
// re-deduplicates with sha256.
function fnv1a(u8) {
  var h = 0x811c9dc5;
  for (var i = 0; i < u8.length; i++) {
    h ^= u8[i];
    h = (h * 0x01000193) >>> 0;
  }
  return h.toString(16);
}

// Null-prototype maps for hygiene (keys here are not attacker-named,
// but the pattern must not invite prototype-key bugs), plus a bound
// on dedup-table growth: past MAX_DEDUP_KEYS new payloads are no
// longer remembered (duplicates may re-emit; the per-fn emission caps
// still bound total output).
var seen = Object.create(null);
var seenCount = 0;
var MAX_DEDUP_KEYS = 65536;
var emitted = Object.create(null);

function emitData(fn, meta, buf, len) {
  if (buf === null || buf.isNull() || len <= 0) return;
  var n = Math.min(len, MAX_CAPTURE_BYTES);
  var ab;
  try { ab = buf.readByteArray(n); } catch (_e) { return; }
  if (ab === null) return;
  var u8 = new Uint8Array(ab);
  var key = len + ':' + fnv1a(u8);
  if (seen[key]) return;
  if (seenCount < MAX_DEDUP_KEYS) {
    seen[key] = true;
    seenCount++;
  }
  emitted[fn] = (emitted[fn] || 0) + 1;
  if (emitted[fn] > MAX_EVENTS_PER_FN) {
    if (emitted[fn] === MAX_EVENTS_PER_FN + 1) {
      // Never truncate silently: one loud marker per hook.
      send({ _meta: 'seed-harvest cap reached', fn: fn, cap: MAX_EVENTS_PER_FN });
    }
    return;
  }
  send(Object.assign({
    category: 'ingest',
    fn: fn,
    args: Object.assign({ len: len, captured: n, data_hex: toHex(u8) }, meta),
    tid: Process.getCurrentThreadId(),
  }));
}

var hooks = [];
var aliased = [];
var attachedAddrs = Object.create(null);

function attach(name, callbacks) {
  var addr = findGlobalExport(name);
  if (addr === null) return;
  // Symbol aliases (e.g. getline/getdelim resolving to one address)
  // must not double-attach: both listeners would fire per call and
  // mis-attribute / double-process every buffer.
  var key = addr.toString();
  if (attachedAddrs[key]) {
    aliased.push(name + '=' + attachedAddrs[key]);
    return;
  }
  attachedAddrs[key] = name;
  try {
    Interceptor.attach(addr, callbacks);
  } catch (_e) {
    // One unhookable address must not kill the remaining hooks.
    delete attachedAddrs[key];
    return;
  }
  hooks.push(name);
}

// ret = byte count, buffer at bufIndex, optional fd at fdIndex.
function hookRetLen(name, bufIndex, fdIndex) {
  attach(name, {
    onEnter: function (args) {
      this.buf = args[bufIndex];
      this.meta = fdIndex === null ? {} : { fd: args[fdIndex].toInt32() };
    },
    onLeave: function (retval) {
      emitData(name, this.meta, this.buf, retval.toInt32());
    },
  });
}

// Per-function buffer readers for the taxonomy-rendered vocabulary.
var readers = {
  'recv':     function () { hookRetLen('recv', 1, 0); },
  'recvfrom': function () { hookRetLen('recvfrom', 1, 0); },
  'SSL_read': function () { hookRetLen('SSL_read', 1, null); },
  'BIO_read': function () { hookRetLen('BIO_read', 1, null); },
  'pread':    function () { hookRetLen('pread', 1, 0); },
  // fgets: ret is a pointer (buf or NULL); usable length is up to the
  // first NUL within the size argument captured on entry.
  'fgets': function () {
    attach('fgets', {
      onEnter: function (args) {
        this.buf = args[0];
        this.size = args[1].toInt32();
      },
      onLeave: function (retval) {
        if (retval.isNull() || this.size <= 0) return;
        var n = Math.min(this.size, MAX_CAPTURE_BYTES);
        var ab;
        try { ab = this.buf.readByteArray(n); } catch (_e) { return; }
        if (ab === null) return;
        var u8 = new Uint8Array(ab);
        var end = u8.indexOf(0);
        emitData('fgets', {}, this.buf, end < 0 ? n : end);
      },
    });
  },
  // getline/getdelim: buffer is *lineptr (may be realloc'd during the
  // call - deref AFTER return), ret is the character count.
  'getline':  function () { hookLinePtr('getline'); },
  'getdelim': function () { hookLinePtr('getdelim'); },
};

function hookLinePtr(name) {
  attach(name, {
    onEnter: function (args) { this.linep = args[0]; },
    onLeave: function (retval) {
      var n = retval.toInt32();
      if (n <= 0 || this.linep.isNull()) return;
      var buf;
      try { buf = this.linep.readPointer(); } catch (_e) { return; }
      emitData(name, {}, buf, n);
    },
  });
}

var ingestHookNames = /*__INGEST_HOOKS__*/ [];
ingestHookNames.forEach(function (name) {
  if (readers[name]) readers[name]();
});

// Ubiquitous input paths, deliberately outside the taxonomy vocabulary.
hookRetLen('read', 1, 0);
attach('fread', {
  onEnter: function (args) {
    this.buf = args[0];
    this.size = args[1].toInt32();
  },
  onLeave: function (retval) {
    var items = retval.toInt32();
    if (items > 0 && this.size > 0) {
      emitData('fread', {}, this.buf, items * this.size);
    }
  },
});

send({ _meta: 'seed-harvest loaded', hooks: hooks, aliased: aliased });
