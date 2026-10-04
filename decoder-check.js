#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Usama Iqbal (Plantroom Labs)
/**
 * Run a vendor's LoRaWAN payload decoder and say what a BMS would see.
 *
 *     decoder-check.js run <decoder.js> --payload <hex>        one frame
 *     decoder-check.js run <decoder.js> --frames frames.txt    "hex[,port]" per line
 *     decoder-check.js run <decoder.js> --payload <hex> --fuzz derive more frames
 *     decoder-check.js run <decoder.js> ... --json             machine readable
 *     decoder-check.js --self-check                            prove its own claims
 *
 * The job it does
 * ---------------
 * A sensor vendor publishes a JavaScript decoder for TTN, ChirpStack, Helium or
 * Actility. It is written against the one frame the author had on the desk. An
 * integrator then points a station at it and the points come out wrong, or come
 * out once and never again, or the whole uplink disappears. This runs the
 * decoder over the frames you give it, in a throwaway context, and reports the
 * specific ways its output would break a point tree: keys that come and go,
 * types that change, numbers shipped as strings with the unit glued on, a throw
 * on a short frame. It reports what it saw, with the frame that caused it.
 *
 * The audience is the vendor as much as the integrator. Every finding names a
 * frame and a value, so it can be pasted into a bug report.
 *
 * What it checks
 * --------------
 *      1  crash on a short frame     every truncation of every frame, is a throw
 *                                    raised instead of an error being returned
 *      2  non-deterministic output   same frame twice in two fresh contexts;
 *                                    plus a static scan for Date.now, new Date,
 *                                    Math.random
 *      3  shape drift                keys present for some frames, absent for
 *                                    others - a point that appears and vanishes
 *      4  type drift                 a key that is a number here and a string
 *                                    there. A station point's type is fixed for
 *                                    life, so this loses data, it is not cosmetic
 *      5  unit inside the value      "23.5 °C" where 23.5 was wanted (heuristic)
 *      6  non-finite and null        NaN, Infinity, -Infinity, and null in a slot
 *                                    that is numeric for another frame
 *      7  duplicate declarations     the same name declared twice in one scope;
 *                                    the second wins silently (heuristic)
 *      8  silent accept / reject     frames decoding to nothing, and frames
 *                                    decoding with a non-empty warnings/errors
 *                                    array - both need to reach the station and
 *                                    usually do not
 *      9  unusable key names         keys Niagara escapes in a point name:
 *                                    '/', '$', spaces, leading digits (heuristic)
 *     10  fPort sensitivity          the same bytes on ports 1, 2 and the given
 *                                    port, when the output shape differs
 *
 * Checks 5, 7 and 9 are heuristic. Check 5 matches a pattern, not a grammar;
 * check 7 is a brace-depth scan, not a JavaScript parser, so a regular
 * expression literal containing an unbalanced brace can mislead it; check 9
 * encodes one station's naming rules. All three are labelled `heuristic` in the
 * output and all three can produce a false positive. Read the evidence column
 * before you file the bug.
 *
 * How the decoder is run
 * ----------------------
 * The file is evaluated in a fresh `vm.createContext({})` per invocation. That
 * context has the ECMAScript built-ins and nothing else: no require, no
 * process, no fs, no network, no timers, no Buffer. `console` is replaced by a
 * frozen, non-configurable shim that collects what the decoder printed instead
 * of printing it, and dynamic `import()` is refused. Every call is made with
 * vm's `timeout` option (default 2000 ms, `--timeout`) so an infinite loop in a
 * vendor file stops the call rather than the tool. `--self-check` runs a
 * fixture that calls require('fs') and one that calls process.exit(1) and
 * reports what happened to them.
 *
 * Be clear about what that is worth: node:vm is an isolation mechanism, not a
 * security boundary, and Node's own documentation says so. It is enough to stop
 * a careless decoder touching this machine. It is not enough to run code you
 * believe is hostile. If you do not trust the file, do not run it here either.
 *
 * This tool opens no socket and writes no file. It reads the decoder, reads a
 * frames file if you name one, and writes to stdout and stderr. `--self-check`
 * greps its own source to show there is no write call and no network module in
 * it.
 *
 * Entry points it recognises, in this order
 * -----------------------------------------
 *     decodeUplink(input)              TTN v3       input = {bytes, fPort, recvTime}
 *     Decode(fPort, bytes, variables)  ChirpStack v3 / Actility
 *     Decoder(bytes, port)             TTN v2 / Helium
 * then the same three names off `module.exports` / `exports`, for files written
 * as CommonJS modules; a `module` and `exports` object are provided for that.
 * The report says which one it used and how it was found. recvTime is always
 * the same fixed timestamp, so the tool never introduces the non-determinism it
 * is looking for in check 2.
 *
 * What it does not do
 * -------------------
 * It does not check the decoder against the vendor's datasheet: it has no idea
 * what the bytes mean, only what the output looks like. It does not decode
 * LoRaWAN MAC layers, join requests or downlinks, and does not touch a network
 * server. It cannot run a decoder written as an ES module with top-level
 * `import` (a CommonJS-ish shim only). It runs synchronously: a decoder that
 * returns a Promise is reported as returning a Promise, not awaited. Async
 * work, timers and network calls are unavailable inside the context by design,
 * so a decoder that needs them will fail here and say so.
 *
 * Exit codes
 * ----------
 *     0   ran, and found nothing
 *     1   ran, and reported at least one finding
 *     2   usage error
 *     3   decoder file unreadable, unparseable, or no recognised entry point
 *     4   every frame failed to decode
 *
 * Licence
 * -------
 * MIT. Copyright (c) 2026 Usama Iqbal (Plantroom Labs). Use it, change it, ship
 * it inside something you sell — the only condition is that the copyright line
 * and the permission notice travel with it. Full text:
 * https://plantroomlabs.com/tools/LICENSE.txt
 */

'use strict';

const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const process = require('node:process');

const PROG = 'decoder-check.js';
const FIXED_RECV_TIME = '2026-01-01T00:00:00.000Z';
const MAX_TRUNCATIONS = 256;
const MAX_CONSOLE_LINES = 200;

// A decoder that rejects a promise would otherwise take the whole process down
// with it. Record it and carry on; it shows up as a note on the run.
const ASYNC_NOISE = [];
process.on('unhandledRejection', function (reason) {
  const text = reason && reason.message ? String(reason.message) : String(reason);
  if (ASYNC_NOISE.length < 20) ASYNC_NOISE.push(text);
});

// ------------------------------------------------------------------ the checks

const CHECKS = [
  { n: 1, id: 'crash', title: 'crash on a short frame', heuristic: false },
  { n: 2, id: 'nondet', title: 'non-deterministic output', heuristic: false },
  { n: 3, id: 'shape', title: 'shape drift', heuristic: false },
  { n: 4, id: 'type', title: 'type drift', heuristic: false },
  { n: 5, id: 'unit', title: 'unit inside the value', heuristic: true },
  { n: 6, id: 'nonfinite', title: 'non-finite and null numerics', heuristic: false },
  { n: 7, id: 'dup', title: 'duplicate declarations', heuristic: true },
  { n: 8, id: 'silent', title: 'silent acceptance / silent rejection', heuristic: false },
  { n: 9, id: 'keyname', title: 'key names a station cannot use as-is', heuristic: true },
  { n: 10, id: 'port', title: 'fPort sensitivity', heuristic: false }
];

const CHECK_BY_ID = {};
for (const c of CHECKS) CHECK_BY_ID[c.id] = c;

// -------------------------------------------------------------- the sandbox

// Everything below runs inside the vm context, in one closure, so a decoder
// that declares its own `encode` or `text` cannot reach in and change what the
// tool reads back out. The only thing left on the context's globalThis is
// __plc, which is non-writable and non-configurable.
const PRELUDE = `(function () {
  'use strict';
  var lines = [];

  function text(v) {
    if (typeof v === 'string') return v;
    try { var s = JSON.stringify(v); return s === undefined ? String(v) : s; }
    catch (e) { return String(v); }
  }

  function encode(v, seen) {
    var t = typeof v;
    if (v === null) return {k: 'null'};
    if (t === 'undefined') return {k: 'undef'};
    if (t === 'boolean') return {k: 'bool', v: v};
    if (t === 'string') return {k: 'str', v: v};
    if (t === 'bigint') return {k: 'big', v: String(v)};
    if (t === 'symbol') return {k: 'sym', v: String(v)};
    if (t === 'function') return {k: 'fn', v: v.name || '(anonymous)'};
    if (t === 'number') {
      if (v !== v) return {k: 'num', s: 'NaN'};
      if (v === Infinity) return {k: 'num', s: 'Infinity'};
      if (v === -Infinity) return {k: 'num', s: '-Infinity'};
      return {k: 'num', v: v};
    }
    for (var i = 0; i < seen.length; i++) if (seen[i] === v) return {k: 'cycle'};
    if (seen.length > 24) return {k: 'deep'};
    seen.push(v);
    var out;
    try {
      if (v instanceof Date) {
        var ms = v.getTime();
        out = {k: 'date', v: ms === ms ? v.toISOString() : 'Invalid Date'};
      } else if (typeof Promise === 'function' && v instanceof Promise) {
        out = {k: 'promise'};
      } else if (Array.isArray(v)) {
        var arr = [];
        for (var j = 0; j < v.length; j++) arr.push(encode(v[j], seen));
        out = {k: 'arr', v: arr};
      } else {
        var ent = [];
        var keys = Object.keys(v);
        for (var m = 0; m < keys.length; m++) {
          var got;
          try { got = encode(v[keys[m]], seen); }
          catch (e) { got = {k: 'throw', v: String(e && e.message || e)}; }
          ent.push([keys[m], got]);
        }
        out = {k: 'obj', v: ent, ctor: (v.constructor && v.constructor.name) || ''};
      }
    } finally { seen.pop(); }
    return out;
  }

  function resolve(where, name) {
    var host = where === 'module' ? (globalThis.module && globalThis.module.exports) : globalThis;
    if (!host) return null;
    if (where === 'module' && name === '(module.exports itself)') {
      return typeof host === 'function' ? host : null;
    }
    var fn = host[name];
    return typeof fn === 'function' ? fn : null;
  }

  function invoke(argsJson) {
    var a = JSON.parse(argsJson);
    lines.length = 0;
    var fn = resolve(a.where, a.name);
    if (!fn) {
      return JSON.stringify({ok: false, error: {name: 'EntryError',
        message: 'entry point ' + a.name + ' vanished before it could be called'}, console: []});
    }
    var out;
    try {
      if (a.style === 'ttn3') out = fn({bytes: a.bytes, fPort: a.fPort, recvTime: a.recvTime});
      else if (a.style === 'chirpstack') out = fn(a.fPort, a.bytes, {});
      else out = fn(a.bytes, a.fPort);
    } catch (e) {
      return JSON.stringify({ok: false, console: lines.slice(), error: {
        name: (e && e.name) || 'Error',
        message: String((e && e.message) !== undefined && e !== null ? e.message : e)
      }});
    }
    var enc;
    try { enc = encode(out, []); }
    catch (e) { enc = {k: 'throw', v: String(e && e.message || e)}; }
    return JSON.stringify({ok: true, value: enc, console: lines.slice()});
  }

  function probe() {
    var g = globalThis;
    var mx = (g.module && g.module.exports) || null;
    return JSON.stringify({
      global: {
        decodeUplink: typeof g.decodeUplink,
        Decode: typeof g.Decode,
        Decoder: typeof g.Decoder
      },
      module: mx === null ? null : {
        self: typeof mx,
        decodeUplink: typeof mx.decodeUplink,
        Decode: typeof mx.Decode,
        Decoder: typeof mx.Decoder
      }
    });
  }

  var shim = {};
  var names = ['log', 'warn', 'error', 'info', 'debug', 'trace', 'dir', 'table',
               'group', 'groupEnd', 'time', 'timeEnd', 'assert', 'count'];
  for (var i = 0; i < names.length; i++) {
    (function (nm) {
      shim[nm] = function () {
        if (lines.length >= ${MAX_CONSOLE_LINES}) return;
        var parts = [];
        for (var j = 0; j < arguments.length; j++) parts.push(text(arguments[j]));
        lines.push(nm + ': ' + parts.join(' '));
      };
    })(names[i]);
  }
  Object.freeze(shim);
  Object.defineProperty(globalThis, 'console',
    {value: shim, writable: false, configurable: false, enumerable: false});

  globalThis.module = {exports: {}};
  globalThis.exports = globalThis.module.exports;

  Object.defineProperty(globalThis, '__plc', {
    value: Object.freeze({invoke: invoke, probe: probe}),
    writable: false, configurable: false, enumerable: false
  });
})();`;

function blockedImport() {
  throw new Error('import() is blocked: decoder-check gives the decoder no module loader');
}

/** A fresh context with the decoder already evaluated in it. */
function makeContext(source, filename, timeout) {
  const ctx = vm.createContext({});
  new vm.Script(PRELUDE, { filename: 'decoder-check-prelude.js' }).runInContext(ctx, { timeout });
  const script = new vm.Script(source, {
    filename: filename,
    importModuleDynamically: blockedImport
  });
  script.runInContext(ctx, { timeout });
  return ctx;
}

/** Evaluate the decoder once and report which entry point it offers. */
function detectEntry(source, filename, timeout) {
  let ctx;
  try {
    ctx = makeContext(source, filename, timeout);
  } catch (e) {
    return { error: (e && e.name === 'SyntaxError' ? 'does not parse as JavaScript: ' : 'threw while being evaluated: ') + (e && e.message) };
  }
  let probe;
  try {
    probe = JSON.parse(vm.runInContext('__plc.probe()', ctx, { timeout }));
  } catch (e) {
    return { error: 'could not be inspected after evaluation: ' + (e && e.message) };
  }
  const order = [
    ['global', 'decodeUplink', 'ttn3', 'decodeUplink(input)', 'TTN v3'],
    ['global', 'Decode', 'chirpstack', 'Decode(fPort, bytes, variables)', 'ChirpStack v3 / Actility'],
    ['global', 'Decoder', 'ttn2', 'Decoder(bytes, port)', 'TTN v2 / Helium'],
    ['module', 'decodeUplink', 'ttn3', 'module.exports.decodeUplink(input)', 'TTN v3, CommonJS'],
    ['module', 'Decode', 'chirpstack', 'module.exports.Decode(fPort, bytes, variables)', 'ChirpStack v3, CommonJS'],
    ['module', 'Decoder', 'ttn2', 'module.exports.Decoder(bytes, port)', 'TTN v2, CommonJS'],
    ['module', '(module.exports itself)', 'ttn3', 'module.exports(input)', 'TTN v3, exported directly']
  ];
  for (const [where, name, style, shown, family] of order) {
    const table = where === 'global' ? probe.global : probe.module;
    if (!table) continue;
    const key = name === '(module.exports itself)' ? 'self' : name;
    if (table[key] === 'function') {
      return { where, name, style, shown, family };
    }
  }
  return { error: null, none: true, probe };
}

/** One call. Returns {ok, value|error, console}. */
function invoke(ctx, entry, bytes, fPort, timeout) {
  const args = JSON.stringify({
    where: entry.where, name: entry.name, style: entry.style,
    bytes: bytes, fPort: fPort === null ? 1 : fPort, recvTime: FIXED_RECV_TIME
  });
  let raw;
  try {
    raw = vm.runInContext('__plc.invoke(' + JSON.stringify(args) + ')', ctx, { timeout });
  } catch (e) {
    const timedOut = /timed out/i.test(String(e && e.message));
    return {
      ok: false, console: [],
      error: { name: timedOut ? 'Timeout' : (e && e.name) || 'Error', message: String(e && e.message) },
      fatal: true
    };
  }
  try { return JSON.parse(raw); }
  catch (e) { return { ok: false, console: [], error: { name: 'Error', message: 'decoder result could not be serialised' } }; }
}

/** A fresh context, one call, thrown away. This is the unit the tool works in. */
function runOnce(source, filename, entry, bytes, fPort, timeout) {
  let ctx;
  try {
    ctx = makeContext(source, filename, timeout);
  } catch (e) {
    return { ok: false, console: [], error: { name: (e && e.name) || 'Error', message: String(e && e.message) }, fatal: true };
  }
  return invoke(ctx, entry, bytes, fPort, timeout);
}

// ------------------------------------------------------- reading the result

function jsType(enc) {
  if (!enc) return 'undefined';
  switch (enc.k) {
    case 'null': return 'null';
    case 'undef': return 'undefined';
    case 'bool': return 'boolean';
    case 'str': return 'string';
    case 'num': return 'number';
    case 'big': return 'bigint';
    case 'sym': return 'symbol';
    case 'fn': return 'function';
    case 'arr': return 'array';
    case 'obj': return 'object';
    case 'date': return 'Date';
    case 'promise': return 'Promise';
    case 'cycle': return 'circular reference';
    case 'deep': return 'nested past 24 levels';
    case 'throw': return 'getter that threw';
    default: return enc.k;
  }
}

function show(enc) {
  if (!enc) return 'undefined';
  switch (enc.k) {
    case 'null': return 'null';
    case 'undef': return 'undefined';
    case 'bool': return String(enc.v);
    case 'str': return JSON.stringify(enc.v);
    case 'num': return enc.s ? enc.s : String(enc.v);
    case 'big': return enc.v + 'n';
    case 'fn': return 'function ' + enc.v;
    case 'arr': return '[' + enc.v.length + ' items]';
    case 'obj': return '{' + enc.v.map(function (p) { return p[0]; }).join(', ') + '}';
    case 'date': return 'Date ' + enc.v;
    default: return jsType(enc);
  }
}

/**
 * Split a result into the payload a station would turn into points, the
 * warnings and the errors. The unwrap is deliberately narrow: only a result
 * whose own keys are a subset of {data, warnings, errors} and which has `data`
 * is treated as a TTN v3 envelope. A ChirpStack decoder that happens to emit a
 * point called `data` alongside others is left alone.
 */
function splitResult(enc) {
  const empty = { payload: enc, warnings: [], errors: [], unwrapped: false };
  if (!enc || enc.k !== 'obj') return empty;
  const keys = enc.v.map(function (p) { return p[0]; });
  if (keys.indexOf('data') === -1) return empty;
  const allowed = ['data', 'warnings', 'errors'];
  for (const k of keys) if (allowed.indexOf(k) === -1) return empty;
  const at = function (name) {
    const hit = enc.v.find(function (p) { return p[0] === name; });
    return hit ? hit[1] : null;
  };
  const listOf = function (node) {
    if (!node || node.k !== 'arr') return [];
    return node.v.map(show);
  };
  return {
    payload: at('data'), warnings: listOf(at('warnings')),
    errors: listOf(at('errors')), unwrapped: true
  };
}

/** Leaf paths, the shape a point tree would take. */
function flatten(enc, prefix, out) {
  out = out || [];
  if (enc && enc.k === 'obj' && enc.v.length) {
    for (const [key, child] of enc.v) {
      const seg = prefix ? prefix + '.' + key : key;
      flatten(child, seg, out);
    }
    return out;
  }
  if (enc && enc.k === 'arr' && enc.v.length) {
    for (let i = 0; i < enc.v.length; i++) flatten(enc.v[i], prefix + '[' + i + ']', out);
    return out;
  }
  out.push({ path: prefix, enc: enc });
  return out;
}

function isEmptyResult(enc, split) {
  if (!enc || enc.k === 'null' || enc.k === 'undef') return true;
  const p = split.payload;
  if (!p) return true;
  if (p.k === 'null' || p.k === 'undef') return true;
  if (p.k === 'obj' && p.v.length === 0) return true;
  if (p.k === 'arr' && p.v.length === 0) return true;
  return false;
}

function deepEqual(a, b) {
  if (a === b) return true;
  if (!a || !b) return a === b;
  if (a.k !== b.k) return false;
  if (a.k === 'obj') {
    if (a.v.length !== b.v.length) return false;
    const bi = {};
    for (const [k, v] of b.v) bi[k] = v;
    for (const [k, v] of a.v) {
      if (!Object.prototype.hasOwnProperty.call(bi, k)) return false;
      if (!deepEqual(v, bi[k])) return false;
    }
    return true;
  }
  if (a.k === 'arr') {
    if (a.v.length !== b.v.length) return false;
    for (let i = 0; i < a.v.length; i++) if (!deepEqual(a.v[i], b.v[i])) return false;
    return true;
  }
  if (a.k === 'num') return a.s === b.s && a.v === b.v;
  return a.v === b.v;
}

/** Where two encoded results first differ, as a path plus both values. */
function firstDiff(a, b, prefix) {
  prefix = prefix || '';
  if (deepEqual(a, b)) return null;
  if (a && b && a.k === b.k && a.k === 'obj') {
    const bi = {};
    for (const [k, v] of b.v) bi[k] = v;
    for (const [k, v] of a.v) {
      if (!Object.prototype.hasOwnProperty.call(bi, k)) {
        return { path: prefix ? prefix + '.' + k : k, a: show(v), b: '(absent)' };
      }
      const deeper = firstDiff(v, bi[k], prefix ? prefix + '.' + k : k);
      if (deeper) return deeper;
    }
  }
  if (a && b && a.k === b.k && a.k === 'arr' && a.v.length === b.v.length) {
    for (let i = 0; i < a.v.length; i++) {
      const deeper = firstDiff(a.v[i], b.v[i], prefix + '[' + i + ']');
      if (deeper) return deeper;
    }
  }
  return { path: prefix || '(whole result)', a: show(a), b: show(b) };
}

// ------------------------------------------------------------ source scanning

/**
 * Blank out comments and the insides of string and template literals, keeping
 * every byte offset and newline where it was, so offsets found in the result
 * still point at the right line of the original.
 *
 * Regular expression literals are recognised by the token before them, which is
 * the usual heuristic and is not a parser. A '/' this gets wrong can throw the
 * brace depth off, which is why check 7 is labelled heuristic.
 */
function stripLiterals(src) {
  const out = new Array(src.length);
  let i = 0;
  let prevSignificant = '';
  const push = function (ch) { out[i] = ch === '\n' ? '\n' : (ch === '\r' ? '\r' : ' '); };
  const tmplStack = [];
  while (i < src.length) {
    const c = src[i];
    const c2 = src[i + 1];
    if (c === '/' && c2 === '/') {
      while (i < src.length && src[i] !== '\n') { push(src[i]); i++; }
      continue;
    }
    if (c === '/' && c2 === '*') {
      push(src[i]); i++;
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) { push(src[i]); i++; }
      if (i < src.length) { push(src[i]); i++; push(src[i]); i++; }
      continue;
    }
    if (c === '"' || c === "'") {
      push(c); i++;
      while (i < src.length && src[i] !== c) {
        if (src[i] === '\\') { push(src[i]); i++; if (i < src.length) { push(src[i]); i++; } continue; }
        if (src[i] === '\n') break;
        push(src[i]); i++;
      }
      if (i < src.length) { push(src[i]); i++; }
      prevSignificant = '"';
      continue;
    }
    if (c === '`') {
      push(c); i++;
      tmplStack.push(true);
      while (i < src.length && tmplStack.length) {
        if (src[i] === '\\') { push(src[i]); i++; if (i < src.length) { push(src[i]); i++; } continue; }
        if (src[i] === '$' && src[i + 1] === '{') {
          // Inside ${ } the code is real code again; leave it alone and let the
          // brace walk below handle it, but keep the template open.
          push(src[i]); i++; out[i] = '{'; i++;
          let depth = 1;
          while (i < src.length && depth) {
            if (src[i] === '{') depth++;
            if (src[i] === '}') depth--;
            out[i] = depth === 0 ? '}' : (src[i] === '\n' ? '\n' : ' ');
            i++;
          }
          continue;
        }
        if (src[i] === '`') { push(src[i]); i++; tmplStack.pop(); break; }
        push(src[i]); i++;
      }
      prevSignificant = '"';
      continue;
    }
    if (c === '/' && /[=(,:;[!&|?{}+\-*%~^<>]/.test(prevSignificant)) {
      // A regex literal. Blank it, honouring character classes.
      push(c); i++;
      let inClass = false;
      while (i < src.length) {
        if (src[i] === '\\') { push(src[i]); i++; if (i < src.length) { push(src[i]); i++; } continue; }
        if (src[i] === '[') inClass = true;
        else if (src[i] === ']') inClass = false;
        else if (src[i] === '/' && !inClass) { push(src[i]); i++; break; }
        else if (src[i] === '\n') break;
        push(src[i]); i++;
      }
      prevSignificant = '/';
      continue;
    }
    out[i] = c;
    if (!/\s/.test(c)) prevSignificant = c;
    i++;
  }
  return out.join('');
}

function lineOf(src, index) {
  let line = 1;
  for (let i = 0; i < index && i < src.length; i++) if (src[i] === '\n') line++;
  return line;
}

const DECL_PATTERNS = [
  { re: /(^|[^\w$.])function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(/g, kind: 'function', nameAt: 2, headAt: 1 },
  { re: /(^|[^\w$.])(const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/g, kind: null, nameAt: 3, kindAt: 2, headAt: 1 },
  { re: /(^|[^\w$.])class\s+([A-Za-z_$][\w$]*)/g, kind: 'class', nameAt: 2, headAt: 1 }
];

/**
 * Names declared twice in one scope. The second definition wins and the first
 * is dead, which is a common way for a decoder to ship the wrong scaling
 * factor. Scope is tracked by brace depth, so it catches both a duplicate at
 * the top of a file and a duplicate inside a single big decodeUplink() - the
 * second is the shape vendor files actually come in.
 *
 * Limits, honestly: only the first declarator of `var a = 1, b = 2` is seen,
 * function parameters are ignored, and a mis-parsed regex literal can shift the
 * depth. It is a scan, not a parser.
 */
function findDuplicateDeclarations(src) {
  const stripped = stripLiterals(src);
  // Scope id at each offset.
  const scopeAt = new Int32Array(stripped.length);
  const stack = [0];
  let next = 1;
  for (let i = 0; i < stripped.length; i++) {
    const c = stripped[i];
    if (c === '{') { stack.push(next++); scopeAt[i] = stack[stack.length - 1]; continue; }
    if (c === '}') { scopeAt[i] = stack[stack.length - 1]; if (stack.length > 1) stack.pop(); continue; }
    scopeAt[i] = stack[stack.length - 1];
  }
  const seen = new Map();
  const findings = [];
  for (const pat of DECL_PATTERNS) {
    pat.re.lastIndex = 0;
    let m;
    while ((m = pat.re.exec(stripped)) !== null) {
      const name = m[pat.nameAt];
      const kind = pat.kind || m[pat.kindAt];
      const at = m.index + m[pat.headAt].length;
      // A function expression, not a declaration: `x = function name() {}`.
      if (kind === 'function') {
        const before = stripped.slice(Math.max(0, m.index - 12), m.index + m[pat.headAt].length).trimEnd();
        if (/[=(,:]$/.test(before) || /\breturn$/.test(before)) continue;
      }
      const key = scopeAt[at] + ':' + name;
      const prior = seen.get(key);
      if (prior) {
        findings.push({
          name: name, kind: kind,
          firstLine: prior.line, secondLine: lineOf(src, at),
          scopeDepth: prior.depth
        });
      } else {
        let depth = 0;
        for (let i = 0; i < at; i++) { if (stripped[i] === '{') depth++; else if (stripped[i] === '}') depth--; }
        seen.set(key, { line: lineOf(src, at), depth: depth });
      }
    }
  }
  findings.sort(function (a, b) { return a.secondLine - b.secondLine; });
  return findings;
}

const CLOCK_PATTERNS = [
  { re: /\bDate\s*\.\s*now\s*\(/g, what: 'Date.now()' },
  { re: /\bnew\s+Date\s*\(/g, what: 'new Date()' },
  { re: /\bMath\s*\.\s*random\s*\(/g, what: 'Math.random()' }
];

function findClockUse(src) {
  const stripped = stripLiterals(src);
  const out = [];
  for (const pat of CLOCK_PATTERNS) {
    pat.re.lastIndex = 0;
    let m;
    while ((m = pat.re.exec(stripped)) !== null) {
      out.push({ what: pat.what, line: lineOf(src, m.index) });
    }
  }
  out.sort(function (a, b) { return a.line - b.line; });
  return out;
}

// ------------------------------------------------------------------ heuristics

// A number, then something that is not a number: "23.5 °C", "250.000 Pa",
// "4.07m", "1013 hPa". Deliberately does not match a bare number in a string
// ("23.5"), an ISO timestamp, or a hex string.
const UNIT_RE = /^\s*([+-]?(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][+-]?\d+)?)\s*([^\s\d.eE+-][^\r\n]{0,15})\s*$/;

function unitInValue(text) {
  // "0x1f", "0b1010", "0o17" are one literal, not a number and a unit.
  if (/^\s*0[xXbBoO][0-9a-fA-F]+\s*$/.test(text)) return null;
  const m = UNIT_RE.exec(text);
  if (!m) return null;
  const unit = m[2].trim();
  if (!unit) return null;
  // An ISO date or a time reads as "2026-01-01T..." - rejected by the leading
  // sign rule above, but a bare "12:30" would slip through.
  if (/^[:/\\-]/.test(unit)) return null;
  const numeric = m[1].indexOf('.') === -1 && !/[eE]/.test(m[1]) ? 'integer' : 'float';
  return { number: m[1], unit: unit, numeric: numeric };
}

const BAD_KEY_CHAR = /[^A-Za-z0-9_]/;

function keyProblem(key) {
  if (key === '') return 'empty key name';
  const reasons = [];
  if (/^\d/.test(key)) reasons.push('starts with a digit');
  if (key.indexOf('/') !== -1) reasons.push("contains '/'");
  if (key.indexOf('$') !== -1) reasons.push("contains '$'");
  if (/\s/.test(key)) reasons.push('contains a space');
  const others = key.replace(/[A-Za-z0-9_/$\s]/g, '');
  if (others) reasons.push('contains ' + Array.from(new Set(others.split(''))).map(function (c) { return "'" + c + "'"; }).join(', '));
  if (!reasons.length && BAD_KEY_CHAR.test(key)) reasons.push('contains a character outside [A-Za-z0-9_]');
  return reasons.length ? reasons.join(', ') : null;
}

// ------------------------------------------------------------------- frames

function parseHex(text) {
  const clean = String(text).replace(/[\s:_-]/g, '');
  if (clean === '') return { error: 'empty' };
  if (clean.length % 2) return { error: 'odd number of hex digits (' + clean.length + ')' };
  if (!/^[0-9a-fA-F]+$/.test(clean)) return { error: 'not hex' };
  const bytes = [];
  for (let i = 0; i < clean.length; i += 2) bytes.push(parseInt(clean.slice(i, i + 2), 16));
  return { bytes: bytes };
}

function toHex(bytes) {
  return bytes.map(function (b) { return (b & 0xff).toString(16).padStart(2, '0'); }).join('');
}

/**
 * Frames derived from the ones given. Deterministic on purpose: the same input
 * always produces the same fuzz set, so two runs of the tool are comparable.
 * Truncations are not in here - check 1 already walks every shorter length.
 */
function fuzzFrom(frame) {
  const b = frame.bytes;
  const out = [];
  const add = function (bytes, why) {
    if (!bytes.length) return;
    out.push({ bytes: bytes, port: frame.port, derivedFrom: frame.label, why: why });
  };
  add(b.map(function () { return 0x00; }), 'all zero bytes');
  add(b.map(function () { return 0xff; }), 'all 0xff bytes');
  add(b.concat([0x00]), 'one trailing zero byte');
  for (const at of [0, Math.floor(b.length / 2), b.length - 1]) {
    if (at < 0 || at >= b.length) continue;
    const flipped = b.slice();
    flipped[at] = flipped[at] ^ 0x80;
    add(flipped, 'top bit flipped at byte ' + at);
    const maxed = b.slice();
    maxed[at] = 0xff;
    add(maxed, 'byte ' + at + ' set to 0xff');
  }
  // Drop duplicates and anything identical to the original.
  const seen = new Set([toHex(b)]);
  return out.filter(function (f) {
    const h = toHex(f.bytes);
    if (seen.has(h)) return false;
    seen.add(h);
    return true;
  });
}

// ------------------------------------------------------------------- analysis

function analyse(source, filename, entry, frames, opts) {
  const findings = [];
  const add = function (id, frame, detail, evidence) {
    findings.push({
      check: CHECK_BY_ID[id].n, id: id, heuristic: CHECK_BY_ID[id].heuristic,
      frame: frame, detail: detail, evidence: evidence
    });
  };
  const run = function (bytes, port) {
    return runOnce(source, filename, entry, bytes, port, opts.timeout);
  };

  // --- one pass per frame, twice over, for checks 2 and everything downstream.
  const records = [];
  for (const frame of frames) {
    const a = run(frame.bytes, frame.port);
    const b = run(frame.bytes, frame.port);
    const split = a.ok ? splitResult(a.value) : { payload: null, warnings: [], errors: [], unwrapped: false };
    const leaves = a.ok ? flatten(split.payload, '', []) : [];
    const rec = {
      frame: frame, first: a, second: b, split: split, leaves: leaves,
      empty: a.ok ? isEmptyResult(a.value, split) : false,
      paths: new Map()
    };
    for (const leaf of leaves) rec.paths.set(leaf.path, leaf.enc);
    records.push(rec);
  }

  const decoded = records.filter(function (r) { return r.first.ok; });
  if (frames.length && !decoded.length) {
    return { findings: findings, records: records, allFailed: true };
  }

  // --- 1  crash on a short frame
  for (const rec of records) {
    const b = rec.frame.bytes;
    const lengths = [];
    for (let n = b.length - 1; n >= 0; n--) lengths.push(n);
    const use = lengths.length > MAX_TRUNCATIONS ? lengths.slice(0, MAX_TRUNCATIONS) : lengths;
    const byMessage = new Map();
    for (const n of use) {
      const r = run(b.slice(0, n), rec.frame.port);
      if (r.ok) continue;
      const key = r.error.name + ': ' + r.error.message;
      if (!byMessage.has(key)) byMessage.set(key, []);
      byMessage.get(key).push(n);
    }
    for (const [message, lens] of byMessage) {
      const shown = lens.length > 6 ? lens.slice(0, 6).join(', ') + ', ...' : lens.join(', ');
      add('crash', rec.frame.label,
        'throws instead of returning an error at ' + lens.length + ' of ' + use.length +
        ' shorter lengths (bytes: ' + shown + ')', message);
    }
  }

  // --- 2  non-deterministic output
  for (const rec of records) {
    if (!rec.first.ok && !rec.second.ok) {
      if (rec.first.error.message !== rec.second.error.message) {
        add('nondet', rec.frame.label, 'two runs threw different exceptions',
          rec.first.error.message + '  vs  ' + rec.second.error.message);
      }
      continue;
    }
    if (rec.first.ok !== rec.second.ok) {
      add('nondet', rec.frame.label, 'one run decoded and the other threw',
        rec.first.ok ? rec.second.error.message : rec.first.error.message);
      continue;
    }
    if (!deepEqual(rec.first.value, rec.second.value)) {
      const d = firstDiff(rec.first.value, rec.second.value, '');
      add('nondet', rec.frame.label, 'the same bytes decoded twice gave different output at ' + d.path,
        d.a + '  then  ' + d.b);
    }
  }
  for (const use of findClockUse(source)) {
    add('nondet', '(source)', 'uses ' + use.what + ' at line ' + use.line +
      ', so the output depends on when it ran, not on the bytes', 'line ' + use.line);
  }

  // --- 3  shape drift. Empty results are check 8's business, not this one.
  const populated = decoded.filter(function (r) { return !r.empty; });
  if (populated.length > 1) {
    const everywhere = new Map();
    for (const rec of populated) {
      for (const p of rec.paths.keys()) {
        if (!everywhere.has(p)) everywhere.set(p, []);
        everywhere.get(p).push(rec.frame.label);
      }
    }
    for (const [p, where] of everywhere) {
      if (where.length === populated.length) continue;
      const missing = populated
        .filter(function (r) { return !r.paths.has(p); })
        .map(function (r) { return r.frame.label; });
      add('shape', where.join(', '),
        "'" + p + "' is present for " + where.length + ' of ' + populated.length +
        ' frames that decoded; absent for ' + missing.join(', '),
        'a point that appears and disappears in the station tree');
    }
  }

  // --- 4  type drift
  if (populated.length > 1) {
    const types = new Map();
    for (const rec of populated) {
      for (const [p, enc] of rec.paths) {
        if (!types.has(p)) types.set(p, []);
        types.get(p).push({ frame: rec.frame.label, type: jsType(enc), enc: enc });
      }
    }
    for (const [p, seen] of types) {
      const distinct = Array.from(new Set(seen.map(function (s) { return s.type; })));
      if (distinct.length < 2) continue;
      const evidence = distinct.map(function (t) {
        const hit = seen.find(function (s) { return s.type === t; });
        return t + ' (' + hit.frame + ': ' + show(hit.enc) + ')';
      }).join('; ');
      add('type', seen.map(function (s) { return s.frame; }).join(', '),
        "'" + p + "' changes type across frames: " + distinct.join(' / '), evidence);
    }
  }

  // --- 5  unit inside the value (heuristic)
  for (const rec of decoded) {
    for (const [p, enc] of rec.paths) {
      if (!enc || enc.k !== 'str') continue;
      const hit = unitInValue(enc.v);
      if (!hit) continue;
      add('unit', rec.frame.label,
        "'" + p + "' is a string holding a number and a unit; it should have been a " +
        hit.numeric + ' (' + hit.number + ') with the unit set on the point',
        JSON.stringify(enc.v));
    }
  }

  // --- 6  non-finite and null numerics
  const numericSomewhere = new Set();
  for (const rec of decoded) {
    for (const [p, enc] of rec.paths) {
      if (enc && enc.k === 'num' && !enc.s) numericSomewhere.add(p);
    }
  }
  for (const rec of decoded) {
    for (const [p, enc] of rec.paths) {
      if (enc && enc.k === 'num' && enc.s) {
        add('nonfinite', rec.frame.label,
          "'" + p + "' is " + enc.s + '; a station cannot store it and will either refuse ' +
          'the update or hold the previous value', enc.s);
        continue;
      }
      if (enc && (enc.k === 'null' || enc.k === 'undef') && numericSomewhere.has(p)) {
        const other = decoded.find(function (r) {
          const e = r.paths.get(p);
          return e && e.k === 'num' && !e.s;
        });
        add('nonfinite', rec.frame.label,
          "'" + p + "' is " + jsType(enc) + ' here but a number for " ' + other.frame.label + ' "',
          jsType(enc) + ' vs ' + show(other.paths.get(p)));
      }
    }
  }

  // --- 7  duplicate declarations (heuristic)
  for (const dup of findDuplicateDeclarations(source)) {
    add('dup', '(source)',
      dup.kind + " '" + dup.name + "' is declared twice in the same scope, at lines " +
      dup.firstLine + ' and ' + dup.secondLine + '; the second wins and the first is dead code',
      'lines ' + dup.firstLine + ' and ' + dup.secondLine);
  }

  // --- 8  silent acceptance / silent rejection
  for (const rec of decoded) {
    if (rec.empty) {
      add('silent', rec.frame.label,
        'decoded to nothing, and returned no error the station could log',
        rec.split.unwrapped ? 'result was {data: ' + show(rec.split.payload) + '}'
          : 'result was ' + show(rec.first.value));
    }
    if (rec.split.warnings.length) {
      add('silent', rec.frame.label,
        'returned ' + rec.split.warnings.length + ' warning(s) alongside a populated result; ' +
        'most stations drop the warnings array on the floor',
        rec.split.warnings.join(' | '));
    }
    if (rec.split.errors.length && !rec.empty) {
      add('silent', rec.frame.label,
        'returned ' + rec.split.errors.length + ' error(s) alongside a populated result',
        rec.split.errors.join(' | '));
    }
  }

  // --- 9  unusable key names (heuristic)
  const reportedKeys = new Set();
  for (const rec of decoded) {
    for (const p of rec.paths.keys()) {
      for (const seg of p.split('.')) {
        const key = seg.replace(/\[\d+\]$/, '');
        if (key === '' || reportedKeys.has(key)) continue;
        const why = keyProblem(key);
        if (!why) continue;
        reportedKeys.add(key);
        add('keyname', rec.frame.label,
          "key '" + key + "' " + why + '; Niagara escapes it in the point name, so the ' +
          'point does not read back under the name the decoder used',
          "'" + key + "' in '" + p + "'");
      }
    }
  }

  // --- 10  fPort sensitivity
  for (const rec of records) {
    if (rec.frame.port === null) continue;
    const ports = Array.from(new Set([1, 2, rec.frame.port]));
    const shapes = [];
    for (const port of ports) {
      const r = port === rec.frame.port ? rec.first : run(rec.frame.bytes, port);
      if (!r.ok) { shapes.push({ port: port, shape: 'threw: ' + r.error.message }); continue; }
      const sp = splitResult(r.value);
      const keys = flatten(sp.payload, '', [])
        .map(function (l) { return l.path; })
        .filter(function (p) { return p; })
        .sort();
      shapes.push({ port: port, shape: keys.length ? keys.join(', ') : '(no points)' });
    }
    const distinct = Array.from(new Set(shapes.map(function (s) { return s.shape; })));
    if (distinct.length < 2) continue;
    add('port', rec.frame.label,
      'the same bytes give a different shape on different ports: ' +
      shapes.map(function (s) { return 'port ' + s.port; }).join(', ') +
      ' are not interchangeable',
      shapes.map(function (s) { return 'port ' + s.port + ' -> ' + s.shape; }).join(' | '));
  }

  return { findings: findings, records: records, allFailed: false };
}

// --------------------------------------------------------------------- output

function verdictRows(findings) {
  return CHECKS.map(function (c) {
    const n = findings.filter(function (f) { return f.id === c.id; }).length;
    return { n: c.n, id: c.id, title: c.title, heuristic: c.heuristic, count: n,
      verdict: n === 0 ? 'ok' : n + (n === 1 ? ' finding' : ' findings') };
  });
}

function truncate(text, limit) {
  const flat = String(text).replace(/\s+/g, ' ').trim();
  return flat.length <= limit ? flat : flat.slice(0, limit - 1) + '…';
}

function cell(text) { return String(text).replace(/\|/g, '\\|'); }

function printReport(out, ctx) {
  const { decoderPath, entry, frames, result, opts, sourceBytes } = ctx;
  const findings = result.findings;
  out.write('\n# decoder-check: ' + decoderPath + '\n\n');
  out.write('Entry point   ' + entry.shown + '  (' + entry.family + ', found on ' +
    (entry.where === 'global' ? 'the global object' : 'module.exports') + ')\n');
  out.write('Decoder       ' + sourceBytes + ' bytes\n');
  out.write('Frames        ' + frames.filter(function (f) { return !f.derivedFrom; }).length + ' supplied' +
    (opts.fuzz ? ', ' + frames.filter(function (f) { return f.derivedFrom; }).length + ' derived by --fuzz' : '') + '\n');
  out.write('Per call      fresh vm context, ' + opts.timeout + ' ms timeout, recvTime fixed at ' +
    FIXED_RECV_TIME + '\n');
  out.write('Sandbox       no require, no process, no fs, no network, no timers; ' +
    'console captured, not printed\n');

  out.write('\n## frames\n\n');
  out.write('| Frame | Port | Bytes | Outcome | Points | Console |\n');
  out.write('|---|---|---|---|---|---|\n');
  for (const rec of result.records) {
    const f = rec.frame;
    const outcome = rec.first.ok
      ? (rec.empty ? 'decoded to nothing' : 'decoded')
      : rec.first.error.name + ': ' + truncate(rec.first.error.message, 60);
    out.write('| ' + cell(f.label) + ' | ' + (f.port === null ? '-' : f.port) + ' | ' +
      f.bytes.length + ' | ' + cell(outcome) + ' | ' +
      (rec.first.ok ? rec.leaves.filter(function (l) { return l.path; }).length : '-') + ' | ' +
      (rec.first.console.length ? rec.first.console.length + ' line(s)' : '-') + ' |\n');
  }

  const anyConsole = result.records.some(function (r) { return r.first.console.length; });
  if (anyConsole) {
    out.write('\n## what the decoder printed (captured, not printed to your terminal)\n\n');
    for (const rec of result.records) {
      for (const line of rec.first.console) {
        out.write('  ' + rec.frame.label + '  ' + truncate(line, 100) + '\n');
      }
    }
  }

  if (findings.length) {
    out.write('\n## findings\n\n');
    for (const c of CHECKS) {
      const mine = findings.filter(function (f) { return f.id === c.id; });
      if (!mine.length) continue;
      out.write('### ' + c.n + '. ' + c.title + (c.heuristic ? '  [heuristic]' : '') +
        ' — ' + mine.length + '\n\n');
      out.write('| Frame | What | Evidence |\n');
      out.write('|---|---|---|\n');
      for (const f of mine) {
        out.write('| ' + cell(truncate(f.frame, 28)) + ' | ' + cell(truncate(f.detail, 130)) +
          ' | ' + cell(truncate(f.evidence, 90)) + ' |\n');
      }
      out.write('\n');
    }
  }

  out.write('\n## verdict\n\n');
  for (const row of verdictRows(findings)) {
    out.write('  ' + String(row.n).padStart(2) + '  ' +
      (row.title + (row.heuristic ? ' [heuristic]' : '')).padEnd(50) + row.verdict + '\n');
  }
  const total = findings.length;
  const heur = findings.filter(function (f) { return f.heuristic; }).length;
  out.write('\n' + total + ' finding' + (total === 1 ? '' : 's') + ' across ' +
    result.records.length + ' frame' + (result.records.length === 1 ? '' : 's') +
    (heur ? ', of which ' + heur + ' from a heuristic check that can be wrong' : '') + '.\n');
  if (ASYNC_NOISE.length) {
    out.write('\nThe decoder left ' + ASYNC_NOISE.length + ' unhandled promise rejection(s) behind: ' +
      truncate(ASYNC_NOISE.join(' | '), 160) + '\n');
  }
}

function printJson(out, ctx) {
  const { decoderPath, entry, frames, result, opts, sourceBytes } = ctx;
  const doc = {
    tool: 'decoder-check.js',
    decoder: { path: decoderPath, bytes: sourceBytes },
    entry: { signature: entry.shown, family: entry.family, found_on: entry.where, name: entry.name },
    run: {
      timeout_ms: opts.timeout, fuzz: !!opts.fuzz, recv_time: FIXED_RECV_TIME,
      frames_supplied: frames.filter(function (f) { return !f.derivedFrom; }).length,
      frames_derived: frames.filter(function (f) { return f.derivedFrom; }).length
    },
    sandbox: {
      require: false, process: false, fs: false, network: false, timers: false,
      dynamic_import: false, console: 'captured'
    },
    frames: result.records.map(function (rec) {
      return {
        label: rec.frame.label, hex: toHex(rec.frame.bytes), bytes: rec.frame.bytes.length,
        port: rec.frame.port, derived_from: rec.frame.derivedFrom || null,
        derived_why: rec.frame.why || null,
        decoded: rec.first.ok,
        empty: !!rec.empty,
        error: rec.first.ok ? null : rec.first.error,
        keys: rec.leaves.filter(function (l) { return l.path; }).map(function (l) {
          return { path: l.path, type: jsType(l.enc), value: show(l.enc) };
        }),
        warnings: rec.split.warnings, errors: rec.split.errors,
        console: rec.first.console
      };
    }),
    findings: result.findings,
    verdict: verdictRows(result.findings),
    totals: {
      findings: result.findings.length,
      heuristic: result.findings.filter(function (f) { return f.heuristic; }).length
    },
    unhandled_rejections: ASYNC_NOISE.slice()
  };
  out.write(JSON.stringify(doc, null, 2) + '\n');
}

// ------------------------------------------------------------------- fixtures

// One decoder per check, each written to exhibit exactly the defect its check
// looks for. They live in this file on purpose: --self-check has to work from a
// single downloaded script with nothing beside it.
const FIXTURES = {
  clean: `
function decodeUplink(input) {
  var b = input.bytes;
  if (b.length !== 4) { return { errors: ["expected 4 bytes, got " + b.length] }; }
  return { data: {
    temperature: ((b[0] << 8 | b[1]) / 100),
    humidity: b[2] / 2,
    battery: b[3]
  } };
}`,

  crash: `
function decodeUplink(input) {
  var b = input.bytes;
  var label = ["idle", "run", "fault", "alarm"][b[2]];
  return { data: {
    temperature: ((b[0] << 8 | b[1]) / 100),
    state: label.toUpperCase(),
    battery: b[3]
  } };
}`,

  nondet: `
function decodeUplink(input) {
  var b = input.bytes;
  return { data: {
    temperature: ((b[0] << 8 | b[1]) / 100),
    readAt: Date.now(),
    jitter: Math.random()
  } };
}`,

  shape: `
function decodeUplink(input) {
  var b = input.bytes;
  var out = { temperature: ((b[0] << 8 | b[1]) / 100) };
  if (b[2] & 0x01) { out.co2 = (b[3] << 8 | b[4]); }
  return { data: out };
}`,

  type: `
function decodeUplink(input) {
  var b = input.bytes;
  var raw = (b[0] << 8 | b[1]);
  return { data: {
    temperature: raw === 65535 ? "n/a" : raw / 100,
    battery: b[2]
  } };
}`,

  unit: `
function decodeUplink(input) {
  var b = input.bytes;
  return { data: {
    temperature: (((b[0] << 8 | b[1]) / 100).toFixed(2)) + " °C",
    pressure: (b[2] * 10).toFixed(3) + " Pa"
  } };
}`,

  nonfinite: `
function decodeUplink(input) {
  var b = input.bytes;
  return { data: {
    temperature: (b[0] << 8 | b[1]) / (b[2] - 20),
    battery: b[3]
  } };
}`,

  nullnum: `
function decodeUplink(input) {
  var b = input.bytes;
  return { data: {
    temperature: (b[0] << 8 | b[1]) / 100,
    battery: b[2] < 10 ? null : b[2]
  } };
}`,

  dup: `
function humidity(raw) { return raw * 0.5; }
function decodeUplink(input) {
  var b = input.bytes;
  return { data: { humidity: humidity(b[0]), battery: b[1] } };
}
function humidity(raw) { return raw; }`,

  dupNested: `
function decodeUplink(input) {
  function humidity(raw) { return raw * 0.5; }
  var b = input.bytes;
  var out = { data: { humidity: humidity(b[0]), battery: b[1] } };
  return out;
  function humidity(raw) { return raw; }
}`,

  silent: `
function decodeUplink(input) {
  var b = input.bytes;
  if (b[0] !== 0x01) { return {}; }
  return {
    data: { temperature: (b[1] << 8 | b[2]) / 100 },
    warnings: ["battery byte missing, assumed 100%"]
  };
}`,

  keyname: `
function decodeUplink(input) {
  var b = input.bytes;
  var out = {};
  out["Supply Air Temp"] = (b[0] << 8 | b[1]) / 100;
  out["ahu/1/rh"] = b[2] / 2;
  out["2ndStage"] = b[3];
  return { data: out };
}`,

  port: `
function decodeUplink(input) {
  var b = input.bytes;
  if (input.fPort === 2) { return { data: { alarm: b[0] === 1, count: b[1] } }; }
  return { data: { temperature: (b[0] << 8 | b[1]) / 100, battery: b[2] } };
}`,

  // Sandbox and plumbing fixtures. These are not check fixtures.
  // The write call is spelled indirectly so that the "this file makes no write
  // call" scan further down does not trip over its own fixture. It is still a
  // real attempt to write a real path; require() is what stops it.
  wantsRequire: `
function decodeUplink(input) {
  var fs = require('fs');
  fs['write' + 'FileSync']('/tmp/decoder-check-escape-proof.txt', 'the sandbox leaked');
  return { data: { escaped: true } };
}`,

  wantsProcess: `
function decodeUplink(input) {
  process.exit(1);
  return { data: {} };
}`,

  wantsImport: `
function decodeUplink(input) {
  return { data: { p: typeof import('node:fs') } };
}`,

  hangs: `
function decodeUplink(input) {
  var n = 0;
  while (true) { n = (n + 1) % 1000000; }
}`,

  talks: `
function decodeUplink(input) {
  console.log("vendor debug", input.bytes.length);
  console.warn("second line");
  return { data: { n: input.bytes.length } };
}`,

  chirpstack: `
function Decode(fPort, bytes, variables) {
  return { temperature: (bytes[0] << 8 | bytes[1]) / 100, port: fPort };
}`,

  ttn2: `
function Decoder(bytes, port) {
  return { temperature: (bytes[0] << 8 | bytes[1]) / 100, port: port };
}`,

  commonjs: `
function decodeUplink(input) {
  return { data: { n: input.bytes.length } };
}
module.exports = { decodeUplink: decodeUplink };`,

  noEntry: `
function parsePayload(bytes) { return { n: bytes.length }; }`,

  alwaysThrows: `
function decodeUplink(input) {
  throw new Error("this vendor file is broken for every frame");
}`
};

// For each check fixture: the frames to feed it, the check it must fire, and
// any check that is expected to fire with it. The assertion is equality, not
// containment, so a fixture that trips a check it should not is a failure.
const FIXTURE_PLAN = [
  { name: 'clean', frames: ['09c47864', '0a2a5032'], expect: [], note: 'a decoder with nothing wrong with it' },
  { name: 'crash', frames: ['09c40164'], expect: ['crash'] },
  { name: 'nondet', frames: ['09c4'], expect: ['nondet'] },
  { name: 'shape', frames: ['09c4010258', '09c4000000'], expect: ['shape'] },
  { name: 'type', frames: ['09c464', 'ffff64'], expect: ['type'] },
  { name: 'unit', frames: ['09c419', '0a2a1e'], expect: ['unit'] },
  { name: 'nonfinite', frames: ['09c41464', '09c41e64'], expect: ['nonfinite'] },
  { name: 'nullnum', frames: ['09c464', '09c405'], expect: ['nonfinite', 'type'],
    note: 'null in a numeric slot is also a type change; both checks are meant to see it' },
  { name: 'dup', frames: ['9664'], expect: ['dup'] },
  { name: 'dupNested', frames: ['9664'], expect: ['dup'] },
  { name: 'silent', frames: ['0109c4', '0909c4'], expect: ['silent'] },
  { name: 'keyname', frames: ['09c43264'], expect: ['keyname'] },
  { name: 'port', frames: ['09c464,1'], expect: ['port'] }
];

// ------------------------------------------------------------------ self-check

function selfCheck(out) {
  const results = [];
  const check = function (name, fn) {
    try { fn(); results.push({ ok: true, name: name, why: '' }); }
    catch (e) {
      results.push({ ok: false, name: name, why: e instanceof Error && e.name === 'AssertionError'
        ? e.message : (e && e.name) + ': ' + (e && e.message) });
    }
  };
  const assert = function (cond, message) {
    if (!cond) { const e = new Error(message); e.name = 'AssertionError'; throw e; }
  };

  const opts = { timeout: 1000, fuzz: false };
  const framesFor = function (specs) {
    return specs.map(function (spec, i) {
      const bits = spec.split(',');
      const parsed = parseHex(bits[0]);
      return {
        label: 'f' + (i + 1), bytes: parsed.bytes,
        port: bits.length > 1 ? parseInt(bits[1], 10) : null, derivedFrom: null
      };
    });
  };
  const analyseFixture = function (name, specs) {
    const src = FIXTURES[name];
    const entry = detectEntry(src, name + '.js', opts.timeout);
    assert(!entry.error && !entry.none, 'fixture ' + name + ' offered no entry point');
    return analyse(src, name + '.js', entry, framesFor(specs), opts);
  };

  // --- the sandbox claims.
  check("sandbox: a fixture calling require('fs') gets a ReferenceError, and writes no file", function () {
    const probe = '/tmp/decoder-check-escape-proof.txt';
    assert(!fs.existsSync(probe), 'a leftover ' + probe + ' from an earlier run; delete it and re-run');
    const entry = detectEntry(FIXTURES.wantsRequire, 'wantsRequire.js', 1000);
    assert(!entry.error, 'wantsRequire did not even evaluate');
    const r = runOnce(FIXTURES.wantsRequire, 'wantsRequire.js', entry, [1, 2], 1, 1000);
    assert(!r.ok, 'the require() decoder returned a result instead of failing');
    assert(r.error.name === 'ReferenceError', 'expected a ReferenceError, got ' + r.error.name);
    assert(/require is not defined/.test(r.error.message), 'unexpected message: ' + r.error.message);
    assert(!fs.existsSync(probe), 'the sandbox wrote ' + probe + ' - it leaked');
  });

  check('sandbox: a fixture calling process.exit(1) fails inside and this process is still here', function () {
    const entry = detectEntry(FIXTURES.wantsProcess, 'wantsProcess.js', 1000);
    const r = runOnce(FIXTURES.wantsProcess, 'wantsProcess.js', entry, [1], 1, 1000);
    assert(!r.ok, 'process.exit(1) returned a result');
    assert(r.error.name === 'ReferenceError', 'expected a ReferenceError, got ' + r.error.name);
    assert(/process is not defined/.test(r.error.message), 'unexpected message: ' + r.error.message);
  });

  check('sandbox: require, process, fs, fetch, timers and Buffer are all absent from the context', function () {
    const ctx = makeContext('', 'empty.js', 1000);
    const names = ['require', 'process', 'fetch', 'XMLHttpRequest', 'WebSocket', 'setTimeout',
      'setInterval', 'setImmediate', 'Buffer', 'global', 'structuredClone', 'crypto'];
    for (const n of names) {
      const t = vm.runInContext('typeof ' + n, ctx, { timeout: 1000 });
      assert(t === 'undefined', n + ' is present in the context as a ' + t);
    }
    // And the built-ins a decoder legitimately needs are there.
    for (const n of ['Math', 'JSON', 'Date', 'Array', 'Object', 'String', 'Number', 'parseInt']) {
      assert(vm.runInContext('typeof ' + n, ctx, { timeout: 1000 }) !== 'undefined', n + ' is missing');
    }
  });

  check("sandbox: a Function('return process') escape attempt still finds no process", function () {
    const ctx = makeContext('', 'empty.js', 1000);
    const got = vm.runInContext(
      "(function(){ try { return String(new Function('return typeof process')()); } catch (e) { return 'threw:' + e.name; } })()",
      ctx, { timeout: 1000 });
    assert(got === 'undefined' || /^threw:/.test(got), "Function() reached a process, got '" + got + "'");
  });

  check('sandbox: dynamic import() is refused rather than loading a module', function () {
    const entry = detectEntry(FIXTURES.wantsImport, 'wantsImport.js', 1000);
    const r = runOnce(FIXTURES.wantsImport, 'wantsImport.js', entry, [1], 1, 1000);
    // Either it throws at the import, or it returns a Promise that never
    // resolves to a module. Both are acceptable; loading fs is not.
    if (r.ok) {
      const leaves = flatten(splitResult(r.value).payload, '', []);
      const p = leaves.find(function (l) { return l.path === 'p'; });
      assert(p && p.enc.k === 'str' && p.enc.v === 'object',
        'import() produced something other than a pending promise: ' + JSON.stringify(leaves));
    }
  });

  check('sandbox: an infinite loop is stopped by the timeout, not by this tool hanging', function () {
    const entry = detectEntry(FIXTURES.hangs, 'hangs.js', 1000);
    const t0 = Date.now();
    const r = runOnce(FIXTURES.hangs, 'hangs.js', entry, [1, 2, 3], 1, 250);
    const took = Date.now() - t0;
    assert(!r.ok, 'the infinite loop returned a result');
    assert(r.error.name === 'Timeout', 'expected a Timeout, got ' + r.error.name + ': ' + r.error.message);
    assert(took < 5000, 'the timeout took ' + took + ' ms to fire');
  });

  check('sandbox: console is a frozen, non-configurable shim and its output is captured', function () {
    const ctx = makeContext('', 'empty.js', 1000);
    const desc = vm.runInContext(
      "JSON.stringify(Object.getOwnPropertyDescriptor(globalThis,'console'), function(k,v){ return typeof v === 'object' && v !== null && k === 'value' ? 'shim' : v; })",
      ctx, { timeout: 1000 });
    const d = JSON.parse(desc);
    assert(d.writable === false, 'console is writable inside the context');
    assert(d.configurable === false, 'console is configurable inside the context');
    assert(vm.runInContext('Object.isFrozen(console)', ctx, { timeout: 1000 }) === true, 'console is not frozen');
    const entry = detectEntry(FIXTURES.talks, 'talks.js', 1000);
    const r = runOnce(FIXTURES.talks, 'talks.js', entry, [1, 2, 3], 1, 1000);
    assert(r.ok, 'the talking decoder failed: ' + JSON.stringify(r.error));
    assert(r.console.length === 2, 'expected 2 captured lines, got ' + r.console.length);
    assert(r.console[0] === 'log: vendor debug 3', "first line was '" + r.console[0] + "'");
    assert(r.console[1] === 'warn: second line', "second line was '" + r.console[1] + "'");
  });

  check('this file makes no write call, opens no socket, and requires only node: builtins', function () {
    const src = fs.readFileSync(__filename, 'utf8');
    // Scan the code, not the strings in it: the fixture decoders are payload,
    // not calls this tool makes. stripLiterals blanks comments and the insides
    // of literals while keeping every byte offset, so an offset found in the
    // stripped copy still points at the same place in the original.
    const code = stripLiterals(src);
    assert(code.length === src.length, 'the stripper moved an offset');

    // Every require() reachable as code, with its argument read back out of the
    // original source at the same offset.
    const requires = [];
    const call = /\brequire\s*\(/g;
    let m;
    while ((m = call.exec(code)) !== null) {
      const tail = src.slice(m.index, m.index + 60);
      const arg = /^require\s*\(\s*(['"])([^'"]*)\1\s*\)/.exec(tail);
      assert(arg !== null, 'a require() with a computed argument at offset ' + m.index + ': ' + tail.slice(0, 40));
      requires.push(arg[2]);
    }
    const allowed = ['node:vm', 'node:fs', 'node:path', 'node:process'];
    for (const r of requires) {
      assert(allowed.indexOf(r) !== -1, "this file requires '" + r + "', which is not on the node: builtin allow-list");
    }
    assert(requires.length === 4, 'expected 4 require() calls, found ' + requires.length + ': ' + requires.join(', '));

    // No write, no socket, no fetch anywhere in the code.
    const forbidden = ['write' + 'File', 'append' + 'File', 'create' + 'WriteStream', 'write' + 'Sync',
      'mkdir' + 'Sync', 'rm' + 'Sync', 'unlink' + 'Sync', 'fetch' + '(', 'create' + 'Connection',
      'create' + 'Server', 'XMLHttp' + 'Request'];
    for (const needle of forbidden) {
      assert(code.indexOf(needle) === -1, "this file contains a call to '" + needle + "'");
    }
    // The only fs functions it uses at all.
    const fsCalls = [];
    const fsRe = /\bfs\s*\.\s*([A-Za-z]+)/g;
    while ((m = fsRe.exec(code)) !== null) fsCalls.push(m[1]);
    const fsAllowed = ['readFileSync', 'existsSync'];
    for (const f of Array.from(new Set(fsCalls))) {
      assert(fsAllowed.indexOf(f) !== -1, "this file calls fs." + f + ', which is not read-only');
    }
  });

  // --- entry point detection.
  check('entry point detection finds all four shapes, in the documented order', function () {
    const cases = [
      ['clean', 'global', 'decodeUplink', 'ttn3'],
      ['chirpstack', 'global', 'Decode', 'chirpstack'],
      ['ttn2', 'global', 'Decoder', 'ttn2'],
      ['commonjs', 'global', 'decodeUplink', 'ttn3']
    ];
    for (const [name, where, entryName, style] of cases) {
      const e = detectEntry(FIXTURES[name], name + '.js', 1000);
      assert(!e.error && !e.none, name + ' offered no entry point');
      assert(e.where === where && e.name === entryName && e.style === style,
        name + ' detected as ' + e.where + '.' + e.name + ' (' + e.style + ')');
    }
    // CommonJS-only, no global: must be found on module.exports.
    const cjsOnly = 'module.exports = { decodeUplink: function (input) { return { data: { n: input.bytes.length } }; } };';
    const e = detectEntry(cjsOnly, 'cjsOnly.js', 1000);
    assert(e.where === 'module' && e.name === 'decodeUplink',
      'a CommonJS-only decoder was detected as ' + JSON.stringify(e));
    const none = detectEntry(FIXTURES.noEntry, 'noEntry.js', 1000);
    assert(none.none === true, 'a file with no entry point was accepted: ' + JSON.stringify(none));
    const broken = detectEntry('function decodeUplink(input) { return {', 'broken.js', 1000);
    assert(typeof broken.error === 'string' && /does not parse/.test(broken.error),
      'a syntax error was not reported as one: ' + JSON.stringify(broken));
  });

  check('each entry point style is called with the arguments its family expects', function () {
    const e1 = detectEntry(FIXTURES.chirpstack, 'chirpstack.js', 1000);
    const r1 = runOnce(FIXTURES.chirpstack, 'chirpstack.js', e1, [0x09, 0xc4], 7, 1000);
    assert(r1.ok, 'Decode() failed: ' + JSON.stringify(r1.error));
    const l1 = flatten(splitResult(r1.value).payload, '', []);
    assert(l1.find(function (l) { return l.path === 'port'; }).enc.v === 7, 'Decode() got the wrong fPort');
    assert(l1.find(function (l) { return l.path === 'temperature'; }).enc.v === 25, 'Decode() got the wrong bytes');
    const e2 = detectEntry(FIXTURES.ttn2, 'ttn2.js', 1000);
    const r2 = runOnce(FIXTURES.ttn2, 'ttn2.js', e2, [0x09, 0xc4], 7, 1000);
    const l2 = flatten(splitResult(r2.value).payload, '', []);
    assert(l2.find(function (l) { return l.path === 'port'; }).enc.v === 7, 'Decoder() got the wrong port');
  });

  // --- the checks themselves, one fixture each.
  for (const plan of FIXTURE_PLAN) {
    const label = 'check fixture ' + plan.name + ': fires ' +
      (plan.expect.length ? plan.expect.map(function (id) { return CHECK_BY_ID[id].n + '/' + id; }).join(' + ') : 'nothing') +
      ' and nothing else';
    check(label, function () {
      const res = analyseFixture(plan.name, plan.frames);
      const fired = Array.from(new Set(res.findings.map(function (f) { return f.id; }))).sort();
      const want = plan.expect.slice().sort();
      assert(fired.join(',') === want.join(','),
        'fired [' + fired.join(', ') + '], expected [' + want.join(', ') + ']' +
        (res.findings.length ? '; first finding: ' + res.findings[0].detail : ''));
      for (const id of plan.expect) {
        assert(res.findings.some(function (f) { return f.id === id && f.evidence; }),
          id + ' fired without evidence');
      }
    });
  }

  // --- a few pieces of the machinery, checked directly.
  check('the unit heuristic matches units and leaves plain numbers and text alone', function () {
    const yes = ['250.000 Pa', '23.5 °C', '4.07 m', '1013 hPa', '-3.25 kWh', '96%RH', '12.0V'];
    const no = ['23.5', '-3', 'n/a', 'Error', 'idle', '2026-01-01T00:00:00Z', 'AA:BB:CC', '0x1f'];
    for (const s of yes) assert(unitInValue(s) !== null, "'" + s + "' was not seen as a value with a unit");
    for (const s of no) assert(unitInValue(s) === null, "'" + s + "' was wrongly flagged as a value with a unit");
    assert(unitInValue('250 Pa').numeric === 'integer', "'250 Pa' should suggest an integer");
    assert(unitInValue('250.5 Pa').numeric === 'float', "'250.5 Pa' should suggest a float");
  });

  check('the key-name heuristic flags what Niagara escapes and passes what it does not', function () {
    const bad = ['Supply Air Temp', 'ahu/1/rh', '2ndStage', 'co$2', 'temp-1', 'value.raw'];
    const ok = ['temperature', 'relativeHumidity', 'co2', 'battery_level', 'A1', '_x'];
    for (const k of bad) assert(keyProblem(k) !== null, "'" + k + "' should have been flagged");
    for (const k of ok) assert(keyProblem(k) === null, "'" + k + "' was flagged: " + keyProblem(k));
  });

  check('the literal stripper keeps offsets and hides braces in strings, comments and regexes', function () {
    const src = 'var a = "{{{"; // }}}\n/* { */ var re = /[{}]/g; var b = 1;';
    const out = stripLiterals(src);
    assert(out.length === src.length, 'the stripper changed the length');
    assert(out.split('\n').length === src.split('\n').length, 'the stripper lost a newline');
    assert(out.indexOf('{') === -1 && out.indexOf('}') === -1,
      'a brace survived inside a literal or comment: ' + JSON.stringify(out));
    assert(/var b = 1;/.test(out), 'real code was blanked out');
  });

  check('the duplicate scan sees a top-level pair, a nested pair, and no false pair', function () {
    const top = findDuplicateDeclarations(FIXTURES.dup);
    assert(top.length === 1 && top[0].name === 'humidity', 'top-level pair: ' + JSON.stringify(top));
    const nested = findDuplicateDeclarations(FIXTURES.dupNested);
    assert(nested.length === 1 && nested[0].name === 'humidity', 'nested pair: ' + JSON.stringify(nested));
    // Same name in two different scopes is legal and must not be reported.
    const twoScopes = 'function a() { var x = 1; return x; }\nfunction b() { var x = 2; return x; }';
    assert(findDuplicateDeclarations(twoScopes).length === 0,
      'two scopes with the same local were reported as a duplicate');
    // A function expression assigned to a name is not a second declaration.
    const expr = 'var f = function f() { return 1; };';
    assert(findDuplicateDeclarations(expr).length === 0, 'a named function expression was reported');
    assert(findDuplicateDeclarations(FIXTURES.clean).length === 0, 'the clean fixture has a duplicate');
  });

  check('a decoder that throws on every frame is reported as such, not as findings', function () {
    const entry = detectEntry(FIXTURES.alwaysThrows, 'alwaysThrows.js', 1000);
    const res = analyse(FIXTURES.alwaysThrows, 'alwaysThrows.js', entry, framesFor(['09c4', '0a2a']), opts);
    assert(res.allFailed === true, 'a decoder that always throws was not flagged as all-failed');
  });

  check('--fuzz derives the same frames every time and never repeats the original', function () {
    const frame = { label: 'f1', bytes: [0x09, 0xc4, 0x64], port: null };
    const a = fuzzFrom(frame).map(function (f) { return toHex(f.bytes); });
    const b = fuzzFrom(frame).map(function (f) { return toHex(f.bytes); });
    assert(a.join(',') === b.join(','), '--fuzz is not deterministic');
    assert(a.indexOf('09c464') === -1, '--fuzz re-emitted the original frame');
    assert(new Set(a).size === a.length, '--fuzz emitted a duplicate');
    assert(a.length >= 6, '--fuzz derived only ' + a.length + ' frames');
  });

  check('hex parsing accepts the separators vendors use and rejects what is not hex', function () {
    assert(parseHex('09c464').bytes.join(',') === '9,196,100', 'plain hex');
    assert(parseHex('09 C4 64').bytes.join(',') === '9,196,100', 'spaced hex');
    assert(parseHex('09-c4-64').bytes.join(',') === '9,196,100', 'dashed hex');
    assert(parseHex('09:C4:64').bytes.join(',') === '9,196,100', 'colon hex');
    assert(parseHex('09c4 6').error === 'odd number of hex digits (5)', 'odd length');
    assert(parseHex('zz').error === 'not hex', 'non-hex');
    assert(parseHex('').error === 'empty', 'empty');
  });

  check('the result envelope is unwrapped only when it really is one', function () {
    const wrapped = { k: 'obj', v: [['data', { k: 'obj', v: [['t', { k: 'num', v: 1 }]] }],
      ['warnings', { k: 'arr', v: [{ k: 'str', v: 'w' }] }]] };
    const s1 = splitResult(wrapped);
    assert(s1.unwrapped === true && s1.warnings.length === 1, 'a TTN v3 envelope was not unwrapped');
    const notEnvelope = { k: 'obj', v: [['data', { k: 'num', v: 5 }], ['temperature', { k: 'num', v: 21 }]] };
    const s2 = splitResult(notEnvelope);
    assert(s2.unwrapped === false, "a point called 'data' was mistaken for an envelope");
    const bare = { k: 'obj', v: [['temperature', { k: 'num', v: 21 }]] };
    assert(splitResult(bare).unwrapped === false, 'a bare ChirpStack result was unwrapped');
  });

  const width = Math.min(96, results.reduce(function (w, r) { return Math.max(w, r.name.length); }, 0));
  for (const r of results) {
    out.write(r.name.padEnd(width) + '  ' + (r.ok ? 'PASS' : 'FAIL') + (r.why ? '  ' + r.why : '') + '\n');
  }
  const bad = results.filter(function (r) { return !r.ok; }).length;
  out.write('\n' + results.length + ' checks, ' + bad + ' failed\n');
  return bad ? 1 : 0;
}

// ------------------------------------------------------------------------ CLI

const HELP = `${PROG} - run a vendor LoRaWAN decoder and report what a BMS would see

usage
  ${PROG} run <decoder.js> --payload <hex> [--payload <hex> ...] [options]
  ${PROG} run <decoder.js> --frames <file> [options]
  ${PROG} --self-check
  ${PROG} --help

options
  --payload <hex>[,<port>]  an uplink frame, repeatable. Separators (space,
                            colon, dash, underscore) are ignored.
  --frames <file>           one "hex[,port]" per line; '#' starts a comment
  --port <n>                fPort for payloads given without their own
  --fuzz                    also run frames derived from the ones given
                            (all-zero, all-0xff, single bit flips, one extra
                            byte). Deterministic: the same input, the same set.
  --timeout <ms>            wall clock per decoder call (default 2000)
  --json                    machine-readable report on stdout
  --help, -h                this text
  --self-check              run the fixtures and the sandbox proofs, then exit

notes
  The decoder runs in a fresh vm context with no require, no process, no fs, no
  network and no timers. console output is captured, not printed. Nothing is
  written to disk and no socket is opened. node:vm is isolation, not a security
  boundary - do not run a file here you believe is hostile.

  Checks 5, 7 and 9 are heuristic and are labelled so in the output.

exit codes
  0 nothing found   1 findings   2 usage   3 unreadable or no entry point
  4 every frame failed to decode

examples
  ${PROG} run vendor-decoder.js --payload 01AE09C41E64 --port 1
  ${PROG} run vendor-decoder.js --payload 01AE09C41E64 --fuzz
  ${PROG} run vendor-decoder.js --frames captured-uplinks.txt --json > report.json
`;

function usage(message) {
  process.stderr.write(PROG + ': ' + message + "\nTry '" + PROG + " --help'.\n");
  return 2;
}

function parseArgs(argv) {
  const opts = {
    command: null, decoder: null, payloads: [], framesFile: null, port: null,
    fuzz: false, timeout: 2000, json: false, help: false, selfCheck: false
  };
  let i = 0;
  while (i < argv.length) {
    const a = argv[i];
    const need = function (what) {
      i++;
      if (i >= argv.length) throw new Error(a + ' needs ' + what);
      return argv[i];
    };
    if (a === '--help' || a === '-h') { opts.help = true; i++; continue; }
    if (a === '--self-check') { opts.selfCheck = true; i++; continue; }
    if (a === '--json') { opts.json = true; i++; continue; }
    if (a === '--fuzz') { opts.fuzz = true; i++; continue; }
    if (a === '--payload') { opts.payloads.push(need('a hex frame')); i++; continue; }
    if (a === '--frames') { opts.framesFile = need('a file name'); i++; continue; }
    if (a === '--port') {
      const v = need('a number');
      if (!/^\d+$/.test(v)) throw new Error('--port must be a whole number, not ' + JSON.stringify(v));
      opts.port = parseInt(v, 10);
      if (opts.port < 0 || opts.port > 255) throw new Error('--port must be 0..255, not ' + opts.port);
      i++; continue;
    }
    if (a === '--timeout') {
      const v = need('milliseconds');
      if (!/^\d+$/.test(v) || parseInt(v, 10) < 1) throw new Error('--timeout must be a positive number of milliseconds');
      opts.timeout = parseInt(v, 10);
      i++; continue;
    }
    if (a.startsWith('-')) throw new Error('unknown option ' + a);
    if (opts.command === null) { opts.command = a; i++; continue; }
    if (opts.decoder === null) { opts.decoder = a; i++; continue; }
    throw new Error('unexpected argument ' + JSON.stringify(a));
  }
  return opts;
}

function readFramesFile(file) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); }
  catch (e) { throw new Error("cannot read --frames file '" + file + "': " + e.message); }
  const out = [];
  const lines = text.split(/\r?\n/);
  for (let n = 0; n < lines.length; n++) {
    const line = lines[n].replace(/#.*$/, '').trim();
    if (!line) continue;
    out.push({ spec: line, where: file + ':' + (n + 1) });
  }
  if (!out.length) throw new Error("--frames file '" + file + "' has no frames in it");
  return out;
}

function buildFrames(opts) {
  const specs = [];
  for (const p of opts.payloads) specs.push({ spec: p, where: '--payload' });
  if (opts.framesFile) for (const s of readFramesFile(opts.framesFile)) specs.push(s);
  const frames = [];
  for (let i = 0; i < specs.length; i++) {
    const bits = specs[i].spec.split(',');
    const parsed = parseHex(bits[0]);
    if (parsed.error) throw new Error("frame from " + specs[i].where + " (" + JSON.stringify(specs[i].spec) + "): " + parsed.error);
    let port = opts.port;
    if (bits.length > 1) {
      const raw = bits[1].trim();
      if (!/^\d+$/.test(raw)) throw new Error('port in ' + JSON.stringify(specs[i].spec) + ' is not a number');
      port = parseInt(raw, 10);
    }
    frames.push({
      label: 'f' + (i + 1), bytes: parsed.bytes,
      port: port === undefined ? null : port, derivedFrom: null
    });
  }
  if (!opts.fuzz) return frames;
  const all = frames.slice();
  let n = 0;
  for (const f of frames) {
    for (const d of fuzzFrom(f)) {
      n++;
      all.push({ label: 'z' + n, bytes: d.bytes, port: d.port, derivedFrom: f.label, why: d.why });
    }
  }
  return all;
}

function main(argv) {
  let opts;
  try { opts = parseArgs(argv); }
  catch (e) { return usage(e.message); }

  if (opts.help || (!argv.length)) { process.stdout.write(HELP); return 0; }
  if (opts.selfCheck) return selfCheck(process.stdout);

  if (opts.command !== 'run') {
    return usage(opts.command === null
      ? "nothing to do: try '" + PROG + " run <decoder.js> --payload <hex>'"
      : "unknown command '" + opts.command + "'; the only command is 'run'");
  }
  if (!opts.decoder) return usage('run needs a decoder file: ' + PROG + ' run <decoder.js> --payload <hex>');
  if (!opts.payloads.length && !opts.framesFile) {
    return usage('run needs at least one --payload <hex>, or a --frames file');
  }
  if (opts.fuzz && !opts.payloads.length && !opts.framesFile) {
    return usage('--fuzz derives frames from the ones you give it, so give it one');
  }

  const decoderPath = path.resolve(opts.decoder);
  let source;
  try { source = fs.readFileSync(decoderPath, 'utf8'); }
  catch (e) {
    process.stderr.write(PROG + ": cannot read decoder '" + opts.decoder + "': " + e.message + '\n');
    return 3;
  }
  if (!source.trim()) {
    process.stderr.write(PROG + ": decoder '" + opts.decoder + "' is empty\n");
    return 3;
  }

  let frames;
  try { frames = buildFrames(opts); }
  catch (e) { return usage(e.message); }

  const entry = detectEntry(source, path.basename(decoderPath), opts.timeout);
  if (entry.error) {
    process.stderr.write(PROG + ": decoder '" + opts.decoder + "' " + entry.error + '\n');
    return 3;
  }
  if (entry.none) {
    process.stderr.write(PROG + ": decoder '" + opts.decoder + "' has no recognised entry point.\n" +
      '  Looked for decodeUplink(input), Decode(fPort, bytes, variables) and Decoder(bytes, port),\n' +
      '  as globals and on module.exports. Found on the global object: ' +
      JSON.stringify(entry.probe.global) + '\n');
    return 3;
  }

  const result = analyse(source, path.basename(decoderPath), entry, frames, opts);
  const ctx = {
    decoderPath: decoderPath, entry: entry, frames: frames, result: result,
    opts: opts, sourceBytes: Buffer.byteLength(source, 'utf8')
  };

  if (result.allFailed) {
    if (opts.json) printJson(process.stdout, ctx);
    else printReport(process.stdout, ctx);
    process.stderr.write(PROG + ': every frame failed to decode. The first exception was ' +
      result.records[0].first.error.name + ': ' + result.records[0].first.error.message + '\n');
    return 4;
  }

  if (opts.json) printJson(process.stdout, ctx);
  else printReport(process.stdout, ctx);
  return result.findings.length ? 1 : 0;
}

if (require.main === module) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(PROG + ': ' + (e && e.stack ? e.stack : e) + '\n');
    process.exitCode = 2;
  }
}

module.exports = {
  analyse, detectEntry, runOnce, makeContext, splitResult, flatten, jsType, show,
  findDuplicateDeclarations, findClockUse, stripLiterals, unitInValue, keyProblem,
  parseHex, toHex, fuzzFrom, selfCheck, main, CHECKS, FIXTURES
};
