# decoder-check

Run a vendor's LoRaWAN payload decoder and say what a building management system would see.

One JavaScript file, Node 18 or newer, nothing from npm.

```
decoder-check.js run <decoder.js> --payload <hex>        one frame
decoder-check.js run <decoder.js> --frames frames.txt    "hex[,port]" per line
decoder-check.js run <decoder.js> --payload <hex> --fuzz derive more frames
decoder-check.js run <decoder.js> ... --json             machine readable
decoder-check.js --self-check                            prove its own claims
```

A sensor vendor publishes a JavaScript decoder for The Things Network, ChirpStack, Helium or
Actility. It is written against the one frame the author had on the desk. An integrator then
points a station at it and the points come out wrong, or come out once and never again, or
the whole uplink disappears. This runs the decoder over the frames you give it, in a
throwaway context, and reports the specific ways its output would break a point tree: keys
that come and go, types that change, numbers shipped as strings with the unit glued on, a
throw on a short frame. Every finding names the frame and the value that caused it, so it can
be pasted into a bug report — the audience is the vendor as much as the integrator.

## What it has actually been run against

Unlike its two siblings, this one has been pointed at the real thing: published decoders that
device vendors ship for The Things Network and ChirpStack. It found real defects in them.
Those went to the maintainers privately, with a patch, which is why no vendor is named here.

What it has never done is talk to a network server. It reads frames you give it, and nothing
else.

## Install

No install. One file, no `package.json`, no `node_modules`, nothing to add to a lock file at
a client who audits them. Written and run on Node 20, which is the only version it has been
executed on; the 18 floor comes from the features it uses rather than from running it there.

```sh
curl -O https://raw.githubusercontent.com/UsamaIqbal0304/decoder-check/main/decoder-check.js
```

## Use

```sh
# one frame, on the fPort the device actually uses
node decoder-check.js run vendor-decoder.js --payload 0FA064641103E80A2800 --port 1

# a file of frames you captured off the network server
node decoder-check.js run vendor-decoder.js --frames uplinks.txt

# also try the frames the device will send you on a bad day
node decoder-check.js run vendor-decoder.js --payload 0FA064641103E80A2800 --fuzz

# for a script, or to keep the result next to the commissioning record
node decoder-check.js run vendor-decoder.js --frames uplinks.txt --json > report.json
```

## What it checks

| # | check | why it matters |
| --- | --- | --- |
| 1 | crash on a short frame | every truncation of every frame: is a throw raised instead of an error returned |
| 2 | non-deterministic output | same frame twice in two fresh contexts, plus a static scan for `Date.now`, `new Date`, `Math.random` |
| 3 | shape drift | keys present for some frames and absent for others — a point that appears and vanishes |
| 4 | type drift | a key that is a number here and a string there. A station point's type is fixed for life, so this loses data; it is not cosmetic |
| 5 | unit inside the value | `"23.5 °C"` where `23.5` was wanted (heuristic) |
| 6 | non-finite and null | `NaN`, `Infinity`, `-Infinity`, and `null` in a slot that is numeric for another frame |
| 7 | duplicate declarations | the same name declared twice in one scope; the second wins silently (heuristic) |
| 8 | silent accept / reject | frames decoding to nothing, and frames decoding with a non-empty `warnings`/`errors` array — both need to reach the station and usually do not |
| 9 | unusable key names | keys a station escapes in a point name: `/`, `$`, spaces, leading digits (heuristic) |
| 10 | fPort sensitivity | the same bytes on ports 1, 2 and the given port, where the output shape differs |

Checks 5, 7 and 9 are heuristic and can produce a false positive: check 5 matches a pattern
rather than a grammar, check 7 is a brace-depth scan rather than a JavaScript parser, and
check 9 encodes one station's naming rules. All three are labelled `heuristic` in the output.
Read the evidence column before filing the bug.

## How the decoder is run, and what that is worth

The file is evaluated in a fresh `vm.createContext({})` per invocation. That context has the
ECMAScript built-ins and nothing else: no `require`, no `process`, no `fs`, no network, no
timers, no `Buffer`. `console` is replaced by a frozen, non-configurable shim that collects
what the decoder printed instead of printing it, and dynamic `import()` is refused. Every
call is made with vm's `timeout` option (default 2000 ms, `--timeout`) so an infinite loop in
a vendor file stops the call rather than the tool.

**Be clear about what that is worth.** `node:vm` is an isolation mechanism, not a security
boundary, and Node's own documentation says so. It is enough to stop a careless decoder
touching your machine. It is not enough to run code you believe is hostile. If you do not
trust the file, do not run it here either.

The tool itself opens no socket and writes no file: it reads the decoder, reads a frames file
if you name one, and writes to stdout and stderr.

## Entry points it recognises

In this order:

```
decodeUplink(input)              TTN v3        input = {bytes, fPort, recvTime}
Decode(fPort, bytes, variables)  ChirpStack v3 / Actility
Decoder(bytes, port)             TTN v2 / Helium
```

then the same three names off `module.exports` / `exports`, for files written as CommonJS
modules. The report says which one it used and how it was found. `recvTime` is always the
same fixed timestamp, so the tool never introduces the non-determinism it is looking for in
check 2.

Two kinds of decoder it cannot run, both stated in `--help`. One written as an ES module
with a top-level `import` will not load — the sandbox is a CommonJS-ish shim, and `import()`
inside it is blocked deliberately. And it runs synchronously: a decoder that returns a
Promise is reported as *returning a Promise*, not awaited, so its result is never checked.
Timers and network calls are unavailable inside the context by design, so a decoder that
needs them fails here and says which one it asked for. In all three cases the report names
what happened rather than silently passing the frame.

## Tests

```sh
node decoder-check.js --self-check
```

```
31 checks, 0 failed
```

That is not a smoke test: it runs a fixture decoder that calls `require('fs')` and one that
calls `process.exit(1)` and reports what happened to them, and it greps its own source to
show there is no write call and no network module in it. The claims on this page are the ones
it checks.

## Licence

MIT. See [LICENSE](LICENSE). Use it, fork it, ship it inside something you sell; no
attribution needed beyond the licence text.

## More

The [tool's page](https://plantroomlabs.com/tools/decoder-check/) has real output from a
sample decoder and the full blind-spot list. Its three siblings are
[bacnet-sweep](https://github.com/UsamaIqbal0304/bacnet-sweep),
[mqtt-tap](https://github.com/UsamaIqbal0304/mqtt-tap) and
[obix-mcp](https://github.com/UsamaIqbal0304/obix-mcp).

Written by [Plantroom Labs](https://plantroomlabs.com) — Niagara Framework engineering:
modules and drivers, bajaux widgets, PX graphics, station and controller work. Issues and
pull requests are read.
