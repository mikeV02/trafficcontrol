# inhomeproxy

A clone of Apache Traffic Server's stock `authproxy` plugin, built as
its own `inhomeproxy.so` instead of overwriting `authproxy.so`. Based
on the revision with `--fail-open` and `--uri-pattern` added (before
the redirect-handling / config-override work) — chosen deliberately to
keep deviation from upstream authproxy small, per your call to stay
close to mainline.

## Why a separate `.so` instead of patching `authproxy.so` in place

- You can keep an unmodified, stock `authproxy.so` installed and
  usable elsewhere (or as a rollback target) without this fork
  overwriting it.
- Distinct plugin identity everywhere it matters: `TSPluginRegister`'s
  `plugin_name`, the `TSDebug`/`TSError` tag, and the `TSUserArgIndexReserve`
  label are all `inhomeproxy`/`InHomeProxy`, not `authproxy`/`AuthProxy`
  — so logs, debug filtering, and any plugin introspection clearly show
  which one is running, even if both happen to be loaded on the same
  box.
- `remap.config` references it explicitly as `@plugin=inhomeproxy.so`,
  so there's no ambiguity about which binary a given remap rule loads.

## What was *not* renamed, and why

Internal C++ identifiers — `AuthOptions`, `AuthRequestContext`, every
`State*` function, the `Auth*` helper macros, etc. — are **left exactly
as upstream has them**. None of that is externally visible (they're
all `static`/file-local, so there's zero symbol-collision risk even
with a real `authproxy.so` loaded in the same `traffic_server`
process), and keeping them unchanged is what makes the diff below
small and meaningful. If ATS ships a new `authproxy.cc` upstream later
and you want to pull in changes, `diff`/`patch` against
`inhomeproxy.patch` stays straightforward — a full internal rename
would obscure exactly what you'd be diffing against.

## Files

```
inhomeproxy.cc      The plugin (renamed clone + fail-open + uri-pattern)
utils.h / utils.cc  Copied from upstream; only the AuthLogDebug tag changed
Makefile.inc        Only relevant if building inside a full ATS source tree
inhomeproxy.patch   Unified diff against pristine upstream authproxy.cc
```

## Exactly what changed vs. upstream `authproxy.cc`

`inhomeproxy.patch` is the full, authoritative answer, but summarized:

1. **Identity** (new, this pass): `plugin_name`, the debug/error tag in
   `utils.h`, and the `TSUserArgIndexReserve` label — the minimum
   needed for `inhomeproxy.so` to be unambiguous at runtime. Also
   replaced the ASF `vendor_name`/`support_email` in
   `TSPluginRegistrationInfo` with placeholders, since this is no
   longer the ASF-maintained binary — fill in your own org's info if
   you care about that showing up in diagnostics.
2. **`--uri-pattern <regex>`**: only requests whose URL path matches
   go to the authorization proxy at all — everything else (segments,
   chunks) bypasses it entirely, with zero added hooks or overhead.
   Matched via `TSUrlPathGet` (query string already stripped) against
   a `std::regex`, checked at the very top of `TSRemapDoRemap`.
3. **`--fail-open`** (+ `--timeout-ms`, default 2000): a
   `TSContSchedule` timer races the normal exchange; if it fires
   first, or the authorization proxy errors out, the request is
   allowed instead of denied. Off by default — omit both flags and
   behavior is byte-for-byte stock authproxy.

Neither addition touches the redirect-handling code path
(`AuthChainAuthorizationResponse`/`StateAuthProxySendResponse`) at
all — that's exactly why this revision has no interaction with ATS's
redirect-follow behavior, which is what made it the right point to
treat as your stable baseline.

## Building

```sh
g++ -std=c++17 -Wall -Wextra -fPIC -shared -O2 \
  -I/path/to/trafficserver/include \
  inhomeproxy.cc utils.cc -o inhomeproxy.so
```

Verified against ATS `9.2.x` branch headers: compiles clean under
`-Wall -Wextra`, links with the expected undefined `TS*` symbols
(resolved by `traffic_server` at load time), and exports
`TSRemapInit`/`TSRemapNewInstance`/`TSRemapDeleteInstance`/
`TSRemapDoRemap`/`TSPluginInit`.

```sh
$ nm -D inhomeproxy.so | grep " T " | grep -E "TSRemap|TSPluginInit"
TSPluginInit
TSRemapDeleteInstance
TSRemapDoRemap
TSRemapInit
TSRemapNewInstance

$ strings inhomeproxy.so | grep -i inhomeproxy
inhomeproxy
inhomeproxy.cc
InHomeProxy
InHomeProxy authorization tag
[inhomeproxy] invalid --timeout-ms ...
[inhomeproxy] invalid --uri-pattern regex ...
```

No `authproxy` (lowercase, the tag/name form) shows up anywhere in the
compiled binary's strings — confirms it won't be confused with, or
picked up by, tooling/log filters aimed at a real `authproxy.so`.

## Installing

```sh
cp inhomeproxy.so /usr/lib64/trafficserver/modules/   # or your plugin dir
```

```
map https://edge.example.com/ https://origin.example.com/ \
    @plugin=inhomeproxy.so \
    @pparam=--auth-host=home-auth.internal.example.com \
    @pparam=--auth-port=8080 \
    @pparam=--auth-transform=head \
    @pparam=--uri-pattern=\.(m3u8|mpd)$ \
    @pparam=--fail-open \
    @pparam=--timeout-ms=1500
```

`traffic_ctl config reload` picks up remap.config changes as usual;
this plugin has no config-file reload mechanism of its own (all
options are `@pparam`s, re-read whenever `TSRemapNewInstance` runs).

## Rebasing against a future upstream authproxy.cc

Since the source file itself was renamed (`authproxy.cc` →
`inhomeproxy.cc`), `inhomeproxy.patch` needs its target renamed first —
`patch` matches by filename otherwise:

```sh
cp /path/to/fresh/upstream/authproxy.cc inhomeproxy.cc
patch inhomeproxy.cc < inhomeproxy.patch
# resolve any conflicts, then re-apply the identity-rename hunks if
# upstream changed nearby lines
```

## Debugging

```sh
traffic_ctl config set proxy.config.diags.debug.enabled 1
traffic_ctl config set proxy.config.diags.debug.tags inhomeproxy
```
