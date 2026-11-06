# inhomeproxy

A fork of Apache Traffic Server's stock `authproxy` plugin, built as its own
`inhomeproxy.so` so it can sit next to an unmodified `authproxy.so`. It
authorizes manifest requests against a backend (your "in-home" check), and this
revision adds what is needed to protect that backend at scale.

Internal C++ names (`AuthOptions`, `State*`, ...) are unchanged from upstream on
purpose, so the diff against upstream stays small. Only the externally visible
identity differs: plugin name, debug tag (`inhomeproxy`), user-arg label.

## What it adds over upstream

| Option | Purpose |
|---|---|
| `--uri-pattern <regex>` | Only requests whose URL **path** matches are authorized (e.g. `\.(m3u8\|mpd)$`). Segments never touch the plugin's state machine. |
| `--fail-open` / `--timeout-ms <ms>` | If the backend times out, errors, or answers 5xx, allow the request instead of denying it. |
| `--cache-ttl-ms <ms>` | Remember a backend **allow** for this long, keyed on (backend, client IP, did). `0` = off. |
| `--cache-jitter-pct <0-90>` | Randomize each entry's lifetime by +/- this percent (default 10). |
| `--breaker-failures <n>` / `--breaker-cooldown-ms <ms>` | Circuit breaker, **requires `--fail-open`** (default cool-down 10000 ms). `0` = off. |

Everything is opt-in. With none of these flags it behaves like stock authproxy.
Cache, breaker and `--uri-pattern` apply in **remap mode** only (not when loaded
globally from `plugin.config`).

## Example

```
map https://FQDN/ http://origin/ \
    @plugin=inhomeproxy.so \
    @pparam=--auth-transform=redirect \
    @pparam=--auth-host=172.26.205.4 \
    @pparam=--auth-port=80 \
    @pparam=--uri-pattern=\.(m3u8|mpd)$ \
    @pparam=--fail-open \
    @pparam=--timeout-ms=1500 \
    @pparam=--cache-ttl-ms=300000 \
    @pparam=--cache-jitter-pct=10 \
    @pparam=--breaker-failures=5 \
    @pparam=--breaker-cooldown-ms=10000
```

## How the cache behaves

* **Process-wide.** One cache for the whole `traffic_server`, shared by every
  remap rule. The key contains the backend (`host:port`), so rules using the
  same backend share verdicts and rules using different backends never do.
  With one rule per channel this is what makes a viewer zapping across
  channels cost **one** check per TTL instead of one per channel. It also
  survives `traffic_ctl config reload`.
* **Key = backend + client IP + did. The request path is NOT in the key.**
  The question being asked is "is this device on its home network", which does
  not depend on the channel. *If your backend ever makes channel-dependent
  decisions (entitlements), this is wrong for you* — tell me and the path goes
  into the key.
* **A different IP is a different key**, so a device that shows up from another
  network is always checked; a cached allow can never carry over to it.
* **Only a real backend 2xx is cached.** Denies are not cached (a device that
  just got home is allowed on its next request). Fail-open outcomes are not
  cached (one timeout must not authorize a viewer for the whole TTL).
* **Fixed lifetime.** A hit does not extend the entry; every viewer is
  re-validated about once per TTL (+/- jitter). Jitter prevents viewers
  authorized in the same burst from all expiring in the same instant.
* **Hard memory cap.** 262,144 entries total, roughly 40-50 MB worst case.
  Expired entries are swept first when a shard fills; beyond that, entries are
  evicted arbitrarily (not LRU).
* **Requests that can never be cached** go to the backend every time: no `did`,
  `did` repeated or with different capitalization (parameter pollution), any
  percent-encoded parameter *name*, or a `did` that is not a plain token
  (`[A-Za-z0-9._~-]`, at most 128 bytes). There is deliberately **no IP-only
  fallback** when `did` is missing. These show up in `cache_skip`; if that
  number is large, your dids contain characters outside the allowed set.

## Circuit breaker

After `--breaker-failures` consecutive failures (timeout, connect error, 5xx)
the breaker opens: for `--breaker-cooldown-ms` requests skip the backend
entirely and fail open immediately, so a struggling backend gets quiet instead
of a retry storm, and viewers do not wait out `--timeout-ms`. Then exactly one
request at a time is let through as a probe; success closes the breaker, failure
re-opens it. A real answer, even a 403 deny, counts as healthy. The breaker is
per backend and shared by all rules using it. **While it is open, out-of-home
viewers are let through** — that is what fail-open means.

Order in `TSRemapDoRemap`: URI pattern, then cache, then breaker. The cache
comes first so a hit never consumes the single probe slot.

## Metrics

```
traffic_ctl metric match inhomeproxy
```

| Metric | Meaning |
|---|---|
| `plugin.inhomeproxy.backend_call` | Requests actually sent to the backend. **This is the load you are protecting.** |
| `plugin.inhomeproxy.cache_hit` / `cache_miss` | Cacheable requests answered from the cache / not. |
| `plugin.inhomeproxy.cache_skip` | Requests that cannot be cached (see above). |
| `plugin.inhomeproxy.backend_fail` | Timeouts, connect errors, 5xx. |
| `plugin.inhomeproxy.breaker_bypass` / `breaker_trip` | Requests that skipped the backend because it was open / times it opened. |

Hit ratio = `cache_hit / (cache_hit + cache_miss + cache_skip)`.

## Sizing

In steady state, backend load is bounded by roughly
`active viewers / TTL seconds` requests per second, because each viewer is
re-checked at most once per TTL. Example with **assumed** numbers: 20,000
viewers and a 300 s TTL is at most about 67 calls/s, against thousands per
second if every DASH manifest poll (every few seconds per viewer) reached the
backend. The first request from each viewer cannot be cached, so a mass start
(restart, big event) still sends one call per distinct viewer; the breaker and
fail-open are what protect the backend in that case.

Each ATS host has its own cache and breaker, so total backend load is the sum
over hosts.

**TTL trade-off:** a longer TTL means fewer calls but a longer window in which a
changed verdict for the *same* IP and did (cancelled account, unregistered
device) is still honoured. Start at 300000 and adjust.

## Not done, on purpose

* **No request coalescing.** Simultaneous requests for the same key each call
  the backend. Bursts are made of distinct viewers, so this buys little; it
  can be added if load testing shows duplicates.
* **No negative caching.** A cached deny would have to replay the backend's
  response, and your 403-to-302 mapping happens in `header_rewrite` on the auth
  host rule, which a replay would bypass.

## Verification status

* `authcache.h` (cache, key builder, breaker) has no ATS dependency and is
  covered by `test/test_authcache.cc`: key edge cases, TTL and jitter bounds,
  hard cap, breaker state machine, single-probe election under 16-thread
  contention, and a multithreaded stress run. Clean under plain,
  ThreadSanitizer (0 warnings) and AddressSanitizer + UBSan.
* The plugin compiles warning-free (`-Wall -Wextra`) against the ATS 9.2.x
  headers and exports the expected entry points.
* **It has not been run inside a live traffic_server.** Try it on one staging
  or canary host first and watch `backend_call`, `cache_hit` and `backend_fail`.

## Build

```sh
g++ -std=c++17 -Wall -Wextra -fPIC -shared -O2 -I/path/to/ats/include \
    inhomeproxy.cc utils.cc -o inhomeproxy.so
# or, against an installed ATS:
tsxs -o inhomeproxy.so inhomeproxy.cc utils.cc -i
```

`authcache.h` must sit next to `inhomeproxy.cc`. Tests:

```sh
g++ -std=c++17 -Wall -Wextra -O1 -pthread -I. test/test_authcache.cc -o test_authcache && ./test_authcache
# add -fsanitize=thread  or  -fsanitize=address,undefined  to re-check
```

## Relation to upstream

`inhomeproxy.patch` is the diff against upstream 9.2.x as of commit `f671e52`
(2026-07-27), the snapshot this fork started from. It touches three files:
`inhomeproxy.cc` (from upstream `authproxy.cc`), `utils.h` (debug tag) and the
new `authcache.h`.

Upstream 9.2.x has since made one change to `authproxy.cc` and `utils.*`: the
three request transforms now strip `Transfer-Encoding`, `Trailer` and `Expect`
from the auth sub-request (relevant to requests that carry a body, not to GET
manifests). This fork does not include it yet. To take it, start from current
upstream and re-apply the patch (verified to apply with only line offsets, and
to compile):

```sh
cp upstream/authproxy.cc inhomeproxy.cc
cp upstream/utils.h upstream/utils.cc .
patch -p1 < inhomeproxy.patch
```
