/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
// authcache.h -- process-wide allow-cache and backend circuit breaker for
// inhomeproxy.
//
// Deliberately free of any Traffic Server dependency so it can be unit- and
// thread-tested on its own (see test/test_authcache.cc).
//
// Design summary
// --------------
//  * AuthCache   64-shard TTL map of "this (backend, client IP, did) was
//                authorized by the backend". Positive results only.
//                Process-wide: every remap rule shares it, so a viewer
//                zapping between channels costs ONE backend call per TTL,
//                not one per channel rule.
//  * Breaker     Per-backend circuit breaker. After N consecutive backend
//                failures, requests skip the backend entirely (and the
//                caller fails open) for a cool-down, then ONE probe at a
//                time is let through to test recovery.
//  * MakeCacheKey  Builds the cache key from the request and refuses
//                (returns "") whenever the request is ambiguous, so an
//                unusual request is always sent to the backend instead of
//                being answered from the cache.
#pragma once

#include <strings.h>

#include <algorithm>
#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <random>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace inhome
{
using Clock = std::chrono::steady_clock;

// ---------------------------------------------------------------------------
// AuthCache
// ---------------------------------------------------------------------------
class AuthCache
{
public:
  static constexpr size_t kShardBits = 6;
  static constexpr size_t kShards    = size_t{1} << kShardBits; // 64

  // max_entries is a HARD ceiling on the total number of entries (split
  // evenly across shards). Memory is therefore bounded no matter what
  // traffic does: roughly 150-200 bytes per entry, so the default of 262144
  // is on the order of 40-50 MB at worst.
  explicit AuthCache(size_t max_entries = 262144) : max_per_shard_(std::max<size_t>(1, max_entries / kShards)) {}

  // True if `key` is present and not yet expired. Shared (reader) lock only.
  bool
  Contains(const std::string &key, Clock::time_point now = Clock::now()) const
  {
    const Shard &s = ShardFor(key);
    std::shared_lock<std::shared_mutex> lock(s.mutex);
    auto it = s.map.find(key);
    return it != s.map.end() && it->second > now;
  }

  // Records `key` as authorized until `expires_at`.
  void
  Insert(const std::string &key, Clock::time_point expires_at, Clock::time_point now = Clock::now())
  {
    Shard &s = ShardFor(key);
    std::unique_lock<std::shared_mutex> lock(s.mutex);
    if (s.map.size() >= max_per_shard_ && s.map.find(key) == s.map.end()) {
      MakeRoom(s, now);
    }
    s.map[key] = expires_at;
  }

  // Expiry time for a new entry: now + ttl, spread by +/- jitter_pct percent.
  // The jitter matters: without it, every viewer authorized in the same burst
  // (a restart, the start of a big event) expires in the same instant and
  // re-checks in one synchronized wave.
  static Clock::time_point
  ExpiryFor(std::chrono::milliseconds ttl, unsigned jitter_pct, Clock::time_point now = Clock::now())
  {
    if (jitter_pct > 90) {
      jitter_pct = 90;
    }
    double factor = 1.0;
    if (jitter_pct > 0) {
      thread_local std::mt19937 rng{std::random_device{}()};
      std::uniform_real_distribution<double> dist(-1.0, 1.0);
      factor += dist(rng) * (static_cast<double>(jitter_pct) / 100.0);
    }
    return now + std::chrono::milliseconds(static_cast<int64_t>(static_cast<double>(ttl.count()) * factor));
  }

  // Entries currently stored, INCLUDING expired ones not yet swept.
  size_t
  Size() const
  {
    size_t total = 0;
    for (const Shard &s : shards_) {
      std::shared_lock<std::shared_mutex> lock(s.mutex);
      total += s.map.size();
    }
    return total;
  }

  size_t
  Capacity() const
  {
    return max_per_shard_ * kShards;
  }

private:
  struct Shard {
    mutable std::shared_mutex mutex;
    std::unordered_map<std::string, Clock::time_point> map;
  };

  // Shard chosen from the TOP bits of a multiplicatively mixed hash, not the
  // low bits: the shard's own unordered_map buckets by the low bits of the
  // same hash, and reusing them would leave most of its buckets unused on
  // implementations with power-of-two bucket counts.
  static size_t
  ShardIndex(const std::string &key)
  {
    uint64_t h = static_cast<uint64_t>(std::hash<std::string>{}(key)) * 0x9E3779B97F4A7C15ull;
    return static_cast<size_t>(h >> (64 - kShardBits));
  }

  Shard &
  ShardFor(const std::string &key)
  {
    return shards_[ShardIndex(key)];
  }
  const Shard &
  ShardFor(const std::string &key) const
  {
    return shards_[ShardIndex(key)];
  }

  // Caller holds the shard's unique lock. Drops expired entries first; if the
  // shard is still full, evicts ~10% arbitrarily (NOT LRU) so the next
  // several hundred inserts do not each pay for another sweep.
  void
  MakeRoom(Shard &s, Clock::time_point now) const
  {
    for (auto it = s.map.begin(); it != s.map.end();) {
      it = (it->second <= now) ? s.map.erase(it) : std::next(it);
    }
    if (s.map.size() >= max_per_shard_) {
      size_t drop = std::max<size_t>(1, max_per_shard_ / 10);
      for (auto it = s.map.begin(); it != s.map.end() && drop > 0; --drop) {
        it = s.map.erase(it);
      }
    }
  }

  std::array<Shard, kShards> shards_;
  size_t max_per_shard_;
};

// ---------------------------------------------------------------------------
// Breaker
// ---------------------------------------------------------------------------
class Breaker
{
public:
  // trip_after <= 0 disables the breaker entirely (ShouldBypass is always
  // false). probe_window is how long a half-open probe may stay silent
  // before another request is allowed to replace it; set it a little above
  // the request timeout so a probe that never reports back cannot wedge the
  // breaker open.
  Breaker(int trip_after, std::chrono::milliseconds cooldown, std::chrono::milliseconds probe_window)
    : trip_after_(trip_after), cooldown_ms_(cooldown.count()), probe_window_ms_(probe_window.count())
  {
  }

  // Milliseconds on a monotonic clock, never 0 (0 is the "closed" sentinel).
  static int64_t
  NowMs()
  {
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count() + 1;
  }

  bool
  Enabled() const
  {
    return trip_after_ > 0;
  }

  // true  => skip the backend; the caller must fail open.
  // false => go ahead and call the backend (breaker closed, or this caller
  //          was elected the single half-open probe).
  bool
  ShouldBypass(int64_t now_ms = NowMs())
  {
    if (!Enabled()) {
      return false;
    }
    int64_t open_until = open_until_.load(std::memory_order_acquire);
    if (open_until == 0) {
      return false; // closed
    }
    if (now_ms < open_until) {
      return true; // open, cooling down
    }
    // Half-open: cool-down elapsed. Let exactly one request through.
    int64_t probe_deadline = probe_deadline_.load(std::memory_order_acquire);
    if (now_ms < probe_deadline) {
      return true; // someone else is already probing
    }
    bool elected = probe_deadline_.compare_exchange_strong(probe_deadline, now_ms + probe_window_ms_, std::memory_order_acq_rel);
    return !elected;
  }

  // The backend answered with a real response (an allow, or a legitimate
  // deny). It is healthy, whatever the verdict.
  void
  OnSuccess()
  {
    consecutive_failures_.store(0, std::memory_order_relaxed);
    probe_deadline_.store(0, std::memory_order_relaxed);
    open_until_.store(0, std::memory_order_release);
  }

  // Timeout, connect failure, or 5xx. Returns true when THIS call opened (or
  // re-opened, after a failed probe) the breaker.
  bool
  OnFailure(int64_t now_ms = NowMs())
  {
    if (!Enabled()) {
      return false;
    }
    int n = consecutive_failures_.fetch_add(1, std::memory_order_relaxed) + 1;
    if (n < trip_after_) {
      return false;
    }
    int64_t open_until = open_until_.load(std::memory_order_acquire);
    if (open_until != 0 && now_ms < open_until) {
      return false; // already open: late failures from in-flight requests do not extend it
    }
    if (open_until_.compare_exchange_strong(open_until, now_ms + cooldown_ms_, std::memory_order_acq_rel)) {
      probe_deadline_.store(0, std::memory_order_relaxed);
      return true;
    }
    return false;
  }

  bool
  IsOpen(int64_t now_ms = NowMs()) const
  {
    int64_t open_until = open_until_.load(std::memory_order_acquire);
    return open_until != 0 && now_ms < open_until;
  }

private:
  const int trip_after_;
  const int64_t cooldown_ms_;
  const int64_t probe_window_ms_;
  std::atomic<int> consecutive_failures_{0};
  std::atomic<int64_t> open_until_{0};      // 0 = closed
  std::atomic<int64_t> probe_deadline_{0};  // 0 = no probe outstanding
};

// One Breaker per backend ("host:port"), shared by every remap rule that uses
// that backend, so they trip together instead of each rule independently
// having to rediscover that the backend is down. Settings come from whichever
// rule creates the entry first. Entries are never freed (one per distinct
// backend, so bounded) which keeps the returned pointer valid for the life of
// the process, across remap.config reloads.
inline Breaker *
GetBreaker(const std::string &backend, int trip_after, std::chrono::milliseconds cooldown, std::chrono::milliseconds probe_window)
{
  static std::mutex mutex;
  static auto *registry = new std::unordered_map<std::string, std::unique_ptr<Breaker>>();

  std::lock_guard<std::mutex> lock(mutex);
  auto &slot = (*registry)[backend];
  if (!slot) {
    slot.reset(new Breaker(trip_after, cooldown, probe_window));
  }
  return slot.get();
}

// ---------------------------------------------------------------------------
// Cache key construction
// ---------------------------------------------------------------------------

constexpr size_t kMaxDidLength = 128;

// Finds the value of query parameter `name` and succeeds only when the
// request is unambiguous: the name appears exactly once, with exactly this
// capitalization, and no parameter name in the query is percent-encoded.
//
// Why so strict: the cache key is built from what THIS code extracts, while
// the backend decides on what ITS parser extracts. If a request can make the
// two disagree (did=A&did=B, or Did=B, or d%69d=B), an attacker with one
// legitimately authorized device could get a cache entry created under a key
// that other requests then reuse. Refusing ambiguous requests removes that
// whole class: they simply always go to the backend.
inline bool
UniqueQueryParam(const std::string &query, const char *name, std::string *out)
{
  const size_t name_len = std::strlen(name);
  bool found            = false;
  size_t pos            = 0;

  while (true) {
    size_t amp = query.find('&', pos);
    size_t end = (amp == std::string::npos) ? query.size() : amp;
    size_t eq  = query.find('=', pos);
    size_t name_end = (eq == std::string::npos || eq > end) ? end : eq;

    for (size_t i = pos; i < name_end; ++i) {
      if (query[i] == '%' || query[i] == '+') {
        return false;
      }
    }

    if (name_end - pos == name_len && ::strncasecmp(query.data() + pos, name, name_len) == 0) {
      if (found) {
        return false; // duplicate (case-insensitively)
      }
      if (std::memcmp(query.data() + pos, name, name_len) != 0) {
        return false; // different capitalization, e.g. "Did="
      }
      found = true;
      *out  = (name_end < end) ? query.substr(name_end + 1, end - name_end - 1) : std::string();
    }

    if (amp == std::string::npos) {
      break;
    }
    pos = amp + 1;
  }
  return found && !out->empty();
}

// Cache key: "<backend>|<client ip>|<did>", or "" when this request must not
// be cached. The did must be a plain token ([A-Za-z0-9._~-], at most 128
// bytes): anything else (encoding, separators, odd characters) is sent to the
// backend every time. There is deliberately NO fallback to an IP-only key
// when the did is missing -- that would let any device behind an authorized
// IP ride on another device's authorization.
//
// The request path is deliberately NOT part of the key: the authorization
// question is "is this device on its home network", which does not depend on
// which channel it asks for. One check therefore covers channel zapping.
inline std::string
MakeCacheKey(const std::string &backend, const std::string &client_ip, const std::string &query)
{
  if (client_ip.empty()) {
    return std::string();
  }
  std::string did;
  if (!UniqueQueryParam(query, "did", &did) || did.size() > kMaxDidLength) {
    return std::string();
  }
  for (unsigned char c : did) {
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
              c == '~';
    if (!ok) {
      return std::string();
    }
  }
  std::string key;
  key.reserve(backend.size() + client_ip.size() + did.size() + 2);
  key.append(backend).push_back('|');
  key.append(client_ip).push_back('|');
  key.append(did);
  return key;
}

} // namespace inhome
