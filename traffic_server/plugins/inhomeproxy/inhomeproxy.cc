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

// InHomeProxy - a small, deliberately-minimal fork of Apache Traffic
// Server's stock "authproxy" plugin, renamed and built as its own
// inhomeproxy.so so it can be installed alongside (or instead of) an
// unmodified authproxy.so without any naming collisions in ATS's
// plugin registry, debug tags, or remap.config.
//
// This file is derived from plugins/authproxy/authproxy.cc in the
// Apache Traffic Server source tree and remains under the Apache
// License 2.0 above. Internal identifiers (AuthOptions,
// AuthRequestContext, State* functions, etc.) are intentionally left
// unchanged from upstream -- only the handful of externally-visible
// names (plugin registration name, debug/error log tag, TSUserArg
// label) were renamed. This keeps `diff` against a fresh upstream
// authproxy.cc small and meaningful, which matters if you want to pull
// in future ATS authproxy changes without re-deriving this fork from
// scratch. See README.md for the two local additions (--fail-open,
// --uri-pattern) and the exact diff against upstream.
//
// AuthProxy - An authorization plugin for Apache Traffic Server that delegates
// the authorization decision to a separate web service. The web service
// (which we refer to here as the Authorization Proxy) is expected to authorize
// the request (or not) by consulting some authoritative source.
//
// This plugin follows the pattern of the basic-auth sample code. We use the
// TS_HTTP_POST_REMAP_HOOK to perform the initial authorization, and
// the TS_HTTP_SEND_RESPONSE_HDR_HOOK to send an error response if necessary.

#include "utils.h"
#include "authcache.h"
#include <string>
#include <memory> // placement new
#include <limits>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <regex>

#include <getopt.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <ts/remap.h>

using std::strlen;

struct AuthRequestContext;

using AuthRequestTransform = bool (*)(AuthRequestContext *);

const static int MAX_HOST_LENGTH = 4096;

// We can operate in global plugin mode or remap plugin mode. If we are in
// global mode, then we will authorize every request. In remap mode, we will
// only authorize tagged requests.
static int AuthTaggedRequestArg = -1;

static TSCont AuthOsDnsContinuation;

// --- Process-wide allow-cache and metrics (local additions; see authcache.h) ---
//
// One cache for the whole traffic_server process, shared by every remap rule
// that loads this plugin. Cache keys include the backend ("host:port"), so
// rules that talk to different authorization hosts never share verdicts, while
// rules that talk to the same one do: a viewer zapping across 100+ channel
// rules costs one backend check per TTL instead of one per rule. It also
// survives `traffic_ctl config reload`, so a reload does not trigger a wave of
// re-authorizations.
static inhome::AuthCache AuthAllowCache;

enum AuthStatId {
  AUTH_STAT_CACHE_HIT,      // request answered from the cache; backend not contacted
  AUTH_STAT_CACHE_MISS,     // cacheable request that was not in the cache
  AUTH_STAT_CACHE_SKIP,     // request that can never be cached (no/odd/ambiguous did); always asks the backend
  AUTH_STAT_BACKEND_CALL,   // authorization requests actually sent to the backend  <-- the load you care about
  AUTH_STAT_BACKEND_FAIL,   // backend timeout / connect error / 5xx
  AUTH_STAT_BREAKER_BYPASS, // requests that skipped the backend because the circuit breaker was open
  AUTH_STAT_BREAKER_TRIP,   // times the circuit breaker opened
  AUTH_STAT_COUNT
};

static const char *const AuthStatNames[AUTH_STAT_COUNT] = {
  "plugin.inhomeproxy.cache_hit",    "plugin.inhomeproxy.cache_miss",     "plugin.inhomeproxy.cache_skip",
  "plugin.inhomeproxy.backend_call", "plugin.inhomeproxy.backend_fail",   "plugin.inhomeproxy.breaker_bypass",
  "plugin.inhomeproxy.breaker_trip",
};

// -1 until registered; AuthStatInc() is a no-op for unregistered stats.
static int AuthStatIds[AUTH_STAT_COUNT] = {-1, -1, -1, -1, -1, -1, -1};

static void
AuthStatsInit()
{
  static std::once_flag once;
  std::call_once(once, [] {
    for (int i = 0; i < AUTH_STAT_COUNT; ++i) {
      int id = -1;
      if (TSStatFindName(AuthStatNames[i], &id) == TS_ERROR) {
        id = TSStatCreate(AuthStatNames[i], TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_SUM);
        if (id == TS_ERROR) {
          AuthLogError("[inhomeproxy] failed to register metric '%s'", AuthStatNames[i]);
          id = -1;
        } else {
          TSStatIntSet(id, 0);
        }
      }
      AuthStatIds[i] = id;
    }
  });
}

static inline void
AuthStatInc(AuthStatId s)
{
  if (AuthStatIds[s] >= 0) {
    TSStatIntIncrement(AuthStatIds[s], 1);
  }
}

struct AuthOptions {
  std::string hostname;
  int hostport                   = -1;
  AuthRequestTransform transform = nullptr;
  bool force                     = false;
  bool cache_internal_requests   = false;

  // --- Local additions -------------------------------------------------
  //
  // has_pattern / uri_pattern: restrict which requests get sent to the
  // authorization proxy at all, based on a regex matched against the
  // request URL's path. Without --uri-pattern, every request is
  // authorized, matching stock authproxy behavior exactly. With it set
  // (e.g. to `\.(m3u8|mpd)$`), only matching requests (HLS/DASH
  // manifests) incur the authorization round trip; everything else
  // (segments/chunks) bypasses authproxy entirely -- no hook is even
  // added for those requests, so there's zero per-chunk overhead.
  bool has_pattern = false;
  std::regex uri_pattern;

  // fail_open / timeout_ms: if the authorization proxy does not
  // complete a response within timeout_ms, treat the request as
  // authorized instead of denying it. Off by default, matching stock
  // authproxy behavior (errors/timeouts deny). See StateTimeout() and
  // the fail_open branch in StateUnauthorized().
  bool fail_open  = false;
  int timeout_ms  = 2000;

  // cache_ttl_ms: remember a backend "authorized" verdict for this long,
  // keyed on (backend, client IP, did) -- see authcache.h. 0 (default)
  // disables caching, giving stock behavior: every matching request is
  // checked. Only real 2xx verdicts are cached: never a deny, and never a
  // fail-open outcome. cache_jitter_pct spreads each entry's lifetime by
  // +/- that percentage so viewers authorized together do not all come due
  // together. Remap mode only (like --uri-pattern).
  int cache_ttl_ms         = 0;
  unsigned cache_jitter_pct = 10;

  // Circuit breaker (requires --fail-open): after breaker_failures
  // consecutive backend failures, stop calling the backend for
  // breaker_cooldown_ms and fail open immediately, then let a single probe
  // request through to test recovery. Protects a struggling backend from
  // the retry storm, and viewers from waiting out timeout_ms on every
  // request. 0 (default) disables it.
  int breaker_failures    = 0;
  int breaker_cooldown_ms = 10000;
  inhome::Breaker *breaker = nullptr; // owned by the process-wide registry, never freed

  // "host:port" of the authorization backend: scope for cache keys and the
  // breaker. Filled in at the end of AuthParseOptions().
  std::string backend_id;

  AuthOptions()  = default;
  ~AuthOptions() = default;
};

// Global options; used when we are in global authorization mode.
static AuthOptions *AuthGlobalOptions;

// Generic state handler callback. This should handle the event, and return a
// new event. The return value controls the subsequent state transition:
//      TS_EVENT_CONTINUE   Continue the state machine, returning to the ATS event loop
//      TS_EVENT_NONE       Stop processing (because a nested dispatch occurred)
//      Anything else       Continue the state machine with this event
using StateHandler = TSEvent (*)(struct AuthRequestContext *, void *);

struct StateTransition {
  TSEvent event;
  StateHandler handler;
  const StateTransition *next;
};

static TSEvent StateAuthProxyConnect(AuthRequestContext *, void *);
static TSEvent StateAuthProxyWriteReady(AuthRequestContext *, void *);
static TSEvent StateAuthProxyWriteComplete(AuthRequestContext *, void *);
static TSEvent StateUnauthorized(AuthRequestContext *, void *);
static TSEvent StateAuthorized(AuthRequestContext *, void *);
static TSEvent StateTimeout(AuthRequestContext *, void *);

static TSEvent StateAuthProxyReadHeaders(AuthRequestContext *, void *);
static TSEvent StateAuthProxyCompleteHeaders(AuthRequestContext *, void *);
static TSEvent StateAuthProxyReadContent(AuthRequestContext *, void *);
static TSEvent StateAuthProxyCompleteContent(AuthRequestContext *, void *);

static TSEvent StateAuthProxySendResponse(AuthRequestContext *, void *);

// Trampoline state that just returns TS_EVENT_CONTINUE. We need this to be
// able to transition between state tables when we are in a loop.
static TSEvent
StateContinue(AuthRequestContext *, void *)
{
  return TS_EVENT_CONTINUE;
}

// State table for sending the auth proxy response to the client.
static const StateTransition StateTableSendResponse[] = {{TS_EVENT_HTTP_SEND_RESPONSE_HDR, StateAuthProxySendResponse, nullptr},
                                                         {TS_EVENT_NONE, nullptr, nullptr}};

// State table for reading the proxy response body content.
static const StateTransition StateTableProxyReadContent[] = {
  {TS_EVENT_VCONN_READ_READY, StateAuthProxyReadContent, StateTableProxyReadContent},
  {TS_EVENT_VCONN_READ_COMPLETE, StateAuthProxyReadContent, StateTableProxyReadContent},
  {TS_EVENT_VCONN_EOS, StateAuthProxyCompleteContent, StateTableProxyReadContent},
  {TS_EVENT_HTTP_SEND_RESPONSE_HDR, StateContinue, StateTableSendResponse},
  {TS_EVENT_ERROR, StateUnauthorized, nullptr},
  {TS_EVENT_IMMEDIATE, StateAuthorized, nullptr},
  {TS_EVENT_TIMEOUT, StateTimeout, nullptr},
  {TS_EVENT_NONE, nullptr, nullptr}};

// State table for reading the auth proxy response header.
static const StateTransition StateTableProxyReadHeader[] = {
  {TS_EVENT_VCONN_READ_READY, StateAuthProxyReadHeaders, StateTableProxyReadHeader},
  {TS_EVENT_VCONN_READ_COMPLETE, StateAuthProxyReadHeaders, StateTableProxyReadHeader},
  {TS_EVENT_HTTP_READ_REQUEST_HDR, StateAuthProxyCompleteHeaders, StateTableProxyReadHeader},
  {TS_EVENT_HTTP_SEND_RESPONSE_HDR, StateContinue, StateTableSendResponse},
  {TS_EVENT_HTTP_CONTINUE, StateAuthProxyReadContent, StateTableProxyReadContent},
  {TS_EVENT_VCONN_EOS, StateUnauthorized, nullptr}, // XXX Should we check headers on EOS?
  {TS_EVENT_ERROR, StateUnauthorized, nullptr},
  {TS_EVENT_IMMEDIATE, StateAuthorized, nullptr},
  {TS_EVENT_TIMEOUT, StateTimeout, nullptr},
  {TS_EVENT_NONE, nullptr, nullptr}};

// State table for sending the request to the auth proxy.
static const StateTransition StateTableProxyRequest[] = {
  {TS_EVENT_VCONN_WRITE_READY, StateAuthProxyWriteReady, StateTableProxyRequest},
  {TS_EVENT_VCONN_WRITE_COMPLETE, StateAuthProxyWriteComplete, StateTableProxyReadHeader},
  {TS_EVENT_ERROR, StateUnauthorized, nullptr},
  {TS_EVENT_TIMEOUT, StateTimeout, nullptr},
  {TS_EVENT_NONE, nullptr, nullptr}};

// Initial state table.
static const StateTransition StateTableInit[] = {{TS_EVENT_HTTP_POST_REMAP, StateAuthProxyConnect, StateTableProxyRequest},
                                                 {TS_EVENT_ERROR, StateUnauthorized, nullptr},
                                                 {TS_EVENT_NONE, nullptr, nullptr}};

struct AuthRequestContext {
  TSHttpTxn txn = nullptr; // Original client transaction we are authorizing.
  TSCont cont   = nullptr; // Continuation for this state machine.
  TSVConn vconn = nullptr; // Virtual connection to the auth proxy.
  TSHttpParser hparser;    // HTTP response header parser.
  HttpHeader rheader;      // HTTP response header.
  HttpIoBuffer iobuf;
  const char *method = nullptr; // Client request method (e.g. GET)
  bool read_body     = true;

  // Fail-open guard timer (see StateAuthProxyConnect / StateTimeout).
  // Left null whenever --fail-open isn't configured, or once it has
  // already fired (StateTimeout nulls it out itself, since canceling an
  // action from within its own firing callback is not something we
  // should rely on being safe).
  TSAction timeout_action = nullptr;

  // Cache key for this request, computed when the context is created (see
  // AuthProxyGlobalHook) from the same client-request URL the backend will
  // see. Empty when caching is off or the request is not cacheable. Used by
  // StateAuthorized to record a genuine backend "allow".
  std::string cache_key;

  const StateTransition *state = nullptr;

  AuthRequestContext()
    : cont(TSContCreate(dispatch, TSMutexCreate())), hparser(TSHttpParserCreate()), rheader(), iobuf(TS_IOBUFFER_SIZE_INDEX_4K)

  {
    TSContDataSet(this->cont, this);
  }

  ~AuthRequestContext()
  {
    if (this->timeout_action) {
      TSActionCancel(this->timeout_action);
    }
    TSContDataSet(this->cont, nullptr);
    TSContDestroy(this->cont);
    TSHttpParserDestroy(this->hparser);
    if (this->vconn) {
      TSVConnClose(this->vconn);
    }
  }

  const AuthOptions *
  options() const
  {
    AuthOptions *opt;

    opt = static_cast<AuthOptions *>(TSUserArgGet(this->txn, AuthTaggedRequestArg));
    return opt ? opt : AuthGlobalOptions;
  }

  static AuthRequestContext *allocate();
  static void destroy(AuthRequestContext *);
  static int dispatch(TSCont, TSEvent, void *);
};

AuthRequestContext *
AuthRequestContext::allocate()
{
  void *ptr = TSmalloc(sizeof(AuthRequestContext));
  return new (ptr) AuthRequestContext();
}

void
AuthRequestContext::destroy(AuthRequestContext *auth)
{
  if (auth) {
    auth->~AuthRequestContext();
    TSfree(auth);
  }
}

int
AuthRequestContext::dispatch(TSCont cont, TSEvent event, void *edata)
{
  AuthRequestContext *auth = static_cast<AuthRequestContext *>(TSContDataGet(cont));
  const StateTransition *s;

pump:
  for (s = auth->state; s && s->event; ++s) {
    if (s->event == event) {
      break;
    }
  }

  // If we don't have a handler, the state machine is borked.
  TSReleaseAssert(s != nullptr);
  TSReleaseAssert(s->handler != nullptr);

  // Move to the next state. We have to set this *before* invoking the
  // handler because the handler itself can invoke the next handler.
  auth->state = s->next;
  event       = s->handler(auth, edata);

  // If the handler returns TS_EVENT_NONE, it means that a re-entrant event
  // was dispatched. In this case, the state machine continues from the
  // nested call to dispatch.
  if (event == TS_EVENT_NONE) {
    return TS_EVENT_NONE;
  }
  // If there are no more states, the state machine has terminated.
  if (auth->state == nullptr) {
    AuthRequestContext::destroy(auth);
    return TS_EVENT_NONE;
  }
  // If the handler gave us an event, pump the it back into the current state
  // table, otherwise we will return back to the ATS event loop.
  if (event != TS_EVENT_CONTINUE) {
    goto pump;
  }

  return TS_EVENT_NONE;
}

// Return whether the client request was a HEAD request.
const char *
AuthRequestGetMethod(TSHttpTxn txn)
{
  TSMBuffer mbuf;
  TSMLoc mhdr;
  int len;
  const char *method;

  TSReleaseAssert(TSHttpTxnClientReqGet(txn, &mbuf, &mhdr) == TS_SUCCESS);

  method = TSHttpHdrMethodGet(mbuf, mhdr, &len);
  TSHandleMLocRelease(mbuf, TS_NULL_MLOC, mhdr);

  return method;
}

// Return whether this request's URL path should go through the
// authorization proxy at all. With no --uri-pattern configured, every
// request is authorized (stock authproxy behavior). With one
// configured, only requests whose path matches it are -- intended for
// e.g. HLS/DASH manifests only (`\.(m3u8|mpd)$`), so that segment/chunk
// requests never make the extra round trip.
static bool
AuthRequestUriRequiresAuthorization(const AuthOptions *options, TSMBuffer bufp, TSMLoc url)
{
  if (!options->has_pattern) {
    return true;
  }

  int len        = 0;
  const char *path = TSUrlPathGet(bufp, url, &len);
  if (path == nullptr || len <= 0) {
    // No path component to match against -- treat conservatively as
    // "not a manifest" rather than risk matching everything.
    return false;
  }

  return std::regex_search(path, path + len, options->uri_pattern);
}

// Chain the response header hook to send the proxy's authorization response.
static void
AuthChainAuthorizationResponse(AuthRequestContext *auth)
{
  if (auth->vconn) {
    TSVConnClose(auth->vconn);
    auth->vconn = nullptr;
  }

  TSHttpTxnHookAdd(auth->txn, TS_HTTP_SEND_RESPONSE_HDR_HOOK, auth->cont);
  TSHttpTxnReenable(auth->txn, TS_EVENT_HTTP_ERROR);
}

// Transform the client request into a HEAD request and write it out.
static bool
AuthWriteHeadRequest(AuthRequestContext *auth)
{
  HttpHeader rq;
  TSMBuffer mbuf;
  TSMLoc mhdr;

  TSReleaseAssert(TSHttpTxnClientReqGet(auth->txn, &mbuf, &mhdr) == TS_SUCCESS);

  // First, copy the whole client request to our new auth proxy request.
  TSReleaseAssert(TSHttpHdrCopy(rq.buffer, rq.header, mbuf, mhdr) == TS_SUCCESS);

  // Next, we need to rewrite the client request URL to be a HEAD request.
  TSReleaseAssert(TSHttpHdrMethodSet(rq.buffer, rq.header, TS_HTTP_METHOD_HEAD, -1) == TS_SUCCESS);

  HttpSetMimeHeader(rq.buffer, rq.header, TS_MIME_FIELD_CONTENT_LENGTH, 0u);
  HttpSetMimeHeader(rq.buffer, rq.header, TS_MIME_FIELD_CACHE_CONTROL, "no-cache");

  HttpDebugHeader(rq.buffer, rq.header);

  // Serialize the HTTP request to the write IO buffer.
  TSHttpHdrPrint(rq.buffer, rq.header, auth->iobuf.buffer);

  // We have to tell the auth context not to try to ready the response
  // body (since HEAD can have a content-length but must not have any
  // content).
  auth->read_body = false;

  TSHandleMLocRelease(mbuf, TS_NULL_MLOC, mhdr);
  return true;
}

// Transform the client request into a GET Range: bytes=0-0 request. This is useful
// for example of the authentication service is a caching proxy which might not
// cache HEAD requests.
static bool
AuthWriteRangeRequest(AuthRequestContext *auth)
{
  HttpHeader rq;
  TSMBuffer mbuf;
  TSMLoc mhdr;

  TSReleaseAssert(TSHttpTxnClientReqGet(auth->txn, &mbuf, &mhdr) == TS_SUCCESS);

  // First, copy the whole client request to our new auth proxy request.
  TSReleaseAssert(TSHttpHdrCopy(rq.buffer, rq.header, mbuf, mhdr) == TS_SUCCESS);

  // Next, assure that the request to the auth server is a GET request, since we'll send a Range:
  if (TS_HTTP_METHOD_GET != auth->method) {
    TSReleaseAssert(TSHttpHdrMethodSet(rq.buffer, rq.header, TS_HTTP_METHOD_GET, -1) == TS_SUCCESS);
  }

  HttpSetMimeHeader(rq.buffer, rq.header, TS_MIME_FIELD_CONTENT_LENGTH, 0u);
  HttpSetMimeHeader(rq.buffer, rq.header, TS_MIME_FIELD_RANGE, "bytes=0-0");
  HttpSetMimeHeader(rq.buffer, rq.header, TS_MIME_FIELD_CACHE_CONTROL, "no-cache");

  HttpDebugHeader(rq.buffer, rq.header);

  // Serialize the HTTP request to the write IO buffer.
  TSHttpHdrPrint(rq.buffer, rq.header, auth->iobuf.buffer);

  // We have to tell the auth context not to try to ready the response
  // body, since we'are asking for a zero length Range.
  auth->read_body = false;

  TSHandleMLocRelease(mbuf, TS_NULL_MLOC, mhdr);
  return true;
}

// Transform the client request into a form that the auth proxy can consume and
// write it out.
static bool
AuthWriteRedirectedRequest(AuthRequestContext *auth)
{
  const AuthOptions *options = auth->options();
  HttpHeader rq;
  TSMBuffer mbuf;
  TSMLoc mhdr;
  TSMLoc murl;
  char hostbuf[MAX_HOST_LENGTH + 1];

  TSReleaseAssert(TSHttpTxnClientReqGet(auth->txn, &mbuf, &mhdr) == TS_SUCCESS);

  // First, copy the whole client request to our new auth proxy request.
  TSReleaseAssert(TSHttpHdrCopy(rq.buffer, rq.header, mbuf, mhdr) == TS_SUCCESS);

  // Next, we need to rewrite the client request URL so that the request goes to
  // the auth proxy instead of the original request.
  TSReleaseAssert(TSHttpHdrUrlGet(rq.buffer, rq.header, &murl) == TS_SUCCESS);

  // XXX Possibly we should rewrite the URL to remove the host, port and
  // scheme, forcing ATS to go to the Host header. I wonder how HTTPS would
  // work in that case. At any rate, we should add a new header containing
  // the original host so that the auth proxy can examine it.
  TSUrlHostSet(rq.buffer, murl, options->hostname.c_str(), options->hostname.size());
  if (-1 != options->hostport) {
    snprintf(hostbuf, sizeof(hostbuf), "%s:%d", options->hostname.c_str(), options->hostport);
    TSUrlPortSet(rq.buffer, murl, options->hostport);
  } else {
    snprintf(hostbuf, sizeof(hostbuf), "%s", options->hostname.c_str());
  }

  TSHandleMLocRelease(rq.buffer, rq.header, murl);

  HttpSetMimeHeader(rq.buffer, rq.header, TS_MIME_FIELD_HOST, hostbuf);
  HttpSetMimeHeader(rq.buffer, rq.header, TS_MIME_FIELD_CONTENT_LENGTH, 0u);
  HttpSetMimeHeader(rq.buffer, rq.header, TS_MIME_FIELD_CACHE_CONTROL, "no-cache");

  HttpDebugHeader(rq.buffer, rq.header);

  // Serialize the HTTP request to the write IO buffer.
  TSHttpHdrPrint(rq.buffer, rq.header, auth->iobuf.buffer);

  TSHandleMLocRelease(mbuf, TS_NULL_MLOC, mhdr);
  TSHandleMLocRelease(rq.buffer, rq.header, murl);
  return true;
}

static TSEvent
StateAuthProxyConnect(AuthRequestContext *auth, void * /* edata ATS_UNUSED */)
{
  const AuthOptions *options = auth->options();
  struct sockaddr const *ip  = TSHttpTxnClientAddrGet(auth->txn);

  TSReleaseAssert(ip); // We must have a client IP.

  auth->method = AuthRequestGetMethod(auth->txn);
  AuthLogDebug("client request %s a HEAD request", auth->method == TS_HTTP_METHOD_HEAD ? "is" : "is not");

  AuthStatInc(AUTH_STAT_BACKEND_CALL);

  auth->vconn = TSHttpConnect(ip);
  if (auth->vconn == nullptr) {
    return TS_EVENT_ERROR;
  }
  // Transform the client request into an auth proxy request and write it
  // out to the auth proxy vconn.
  if (!options->transform(auth)) {
    return TS_EVENT_ERROR;
  }

  // Arm the fail-open guard timer, if configured. StateTimeout (see
  // below) handles it firing; the AuthRequestContext destructor cancels
  // it if we reach a terminal state some other way first.
  if (options->fail_open) {
    auth->timeout_action = TSContSchedule(auth->cont, options->timeout_ms);
  }

  // Start a write and transition to WriteAuthProxyState.
  TSVConnWrite(auth->vconn, auth->cont, auth->iobuf.reader, TSIOBufferReaderAvail(auth->iobuf.reader));
  return TS_EVENT_CONTINUE;
}

static TSEvent
StateAuthProxyCompleteHeaders(AuthRequestContext *auth, void * /* edata ATS_UNUSED */)
{
  TSHttpStatus status;

  HttpDebugHeader(auth->rheader.buffer, auth->rheader.header);

  status = TSHttpHdrStatusGet(auth->rheader.buffer, auth->rheader.header);
  AuthLogDebug("authorization proxy returned status %d", (int)status);

  // Authorize the original request on a 2xx response. The backend answered,
  // so it is healthy as far as the circuit breaker is concerned.
  if (status >= 200 && status < 300) {
    if (auth->options()->breaker) {
      auth->options()->breaker->OnSuccess();
    }
    return TS_EVENT_IMMEDIATE;
  }

  // With --fail-open: a *reachable* authorization proxy that answers
  // with a real status (say, an app-level 403) still goes through the
  // relay path below, unaffected by fail_open, exactly like a normal
  // deny. But when the proxy itself can't be reached at all -- e.g. the
  // auth host is down -- that failure does NOT surface here as a raw
  // vconn TS_EVENT_ERROR the way a plain TCP-level failure would.
  // TSHttpConnect() (see StateAuthProxyConnect) connects to ATS's own
  // internal HTTP engine, which then tries to reach options->hostname
  // on our behalf; when *that* fails, ATS's engine synthesizes an
  // ordinary-looking 502/503/504 "response" and hands it back through
  // our vconn just like a real one. Without this check, that response
  // would flow straight into AuthChainAuthorizationResponse() below and
  // get relayed to the client verbatim -- fail_open would never trigger,
  // and it would look instantaneous (no TS_EVENT_ERROR, no timeout
  // needed) even though nothing ever actually reached the auth proxy.
  // Route it through the exact same TS_EVENT_ERROR -> StateUnauthorized
  // path a raw connect failure takes, so the existing fail_open branch
  // there handles both uniformly.
  //
  // Any 5xx counts, not only 502/503/504: a backend that is overloaded or
  // crashing typically answers 500, and with --fail-open the intent is that
  // an unhealthy backend must not block viewers. (A deliberate deny should
  // be a 4xx, e.g. 403, which is relayed as before.)
  if (auth->options()->fail_open && (status == TS_HTTP_STATUS_NONE || status >= 500)) {
    AuthLogDebug("authorization proxy unreachable or unhealthy (status %d) -- failing open", (int)status);
    return TS_EVENT_ERROR;
  }

  // A real, non-5xx answer (e.g. a deliberate 403 deny): the backend is
  // healthy, whatever its verdict. Denies are never cached.
  if (auth->options()->breaker) {
    auth->options()->breaker->OnSuccess();
  }

  if (auth->read_body) {
    // We can't support sending the auth proxy response back to the client
    // without writing a transform. Since that's more trouble than I want to
    // deal with right now, let's just fail fast ...
    if (HttpIsChunkedEncoding(auth->rheader.buffer, auth->rheader.header)) {
      AuthLogDebug("ignoring chunked authorization proxy response");
    } else {
      // OK, we have a non-chunked response. If there's any content, let's go and
      // buffer it so that we can send it on to the client.
      unsigned nbytes = HttpGetContentLength(auth->rheader.buffer, auth->rheader.header);
      if (nbytes > 0) {
        AuthLogDebug("content length is %u", nbytes);
        return TS_EVENT_HTTP_CONTINUE;
      }
    }
  }
  // We are going to reply with the auth proxy's response. The response body
  // is empty in this case.
  AuthChainAuthorizationResponse(auth);
  return TS_EVENT_HTTP_SEND_RESPONSE_HDR;
}

static TSEvent
StateAuthProxySendResponse(AuthRequestContext *auth, void * /* edata ATS_UNUSED */)
{
  TSMBuffer mbuf;
  TSMLoc mhdr;
  TSHttpStatus status;
  char msg[128];

  // The auth proxy denied this request. We need to copy the auth proxy
  // response header to the client response header, then read any available
  // body data and copy that as well.

  // There's only a client response if the auth proxy sent one. There
  TSReleaseAssert(TSHttpTxnClientRespGet(auth->txn, &mbuf, &mhdr) == TS_SUCCESS);

  TSReleaseAssert(TSHttpHdrCopy(mbuf, mhdr, auth->rheader.buffer, auth->rheader.header) == TS_SUCCESS);

  status = TSHttpHdrStatusGet(mbuf, mhdr);
  snprintf(msg, sizeof(msg), "%d %s\n", status, TSHttpHdrReasonLookup(status));

  TSHttpTxnErrorBodySet(auth->txn, TSstrdup(msg), strlen(msg), TSstrdup("text/plain"));

  // We must not whack the content length for HEAD responses, since the
  // client already knows that there is no body. Forcing content length to
  // zero breaks hdiutil(1) on macOS
  if (TS_HTTP_METHOD_HEAD != auth->method) {
    HttpSetMimeHeader(mbuf, mhdr, TS_MIME_FIELD_CONTENT_LENGTH, 0u);
  }

  AuthLogDebug("sending auth proxy response for status %d", status);

  TSHandleMLocRelease(mbuf, TS_NULL_MLOC, mhdr);
  TSHttpTxnReenable(auth->txn, TS_EVENT_HTTP_CONTINUE);

  return TS_EVENT_CONTINUE;
}

static TSEvent
StateAuthProxyReadHeaders(AuthRequestContext *auth, void * /* edata ATS_UNUSED */)
{
  TSIOBufferBlock blk;
  ssize_t consumed = 0;
  bool complete    = false;

  AuthLogDebug("reading header data, %u bytes available", (unsigned)TSIOBufferReaderAvail(auth->iobuf.reader));

  for (blk = TSIOBufferReaderStart(auth->iobuf.reader); blk; blk = TSIOBufferBlockNext(blk)) {
    const char *ptr;
    const char *end;
    int64_t nbytes;
    TSParseResult result;

    ptr = TSIOBufferBlockReadStart(blk, auth->iobuf.reader, &nbytes);
    if (ptr == nullptr || nbytes == 0) {
      continue;
    }

    end    = ptr + nbytes;
    result = TSHttpHdrParseResp(auth->hparser, auth->rheader.buffer, auth->rheader.header, &ptr, end);
    switch (result) {
    case TS_PARSE_ERROR:
      return TS_EVENT_ERROR;
    case TS_PARSE_DONE:
      // We consumed the buffer we got minus the remainder.
      consumed += (nbytes - std::distance(ptr, end));
      complete = true;
      break;
    case TS_PARSE_CONT:
      consumed += (nbytes - std::distance(ptr, end));
      break;
    }

    if (complete) {
      break;
    }
  }

  AuthLogDebug("consuming %u bytes, %u remain", (unsigned)consumed, (unsigned)TSIOBufferReaderAvail(auth->iobuf.reader));
  TSIOBufferReaderConsume(auth->iobuf.reader, consumed);

  // If the headers are complete, send a completion event.
  return complete ? TS_EVENT_HTTP_READ_REQUEST_HDR : TS_EVENT_CONTINUE;
}

static TSEvent
StateAuthProxyWriteReady(AuthRequestContext *auth, void * /* edata ATS_UNUSED */)
{
  TSVConnWrite(auth->vconn, auth->cont, auth->iobuf.reader, TSIOBufferReaderAvail(auth->iobuf.reader));
  return TS_EVENT_CONTINUE;
}

static TSEvent
StateAuthProxyWriteComplete(AuthRequestContext *auth, void * /* edata ATS_UNUSED */)
{
  // We finished writing the auth proxy request. Kick off a read to get the response.
  auth->iobuf.reset();

  TSVConnRead(auth->vconn, auth->cont, auth->iobuf.buffer, std::numeric_limits<int64_t>::max());

  // XXX Do we need to keep the read and write VIOs and close them?

  return TS_EVENT_CONTINUE;
}

static TSEvent
StateAuthProxyReadContent(AuthRequestContext *auth, void * /* edata ATS_UNUSED */)
{
  unsigned needed;
  int64_t avail = 0;

  avail  = TSIOBufferReaderAvail(auth->iobuf.reader);
  needed = HttpGetContentLength(auth->rheader.buffer, auth->rheader.header);

  AuthLogDebug("we have %u of %u needed bytes", (unsigned)avail, needed);

  if (avail >= needed) {
    // OK, we have what we need. Let's respond to the client request.
    AuthChainAuthorizationResponse(auth);
    return TS_EVENT_HTTP_SEND_RESPONSE_HDR;
  }

  return TS_EVENT_CONTINUE;
}

static TSEvent
StateAuthProxyCompleteContent(AuthRequestContext *auth, void * /* edata ATS_UNUSED */)
{
  unsigned needed;
  int64_t avail;

  avail  = TSIOBufferReaderAvail(auth->iobuf.reader);
  needed = HttpGetContentLength(auth->rheader.buffer, auth->rheader.header);

  AuthLogDebug("we have %u of %u needed bytes", (unsigned)avail, needed);

  if (avail >= needed) {
    // OK, we have what we need. Let's respond to the client request.
    AuthChainAuthorizationResponse(auth);
    return TS_EVENT_HTTP_SEND_RESPONSE_HDR;
  }
  // We got EOS before reading all the content we expected.
  return TS_EVENT_ERROR;
}

// Lets the original request proceed (applying --force-cacheability if
// configured). Deliberately does NOT touch the allow-cache: callers decide.
// A genuine backend 2xx (StateAuthorized) is recorded; a fail-open bypass
// (StateUnauthorized) is an unverified guess and must not be, or a single
// timeout would silently authorize that viewer for the whole cache TTL.
static TSEvent
AuthAuthorizeAndReenable(AuthRequestContext *auth)
{
  const AuthOptions *options = auth->options();

  // Since the original request might have authentication headers, we may
  // need to force ATS to ignore those in order to make it cacheable.
  if (options->force) {
    TSHttpTxnConfigIntSet(auth->txn, TS_CONFIG_HTTP_CACHE_IGNORE_AUTHENTICATION, 1);
  }

  TSHttpTxnReenable(auth->txn, TS_EVENT_HTTP_CONTINUE);
  return TS_EVENT_CONTINUE;
}

// Terminal state. Force a 403 Forbidden response, unless --fail-open is
// configured, in which case we treat "couldn't reach/parse the auth
// proxy" as authorized instead. Note this path is only ever reached via
// TS_EVENT_ERROR / connection-level failures (or, via StateTimeout, our
// own timeout) -- a *legitimate* deny answer from the auth proxy itself
// goes through StateAuthProxySendResponse instead, and is never
// affected by fail_open.
static TSEvent
StateUnauthorized(AuthRequestContext *auth, void *)
{
  const AuthOptions *options = auth->options();

  // Every way into this state is a backend failure (timeout, connect error,
  // EOS, 5xx): feed the circuit breaker and the metrics.
  AuthStatInc(AUTH_STAT_BACKEND_FAIL);
  if (options->breaker && options->breaker->OnFailure()) {
    AuthStatInc(AUTH_STAT_BREAKER_TRIP);
    AuthLogDebug("circuit breaker opened for %s", options->backend_id.c_str());
  }

  if (options->fail_open) {
    AuthLogDebug("authorization proxy unreachable or failed -- failing open");
    return AuthAuthorizeAndReenable(auth); // not StateAuthorized(): must not be cached
  }

  static const char msg[] = "authorization denied\n";

  TSHttpTxnStatusSet(auth->txn, TS_HTTP_STATUS_FORBIDDEN);
  TSHttpTxnErrorBodySet(auth->txn, TSstrdup(msg), sizeof(msg) - 1, TSstrdup("text/plain"));

  TSHttpTxnReenable(auth->txn, TS_EVENT_HTTP_ERROR);
  return TS_EVENT_CONTINUE;
}

// Terminal state. Our own fail-open guard timer fired before the auth
// proxy answered. The action has already fired -- this callback *is*
// that firing -- so there's nothing left to cancel; just null the
// pointer (so ~AuthRequestContext doesn't try to cancel a
// no-longer-pending action) and fall through to the same decision
// StateUnauthorized would make for any other auth-proxy failure.
static TSEvent
StateTimeout(AuthRequestContext *auth, void *edata)
{
  auth->timeout_action = nullptr;
  AuthLogDebug("authorization proxy timed out");
  return StateUnauthorized(auth, edata);
}

// Terminal state. The authorization proxy answered 2xx: allow the original
// request to proceed, and remember the verdict so the next requests from
// this (client IP, did) skip the backend until the entry expires.
static TSEvent
StateAuthorized(AuthRequestContext *auth, void *)
{
  const AuthOptions *options = auth->options();

  AuthLogDebug("request authorized");

  if (options->cache_ttl_ms > 0 && !auth->cache_key.empty()) {
    AuthAllowCache.Insert(auth->cache_key,
                          inhome::AuthCache::ExpiryFor(std::chrono::milliseconds(options->cache_ttl_ms), options->cache_jitter_pct));
  }

  return AuthAuthorizeAndReenable(auth);
}

// Return true if the given request was tagged by a remap rule as needing
// authorization.
static bool
AuthRequestIsTagged(TSHttpTxn txn)
{
  return AuthTaggedRequestArg != -1 && TSUserArgGet(txn, AuthTaggedRequestArg) != nullptr;
}

// Return true if the internal requests can be cached.
static bool
CacheInternalRequests(TSHttpTxn txn)
{
  AuthOptions *opt = static_cast<AuthOptions *>(TSUserArgGet(txn, AuthTaggedRequestArg));
  return opt ? opt->cache_internal_requests : false;
}

// Client address as text ("203.0.113.7", "2001:db8::1"); "" if unavailable.
// This is the same address StateAuthProxyConnect hands to TSHttpConnect(), i.e.
// the one the backend is being asked about.
static std::string
AuthClientIpString(TSHttpTxn txn)
{
  const sockaddr *addr       = TSHttpTxnClientAddrGet(txn);
  char buf[INET6_ADDRSTRLEN] = {0};

  if (addr == nullptr) {
    return std::string();
  }
  if (addr->sa_family == AF_INET) {
    const auto *sin = reinterpret_cast<const sockaddr_in *>(addr);
    if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) == nullptr) {
      return std::string();
    }
  } else if (addr->sa_family == AF_INET6) {
    const auto *sin6 = reinterpret_cast<const sockaddr_in6 *>(addr);
    if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)) == nullptr) {
      return std::string();
    }
  } else {
    return std::string();
  }
  return std::string(buf);
}

// Cache key for the request whose URL is (bufp, url); "" if it must not be
// cached (see inhome::MakeCacheKey for exactly when).
static std::string
AuthCacheKeyFor(const AuthOptions *options, TSHttpTxn txn, TSMBuffer bufp, TSMLoc url)
{
  int qlen          = 0;
  const char *query = TSUrlHttpQueryGet(bufp, url, &qlen);

  return inhome::MakeCacheKey(options->backend_id, AuthClientIpString(txn),
                              (query != nullptr && qlen > 0) ? std::string(query, qlen) : std::string());
}

// Same key, taken from the transaction's client request. Used once the request
// is past remap (no rri any more), at the moment the backend request is built
// from that very same URL.
static std::string
AuthCacheKeyForTxn(const AuthOptions *options, TSHttpTxn txn)
{
  TSMBuffer bufp;
  TSMLoc hdr, url;
  std::string key;

  if (TSHttpTxnClientReqGet(txn, &bufp, &hdr) != TS_SUCCESS) {
    return key;
  }
  if (TSHttpHdrUrlGet(bufp, hdr, &url) == TS_SUCCESS) {
    key = AuthCacheKeyFor(options, txn, bufp, url);
    TSHandleMLocRelease(bufp, hdr, url);
  }
  TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr);
  return key;
}

static int
AuthProxyGlobalHook(TSCont /* cont ATS_UNUSED */, TSEvent event, void *edata)
{
  TSHttpTxn txn = static_cast<TSHttpTxn>(edata);

  AuthLogDebug("handling event=%d edata=%p", (int)event, edata);

  switch (event) {
  case TS_EVENT_HTTP_POST_REMAP:
    // Ignore internal requests since we generated them.
    if (TSHttpTxnIsInternal(txn)) {
      // All our internal requests *must* hit the origin since it is the
      // agent that needs to make the authorization decision. We can't
      // allow that to be cached. Note that this only affects the remap
      // rule that this plugin is instantiated for, *unless* you are using
      // it as a global plugin (not highly recommended). Also remember that
      // the HEAD auth request might trip a different remap rule, particularly
      // if you do not have pristine host-headers enabled.
      if (!CacheInternalRequests(txn))
        TSHttpTxnConfigIntSet(txn, TS_CONFIG_HTTP_CACHE_HTTP, 0);
      AuthLogDebug("re-enabling internal transaction");
      TSHttpTxnReenable(txn, TS_EVENT_HTTP_CONTINUE);
      return TS_EVENT_NONE;
    }
    // Hook this request if we are in global authorization mode or if a
    // remap rule tagged it.
    if (AuthGlobalOptions != nullptr || AuthRequestIsTagged(txn)) {
      AuthRequestContext *auth = AuthRequestContext::allocate();
      auth->state              = StateTableInit;
      auth->txn                = txn;
      // Remap mode only (tagged by TSRemapDoRemap): remember which cache
      // entry a backend "allow" should be recorded under.
      if (AuthRequestIsTagged(txn) && auth->options()->cache_ttl_ms > 0) {
        auth->cache_key = AuthCacheKeyForTxn(auth->options(), txn);
      }
      return AuthRequestContext::dispatch(auth->cont, event, edata);
    }
    // fallthrough

  default:
    return TS_EVENT_NONE;
  }
}

static AuthOptions *
AuthParseOptions(int argc, const char **argv)
{
  // The const_cast<> here is magic to work around a flaw in the definition of struct option
  // on some platforms (e.g. Solaris / Illumos). On sane platforms (e.g. linux), it'll get
  // automatically casted back to the const char*, as the struct is defined in <getopt.h>.
  static const struct option longopt[] = {
    {const_cast<char *>("auth-host"), required_argument, nullptr, 'h'},
    {const_cast<char *>("auth-port"), required_argument, nullptr, 'p'},
    {const_cast<char *>("auth-transform"), required_argument, nullptr, 't'},
    {const_cast<char *>("force-cacheability"), no_argument, nullptr, 'c'},
    {const_cast<char *>("cache-internal"), no_argument, nullptr, 'i'},
    {const_cast<char *>("uri-pattern"), required_argument, nullptr, 'u'},
    {const_cast<char *>("fail-open"), no_argument, nullptr, 'f'},
    {const_cast<char *>("timeout-ms"), required_argument, nullptr, 'm'},
    {const_cast<char *>("cache-ttl-ms"), required_argument, nullptr, 'T'},
    {const_cast<char *>("cache-jitter-pct"), required_argument, nullptr, 'J'},
    {const_cast<char *>("breaker-failures"), required_argument, nullptr, 'B'},
    {const_cast<char *>("breaker-cooldown-ms"), required_argument, nullptr, 'K'},
    {nullptr, 0, nullptr, 0},
  };

  AuthOptions *options = AuthNew<AuthOptions>();

  options->transform = AuthWriteRedirectedRequest;

  for (;;) {
    int opt;

    opt = getopt_long(argc, const_cast<char *const *>(argv), "", longopt, nullptr);
    switch (opt) {
    case 'h':
      options->hostname = optarg;
      break;
    case 'p':
      options->hostport = std::atoi(optarg);
      break;
    case 'c':
      options->force = true;
      break;
    case 'i':
      options->cache_internal_requests = true;
      break;
    case 'u':
      try {
        options->uri_pattern = std::regex(optarg, std::regex::icase | std::regex::optimize);
        options->has_pattern = true;
      } catch (const std::regex_error &e) {
        AuthLogError("[inhomeproxy] invalid --uri-pattern regex '%s': %s -- authorizing ALL requests for this rule", optarg,
                     e.what());
        // Fail safe on a config mistake: fall back to "authorize
        // everything" (stock behavior) rather than silently exempting
        // every request from authorization because a regex typo made
        // has_pattern stay false in some *other*, more dangerous way.
        options->has_pattern = false;
      }
      break;
    case 'f':
      options->fail_open = true;
      break;
    case 'm':
      options->timeout_ms = std::atoi(optarg);
      if (options->timeout_ms <= 0) {
        AuthLogError("[inhomeproxy] invalid --timeout-ms '%s', using default of 2000ms", optarg);
        options->timeout_ms = 2000;
      }
      break;
    case 'T':
      options->cache_ttl_ms = std::atoi(optarg);
      if (options->cache_ttl_ms < 0) {
        AuthLogError("[inhomeproxy] invalid --cache-ttl-ms '%s', caching disabled", optarg);
        options->cache_ttl_ms = 0;
      }
      break;
    case 'J': {
      int pct = std::atoi(optarg);
      if (pct < 0 || pct > 90) {
        AuthLogError("[inhomeproxy] --cache-jitter-pct '%s' out of range 0-90, using %d", optarg, pct < 0 ? 0 : 90);
        pct = pct < 0 ? 0 : 90;
      }
      options->cache_jitter_pct = static_cast<unsigned>(pct);
      break;
    }
    case 'B':
      options->breaker_failures = std::atoi(optarg);
      if (options->breaker_failures < 0) {
        AuthLogError("[inhomeproxy] invalid --breaker-failures '%s', breaker disabled", optarg);
        options->breaker_failures = 0;
      }
      break;
    case 'K':
      options->breaker_cooldown_ms = std::atoi(optarg);
      if (options->breaker_cooldown_ms <= 0) {
        AuthLogError("[inhomeproxy] invalid --breaker-cooldown-ms '%s', using default of 10000ms", optarg);
        options->breaker_cooldown_ms = 10000;
      }
      break;
    case 't':
      if (strcasecmp(optarg, "redirect") == 0) {
        options->transform = AuthWriteRedirectedRequest;
      } else if (strcasecmp(optarg, "head") == 0) {
        options->transform = AuthWriteHeadRequest;
      } else if (strcasecmp(optarg, "range") == 0) {
        options->transform = AuthWriteRangeRequest;
      } else {
        AuthLogError("invalid authorization transform '%s'", optarg);
        // XXX make this a fatal error?
      }
      break;
    }

    if (opt == -1) {
      break;
    }
  }

  if (options->hostname.empty()) {
    options->hostname = "127.0.0.1";
  }

  // Scope for cache keys and the breaker: rules that talk to the same backend
  // share verdicts and breaker state; rules that talk to different ones never do.
  options->backend_id = options->hostname;
  if (options->hostport != -1) {
    options->backend_id += ":" + std::to_string(options->hostport);
  }

  if (options->breaker_failures > 0) {
    if (!options->fail_open) {
      AuthLogError("[inhomeproxy] --breaker-failures requires --fail-open (an open breaker bypasses the backend and allows the "
                   "request); circuit breaker disabled");
    } else {
      // probe window a little above the request timeout, so a probe that never
      // reports back cannot keep the breaker open forever.
      options->breaker = inhome::GetBreaker(options->backend_id, options->breaker_failures,
                                            std::chrono::milliseconds(options->breaker_cooldown_ms),
                                            std::chrono::milliseconds(options->timeout_ms + 1000));
    }
  }

  return options;
}

#undef LONGOPT_OPTION_CAST

void
TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;

  info.plugin_name   = (char *)"inhomeproxy";
  // NOTE: this is a locally-modified fork, not the ASF-maintained
  // authproxy plugin -- vendor_name/support_email below are
  // placeholders. Replace with your own org's info if you want
  // TSPluginRegister's diagnostics to reflect that accurately.
  info.vendor_name   = (char *)"local-fork-of-authproxy";
  info.support_email = (char *)"";

  if (TSPluginRegister(&info) != TS_SUCCESS) {
    AuthLogError("plugin registration failed");
  }

  AuthStatsInit();

  TSReleaseAssert(TSUserArgIndexReserve(TS_USER_ARGS_TXN, "InHomeProxy", "InHomeProxy authorization tag", &AuthTaggedRequestArg) ==
                  TS_SUCCESS);

  AuthOsDnsContinuation = TSContCreate(AuthProxyGlobalHook, nullptr);
  AuthGlobalOptions     = AuthParseOptions(argc, argv);
  AuthLogDebug("using authorization proxy at %s:%d", AuthGlobalOptions->hostname.c_str(), AuthGlobalOptions->hostport);

  // Use the appropriate hook for consistent auth checks.
  TSHttpHookAdd(TS_HTTP_POST_REMAP_HOOK, AuthOsDnsContinuation);
}

TSReturnCode
TSRemapInit(TSRemapInterface * /* api ATS_UNUSED */, char * /* err ATS_UNUSED */, int /* errsz ATS_UNUSED */)
{
  AuthStatsInit();

  TSReleaseAssert(TSUserArgIndexReserve(TS_USER_ARGS_TXN, "InHomeProxy", "InHomeProxy authorization tag", &AuthTaggedRequestArg) ==
                  TS_SUCCESS);

  AuthOsDnsContinuation = TSContCreate(AuthProxyGlobalHook, nullptr);
  return TS_SUCCESS;
}

TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **instance, char * /* err ATS_UNUSED */, int /* errsz ATS_UNUSED */)
{
  AuthOptions *options;

  AuthLogDebug("using authorization proxy for remapping %s -> %s", argv[0], argv[1]);

  // The first two arguments are the "from" and "to" URL string. We need to
  // skip them, but we also require that there be an option to masquerade as
  // argv[0], so we increment the argument indexes by 1 rather than by 2.
  argc--;
  argv++;
  options = AuthParseOptions(argc, (const char **)argv);

  *instance = options;
  return TS_SUCCESS;
}

void
TSRemapDeleteInstance(void *instance)
{
  AuthOptions *options = static_cast<AuthOptions *>(instance);
  AuthDelete(options);
}

TSRemapStatus
TSRemapDoRemap(void *instance, TSHttpTxn txn, TSRemapRequestInfo *rri)
{
  AuthOptions *options = static_cast<AuthOptions *>(instance);

  if (!AuthRequestUriRequiresAuthorization(options, rri->requestBufp, rri->requestUrl)) {
    AuthLogDebug("request URI does not match --uri-pattern; skipping authorization proxy entirely");
    return TSREMAP_NO_REMAP;
  }

  // The plugin's own authorization sub-requests must never take the cache or
  // breaker shortcuts below: the POST_REMAP hook ignores them, so a breaker
  // probe elected here would never report back.
  if (!TSHttpTxnIsInternal(txn)) {
    // 1. Cache first. A cache hit is a legitimate allow whatever state the
    //    breaker is in -- and checking the breaker first could elect a
    //    half-open probe for a request that then never reaches the backend.
    if (options->cache_ttl_ms > 0) {
      std::string key = AuthCacheKeyFor(options, txn, rri->requestBufp, rri->requestUrl);
      if (key.empty()) {
        AuthStatInc(AUTH_STAT_CACHE_SKIP); // uncacheable: always asks the backend
      } else if (AuthAllowCache.Contains(key)) {
        AuthStatInc(AUTH_STAT_CACHE_HIT);
        AuthLogDebug("cache hit for '%s' -- skipping authorization proxy entirely", key.c_str());
        // StateAuthorized would have applied this; we are bypassing it.
        if (options->force) {
          TSHttpTxnConfigIntSet(txn, TS_CONFIG_HTTP_CACHE_IGNORE_AUTHENTICATION, 1);
        }
        return TSREMAP_NO_REMAP;
      } else {
        AuthStatInc(AUTH_STAT_CACHE_MISS);
      }
    }

    // 2. Circuit breaker. Open => do not call the backend; fail open at once.
    //    Never cached, so viewers are re-checked as soon as the backend is back.
    if (options->breaker && options->breaker->ShouldBypass()) {
      AuthStatInc(AUTH_STAT_BREAKER_BYPASS);
      AuthLogDebug("circuit breaker open for %s -- failing open without calling it", options->backend_id.c_str());
      return TSREMAP_NO_REMAP;
    }
  }

  TSUserArgSet(txn, AuthTaggedRequestArg, options);
  TSHttpTxnHookAdd(txn, TS_HTTP_POST_REMAP_HOOK, AuthOsDnsContinuation);

  return TSREMAP_NO_REMAP;
}

// vim: set ts=4 sw=4 et :
