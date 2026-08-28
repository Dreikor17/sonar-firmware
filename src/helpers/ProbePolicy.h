#pragma once

// Echo Observer-Probe -- pure policy predicates.
//
// Extracted so the safety-critical decisions are host-testable with no Arduino,
// radio or crypto in the way, following the convention already used by
// MQTTConnectionPolicy.h / MQTTPacketQueuePolicy.h (see test/README.md, "Keep
// logic testable by extracting pure functions into headers").
//
// Exercised by test/test_probe_policy.

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Mirror of OUT_PATH_UNKNOWN (src/helpers/ContactInfo.h:6) so this header does
// not have to pull in the Arduino-side contact types.
#ifndef PROBE_OUT_PATH_UNKNOWN
  #define PROBE_OUT_PATH_UNKNOWN 0xFF
#endif

// Default ceiling on probe SESSIONS per hour when probe_max_per_hour is 0.
//
// 60 covers a ~50-node mesh on an hourly cadence with retry headroom. The old 12
// was sized for occasional gap-filling and would refuse most of a sweep.
//
// NOTE the window is FIXED, not sliding: it resets wholesale when it expires, so
// up to 2x this can land inside an arbitrary rolling hour. Size with that in mind
// -- 60 means "120 worst case". Raising it was deliberately held back until route
// persistence landed, because before that a higher budget was just a flood
// multiplier.
#ifndef PROBE_DEFAULT_MAX_PER_HOUR
  #define PROBE_DEFAULT_MAX_PER_HOUR 60
#endif

// The packet-level runaway backstop is deliberately far above the session
// budget: a well-behaved multi-step session must never reach it.
#ifndef PROBE_PACKET_GUARD_MULTIPLIER
  #define PROBE_PACKET_GUARD_MULTIPLIER 8
#endif

// How far apart the Observer clock and a command timestamp may be, in seconds.
#ifndef PROBE_DEFAULT_CLOCK_SKEW_SECS
  #define PROBE_DEFAULT_CLOCK_SKEW_SECS 300
#endif

// ---------------------------------------------------------------------------
// Flood safety
// ---------------------------------------------------------------------------

// THE hard safety rule, as a pure predicate.
//
// Reaching a target with no learned path means the send primitive would FLOOD a
// login/request datagram. That is never a PAYLOAD_TYPE_ADVERT -- the Observer
// emits no flood adverts at all -- but it is still a flood, so it stays behind
// an explicitly enabled, rate-limited switch that defaults OFF.
//
// Returns true when the flood must be vetoed (caller falls back to zero hop).
static inline bool probeShouldVetoFlood(bool allow_flood, uint8_t out_path_len) {
  if (out_path_len != PROBE_OUT_PATH_UNKNOWN) return false;  // routed: send direct
  return !allow_flood;
}

// True when the session has a usable learned path and should be sent direct.
static inline bool probeRouteIsDirect(uint8_t out_path_len) {
  return out_path_len != PROBE_OUT_PATH_UNKNOWN;
}

// Effective session budget: 0 in prefs means "use the built-in default".
static inline uint16_t probeEffectiveMaxPerHour(uint16_t configured) {
  return configured ? configured : (uint16_t)PROBE_DEFAULT_MAX_PER_HOUR;
}

static inline uint16_t probePacketGuardCeiling(uint16_t configured) {
  uint32_t v = (uint32_t)probeEffectiveMaxPerHour(configured) * PROBE_PACKET_GUARD_MULTIPLIER;
  return (v > 0xFFFFu) ? 0xFFFFu : (uint16_t)v;
}

// ---------------------------------------------------------------------------
// Route cache
// ---------------------------------------------------------------------------

// How many target routes an Observer remembers between sessions.
//
// SIZE THIS TO THE NUMBER OF REGULARLY-PROBED NODES. It is an LRU, so exceeding
// it does not fail -- the oldest entry is evicted and that node pays one flood on
// its next probe, then re-caches, evicting someone else. Past capacity that
// degenerates into thrashing and the per-sweep floods come back, which is the
// whole problem the cache exists to solve. 64 covers a ~50-node mesh with
// headroom; raising it is a rebuild, not a redesign.
//
// It is also PER-OBSERVER: sharding targets across several Observers divides the
// pressure, so three Observers covering 100 nodes need ~35 entries each.
#ifndef PROBE_ROUTE_CACHE
  #define PROBE_ROUTE_CACHE 64
#endif

// Bytes of path stored per entry. MAX_PATH_SIZE is 64, but that is the
// theoretical worst case (63 hops); MeshCore routes on 1-byte hop hashes and
// real paths run a handful of hops, so storing 64 would waste ~59 bytes an entry.
// 16 holds 16 single-byte hops. A longer path simply is not cached -- that probe
// keeps flooding, which is graceful rather than a cliff.
#ifndef PROBE_ROUTE_MAX_PATH
  #define PROBE_ROUTE_MAX_PATH 16
#endif

// Decoded byte length of an encoded path_len (hash count in the low 6 bits,
// hash size - 1 in the top 2). Used to reject paths too long to cache.
static inline uint8_t probeRoutePathBytes(uint8_t path_len) {
  uint8_t hash_count = path_len & 63;
  uint8_t hash_size  = (uint8_t)((path_len >> 6) + 1);
  return (uint8_t)(hash_count * hash_size);
}

static inline bool probeRoutePathCacheable(uint8_t path_len) {
  return probeRoutePathBytes(path_len) <= PROBE_ROUTE_MAX_PATH;
}

// A cached route older than this is not trusted. The mesh reshapes, and a stale
// path fails silently (the target never answers) rather than loudly, so the
// ceiling matters more than precision.
#ifndef PROBE_ROUTE_TTL_SECS
  #define PROBE_ROUTE_TTL_SECS (8u * 3600u)
#endif

// True when a cached route is still inside its TTL. now/learned_at are epoch
// seconds; a clock that has gone backwards fails the entry closed rather than
// trusting it forever.
static inline bool probeRouteFresh(uint32_t now, uint32_t learned_at, uint32_t ttl_secs) {
  if (learned_at == 0) return false;
  if (now < learned_at) return false;          // clock stepped back: distrust
  return (now - learned_at) <= ttl_secs;
}

// Minimum seconds between the END of one session and the START of the next.
// The Observer has no pacing of its own otherwise -- it starts the next queued
// session immediately -- so a controller that batches would put back-to-back
// sessions on the radio. 0 disables the gap.
#ifndef PROBE_DEFAULT_GAP_SECS
  #define PROBE_DEFAULT_GAP_SECS 5
#endif

// ---------------------------------------------------------------------------
// Freshness / replay
// ---------------------------------------------------------------------------

// Below this the node's clock cannot plausibly be NTP-corrected, so iat/exp are
// meaningless and every command must be refused. A bare `now == 0` test does not
// work: an un-synced node still reports a non-zero build-time epoch.
#ifndef PROBE_MIN_VALID_EPOCH
  #define PROBE_MIN_VALID_EPOCH 1767225600u        // 2026-01-01T00:00:00Z
#endif

// A tasking command carries iat/exp in epoch seconds. Reject anything issued too
// far in the past or already expired, and fail closed while the clock is
// implausible (the bridge defers slot setup until NTP has synced).
static inline bool probeTimestampOk(uint32_t now, uint32_t iat, uint32_t exp, uint32_t skew_secs) {
  if (now < PROBE_MIN_VALID_EPOCH) return false;    // fail closed: clock not trustworthy
  if (exp != 0 && now > exp) return false;          // expired
  if (iat != 0) {
    if (iat > now && (iat - now) > skew_secs) return false;   // too far in the future
    if (now > iat && (now - iat) > skew_secs) return false;   // too stale
  }
  return true;
}

// Small ring of recently accepted nonces. Fixed size, no allocation, so it is
// safe to hold as a member on the mesh loop task.
// At gap-filler rates 8 was plenty. At mesh-polling rates it covers well under a
// second, which would quietly degrade replay protection to the iat window alone.
#ifndef PROBE_NONCE_RING
  #define PROBE_NONCE_RING 32
#endif

struct ProbeNonceRing {
  uint32_t seen[PROBE_NONCE_RING];
  uint8_t  next;
  uint8_t  count;
};

static inline void probeNonceRingInit(ProbeNonceRing* r) {
  if (!r) return;
  memset(r, 0, sizeof(*r));
}

static inline bool probeNonceSeen(const ProbeNonceRing* r, uint32_t nonce) {
  if (!r) return false;
  for (uint8_t i = 0; i < r->count; i++) {
    if (r->seen[i] == nonce) return true;
  }
  return false;
}

// Records the nonce. Returns false when it was already present (a replay), in
// which case nothing is recorded and the caller must refuse the command.
static inline bool probeNonceAccept(ProbeNonceRing* r, uint32_t nonce) {
  if (!r) return false;
  if (probeNonceSeen(r, nonce)) return false;
  r->seen[r->next] = nonce;
  r->next = (uint8_t)((r->next + 1) % PROBE_NONCE_RING);
  if (r->count < PROBE_NONCE_RING) r->count++;
  return true;
}

// Combined admission check for a decoded command envelope.
static inline bool probeReplayOk(ProbeNonceRing* ring, uint32_t now, uint32_t iat,
                                 uint32_t exp, uint32_t nonce, uint32_t skew_secs) {
  if (!probeTimestampOk(now, iat, exp, skew_secs)) return false;
  return probeNonceAccept(ring, nonce);
}

// ---------------------------------------------------------------------------
// Controller key
// ---------------------------------------------------------------------------

// An all-zero controller public key means "unset". Fail closed: a node that has
// not been given a controller key refuses every command.
static inline bool probeControllerKeySet(const uint8_t* pubkey, size_t len) {
  if (!pubkey || len == 0) return false;
  for (size_t i = 0; i < len; i++) {
    if (pubkey[i] != 0) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Per-target flood backoff
// ---------------------------------------------------------------------------
//
// A flood is re-broadcast by every node in the mesh, so it is the single most
// expensive thing a probe can do. One flood to learn a path is a fair price; the
// problem is a target that never answers -- a node that is switched off, moved
// out of range, or gone for good. Without a brake, every scheduled poll of that
// target floods again, forever, on somebody else's mesh.
//
// So each CONSECUTIVE failed flood pushes the next permitted flood for that
// target further out. A healthy node never enters the ladder at all (its floods
// succeed and the counter resets); a dead one costs a handful of floods over the
// first hour and then roughly one per hour, instead of one per poll.
//
// This is deliberately per TARGET, not global: one unreachable node must not
// block probing of the other forty-nine.

#ifndef PROBE_FLOOD_BACKOFF_SLOTS
  #define PROBE_FLOOD_BACKOFF_SLOTS 32
#endif

// Consecutive-failure ladder, in seconds. Index is capped at the last entry, so a
// permanently dead target settles at one flood per hour rather than growing without
// bound -- a node that comes back should be found again within the hour.
//
// THE FIRST FAILURE IS FREE (0s), and that is load-bearing rather than lenient. One
// unanswered flood is usually transient: a node mid-reboot, a collision, a moment of
// interference. Holding off after a single miss broke Echo's own clock-sync recovery --
// it reboots a node deliberately, then retries for 60s while the node comes back, and a
// 5-minute hold meant every one of those retries was refused. Charging from the SECOND
// consecutive failure keeps that working while still bounding a target that is really
// gone: it reaches the 30-minute rung after four misses.
static inline uint32_t probeFloodBackoffSecs(uint8_t consecutive_fails) {
  static const uint32_t kLadder[] = { 0u, 30u, 120u, 600u, 1800u, 3600u };
  const size_t n = sizeof(kLadder) / sizeof(kLadder[0]);
  if (consecutive_fails == 0) return 0;
  size_t i = (size_t)(consecutive_fails - 1);
  if (i >= n) i = n - 1;
  return kLadder[i];
}

// True when a flood to this target is still held off. Fails OPEN on an untrusted
// clock: before NTP we cannot compare timestamps, and refusing every flood then
// would leave a freshly booted node unable to learn any route at all.
static inline bool probeFloodHeldOff(uint32_t now, uint32_t next_ok_at) {
  if (next_ok_at == 0) return false;
  if (now < PROBE_MIN_VALID_EPOCH) return false;
  return now < next_ok_at;
}
