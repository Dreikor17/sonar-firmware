// Host contract tests for the Echo Observer-Probe safety policy.
//
// These cover the project's HARD rule: a probe must never cause repeated flood
// traffic, and a node that has not been given a controller key must refuse every
// command.

#include <gtest/gtest.h>

#include "helpers/ProbePolicy.h"

namespace {

// --- flood veto ------------------------------------------------------------

TEST(ProbePolicy, FloodVetoTruthTable) {
  // No learned path + flood disabled  => VETO (caller falls back to zero hop)
  EXPECT_TRUE(probeShouldVetoFlood(false, PROBE_OUT_PATH_UNKNOWN));
  // No learned path + flood explicitly enabled => allowed
  EXPECT_FALSE(probeShouldVetoFlood(true, PROBE_OUT_PATH_UNKNOWN));
  // A learned path is never a flood either way
  EXPECT_FALSE(probeShouldVetoFlood(false, 0));
  EXPECT_FALSE(probeShouldVetoFlood(false, 1));
  EXPECT_FALSE(probeShouldVetoFlood(true, 3));
}

// The default must be OFF. If this test ever needs changing, the change is
// almost certainly wrong.
TEST(ProbePolicy, FloodIsVetoedByDefault) {
  const bool default_allow_flood = false;
  EXPECT_TRUE(probeShouldVetoFlood(default_allow_flood, PROBE_OUT_PATH_UNKNOWN));
}

TEST(ProbePolicy, RouteIsDirectOnlyWithAKnownPath) {
  EXPECT_FALSE(probeRouteIsDirect(PROBE_OUT_PATH_UNKNOWN));
  EXPECT_TRUE(probeRouteIsDirect(0));      // zero hop is still a known path
  EXPECT_TRUE(probeRouteIsDirect(5));
}

// --- budget ----------------------------------------------------------------

TEST(ProbePolicy, ZeroMaxPerHourMeansBuiltInDefault) {
  EXPECT_EQ(probeEffectiveMaxPerHour(0), PROBE_DEFAULT_MAX_PER_HOUR);
  EXPECT_EQ(probeEffectiveMaxPerHour(3), 3);
}

// The packet guard must sit well above the session budget so a normal multi-step
// session (login + ver-ident + status + telemetry) can never trip it.
TEST(ProbePolicy, PacketGuardLeavesRoomForMultiStepSessions) {
  EXPECT_GE(probePacketGuardCeiling(2), (uint16_t)(2 * 4));
  EXPECT_EQ(probePacketGuardCeiling(2), (uint16_t)(2 * PROBE_PACKET_GUARD_MULTIPLIER));
  EXPECT_EQ(probePacketGuardCeiling(0),
            (uint16_t)(PROBE_DEFAULT_MAX_PER_HOUR * PROBE_PACKET_GUARD_MULTIPLIER));
}

TEST(ProbePolicy, PacketGuardSaturatesRatherThanWrapping) {
  EXPECT_EQ(probePacketGuardCeiling(60000), 0xFFFFu);
}

// --- route cache freshness --------------------------------------------------

// A cached route is what stops every login-based session re-flooding its first
// step. Trusting a stale one is the opposite failure: the target never answers
// and the session times out silently, so the TTL has to actually bite.
TEST(ProbePolicy, RouteIsFreshInsideTheTtlAndStaleOutside) {
  const uint32_t learned = PROBE_MIN_VALID_EPOCH + 10000;
  const uint32_t ttl = PROBE_ROUTE_TTL_SECS;
  EXPECT_TRUE(probeRouteFresh(learned, learned, ttl));            // same instant
  EXPECT_TRUE(probeRouteFresh(learned + ttl, learned, ttl));      // boundary is inclusive
  EXPECT_FALSE(probeRouteFresh(learned + ttl + 1, learned, ttl)); // one second past
}

// learned_at == 0 is the free-slot marker, never a route learned at the epoch.
TEST(ProbePolicy, UnsetRouteSlotIsNeverFresh) {
  EXPECT_FALSE(probeRouteFresh(PROBE_MIN_VALID_EPOCH + 5000, 0, PROBE_ROUTE_TTL_SECS));
}

// A backward NTP correction would otherwise make now - learned_at underflow and
// wrap to something enormous, which reads as "fresh forever".
TEST(ProbePolicy, ClockGoingBackwardsDistrustsTheEntry) {
  const uint32_t learned = PROBE_MIN_VALID_EPOCH + 10000;
  EXPECT_FALSE(probeRouteFresh(learned - 1, learned, PROBE_ROUTE_TTL_SECS));
  EXPECT_FALSE(probeRouteFresh(learned - 100000, learned, PROBE_ROUTE_TTL_SECS));
}

// --- freshness -------------------------------------------------------------

// A node whose clock is not plausibly NTP-corrected must refuse to act on
// iat/exp rather than guess. Note a bare now == 0 test would NOT catch this: an
// un-synced node still reports a non-zero build-time epoch, which is exactly why
// the predicate uses a plausibility floor.
TEST(ProbePolicy, FailsClosedWhileClockIsImplausible) {
  const uint32_t below = PROBE_MIN_VALID_EPOCH - 1;
  EXPECT_FALSE(probeTimestampOk(0, below, below + 60, 300));
  EXPECT_FALSE(probeTimestampOk(below, below, below + 60, 300));
  EXPECT_FALSE(probeTimestampOk(1000, 1000, 2000, 300));   // a stale build epoch
  // ...and accepts once the clock is plausible
  const uint32_t ok_now = PROBE_MIN_VALID_EPOCH + 10;
  EXPECT_TRUE(probeTimestampOk(ok_now, ok_now, ok_now + 60, 300));
}

TEST(ProbePolicy, RejectsExpiredAndStaleAndFarFuture) {
  const uint32_t now = PROBE_MIN_VALID_EPOCH + 1000000;
  const uint32_t skew = 300;
  EXPECT_TRUE(probeTimestampOk(now, now, now + 60, skew));
  EXPECT_FALSE(probeTimestampOk(now, now, now - 1, skew));            // expired
  EXPECT_FALSE(probeTimestampOk(now, now - (skew + 1), 0, skew));     // too stale
  EXPECT_FALSE(probeTimestampOk(now, now + (skew + 1), 0, skew));     // too far ahead
}

TEST(ProbePolicy, SkewBoundariesAreInclusive) {
  const uint32_t now = PROBE_MIN_VALID_EPOCH + 500000;
  const uint32_t skew = 300;
  EXPECT_TRUE(probeTimestampOk(now, now - skew, 0, skew));
  EXPECT_TRUE(probeTimestampOk(now, now + skew, 0, skew));
  EXPECT_FALSE(probeTimestampOk(now, now - skew - 1, 0, skew));
  EXPECT_FALSE(probeTimestampOk(now, now + skew + 1, 0, skew));
}

TEST(ProbePolicy, ZeroExpMeansNoExpiry) {
  const uint32_t now = PROBE_MIN_VALID_EPOCH + 1000;
  EXPECT_TRUE(probeTimestampOk(now, now, 0, 300));
}

// --- replay ----------------------------------------------------------------

TEST(ProbePolicy, NonceIsAcceptedOnceThenRefused) {
  ProbeNonceRing r;
  probeNonceRingInit(&r);
  EXPECT_TRUE(probeNonceAccept(&r, 42));
  EXPECT_FALSE(probeNonceAccept(&r, 42));      // replay
  EXPECT_TRUE(probeNonceAccept(&r, 43));
}

TEST(ProbePolicy, NonceRingEvictsOldestWhenFull) {
  ProbeNonceRing r;
  probeNonceRingInit(&r);
  for (uint32_t i = 0; i < PROBE_NONCE_RING; i++) {
    EXPECT_TRUE(probeNonceAccept(&r, i + 1)) << "nonce " << (i + 1);
  }
  EXPECT_FALSE(probeNonceAccept(&r, 1));       // still remembered
  EXPECT_TRUE(probeNonceAccept(&r, 999));      // pushes the oldest out
  EXPECT_TRUE(probeNonceAccept(&r, 1));        // 1 has now aged out of the ring
}

TEST(ProbePolicy, ReplayOkCombinesFreshnessAndNonce) {
  ProbeNonceRing r;
  probeNonceRingInit(&r);
  const uint32_t now = PROBE_MIN_VALID_EPOCH + 2000000;
  EXPECT_TRUE(probeReplayOk(&r, now, now, now + 60, 7, 300));
  EXPECT_FALSE(probeReplayOk(&r, now, now, now + 60, 7, 300));   // same nonce
  // A stale command must not consume a nonce slot
  EXPECT_FALSE(probeReplayOk(&r, now, now - 5000, 0, 8, 300));
  EXPECT_TRUE(probeReplayOk(&r, now, now, now + 60, 8, 300));
}

// --- controller key --------------------------------------------------------

TEST(ProbePolicy, UnsetControllerKeyFailsClosed) {
  uint8_t zero[32] = {0};
  EXPECT_FALSE(probeControllerKeySet(zero, sizeof(zero)));

  uint8_t set[32] = {0};
  set[31] = 1;                       // a single non-zero byte counts as set
  EXPECT_TRUE(probeControllerKeySet(set, sizeof(set)));

  EXPECT_FALSE(probeControllerKeySet(nullptr, 32));
  EXPECT_FALSE(probeControllerKeySet(set, 0));
}


// --- per-target flood backoff ---------------------------------------------
// A flood is rebroadcast by every node in the mesh, so an unanswered target must
// not be re-flooded on every poll. These pin the ladder's shape.

TEST(ProbePolicy, FloodBackoffLadderGrowsThenCaps) {
  EXPECT_EQ(0u,    probeFloodBackoffSecs(0));      // no failures at all
  // The FIRST miss is free. One unanswered flood is usually transient, and holding off
  // after it broke clock-sync recovery: that flow reboots a node on purpose and then
  // retries for ~60s while it comes back.
  EXPECT_EQ(0u,    probeFloodBackoffSecs(1));
  EXPECT_EQ(30u,   probeFloodBackoffSecs(2));
  EXPECT_EQ(120u,  probeFloodBackoffSecs(3));      // 2m
  EXPECT_EQ(600u,  probeFloodBackoffSecs(4));      // 10m
  EXPECT_EQ(1800u, probeFloodBackoffSecs(5));      // 30m
  EXPECT_EQ(3600u, probeFloodBackoffSecs(6));      // 1h
  // Caps rather than growing without bound: a node that comes back should be
  // found again within the hour, not after a day.
  EXPECT_EQ(3600u, probeFloodBackoffSecs(7));
  EXPECT_EQ(3600u, probeFloodBackoffSecs(200));
  EXPECT_EQ(3600u, probeFloodBackoffSecs(255));
}

TEST(ProbePolicy, FloodBackoffStillBoundsATrulyDeadTarget) {
  // The free first miss must not defeat the point of the brake. Four consecutive
  // misses still reach half an hour, so a node that is really gone stops costing
  // one flood per poll.
  EXPECT_GE(probeFloodBackoffSecs(5), 1800u);
  uint32_t total = 0;
  for (uint8_t i = 1; i <= 6; i++) total += probeFloodBackoffSecs(i);
  EXPECT_GE(total, 3600u);   // ~6 misses buys well over an hour of quiet
}

TEST(ProbePolicy, FloodHeldOffOnlyInsideTheWindow) {
  const uint32_t now = PROBE_MIN_VALID_EPOCH + 10000;
  EXPECT_TRUE(probeFloodHeldOff(now, now + 1));         // window still open
  EXPECT_FALSE(probeFloodHeldOff(now, now));            // expires exactly on time
  EXPECT_FALSE(probeFloodHeldOff(now, now - 1));        // long past
  EXPECT_FALSE(probeFloodHeldOff(now, 0));              // 0 = no entry
}

TEST(ProbePolicy, FloodBackoffFailsOpenBeforeNtp) {
  // Deliberately the OPPOSITE of the clock window's fail-closed stance. Refusing
  // every flood on an untrusted clock would leave a freshly booted node unable to
  // learn ANY route; the cost of being wrong here is one flood, not a bad login.
  const uint32_t pre_ntp = PROBE_MIN_VALID_EPOCH - 1;
  EXPECT_FALSE(probeFloodHeldOff(pre_ntp, pre_ntp + 100000));
}

}  // namespace
