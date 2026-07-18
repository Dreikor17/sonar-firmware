#pragma once

#include <stdint.h>

// Pure timing and state-transition policy used by MQTTBridge's connection
// maintenance loop. Keeping these decisions independent of Arduino, WiFi, and
// the MQTT client lets host tests exercise the exact production policy with a
// deterministic clock.
namespace MQTTConnectionPolicy {

static const uint32_t kReconnectGuardMs = 15000UL;
static const uint32_t kStableResetMs = 120000UL;
static const uint32_t kCircuitBreakerProbeMs = 1800000UL;
static const uint32_t kRenewalThrottleMs = 60000UL;
static const uint32_t kSlotStaggerMs = 3000UL;
static const uint8_t kMaxFailuresAtMaxBackoff = 3;
static const uint32_t kDefaultJwtLifetimeSecs = 86400UL;
static const uint32_t kMaxJwtStaggerSecs = 300UL;
static const uint32_t kMinimumValidEpoch = 1000000000UL;
static const uint32_t kJwtClockThreshold = 1735689600UL; // 2025-01-01 UTC

// Unsigned subtraction is intentionally used: it is the standard millis()
// idiom and remains correct across a single 32-bit counter rollover.
static inline uint32_t elapsedMs(uint32_t now, uint32_t then) {
  return now - then;
}

static inline bool reconnectGuardActive(uint32_t now, uint32_t last_reconnect) {
  return elapsedMs(now, last_reconnect) < kReconnectGuardMs;
}

static inline bool stableConnection(uint32_t now, uint32_t connected_at) {
  return connected_at != 0 && elapsedMs(now, connected_at) >= kStableResetMs;
}

static inline uint32_t reconnectBackoffMs(uint8_t reconnect_backoff) {
  static const uint32_t kBackoffMs[] = {
    10000UL, 30000UL, 60000UL, 120000UL, 300000UL
  };
  const uint8_t index = reconnect_backoff < 5 ? reconnect_backoff : 4;
  return kBackoffMs[index];
}

static inline uint32_t reconnectDelayMs(uint8_t reconnect_backoff, uint8_t slot_index) {
  return reconnectBackoffMs(reconnect_backoff) +
         static_cast<uint32_t>(slot_index) * kSlotStaggerMs;
}

static inline bool reconnectDue(uint32_t now, uint32_t last_attempt,
                                uint8_t reconnect_backoff, uint8_t slot_index) {
  return elapsedMs(now, last_attempt) >= reconnectDelayMs(reconnect_backoff, slot_index);
}

struct BackoffAdvance {
  uint8_t reconnect_backoff;
  uint8_t max_backoff_failures;
  bool circuit_breaker_tripped;
  bool should_reconnect;
};

// Advance the ladder immediately before a due reconnect. The first visit to
// the 300-second rung changes level 4 to the saturated marker 5. Three later
// failures at that rung trip the breaker; the third does not launch another
// connection attempt.
static inline BackoffAdvance advanceBackoff(uint8_t reconnect_backoff,
                                            uint8_t max_backoff_failures) {
  BackoffAdvance result = {
    reconnect_backoff, max_backoff_failures, false, true
  };
  if (result.reconnect_backoff < 5) {
    result.reconnect_backoff++;
    return result;
  }

  if (result.max_backoff_failures < UINT8_MAX) {
    result.max_backoff_failures++;
  }
  if (result.max_backoff_failures >= kMaxFailuresAtMaxBackoff) {
    result.circuit_breaker_tripped = true;
    result.should_reconnect = false;
  }
  return result;
}

static inline bool circuitBreakerProbeDue(uint32_t now, uint32_t last_attempt) {
  return elapsedMs(now, last_attempt) >= kCircuitBreakerProbeMs;
}

// Each later slot expires up to five percent of the base lifetime earlier,
// capped at five minutes per slot. Runtime slot indexes are bounded by the
// persisted MQTT slot count; the final clamp also prevents underflow if this
// helper is used with unexpected input.
static inline uint32_t jwtLifetimeSecs(uint32_t base_lifetime, uint8_t slot_index) {
  uint32_t per_slot_stagger = base_lifetime / 20UL;
  if (per_slot_stagger > kMaxJwtStaggerSecs) {
    per_slot_stagger = kMaxJwtStaggerSecs;
  }
  uint64_t stagger = static_cast<uint64_t>(slot_index) * per_slot_stagger;
  if (stagger > base_lifetime) {
    stagger = base_lifetime;
  }
  return base_lifetime - static_cast<uint32_t>(stagger);
}

static inline uint32_t renewalBufferSecs(uint32_t lifetime_secs) {
  uint32_t buffer = lifetime_secs / 10UL;
  if (buffer < 60UL) buffer = 60UL;
  if (buffer > 300UL) buffer = 300UL;
  return buffer;
}

static inline bool tokenNeedsRenewal(bool time_synced, uint32_t current_time,
                                     uint32_t token_expires_at,
                                     uint32_t renewal_buffer_secs) {
  if (!time_synced) {
    return token_expires_at == 0;
  }
  if (token_expires_at < kMinimumValidEpoch) {
    return true;
  }
  if (current_time >= token_expires_at) {
    return true;
  }
  return current_time >= token_expires_at - renewal_buffer_secs;
}

static inline bool renewalAttemptAllowed(uint32_t now, uint32_t last_attempt) {
  return elapsedMs(now, last_attempt) >= kRenewalThrottleMs;
}

static inline bool jwtClockAvailable(bool ntp_synced, uint32_t current_time) {
  return ntp_synced || current_time >= kJwtClockThreshold;
}

} // namespace MQTTConnectionPolicy
