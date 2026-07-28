#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Pure per-broker packet-type allowlist helpers. MeshCore payload types occupy
// the low four bits of the packet header, so a uint16_t stores the complete
// 0..15 allowlist without dynamic allocation.
namespace MQTTPacketFilter {

static const uint8_t kMinPacketType = 0;
static const uint8_t kMaxPacketType = 15;
static const uint16_t kAllPacketTypes = 0xFFFFu;
// "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15" plus the terminator.
static const size_t kFilterTextSize = 38;

inline bool isAsciiSpace(char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

inline bool tokenEquals(const char* begin, size_t len, const char* token) {
  return token != nullptr && strlen(token) == len && memcmp(begin, token, len) == 0;
}

// Parse a canonical allowlist value. Empty input means "all" so WebConfig can
// clear a field and retain the same backwards-compatible default as an older
// /mqtt_prefs file. Keywords are deliberately lowercase and cannot be mixed
// with numeric entries. Decimal entries may contain surrounding ASCII
// whitespace, must be in 0..15, and may be repeated.
inline bool parse(const char* input, uint16_t* mask_out) {
  if (input == nullptr || mask_out == nullptr) return false;

  const char* begin = input;
  while (*begin && isAsciiSpace(*begin)) begin++;
  const char* end = begin + strlen(begin);
  while (end > begin && isAsciiSpace(end[-1])) end--;

  const size_t len = static_cast<size_t>(end - begin);
  if (len == 0 || tokenEquals(begin, len, "all")) {
    *mask_out = kAllPacketTypes;
    return true;
  }
  if (tokenEquals(begin, len, "none")) {
    *mask_out = 0;
    return true;
  }

  uint16_t parsed = 0;
  const char* cursor = begin;
  while (cursor < end) {
    while (cursor < end && isAsciiSpace(*cursor)) cursor++;
    if (cursor >= end || *cursor < '0' || *cursor > '9') return false;

    unsigned value = 0;
    while (cursor < end && *cursor >= '0' && *cursor <= '9') {
      value = value * 10u + static_cast<unsigned>(*cursor - '0');
      if (value > kMaxPacketType) return false;
      cursor++;
    }
    while (cursor < end && isAsciiSpace(*cursor)) cursor++;

    parsed |= static_cast<uint16_t>(1u << value);
    if (cursor == end) break;
    if (*cursor != ',') return false;
    cursor++;
    if (cursor == end) return false;
  }

  *mask_out = parsed;
  return true;
}

// Format masks deterministically for CLI/API output. Subsets are emitted in
// ascending order; the two useful extremes use concise keywords.
inline bool format(uint16_t mask, char* output, size_t output_size) {
  if (output == nullptr || output_size == 0) return false;
  output[0] = '\0';

  const char* keyword = nullptr;
  if (mask == kAllPacketTypes) keyword = "all";
  else if (mask == 0) keyword = "none";
  if (keyword != nullptr) {
    const size_t len = strlen(keyword);
    if (output_size <= len) return false;
    memcpy(output, keyword, len + 1);
    return true;
  }

  char formatted[kFilterTextSize];
  size_t pos = 0;
  bool first = true;
  for (uint8_t type = kMinPacketType; type <= kMaxPacketType; ++type) {
    if ((mask & static_cast<uint16_t>(1u << type)) == 0) continue;
    if (!first) formatted[pos++] = ',';
    if (type >= 10) formatted[pos++] = '1';
    formatted[pos++] = static_cast<char>('0' + (type % 10));
    first = false;
  }
  formatted[pos] = '\0';

  if (output_size <= pos) return false;
  memcpy(output, formatted, pos + 1);
  return true;
}

inline bool allows(uint16_t mask, uint8_t packet_type) {
  return packet_type <= kMaxPacketType &&
      (mask & static_cast<uint16_t>(1u << packet_type)) != 0;
}

// Eligibility deliberately excludes connection state. A temporarily
// disconnected broker that is configured for this type still requires the
// shared queue's existing bounded retry policy.
inline bool slotEligible(bool slot_enabled, bool topic_supported,
                         uint16_t mask, uint8_t packet_type) {
  return slot_enabled && topic_supported && allows(mask, packet_type);
}

// A fully filtered/topic-incompatible packet is intentionally complete. Once
// any eligible target exists, at least one actual publish must succeed.
inline bool publishComplete(bool has_eligible_target, bool any_publish_succeeded) {
  return any_publish_succeeded || !has_eligible_target;
}

}  // namespace MQTTPacketFilter
