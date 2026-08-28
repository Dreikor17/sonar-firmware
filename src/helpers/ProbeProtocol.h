#pragma once

// Echo Observer-Probe -- wire formats for the client side of a probe session.
//
// SOURCE OF TRUTH: examples/simple_repeater/MyMesh.cpp lines 51-62 define these
// request types on the SERVER side, and the handlers that produce each reply are
// handleRequest() / handleAnonReq() in that same file. This header mirrors them
// for the CLIENT side, which src/helpers/BaseChatMesh.h does not cover (it only
// declares REQ_TYPE_GET_STATUS and REQ_TYPE_KEEP_ALIVE).
//
// Deliberately free of Arduino, radio and crypto dependencies so the whole file
// is exercised host-side by test/test_probe_protocol. Convention follows
// src/helpers/MQTTTopicRouter.h and MQTTConnectionPolicy.h.
//
// Vocabulary: this node is an Observer in a mesh of nodes. The node roles are
// Repeater, Companion, Sensor, Observer.

#include <stdint.h>
#include <string.h>
#include <stddef.h>

// ---------------------------------------------------------------------------
// Request types (mirror of examples/simple_repeater/MyMesh.cpp:51-56)
// ---------------------------------------------------------------------------
#define PROBE_REQ_TYPE_GET_STATUS          0x01
#define PROBE_REQ_TYPE_KEEP_ALIVE          0x02
#define PROBE_REQ_TYPE_GET_TELEMETRY_DATA  0x03
#define PROBE_REQ_TYPE_GET_ACCESS_LIST     0x05
#define PROBE_REQ_TYPE_GET_NEIGHBOURS      0x06
#define PROBE_REQ_TYPE_GET_OWNER_INFO      0x07   // needs target FIRMWARE_VER_LEVEL >= 2

// Anon request types (mirror of MyMesh.cpp:60-62) -- these need no login.
#define PROBE_ANON_REQ_TYPE_REGIONS        0x01
#define PROBE_ANON_REQ_TYPE_OWNER          0x02
#define PROBE_ANON_REQ_TYPE_BASIC          0x03

// ---------------------------------------------------------------------------
// Remote CLI command (PAYLOAD_TYPE_TXT_MSG)
// ---------------------------------------------------------------------------
// Mirrors the SERVER side at examples/simple_repeater/MyMesh.cpp:890-948. The
// body is {sender_timestamp u32 LE}{flags u8}{command text}, where flags is the
// text type shifted left by 2, and the reply comes back in the same shape.
//
// The target gates this on client->isAdmin() (MyMesh.cpp:890), so a guest login
// is silently ignored -- a command op needs the sealed password.
#define PROBE_TXT_TYPE_PLAIN     0x00
#define PROBE_TXT_TYPE_CLI_DATA  0x01
#define PROBE_CLI_HEADER_LEN     5

// The target builds its reply in uint8_t temp[166] with the text at &temp[5],
// and CommonCLI writes up to 160 bytes there, so a reply never exceeds 160.
// Commands are held to the same ceiling.
#define PROBE_CLI_MAX_TEXT       160

// Login reply discriminator (MyMesh.cpp:58)
#define PROBE_RESP_SERVER_LOGIN_OK         0

// Fixed body sizes
#define PROBE_REQ_BODY_LEN                 13   // {tag u32}{type u8}{4x00}{4 rand}
#define PROBE_ANON_BODY_LEN                6    // {tag u32}{anon_type u8}{reply_path_len u8}
#define PROBE_LOGIN_REPLY_LEN              13
#define PROBE_STATS_WIRE_LEN               56
#define PROBE_STATUS_REPLY_LEN             (4 + PROBE_STATS_WIRE_LEN)  // 60

// ---------------------------------------------------------------------------
// Wire layout of RepeaterStats (examples/simple_repeater/MyMesh.h:53-69).
// memcpy'd raw at MyMesh.cpp:280, little-endian, no padding (every field is
// naturally aligned, sizeof == 56). Re-declared here rather than included so
// this header stays host-testable.
// ---------------------------------------------------------------------------
struct ProbeRepeaterStats {
  uint16_t batt_milli_volts;
  uint16_t curr_tx_queue_len;
  int16_t  noise_floor;
  int16_t  last_rssi;
  uint32_t n_packets_recv;
  uint32_t n_packets_sent;
  uint32_t total_air_time_secs;
  uint32_t total_up_time_secs;
  uint32_t n_sent_flood, n_sent_direct;
  uint32_t n_recv_flood, n_recv_direct;
  uint16_t err_events;
  int16_t  last_snr;                 // x4
  uint16_t n_direct_dups, n_flood_dups;
  uint32_t total_rx_air_time_secs;
  uint32_t n_recv_errors;
};

// Parsed GET_OWNER_INFO reply. The pointers are NOT NUL-terminated in place;
// the lengths are authoritative (see probeParseOwnerInfo).
struct ProbeOwnerInfo {
  const char* firmware_version; size_t firmware_version_len;
  const char* node_name;        size_t node_name_len;
  const char* owner_info;       size_t owner_info_len;
};

struct ProbeLoginReply {
  uint32_t server_clock;
  uint8_t  is_admin;
  uint8_t  permissions;
  uint8_t  firmware_ver_level;
};

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

// {tag u32 LE}{req_type u8}{00 00 00 00 reserved}{4 random} == 13 bytes.
// Mirrors BaseChatMesh::sendRequest (src/helpers/BaseChatMesh.cpp:661-669).
// rand4 may be NULL, in which case the random blob is zeroed (tests do this; on
// device always pass real RNG bytes so the packet hash stays unique).
static inline bool probeBuildReqBody(uint8_t* buf, size_t buf_size, uint32_t tag,
                                     uint8_t req_type, const uint8_t* rand4) {
  if (!buf || buf_size < PROBE_REQ_BODY_LEN) return false;
  memcpy(buf, &tag, 4);
  buf[4] = req_type;
  memset(&buf[5], 0, 4);
  if (rand4) memcpy(&buf[9], rand4, 4); else memset(&buf[9], 0, 4);
  return true;
}

// {tag u32}{anon_type u8}{reply_path_len u8} == 6 bytes.
// Mirrors MyMesh::sendAnonRegionsReq (examples/simple_repeater/MyMesh.cpp:1885-1890).
// reply_path_len 0x00 asks the target for a zero-hop reply path.
static inline bool probeBuildAnonBody(uint8_t* buf, size_t buf_size, uint32_t tag,
                                      uint8_t anon_type, uint8_t reply_path_len) {
  if (!buf || buf_size < PROBE_ANON_BODY_LEN) return false;
  memcpy(buf, &tag, 4);
  buf[4] = anon_type;
  buf[5] = reply_path_len;
  return true;
}

// Guest login body: {now u32}{password bytes, max 15}. An empty password yields
// exactly 4 bytes. Mirrors the non-ADV_TYPE_ROOM branch of
// BaseChatMesh::sendLogin (src/helpers/BaseChatMesh.cpp:584-587).
static inline int probeBuildLoginBody(uint8_t* buf, size_t buf_size, uint32_t now,
                                      const char* password) {
  if (!buf || buf_size < 4) return -1;
  memcpy(buf, &now, 4);
  size_t len = password ? strlen(password) : 0;
  if (len > 15) len = 15;
  if (buf_size < 4 + len) return -1;
  if (len) memcpy(&buf[4], password, len);
  return (int)(4 + len);
}

// Is this a command we are willing to put on the air?
//
// probeJsonGetString does NOT unescape, so the slice is raw JSON string content.
// Rather than implement unescaping, refuse anything that could have needed it:
// printable ASCII only, no quote and no backslash. That also keeps the text safe
// to echo back into the result JSON.
static inline bool probeCliTextValid(const char* text, size_t len) {
  if (!text || len == 0 || len > PROBE_CLI_MAX_TEXT) return false;
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)text[i];
    if (c < 0x20 || c > 0x7E) return false;      // control chars and non-ASCII
    if (c == '"' || c == 0x5C) return false;      // would have needed escaping
  }
  return true;
}

// Build a CLI command body: {now u32 LE}{TXT_TYPE_CLI_DATA << 2}{text}.
// Returns the body length, or -1. The text is NOT NUL-terminated on the wire --
// the target re-terminates it from the received length (MyMesh.cpp:905).
static inline int probeBuildCliBody(uint8_t* buf, size_t buf_size, uint32_t now,
                                    const char* text, size_t text_len) {
  if (!buf || !text) return -1;
  if (text_len == 0 || text_len > PROBE_CLI_MAX_TEXT) return -1;
  if (buf_size < PROBE_CLI_HEADER_LEN + text_len) return -1;
  memcpy(buf, &now, 4);
  buf[4] = (uint8_t)(PROBE_TXT_TYPE_CLI_DATA << 2);
  memcpy(&buf[PROBE_CLI_HEADER_LEN], text, text_len);
  return (int)(PROBE_CLI_HEADER_LEN + text_len);
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

// MeshCore hands back the CIPHER-BLOCK-PADDED plaintext length: MACThenDecrypt
// returns decrypt(), which reports the block-aligned size (src/Utils.cpp:147-169).
// Text replies therefore arrive with trailing NUL padding, which would otherwise
// end up inside node names, owner strings and telemetry blobs.
//
// The trim is BOUNDED to one cipher block minus one byte: padding can never be
// longer than that, so a legitimate payload that genuinely ends in zero bytes
// cannot be over-trimmed.
#ifndef PROBE_MAX_PAD_TRIM
  #define PROBE_MAX_PAD_TRIM 15
#endif
static inline size_t probeTrimPadding(const uint8_t* data, size_t len) {
  if (!data) return 0;
  size_t trimmed = 0;
  while (len > 0 && trimmed < PROBE_MAX_PAD_TRIM && data[len - 1] == 0) {
    len--;
    trimmed++;
  }
  return len;
}

// Extract the reply text from a CLI reply body. Points into `data`; the length is
// authoritative, and trailing cipher padding is trimmed as everywhere else.
static inline bool probeParseCliReply(const uint8_t* data, size_t len,
                                      const char** out_text, size_t* out_len) {
  if (!data || len <= PROBE_CLI_HEADER_LEN) return false;
  uint8_t flags = (uint8_t)(data[4] >> 2);
  if (flags != PROBE_TXT_TYPE_CLI_DATA && flags != PROBE_TXT_TYPE_PLAIN) return false;
  size_t n = probeTrimPadding(&data[PROBE_CLI_HEADER_LEN], len - PROBE_CLI_HEADER_LEN);
  if (out_text) *out_text = (const char*)&data[PROBE_CLI_HEADER_LEN];
  if (out_len) *out_len = n;
  return true;
}

// Login reply, 13 bytes (examples/simple_repeater/MyMesh.cpp:146-155):
//   {server clock u32}{0x00 RESP_SERVER_LOGIN_OK}{0x00 legacy}{is_admin u8}
//   {permissions u8}{4 random}{FIRMWARE_VER_LEVEL u8}
// NOTE the asymmetry against REQ replies: the first four bytes are the SERVER
// clock, not the echoed tag. Login correlation therefore relies on there being
// exactly one login in flight.
static inline bool probeParseLoginReply(const uint8_t* data, size_t len, ProbeLoginReply* out) {
  if (!data || !out || len < PROBE_LOGIN_REPLY_LEN) return false;
  if (data[4] != PROBE_RESP_SERVER_LOGIN_OK) return false;
  memcpy(&out->server_clock, data, 4);
  out->is_admin           = data[6];
  out->permissions        = data[7];
  out->firmware_ver_level = data[12];
  return true;
}

// Echoed tag on a REQ reply (MyMesh.cpp:258 reflects the sender timestamp).
static inline bool probeParseReplyTag(const uint8_t* data, size_t len, uint32_t* out_tag) {
  if (!data || !out_tag || len < 4) return false;
  memcpy(out_tag, data, 4);
  return true;
}

// GET_STATUS reply: {tag u32}{RepeaterStats} == 60 bytes (MyMesh.cpp:260-283).
static inline bool probeParseStatusReply(const uint8_t* data, size_t len,
                                         uint32_t* out_tag, ProbeRepeaterStats* out) {
  if (!data || !out || len < PROBE_STATUS_REPLY_LEN) return false;
  if (out_tag) memcpy(out_tag, data, 4);
  memcpy(out, &data[4], PROBE_STATS_WIRE_LEN);
  return true;
}

// GET_TELEMETRY_DATA reply: {tag u32}{Cayenne LPP} (MyMesh.cpp:284-305).
// The LPP blob is returned by reference; Echo decodes it.
// CAVEAT: a guest login is forced to perm_mask 0x00 (MyMesh.cpp:291-293), so
// this carries channel-1 base telemetry only -- never external sensors.
static inline bool probeParseTelemetryReply(const uint8_t* data, size_t len, uint32_t* out_tag,
                                            const uint8_t** out_lpp, size_t* out_lpp_len) {
  if (!data || len < 4) return false;
  if (out_tag) memcpy(out_tag, data, 4);
  if (out_lpp) *out_lpp = &data[4];
  // Trimmed too: trailing padding would otherwise decode as a bogus LPP record
  // with channel 0 on the Echo side.
  if (out_lpp_len) *out_lpp_len = probeTrimPadding(&data[4], len - 4);
  return true;
}

// GET_OWNER_INFO reply: {tag u32}{"FIRMWARE_VERSION\nnode_name\nowner_info"}
// (MyMesh.cpp:421-424, which returns 4 + strlen(&reply_data[4])).
//
// LENGTH-DELIMITED, NOT NUL-terminated inside the reported length: slice by len,
// never scan for a NUL. A node_name may itself contain a newline, so only the
// FIRST TWO separators are structural and the remainder is owner_info verbatim.
static inline bool probeParseOwnerInfo(const uint8_t* data, size_t len, uint32_t* out_tag,
                                       ProbeOwnerInfo* out) {
  if (!data || !out || len < 4) return false;
  if (out_tag) memcpy(out_tag, data, 4);

  const char* p = (const char*)&data[4];
  size_t      n = probeTrimPadding(&data[4], len - 4);   // strip cipher padding
  memset(out, 0, sizeof(*out));

  size_t i = 0;
  while (i < n && p[i] != '\n') i++;
  out->firmware_version = p; out->firmware_version_len = i;
  if (i >= n) return true;                 // version only

  size_t start = ++i;
  while (i < n && p[i] != '\n') i++;
  out->node_name = p + start; out->node_name_len = i - start;
  if (i >= n) return true;                 // no owner field

  start = ++i;
  out->owner_info = p + start; out->owner_info_len = n - start;
  return true;
}

// Anon-request reply: {echoed tag u32}{server clock u32}{payload}
// (MyMesh.cpp:191-253 for REGIONS / OWNER / BASIC).
static inline bool probeParseAnonReply(const uint8_t* data, size_t len, uint32_t* out_tag,
                                       uint32_t* out_clock, const uint8_t** out_body,
                                       size_t* out_body_len) {
  if (!data || len < 8) return false;
  if (out_tag)   memcpy(out_tag, data, 4);
  if (out_clock) memcpy(out_clock, &data[4], 4);
  if (out_body)     *out_body = &data[8];
  if (out_body_len) *out_body_len = len - 8;
  return true;
}
