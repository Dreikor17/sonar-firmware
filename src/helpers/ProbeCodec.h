#pragma once

// Echo Observer-Probe -- compact-token codec (base64url + a strict flat-JSON
// claim scanner).
//
// WHY NOT JWTHelper: JWTHelper::createAuthToken hex-encodes the signature and
// advertises alg "Ed25519" (src/helpers/JWTHelper.cpp:91-96, :146-148), which no
// stock JWT library will verify. That format is load-bearing for broker
// authentication, so it is left completely untouched. The probe channel is a
// brand-new protocol, so it uses a standards-correct EdDSA compact token here
// (DIRECTIONS-firmware.md section D.3, Option 2), and base64UrlEncode in
// JWTHelper is private with no decoder counterpart anyway.
//
// SAFETY ORDER: split and base64url-decode are the only operations that ever
// touch unauthenticated bytes. Claims are parsed ONLY after the Ed25519
// signature over "header.payload" has verified, so the scanner below never sees
// attacker-chosen input on an accepted path.
//
// Pure: no Arduino, no radio, no crypto. Exercised by test/test_probe_codec.

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// ---------------------------------------------------------------------------
// base64url (RFC 4648 section 5), unpadded
// ---------------------------------------------------------------------------

static const char PROBE_B64URL_ALPHABET[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Returns encoded length, or 0 on error. Always NUL-terminates when it succeeds.
static inline size_t probeB64UrlEncode(const uint8_t* in, size_t in_len,
                                       char* out, size_t out_size) {
  if (!in || !out) return 0;
  size_t need = ((in_len + 2) / 3) * 4;
  // unpadded: 1 leftover byte -> 2 chars, 2 leftover bytes -> 3 chars
  size_t rem = in_len % 3;
  if (rem == 1) need -= 2;
  else if (rem == 2) need -= 1;
  if (out_size < need + 1) return 0;

  size_t o = 0;
  size_t i = 0;
  while (i + 2 < in_len) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
    out[o++] = PROBE_B64URL_ALPHABET[(v >> 18) & 0x3F];
    out[o++] = PROBE_B64URL_ALPHABET[(v >> 12) & 0x3F];
    out[o++] = PROBE_B64URL_ALPHABET[(v >> 6) & 0x3F];
    out[o++] = PROBE_B64URL_ALPHABET[v & 0x3F];
    i += 3;
  }
  if (rem == 1) {
    uint32_t v = (uint32_t)in[i] << 16;
    out[o++] = PROBE_B64URL_ALPHABET[(v >> 18) & 0x3F];
    out[o++] = PROBE_B64URL_ALPHABET[(v >> 12) & 0x3F];
  } else if (rem == 2) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
    out[o++] = PROBE_B64URL_ALPHABET[(v >> 18) & 0x3F];
    out[o++] = PROBE_B64URL_ALPHABET[(v >> 12) & 0x3F];
    out[o++] = PROBE_B64URL_ALPHABET[(v >> 6) & 0x3F];
  }
  out[o] = '\0';
  return o;
}

static inline int probeB64UrlValue(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}

// Returns decoded length, or -1 on error. Rejects padding, whitespace and any
// character outside the base64url alphabet: this runs on unauthenticated bytes.
static inline int probeB64UrlDecode(const char* in, size_t in_len,
                                    uint8_t* out, size_t out_size) {
  if (!in || !out) return -1;
  if (in_len % 4 == 1) return -1;                 // impossible length

  size_t full = in_len / 4;
  size_t rem  = in_len % 4;
  size_t need = full * 3 + (rem == 2 ? 1 : (rem == 3 ? 2 : 0));
  if (out_size < need) return -1;

  size_t o = 0, i = 0;
  for (size_t b = 0; b < full; b++) {
    int c0 = probeB64UrlValue(in[i]), c1 = probeB64UrlValue(in[i + 1]);
    int c2 = probeB64UrlValue(in[i + 2]), c3 = probeB64UrlValue(in[i + 3]);
    if (c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0) return -1;
    uint32_t v = ((uint32_t)c0 << 18) | ((uint32_t)c1 << 12) | ((uint32_t)c2 << 6) | (uint32_t)c3;
    out[o++] = (uint8_t)((v >> 16) & 0xFF);
    out[o++] = (uint8_t)((v >> 8) & 0xFF);
    out[o++] = (uint8_t)(v & 0xFF);
    i += 4;
  }
  if (rem == 2) {
    int c0 = probeB64UrlValue(in[i]), c1 = probeB64UrlValue(in[i + 1]);
    if (c0 < 0 || c1 < 0) return -1;
    out[o++] = (uint8_t)(((c0 << 2) | (c1 >> 4)) & 0xFF);
  } else if (rem == 3) {
    int c0 = probeB64UrlValue(in[i]), c1 = probeB64UrlValue(in[i + 1]), c2 = probeB64UrlValue(in[i + 2]);
    if (c0 < 0 || c1 < 0 || c2 < 0) return -1;
    out[o++] = (uint8_t)(((c0 << 2) | (c1 >> 4)) & 0xFF);
    out[o++] = (uint8_t)(((c1 << 4) | (c2 >> 2)) & 0xFF);
  }
  return (int)o;
}

// ---------------------------------------------------------------------------
// Compact token splitting
// ---------------------------------------------------------------------------

// Splits "header.payload.signature" without copying. Rejects empty segments and
// any extra dots. Safe on unauthenticated input.
static inline bool probeTokenSplit(const char* tok, size_t tok_len,
                                   const char** h, size_t* h_len,
                                   const char** p, size_t* p_len,
                                   const char** s, size_t* s_len) {
  if (!tok || tok_len == 0) return false;
  size_t d1 = 0;
  while (d1 < tok_len && tok[d1] != '.') d1++;
  if (d1 == 0 || d1 >= tok_len) return false;

  size_t d2 = d1 + 1;
  while (d2 < tok_len && tok[d2] != '.') d2++;
  if (d2 == d1 + 1 || d2 >= tok_len) return false;
  if (d2 + 1 >= tok_len) return false;                    // empty signature

  for (size_t i = d2 + 1; i < tok_len; i++) {
    if (tok[i] == '.') return false;                      // extra dot
  }
  if (h) *h = tok;
  if (h_len) *h_len = d1;
  if (p) *p = tok + d1 + 1;
  if (p_len) *p_len = d2 - d1 - 1;
  if (s) *s = tok + d2 + 1;
  if (s_len) *s_len = tok_len - d2 - 1;
  return true;
}

// ---------------------------------------------------------------------------
// Strict flat-JSON claim scanner
// ---------------------------------------------------------------------------
//
// Only handles the flat objects this protocol defines. It does NOT implement
// JSON: no nesting, no escapes beyond a literal backslash skip, no unicode. That
// is deliberate -- it runs only on bytes that have already been authenticated,
// and a smaller scanner is a smaller thing to get wrong.

// Locates "key" and returns a pointer to the first character of its raw value.
static inline const char* probeJsonFindRaw(const char* json, size_t len, const char* key) {
  if (!json || !key) return NULL;
  size_t klen = strlen(key);
  if (klen == 0 || len < klen + 3) return NULL;

  for (size_t i = 0; i + klen + 2 < len; i++) {
    if (json[i] != '"') continue;
    if (memcmp(&json[i + 1], key, klen) != 0) continue;
    if (json[i + 1 + klen] != '"') continue;
    size_t j = i + 2 + klen;
    while (j < len && (json[j] == ' ' || json[j] == '\t')) j++;
    if (j >= len || json[j] != ':') continue;
    j++;
    while (j < len && (json[j] == ' ' || json[j] == '\t')) j++;
    return (j < len) ? &json[j] : NULL;
  }
  return NULL;
}

// String claim. Returns false when absent or not a string.
static inline bool probeJsonGetString(const char* json, size_t len, const char* key,
                                      const char** out, size_t* out_len) {
  const char* v = probeJsonFindRaw(json, len, key);
  if (!v || *v != '"') return false;
  const char* end = json + len;
  const char* p   = v + 1;
  const char* start = p;
  while (p < end && *p != '"') {
    if (*p == '\\' && p + 1 < end) p++;                   // skip escaped char
    p++;
  }
  if (p >= end) return false;
  if (out) *out = start;
  if (out_len) *out_len = (size_t)(p - start);
  return true;
}

// Unsigned integer claim. Returns false when absent or not a bare number.
static inline bool probeJsonGetUInt(const char* json, size_t len, const char* key, uint32_t* out) {
  const char* v = probeJsonFindRaw(json, len, key);
  if (!v) return false;
  const char* end = json + len;
  if (v >= end || *v < '0' || *v > '9') return false;
  uint64_t acc = 0;
  while (v < end && *v >= '0' && *v <= '9') {
    acc = acc * 10 + (uint64_t)(*v - '0');
    if (acc > 0xFFFFFFFFull) return false;                // overflow
    v++;
  }
  if (out) *out = (uint32_t)acc;
  return true;
}

// ---------------------------------------------------------------------------
// Hex helpers (pure; the Arduino tree has mesh::Utils but this stays testable)
// ---------------------------------------------------------------------------

static inline bool probeHexToBytes(const char* hex, size_t hex_len, uint8_t* out, size_t out_len) {
  if (!hex || !out) return false;
  if (hex_len != out_len * 2) return false;
  for (size_t i = 0; i < out_len; i++) {
    int hi = -1, lo = -1;
    char a = hex[i * 2], b = hex[i * 2 + 1];
    if (a >= '0' && a <= '9') hi = a - '0';
    else if (a >= 'a' && a <= 'f') hi = a - 'a' + 10;
    else if (a >= 'A' && a <= 'F') hi = a - 'A' + 10;
    if (b >= '0' && b <= '9') lo = b - '0';
    else if (b >= 'a' && b <= 'f') lo = b - 'a' + 10;
    else if (b >= 'A' && b <= 'F') lo = b - 'A' + 10;
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

static inline size_t probeBytesToHex(const uint8_t* in, size_t in_len, char* out, size_t out_size) {
  static const char* D = "0123456789ABCDEF";
  if (!in || !out || out_size < in_len * 2 + 1) return 0;
  for (size_t i = 0; i < in_len; i++) {
    out[i * 2]     = D[(in[i] >> 4) & 0x0F];
    out[i * 2 + 1] = D[in[i] & 0x0F];
  }
  out[in_len * 2] = '\0';
  return in_len * 2;
}
