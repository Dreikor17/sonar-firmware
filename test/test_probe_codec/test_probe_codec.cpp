// Host contract tests for the Echo Observer-Probe token codec.
//
// probeTokenSplit and probeB64UrlDecode are the ONLY operations that ever run on
// unauthenticated bytes, so their rejection behaviour is the security-relevant
// part of this suite.

#include <gtest/gtest.h>
#include <cstring>
#include <string>

#include "helpers/ProbeCodec.h"

namespace {

std::string enc(const std::string& in) {
  char out[512];
  size_t n = probeB64UrlEncode((const uint8_t*)in.data(), in.size(), out, sizeof(out));
  return std::string(out, n);
}

// --- base64url -------------------------------------------------------------

TEST(ProbeCodec, EncodesRfc4648TestVectorsUnpadded) {
  EXPECT_EQ(enc(""), "");
  EXPECT_EQ(enc("f"), "Zg");
  EXPECT_EQ(enc("fo"), "Zm8");
  EXPECT_EQ(enc("foo"), "Zm9v");
  EXPECT_EQ(enc("foob"), "Zm9vYg");
  EXPECT_EQ(enc("fooba"), "Zm9vYmE");
  EXPECT_EQ(enc("foobar"), "Zm9vYmFy");
}

TEST(ProbeCodec, UsesUrlSafeAlphabetNotStandardBase64) {
  // 0xFB 0xFF encodes to "-_8" in base64url ("+/8" in standard base64).
  const uint8_t raw[] = {0xFB, 0xFF};
  char out[16];
  size_t n = probeB64UrlEncode(raw, sizeof(raw), out, sizeof(out));
  std::string s(out, n);
  EXPECT_EQ(s, "-_8");
  EXPECT_EQ(s.find('+'), std::string::npos);
  EXPECT_EQ(s.find('/'), std::string::npos);
}

TEST(ProbeCodec, RoundTripsAllByteValues) {
  uint8_t raw[256];
  for (int i = 0; i < 256; i++) raw[i] = (uint8_t)i;
  char out[512];
  size_t n = probeB64UrlEncode(raw, sizeof(raw), out, sizeof(out));
  ASSERT_GT(n, 0u);
  uint8_t back[256];
  int d = probeB64UrlDecode(out, n, back, sizeof(back));
  ASSERT_EQ(d, 256);
  EXPECT_EQ(0, memcmp(raw, back, 256));
}

TEST(ProbeCodec, DecodeRejectsPaddingAndForeignCharacters) {
  uint8_t out[32];
  EXPECT_LT(probeB64UrlDecode("Zm9vYg==", 8, out, sizeof(out)), 0);   // padding
  EXPECT_LT(probeB64UrlDecode("Zm9v Yg", 7, out, sizeof(out)), 0);    // space
  EXPECT_LT(probeB64UrlDecode("Zm9v+g", 6, out, sizeof(out)), 0);     // standard b64
  EXPECT_LT(probeB64UrlDecode("Zm9v/g", 6, out, sizeof(out)), 0);
  EXPECT_LT(probeB64UrlDecode("Zg\n", 3, out, sizeof(out)), 0);       // newline
}

TEST(ProbeCodec, DecodeRejectsImpossibleLengthAndShortBuffer) {
  uint8_t out[32];
  EXPECT_LT(probeB64UrlDecode("Zm9vY", 5, out, sizeof(out)), 0);      // len % 4 == 1
  uint8_t tiny[1];
  EXPECT_LT(probeB64UrlDecode("Zm9vYmFy", 8, tiny, sizeof(tiny)), 0); // no room
}

TEST(ProbeCodec, EncodeRefusesUndersizedOutput) {
  const uint8_t raw[] = {1, 2, 3};
  char out[4];                       // needs 4 chars + NUL
  EXPECT_EQ(probeB64UrlEncode(raw, sizeof(raw), out, sizeof(out)), 0u);
}

// --- token splitting -------------------------------------------------------

TEST(ProbeCodec, SplitsThreeSegments) {
  const char* tok = "aGRy.cGF5.c2ln";
  const char *h, *p, *s;
  size_t hl, pl, sl;
  ASSERT_TRUE(probeTokenSplit(tok, strlen(tok), &h, &hl, &p, &pl, &s, &sl));
  EXPECT_EQ(std::string(h, hl), "aGRy");
  EXPECT_EQ(std::string(p, pl), "cGF5");
  EXPECT_EQ(std::string(s, sl), "c2ln");
}

TEST(ProbeCodec, SplitRejectsMalformedTokens) {
  const char *h, *p, *s;
  size_t hl, pl, sl;
  auto bad = [&](const char* t) {
    return !probeTokenSplit(t, strlen(t), &h, &hl, &p, &pl, &s, &sl);
  };
  EXPECT_TRUE(bad(""));
  EXPECT_TRUE(bad("onlyone"));
  EXPECT_TRUE(bad("two.parts"));
  EXPECT_TRUE(bad(".b.c"));          // empty header
  EXPECT_TRUE(bad("a..c"));          // empty payload
  EXPECT_TRUE(bad("a.b."));          // empty signature
  EXPECT_TRUE(bad("a.b.c.d"));       // extra dot
}

// The signing input is the raw "header.payload" prefix, so its length must be
// exactly header + 1 + payload -- this is what the Ed25519 verify covers.
TEST(ProbeCodec, SigningInputIsHeaderDotPayload) {
  const char* tok = "aGRy.cGF5bG9hZA.c2ln";
  const char *h, *p, *s;
  size_t hl, pl, sl;
  ASSERT_TRUE(probeTokenSplit(tok, strlen(tok), &h, &hl, &p, &pl, &s, &sl));
  size_t signing_len = hl + 1 + pl;
  EXPECT_EQ(std::string(h, signing_len), "aGRy.cGF5bG9hZA");
}

// --- claim scanner ---------------------------------------------------------

TEST(ProbeCodec, ReadsStringAndUnsignedClaims) {
  const char* js = "{\"jid\":\"job-1\",\"tgt\":\"AABB\",\"ops\":6,\"n\":4294967295}";
  size_t len = strlen(js);
  const char* v; size_t vl; uint32_t u;

  ASSERT_TRUE(probeJsonGetString(js, len, "jid", &v, &vl));
  EXPECT_EQ(std::string(v, vl), "job-1");
  ASSERT_TRUE(probeJsonGetString(js, len, "tgt", &v, &vl));
  EXPECT_EQ(std::string(v, vl), "AABB");
  ASSERT_TRUE(probeJsonGetUInt(js, len, "ops", &u));
  EXPECT_EQ(u, 6u);
  ASSERT_TRUE(probeJsonGetUInt(js, len, "n", &u));
  EXPECT_EQ(u, 4294967295u);
}

TEST(ProbeCodec, ToleratesWhitespaceAroundColon) {
  const char* js = "{\"ops\" : 3}";
  uint32_t u;
  ASSERT_TRUE(probeJsonGetUInt(js, strlen(js), "ops", &u));
  EXPECT_EQ(u, 3u);
}

TEST(ProbeCodec, MissingOrMistypedClaimsAreRefused) {
  const char* js = "{\"ops\":6,\"jid\":\"x\"}";
  size_t len = strlen(js);
  uint32_t u; const char* v; size_t vl;
  EXPECT_FALSE(probeJsonGetUInt(js, len, "nope", &u));
  EXPECT_FALSE(probeJsonGetUInt(js, len, "jid", &u));       // string, not a number
  EXPECT_FALSE(probeJsonGetString(js, len, "ops", &v, &vl));// number, not a string
}

TEST(ProbeCodec, RejectsOverflowingIntegerClaim) {
  const char* js = "{\"n\":4294967296}";                    // 2^32
  uint32_t u;
  EXPECT_FALSE(probeJsonGetUInt(js, strlen(js), "n", &u));
}

TEST(ProbeCodec, DoesNotMatchAKeySubstring) {
  const char* js = "{\"opsx\":1,\"ops\":2}";
  uint32_t u;
  ASSERT_TRUE(probeJsonGetUInt(js, strlen(js), "ops", &u));
  EXPECT_EQ(u, 2u);
}

// --- hex -------------------------------------------------------------------

TEST(ProbeCodec, HexRoundTripAndStrictLength) {
  uint8_t key[32];
  for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7);
  char hex[65];
  ASSERT_EQ(probeBytesToHex(key, 32, hex, sizeof(hex)), 64u);

  uint8_t back[32];
  ASSERT_TRUE(probeHexToBytes(hex, 64, back, 32));
  EXPECT_EQ(0, memcmp(key, back, 32));

  // wrong length must be refused rather than silently truncated
  EXPECT_FALSE(probeHexToBytes(hex, 62, back, 32));
  EXPECT_FALSE(probeHexToBytes("zz", 2, back, 1));
}

TEST(ProbeCodec, HexAcceptsBothCases) {
  uint8_t out[2];
  ASSERT_TRUE(probeHexToBytes("aB0F", 4, out, 2));
  EXPECT_EQ(out[0], 0xAB);
  EXPECT_EQ(out[1], 0x0F);
}

}  // namespace
