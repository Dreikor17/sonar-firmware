// Host contract tests for the Observer-Probe sealed-password envelope.
//
// The point of this envelope is that a repeater admin password must not travel
// readable through the broker, and that a sealed blob captured from one command
// cannot be replayed inside another. Both properties are asserted here.

#include <gtest/gtest.h>
#include <cstring>
#include <string>

#include "helpers/ProbeSecret.h"

namespace {

const uint32_t N   = 918273;
const uint32_t IAT = 1787700000;

// --- plaintext round trip ----------------------------------------------------

TEST(ProbeSecret, BuildsAndParsesARoundTrip) {
  uint8_t pt[PROBE_PW_CT_LEN];
  ASSERT_TRUE(probePwBuildPlaintext(pt, sizeof(pt), N, IAT, "hunter2"));

  ProbePasswordClaim c;
  ASSERT_EQ(probePwParsePlaintext(pt, sizeof(pt), N, IAT, &c), PROBE_PW_OK);
  EXPECT_EQ(std::string(c.password), "hunter2");
  EXPECT_EQ(c.pw_len, 7);
  EXPECT_EQ(c.nonce, N);
  EXPECT_EQ(c.iat, IAT);
}

TEST(ProbeSecret, PlaintextIsZeroPaddedToAFullBlockSpan) {
  uint8_t pt[PROBE_PW_CT_LEN];
  memset(pt, 0xAA, sizeof(pt));
  ASSERT_TRUE(probePwBuildPlaintext(pt, sizeof(pt), N, IAT, "ab"));
  // everything past the password must be zeroed, not left as caller garbage
  for (size_t i = 10 + 2; i < sizeof(pt); i++) {
    EXPECT_EQ(pt[i], 0) << "byte " << i << " was not padded";
  }
}

// The wire format must not depend on host endianness, so the integers are
// written byte by byte rather than memcpy'd.
TEST(ProbeSecret, IntegersAreLittleEndianOnTheWire) {
  uint8_t pt[PROBE_PW_CT_LEN];
  ASSERT_TRUE(probePwBuildPlaintext(pt, sizeof(pt), 0x11223344u, 0xAABBCCDDu, "x"));
  EXPECT_EQ(pt[1], 0x44); EXPECT_EQ(pt[4], 0x11);
  EXPECT_EQ(pt[5], 0xDD); EXPECT_EQ(pt[8], 0xAA);
  EXPECT_EQ(probePwReadU32(&pt[1]), 0x11223344u);
  EXPECT_EQ(probePwReadU32(&pt[5]), 0xAABBCCDDu);
}

// --- the binding, which is what stops replay ---------------------------------

// A blob lifted out of one command and pasted into another must not open. The
// signature covers the whole payload, so an attacker cannot re-sign; this is the
// belt to that braces.
TEST(ProbeSecret, RefusesABlobBoundToADifferentCommand) {
  uint8_t pt[PROBE_PW_CT_LEN];
  ASSERT_TRUE(probePwBuildPlaintext(pt, sizeof(pt), N, IAT, "secret"));

  ProbePasswordClaim c;
  EXPECT_EQ(probePwParsePlaintext(pt, sizeof(pt), N + 1, IAT, &c), PROBE_PW_BINDING);
  EXPECT_EQ(probePwParsePlaintext(pt, sizeof(pt), N, IAT + 1, &c), PROBE_PW_BINDING);
  EXPECT_EQ(probePwParsePlaintext(pt, sizeof(pt), N, IAT, &c), PROBE_PW_OK);
}

// --- malformed input ---------------------------------------------------------

TEST(ProbeSecret, RejectsWrongVersion) {
  uint8_t pt[PROBE_PW_CT_LEN];
  ASSERT_TRUE(probePwBuildPlaintext(pt, sizeof(pt), N, IAT, "pw"));
  pt[0] = 0x02;
  ProbePasswordClaim c;
  EXPECT_EQ(probePwParsePlaintext(pt, sizeof(pt), N, IAT, &c), PROBE_PW_BAD_VERSION);
}

TEST(ProbeSecret, RejectsImplausiblePasswordLength) {
  uint8_t pt[PROBE_PW_CT_LEN];
  ASSERT_TRUE(probePwBuildPlaintext(pt, sizeof(pt), N, IAT, "pw"));
  ProbePasswordClaim c;

  pt[9] = 0;                       // empty
  EXPECT_EQ(probePwParsePlaintext(pt, sizeof(pt), N, IAT, &c), PROBE_PW_BAD_FIELDS);

  pt[9] = PROBE_PW_MAX + 1;        // would read past the plaintext
  EXPECT_EQ(probePwParsePlaintext(pt, sizeof(pt), N, IAT, &c), PROBE_PW_BAD_FIELDS);

  pt[9] = 0xFF;
  EXPECT_EQ(probePwParsePlaintext(pt, sizeof(pt), N, IAT, &c), PROBE_PW_BAD_FIELDS);
}

TEST(ProbeSecret, RejectsShortPlaintextAndNulls) {
  uint8_t pt[PROBE_PW_CT_LEN];
  ASSERT_TRUE(probePwBuildPlaintext(pt, sizeof(pt), N, IAT, "pw"));
  ProbePasswordClaim c;
  EXPECT_EQ(probePwParsePlaintext(pt, PROBE_PW_PT_LEN - 1, N, IAT, &c), PROBE_PW_BAD_LEN);
  EXPECT_EQ(probePwParsePlaintext(nullptr, sizeof(pt), N, IAT, &c), PROBE_PW_BAD_LEN);
  EXPECT_EQ(probePwParsePlaintext(pt, sizeof(pt), N, IAT, nullptr), PROBE_PW_BAD_LEN);
}

TEST(ProbeSecret, BuildRefusesEmptyOrOverlongPasswords) {
  uint8_t pt[PROBE_PW_CT_LEN];
  EXPECT_FALSE(probePwBuildPlaintext(pt, sizeof(pt), N, IAT, ""));
  EXPECT_FALSE(probePwBuildPlaintext(pt, sizeof(pt), N, IAT, "0123456789abcdefg"));  // 17
  EXPECT_TRUE(probePwBuildPlaintext(pt, sizeof(pt), N, IAT, "0123456789abcde"));     // 15, the max
  EXPECT_FALSE(probePwBuildPlaintext(pt, 8, N, IAT, "ok"));                          // buffer too small
  EXPECT_FALSE(probePwBuildPlaintext(pt, sizeof(pt), N, IAT, nullptr));
}

// --- blob framing ------------------------------------------------------------

TEST(ProbeSecret, SplitsTheBlobIntoSaltAndMacCiphertext) {
  uint8_t blob[PROBE_PW_BLOB_LEN];
  for (size_t i = 0; i < sizeof(blob); i++) blob[i] = (uint8_t)i;

  const uint8_t *salt = nullptr, *mac_ct = nullptr; size_t mac_ct_len = 0;
  ASSERT_TRUE(probePwSplitBlob(blob, sizeof(blob), &salt, &mac_ct, &mac_ct_len));
  EXPECT_EQ(salt, blob);
  EXPECT_EQ(mac_ct, blob + PROBE_PW_SALT_LEN);
  EXPECT_EQ(mac_ct_len, (size_t)(PROBE_PW_MAC_LEN + PROBE_PW_CT_LEN));
  // the span handed to MACThenDecrypt must cover exactly mac + ciphertext
  EXPECT_EQ(PROBE_PW_SALT_LEN + mac_ct_len, sizeof(blob));
}

TEST(ProbeSecret, SplitRejectsAnyOtherLength) {
  uint8_t blob[PROBE_PW_BLOB_LEN + 1] = {0};
  const uint8_t *salt, *mac_ct; size_t n;
  EXPECT_FALSE(probePwSplitBlob(blob, PROBE_PW_BLOB_LEN - 1, &salt, &mac_ct, &n));
  EXPECT_FALSE(probePwSplitBlob(blob, PROBE_PW_BLOB_LEN + 1, &salt, &mac_ct, &n));
  EXPECT_FALSE(probePwSplitBlob(nullptr, PROBE_PW_BLOB_LEN, &salt, &mac_ct, &n));
}

// The hex claim is fixed width, which lets the parser reject a wrong-sized
// field before doing any crypto.
TEST(ProbeSecret, HexClaimWidthIsFixedAndMatchesTheBlob) {
  EXPECT_EQ(PROBE_PW_BLOB_LEN, 50);
  EXPECT_EQ(PROBE_PW_HEX_LEN, 100);
  EXPECT_EQ(PROBE_PW_SALT_LEN + PROBE_PW_MAC_LEN + PROBE_PW_CT_LEN, PROBE_PW_BLOB_LEN);
}

// --- hygiene -----------------------------------------------------------------

TEST(ProbeSecret, WipeClearsTheRecoveredPassword) {
  uint8_t pt[PROBE_PW_CT_LEN];
  ASSERT_TRUE(probePwBuildPlaintext(pt, sizeof(pt), N, IAT, "topsecret"));
  ProbePasswordClaim c;
  ASSERT_EQ(probePwParsePlaintext(pt, sizeof(pt), N, IAT, &c), PROBE_PW_OK);
  ASSERT_EQ(std::string(c.password), "topsecret");

  probePwWipe(&c);
  for (size_t i = 0; i < sizeof(c.password); i++) EXPECT_EQ(c.password[i], 0);
  EXPECT_EQ(c.pw_len, 0);
  EXPECT_EQ(c.nonce, 0u);
  probePwWipe(nullptr);   // must not crash
}

}  // namespace
