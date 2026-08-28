// Host contract tests for the Echo Observer-Probe wire formats.
//
// Every expectation here is anchored to the SERVER implementation in
// examples/simple_repeater/MyMesh.cpp, which is what a probe actually talks to.

#include <gtest/gtest.h>
#include <cstring>
#include <string>

#include "helpers/ProbeProtocol.h"

namespace {

// --- request builders ------------------------------------------------------

TEST(ProbeProtocol, ReqBodyMatchesBaseChatMeshLayout) {
  // {tag u32 LE}{req_type u8}{00 00 00 00}{4 random} == 13 bytes
  // (src/helpers/BaseChatMesh.cpp:661-669)
  uint8_t buf[PROBE_REQ_BODY_LEN];
  const uint8_t rnd[4] = {0xDE, 0xAD, 0xBE, 0xEF};
  ASSERT_TRUE(probeBuildReqBody(buf, sizeof(buf), 0x11223344u,
                                PROBE_REQ_TYPE_GET_OWNER_INFO, rnd));
  EXPECT_EQ(buf[0], 0x44);          // little endian
  EXPECT_EQ(buf[1], 0x33);
  EXPECT_EQ(buf[2], 0x22);
  EXPECT_EQ(buf[3], 0x11);
  EXPECT_EQ(buf[4], 0x07);          // REQ_TYPE_GET_OWNER_INFO
  for (int i = 5; i < 9; i++) EXPECT_EQ(buf[i], 0x00) << "reserved byte " << i;
  EXPECT_EQ(0, memcmp(&buf[9], rnd, 4));
}

TEST(ProbeProtocol, ReqBodyRejectsShortBuffer) {
  uint8_t small[PROBE_REQ_BODY_LEN - 1];
  EXPECT_FALSE(probeBuildReqBody(small, sizeof(small), 1, PROBE_REQ_TYPE_GET_STATUS, nullptr));
}

TEST(ProbeProtocol, ReqTypeConstantsMatchTheServer) {
  // examples/simple_repeater/MyMesh.cpp:51-56
  EXPECT_EQ(PROBE_REQ_TYPE_GET_STATUS, 0x01);
  EXPECT_EQ(PROBE_REQ_TYPE_KEEP_ALIVE, 0x02);
  EXPECT_EQ(PROBE_REQ_TYPE_GET_TELEMETRY_DATA, 0x03);
  EXPECT_EQ(PROBE_REQ_TYPE_GET_OWNER_INFO, 0x07);
  // MyMesh.cpp:60-62
  EXPECT_EQ(PROBE_ANON_REQ_TYPE_REGIONS, 0x01);
  EXPECT_EQ(PROBE_ANON_REQ_TYPE_OWNER, 0x02);
  EXPECT_EQ(PROBE_ANON_REQ_TYPE_BASIC, 0x03);
}

TEST(ProbeProtocol, AnonBodyCarriesZeroHopReplyPath) {
  // {tag u32}{anon_type u8}{reply_path_len u8} (MyMesh.cpp:1885-1890)
  uint8_t buf[PROBE_ANON_BODY_LEN];
  ASSERT_TRUE(probeBuildAnonBody(buf, sizeof(buf), 0xAABBCCDDu,
                                 PROBE_ANON_REQ_TYPE_OWNER, 0x00));
  EXPECT_EQ(buf[4], PROBE_ANON_REQ_TYPE_OWNER);
  EXPECT_EQ(buf[5], 0x00);
}

// A guest login with an empty password is exactly 4 bytes. The server then
// writes data[len] = 0 and reads data[4] == 0 as "blank password"
// (MyMesh.cpp:669, :674, :103).
TEST(ProbeProtocol, EmptyPasswordLoginBodyIsExactlyFourBytes) {
  uint8_t buf[24];
  EXPECT_EQ(4, probeBuildLoginBody(buf, sizeof(buf), 0x01020304u, ""));
  EXPECT_EQ(buf[0], 0x04);
  EXPECT_EQ(buf[3], 0x01);
}

TEST(ProbeProtocol, LoginPasswordIsClampedToFifteenChars) {
  uint8_t buf[64];
  const char* long_pw = "0123456789abcdefGHIJ";      // 20 chars
  EXPECT_EQ(4 + 15, probeBuildLoginBody(buf, sizeof(buf), 0, long_pw));
}

// --- remote CLI command ------------------------------------------------------

// Body layout mirrors the SERVER side at MyMesh.cpp:936-938:
// {sender_timestamp u32 LE}{text type << 2}{text}.
TEST(ProbeProtocol, CliBodyMatchesTheServerLayout) {
  uint8_t buf[64];
  int n = probeBuildCliBody(buf, sizeof(buf), 0x11223344u, "ver", 3);
  ASSERT_EQ(n, PROBE_CLI_HEADER_LEN + 3);
  EXPECT_EQ(buf[0], 0x44);                                   // little endian
  EXPECT_EQ(buf[3], 0x11);
  EXPECT_EQ(buf[4], (uint8_t)(PROBE_TXT_TYPE_CLI_DATA << 2));  // shifted, per the server
  EXPECT_EQ(0, memcmp(&buf[5], "ver", 3));
}

TEST(ProbeProtocol, CliBodyRejectsEmptyOverlongAndShortBuffers) {
  uint8_t buf[8];
  EXPECT_LT(probeBuildCliBody(buf, sizeof(buf), 0, "", 0), 0);
  EXPECT_LT(probeBuildCliBody(buf, sizeof(buf), 0, "toolong", 7), 0);   // buffer
  uint8_t big[PROBE_CLI_HEADER_LEN + PROBE_CLI_MAX_TEXT + 8];
  std::string max_text(PROBE_CLI_MAX_TEXT, 'a');
  EXPECT_GT(probeBuildCliBody(big, sizeof(big), 0, max_text.c_str(), max_text.size()), 0);
  std::string over(PROBE_CLI_MAX_TEXT + 1, 'a');
  EXPECT_LT(probeBuildCliBody(big, sizeof(big), 0, over.c_str(), over.size()), 0);
}

TEST(ProbeProtocol, CliReplyParsesAndTrimsCipherPadding) {
  uint8_t data[48];
  memset(data, 0, sizeof(data));
  data[4] = (uint8_t)(PROBE_TXT_TYPE_CLI_DATA << 2);
  const char* text = "OK - done";
  memcpy(&data[5], text, strlen(text));

  // The transport reports the CIPHER-BLOCK-ALIGNED length. The real body here is
  // 5 + 9 = 14 bytes, so it is reported as 16 -- two bytes of padding. Padding can
  // never exceed one block minus one, which is exactly why probeTrimPadding caps
  // its trim at 15: a longer run of zeros is real payload, not padding.
  const char* out = nullptr; size_t out_len = 0;
  ASSERT_TRUE(probeParseCliReply(data, 16, &out, &out_len));
  EXPECT_EQ(std::string(out, out_len), "OK - done");
}

// A full-length reply is the case where the alignment padding is largest, so it
// is worth pinning down separately.
TEST(ProbeProtocol, CliReplyTrimsAcrossABlockBoundary) {
  uint8_t data[PROBE_CLI_HEADER_LEN + PROBE_CLI_MAX_TEXT + 16];
  memset(data, 0, sizeof(data));
  data[4] = (uint8_t)(PROBE_TXT_TYPE_CLI_DATA << 2);
  std::string text(33, 'x');                       // 5 + 33 = 38 -> reported as 48
  memcpy(&data[5], text.data(), text.size());

  const char* out = nullptr; size_t out_len = 0;
  ASSERT_TRUE(probeParseCliReply(data, 48, &out, &out_len));
  EXPECT_EQ(std::string(out, out_len), text);
}

TEST(ProbeProtocol, CliReplyRejectsShortAndForeignTextTypes) {
  uint8_t data[32];
  memset(data, 0, sizeof(data));
  data[4] = (uint8_t)(PROBE_TXT_TYPE_CLI_DATA << 2);
  memcpy(&data[5], "hi", 2);
  const char* out; size_t n;
  EXPECT_FALSE(probeParseCliReply(data, PROBE_CLI_HEADER_LEN, &out, &n));   // no text
  EXPECT_FALSE(probeParseCliReply(nullptr, 32, &out, &n));
  data[4] = (uint8_t)(0x07 << 2);                                          // unknown type
  EXPECT_FALSE(probeParseCliReply(data, 16, &out, &n));
}

// probeJsonGetString does NOT unescape, so anything that could have needed
// escaping is refused outright rather than half-handled.
TEST(ProbeProtocol, CliTextValidatorRefusesAnythingNeedingEscaping) {
  EXPECT_TRUE(probeCliTextValid("get freq", 8));
  EXPECT_TRUE(probeCliTextValid("set repeat off", 14));

  EXPECT_FALSE(probeCliTextValid("say \"hi\"", 8));      // quote
  EXPECT_FALSE(probeCliTextValid("back\\slash", 10));    // backslash
  EXPECT_FALSE(probeCliTextValid("line\nbreak", 10));    // control char
  EXPECT_FALSE(probeCliTextValid("tab\there", 8));
  EXPECT_FALSE(probeCliTextValid("caf\xC3\xA9", 5));     // non-ASCII
  EXPECT_FALSE(probeCliTextValid("", 0));
  EXPECT_FALSE(probeCliTextValid(nullptr, 4));

  std::string over(PROBE_CLI_MAX_TEXT + 1, 'a');
  EXPECT_FALSE(probeCliTextValid(over.c_str(), over.size()));
}

// --- reply parsers ---------------------------------------------------------

TEST(ProbeProtocol, LoginReplyParsesAndRejectsNonOk) {
  // {clock u32}{0x00 OK}{0x00 legacy}{is_admin}{perms}{4 rand}{fw_level}
  // (MyMesh.cpp:146-155)
  uint8_t data[PROBE_LOGIN_REPLY_LEN] = {0};
  data[0] = 0x10; data[1] = 0x20; data[2] = 0x30; data[3] = 0x40;
  data[4] = PROBE_RESP_SERVER_LOGIN_OK;
  data[6] = 0;      // not admin
  data[7] = 0x02;   // permissions
  data[12] = 2;     // FIRMWARE_VER_LEVEL

  ProbeLoginReply lr;
  ASSERT_TRUE(probeParseLoginReply(data, sizeof(data), &lr));
  EXPECT_EQ(lr.server_clock, 0x40302010u);
  EXPECT_EQ(lr.permissions, 0x02);
  EXPECT_EQ(lr.firmware_ver_level, 2);

  data[4] = 0x01;   // any non-zero is not a login-OK
  EXPECT_FALSE(probeParseLoginReply(data, sizeof(data), &lr));
}

TEST(ProbeProtocol, LoginReplyRejectsShortInput) {
  uint8_t data[PROBE_LOGIN_REPLY_LEN - 1] = {0};
  ProbeLoginReply lr;
  EXPECT_FALSE(probeParseLoginReply(data, sizeof(data), &lr));
}

// RepeaterStats is memcpy'd raw (MyMesh.cpp:280); the wire struct must stay
// exactly 56 bytes or every field after the first mismatch silently shifts.
TEST(ProbeProtocol, RepeaterStatsWireLayoutIsFiftySixBytes) {
  EXPECT_EQ(sizeof(ProbeRepeaterStats), (size_t)PROBE_STATS_WIRE_LEN);
  EXPECT_EQ(PROBE_STATUS_REPLY_LEN, 60);
}

TEST(ProbeProtocol, StatusReplyParsesLittleEndianFields) {
  uint8_t data[PROBE_STATUS_REPLY_LEN] = {0};
  data[0] = 0x01; data[1] = 0x00; data[2] = 0x00; data[3] = 0x00;   // tag
  ProbeRepeaterStats src;
  memset(&src, 0, sizeof(src));
  src.batt_milli_volts = 4123;
  src.noise_floor = -97;
  src.last_snr = -20;
  src.n_packets_recv = 123456;
  src.n_sent_flood = 7;
  src.n_recv_errors = 3;
  memcpy(&data[4], &src, sizeof(src));

  uint32_t tag = 0;
  ProbeRepeaterStats out;
  ASSERT_TRUE(probeParseStatusReply(data, sizeof(data), &tag, &out));
  EXPECT_EQ(tag, 1u);
  EXPECT_EQ(out.batt_milli_volts, 4123);
  EXPECT_EQ(out.noise_floor, -97);
  EXPECT_EQ(out.last_snr, -20);
  EXPECT_EQ(out.n_packets_recv, 123456u);
  EXPECT_EQ(out.n_sent_flood, 7u);
  EXPECT_EQ(out.n_recv_errors, 3u);
}

TEST(ProbeProtocol, StatusReplyRejectsTruncatedPayload) {
  uint8_t data[PROBE_STATUS_REPLY_LEN - 1] = {0};
  ProbeRepeaterStats out;
  EXPECT_FALSE(probeParseStatusReply(data, sizeof(data), nullptr, &out));
}

// GET_OWNER_INFO is LENGTH-delimited, not NUL-terminated within the reported
// length (MyMesh.cpp:421-424 returns 4 + strlen(&reply_data[4])).
TEST(ProbeProtocol, OwnerInfoSplitsOnFirstTwoNewlinesOnly) {
  const char body[] = "v1.17.1\nLake Edge\nowner\nwith newline";
  uint8_t data[128];
  memcpy(data, "\x01\x00\x00\x00", 4);
  memcpy(&data[4], body, sizeof(body) - 1);
  size_t len = 4 + (sizeof(body) - 1);

  uint32_t tag = 0;
  ProbeOwnerInfo oi;
  ASSERT_TRUE(probeParseOwnerInfo(data, len, &tag, &oi));
  EXPECT_EQ(tag, 1u);
  EXPECT_EQ(std::string(oi.firmware_version, oi.firmware_version_len), "v1.17.1");
  EXPECT_EQ(std::string(oi.node_name, oi.node_name_len), "Lake Edge");
  // everything after the second separator is owner_info verbatim, newlines and all
  EXPECT_EQ(std::string(oi.owner_info, oi.owner_info_len), "owner\nwith newline");
}

TEST(ProbeProtocol, OwnerInfoHandlesVersionOnlyAndMissingOwner) {
  uint8_t data[64];
  memcpy(data, "\x00\x00\x00\x00", 4);

  const char only[] = "v1.2.3";
  memcpy(&data[4], only, sizeof(only) - 1);
  ProbeOwnerInfo oi;
  ASSERT_TRUE(probeParseOwnerInfo(data, 4 + sizeof(only) - 1, nullptr, &oi));
  EXPECT_EQ(std::string(oi.firmware_version, oi.firmware_version_len), "v1.2.3");
  EXPECT_EQ(oi.node_name_len, 0u);
  EXPECT_EQ(oi.owner_info_len, 0u);

  const char two[] = "v1.2.3\nNodeName";
  memcpy(&data[4], two, sizeof(two) - 1);
  ASSERT_TRUE(probeParseOwnerInfo(data, 4 + sizeof(two) - 1, nullptr, &oi));
  EXPECT_EQ(std::string(oi.node_name, oi.node_name_len), "NodeName");
  EXPECT_EQ(oi.owner_info_len, 0u);
}

// The parser must never run past the reported length even when the buffer
// happens to hold more bytes -- this is the "slice by length" contract.
TEST(ProbeProtocol, OwnerInfoNeverReadsPastReportedLength) {
  uint8_t data[64];
  memset(data, 'X', sizeof(data));
  memcpy(data, "\x00\x00\x00\x00", 4);
  memcpy(&data[4], "v1\nname\nowner", 13);
  ProbeOwnerInfo oi;
  ASSERT_TRUE(probeParseOwnerInfo(data, 4 + 7, nullptr, &oi));   // only "v1\nname"
  EXPECT_EQ(std::string(oi.firmware_version, oi.firmware_version_len), "v1");
  EXPECT_EQ(std::string(oi.node_name, oi.node_name_len), "name");
  EXPECT_EQ(oi.owner_info_len, 0u);
}

// MeshCore returns the CIPHER-BLOCK-PADDED plaintext length, so every reply can
// carry trailing NUL padding. Without trimming it lands inside node names, owner
// strings and the LPP blob.
TEST(ProbeProtocol, OwnerInfoStripsCipherBlockPadding) {
  const char body[] = "v1.17.1\nLake Edge\nowner";
  uint8_t data[80];
  memset(data, 0, sizeof(data));
  memcpy(data, "\x01\x00\x00\x00", 4);
  memcpy(&data[4], body, sizeof(body) - 1);
  // 4 + 23 = 27 -> the transport reports the next 16-byte boundary, 32
  size_t padded_len = 32;

  ProbeOwnerInfo oi;
  ASSERT_TRUE(probeParseOwnerInfo(data, padded_len, nullptr, &oi));
  EXPECT_EQ(std::string(oi.firmware_version, oi.firmware_version_len), "v1.17.1");
  EXPECT_EQ(std::string(oi.node_name, oi.node_name_len), "Lake Edge");
  EXPECT_EQ(std::string(oi.owner_info, oi.owner_info_len), "owner")
      << "trailing NUL padding leaked into owner_info";
}

TEST(ProbeProtocol, TrimIsBoundedToOneCipherBlock) {
  // A payload that legitimately ends in many zero bytes must not be eaten: the
  // trim stops after at most 15 bytes.
  uint8_t data[64];
  memset(data, 0, sizeof(data));
  data[0] = 'x';
  EXPECT_EQ(probeTrimPadding(data, 64), 64u - PROBE_MAX_PAD_TRIM);
  // ...and a fully-populated payload is untouched
  memset(data, 'a', sizeof(data));
  EXPECT_EQ(probeTrimPadding(data, 64), 64u);
}

TEST(ProbeProtocol, TelemetryLppLengthExcludesPadding) {
  uint8_t data[32];
  memset(data, 0, sizeof(data));
  memcpy(data, "\x09\x00\x00\x00", 4);
  data[4] = 0x01; data[5] = 0x67; data[6] = 0x01; data[7] = 0x10;
  const uint8_t* lpp = nullptr; size_t lpp_len = 0;
  ASSERT_TRUE(probeParseTelemetryReply(data, 16, nullptr, &lpp, &lpp_len));
  EXPECT_EQ(lpp_len, 4u) << "padding would decode as a bogus channel-0 record";
}

TEST(ProbeProtocol, TelemetryReplyExposesRawLppByReference) {
  uint8_t data[16] = {0x09, 0, 0, 0, 0x01, 0x67, 0x01, 0x10};
  uint32_t tag = 0;
  const uint8_t* lpp = nullptr;
  size_t lpp_len = 0;
  ASSERT_TRUE(probeParseTelemetryReply(data, 8, &tag, &lpp, &lpp_len));
  EXPECT_EQ(tag, 9u);
  EXPECT_EQ(lpp_len, 4u);
  EXPECT_EQ(lpp[0], 0x01);
  EXPECT_EQ(lpp[1], 0x67);
}

TEST(ProbeProtocol, AnonReplyCarriesEchoedTagThenServerClock) {
  // {echoed tag u32}{server clock u32}{payload} (MyMesh.cpp:191-253)
  uint8_t data[16] = {0};
  data[0] = 0x05;
  data[4] = 0x99;
  memcpy(&data[8], "abc", 3);
  uint32_t tag = 0, clk = 0;
  const uint8_t* body = nullptr;
  size_t body_len = 0;
  ASSERT_TRUE(probeParseAnonReply(data, 11, &tag, &clk, &body, &body_len));
  EXPECT_EQ(tag, 5u);
  EXPECT_EQ(clk, 0x99u);
  EXPECT_EQ(body_len, 3u);
  EXPECT_EQ(std::string((const char*)body, body_len), "abc");
}

TEST(ProbeProtocol, AnonReplyRejectsShortInput) {
  uint8_t data[7] = {0};
  EXPECT_FALSE(probeParseAnonReply(data, sizeof(data), nullptr, nullptr, nullptr, nullptr));
}

}  // namespace
