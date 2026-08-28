// Host contract tests for the complete MQTT publication-topic routing policy.
#define WITH_MQTT_BRIDGE 1
#define PROGMEM

#include <gtest/gtest.h>
#include <algorithm>
#include <cstring>
#include <string>

#include "helpers/MQTTPresets.h"
#include "helpers/MQTTTopicRouter.h"

namespace {

constexpr const char* IATA = "DEN";
constexpr const char* DEVICE = "0123456789ABCDEF";
constexpr const char* TOKEN = "account-token";

struct TypeCase {
  int type;
  const char* name;
};

const TypeCase kTypes[] = {
  {MQTT_PUBLICATION_STATUS, "status"},
  {MQTT_PUBLICATION_PACKETS, "packets"},
  {MQTT_PUBLICATION_RAW, "raw"},
  {MQTT_PUBLICATION_NEIGHBORS, "neighbors"},
};

TEST(MQTTTopicRouter, EveryMeshCorePresetSupportsEveryPublicationType) {
  for (int preset_index = 0; preset_index < MQTT_PRESET_COUNT; ++preset_index) {
    const MQTTPresetDef& preset = MQTT_PRESETS[preset_index];
    if (preset.topic_style != MQTT_TOPIC_MESHCORE) continue;

    for (const TypeCase& type : kTypes) {
      char topic[128];
      ASSERT_TRUE(mqttBuildPublicationTopic(MQTT_ROUTE_MESHCORE, type.type, nullptr,
                                            IATA, DEVICE, TOKEN, topic, sizeof(topic)))
          << preset.name << " / " << type.name;
      EXPECT_EQ(std::string("meshcore/DEN/0123456789ABCDEF/") + type.name, topic)
          << preset.name;
    }
  }
}

// Guards the raw exclusion: a merge from observer-firmware must not re-enable it.
TEST(MQTTTopicRouter, MeshRankTakesEveryTypeExceptRaw) {
  const MQTTPresetDef* preset = findMQTTPreset("meshrank");
  ASSERT_NE(nullptr, preset);
  ASSERT_EQ(MQTT_TOPIC_MESHRANK, preset->topic_style);

  for (const TypeCase& type : kTypes) {
    char topic[128];
    if (type.type == MQTT_PUBLICATION_RAW) {
      EXPECT_FALSE(mqttBuildPublicationTopic(MQTT_ROUTE_MESHRANK, type.type, nullptr,
                                             IATA, DEVICE, TOKEN, topic, sizeof(topic)));
      EXPECT_STREQ("", topic);
      continue;
    }
    ASSERT_TRUE(mqttBuildPublicationTopic(MQTT_ROUTE_MESHRANK, type.type, nullptr,
                                          IATA, DEVICE, TOKEN, topic, sizeof(topic)))
        << type.name;
    EXPECT_EQ(std::string("meshrank/uplink/account-token/0123456789ABCDEF/") + type.name,
              topic)
        << type.name;
  }
}

TEST(MQTTTopicRouter, MeshCoreRequiresUsableIataAndDevice) {
  char topic[64];
  const char* invalid_iatas[] = {nullptr, "", "XX", "XXXX", "X/X", "XXX"};
  for (const char* iata : invalid_iatas) {
    EXPECT_FALSE(mqttBuildPublicationTopic(MQTT_ROUTE_MESHCORE, MQTT_PUBLICATION_STATUS,
                                           nullptr, iata, DEVICE, TOKEN, topic, sizeof(topic)));
    EXPECT_STREQ("", topic);
  }
  EXPECT_FALSE(mqttBuildPublicationTopic(MQTT_ROUTE_MESHCORE, MQTT_PUBLICATION_STATUS,
                                         nullptr, IATA, nullptr, TOKEN, topic, sizeof(topic)));
  EXPECT_FALSE(mqttBuildPublicationTopic(MQTT_ROUTE_MESHCORE, MQTT_PUBLICATION_STATUS,
                                         nullptr, IATA, "", TOKEN, topic, sizeof(topic)));
}

TEST(MQTTTopicRouter, MeshRankRequiresTokenAndDeviceButNotIata) {
  char topic[128];
  const char* missing_tokens[] = {nullptr, ""};
  for (const char* token : missing_tokens) {
    EXPECT_FALSE(mqttBuildPublicationTopic(MQTT_ROUTE_MESHRANK, MQTT_PUBLICATION_PACKETS,
                                           nullptr, nullptr, DEVICE, token, topic, sizeof(topic)));
    EXPECT_STREQ("", topic);
  }
  EXPECT_FALSE(mqttBuildPublicationTopic(MQTT_ROUTE_MESHRANK, MQTT_PUBLICATION_PACKETS,
                                         nullptr, nullptr, nullptr, TOKEN, topic, sizeof(topic)));
  EXPECT_TRUE(mqttBuildPublicationTopic(MQTT_ROUTE_MESHRANK, MQTT_PUBLICATION_PACKETS,
                                        nullptr, nullptr, DEVICE, TOKEN, topic, sizeof(topic)));
}

TEST(MQTTTopicRouter, CustomTemplateExpandsEveryType) {
  for (const TypeCase& type : kTypes) {
    char topic[128];
    ASSERT_TRUE(mqttBuildPublicationTopic(
        MQTT_ROUTE_CUSTOM, type.type, "custom/{iata}/{token}/{device}/{type}",
        IATA, DEVICE, TOKEN, topic, sizeof(topic)));
    EXPECT_EQ(std::string("custom/DEN/account-token/0123456789ABCDEF/") + type.name, topic);
  }
}

TEST(MQTTTopicRouter, CustomLiteralDoesNotRequireIataTokenOrDevice) {
  char topic[32];
  ASSERT_TRUE(mqttBuildPublicationTopic(MQTT_ROUTE_CUSTOM, MQTT_PUBLICATION_RAW,
                                        "private/raw", nullptr, nullptr, nullptr,
                                        topic, sizeof(topic)));
  EXPECT_STREQ("private/raw", topic);
}

TEST(MQTTTopicRouter, EmptyCustomTemplateFailsRatherThanFallingBackImplicitly) {
  char topic[64];
  EXPECT_FALSE(mqttBuildPublicationTopic(MQTT_ROUTE_CUSTOM, MQTT_PUBLICATION_STATUS,
                                         "", IATA, DEVICE, TOKEN, topic, sizeof(topic)));
  EXPECT_STREQ("", topic);

  // MQTTBridge selects the MeshCore style explicitly for a custom slot whose
  // template is empty; make that default contract visible here.
  EXPECT_TRUE(mqttBuildPublicationTopic(MQTT_ROUTE_MESHCORE, MQTT_PUBLICATION_STATUS,
                                        nullptr, IATA, DEVICE, TOKEN, topic, sizeof(topic)));
  EXPECT_STREQ("meshcore/DEN/0123456789ABCDEF/status", topic);
}

TEST(MQTTTopicRouter, FormattedTopicsRequireRoomForTerminator) {
  const char* expected = "meshcore/DEN/0123456789ABCDEF/status";
  const size_t exact_size = strlen(expected) + 1;
  char exact[64];
  ASSERT_LE(exact_size, sizeof(exact));
  EXPECT_TRUE(mqttBuildPublicationTopic(MQTT_ROUTE_MESHCORE, MQTT_PUBLICATION_STATUS,
                                        nullptr, IATA, DEVICE, TOKEN, exact, exact_size));
  EXPECT_STREQ(expected, exact);

  char short_buf[64];
  memset(short_buf, 0x7f, sizeof(short_buf));
  EXPECT_FALSE(mqttBuildPublicationTopic(MQTT_ROUTE_MESHCORE, MQTT_PUBLICATION_STATUS,
                                         nullptr, IATA, DEVICE, TOKEN,
                                         short_buf, exact_size - 1));
  EXPECT_EQ('\0', short_buf[exact_size - 2]);
}

TEST(MQTTTopicRouter, CustomTopicHonorsExactBoundary) {
  const char* expected = "custom/DEN/raw";
  char exact[15];
  static_assert(sizeof(exact) == 15, "fixture includes the terminator");
  EXPECT_TRUE(mqttBuildPublicationTopic(MQTT_ROUTE_CUSTOM, MQTT_PUBLICATION_RAW,
                                        "custom/{iata}/{type}", IATA, DEVICE, TOKEN,
                                        exact, sizeof(exact)));
  EXPECT_STREQ(expected, exact);

  char short_buf[14];
  EXPECT_FALSE(mqttBuildPublicationTopic(MQTT_ROUTE_CUSTOM, MQTT_PUBLICATION_RAW,
                                         "custom/{iata}/{type}", IATA, DEVICE, TOKEN,
                                         short_buf, sizeof(short_buf)));
  EXPECT_LT(strlen(short_buf), sizeof(short_buf));
}

TEST(MQTTTopicRouter, RejectsInvalidStyleTypeSlotAndOutput) {
  char topic[64] = "dirty";
  EXPECT_FALSE(mqttBuildPublicationTopic(MQTT_ROUTE_MESHCORE, 99, nullptr,
                                         IATA, DEVICE, TOKEN, topic, sizeof(topic)));
  EXPECT_STREQ("", topic);
  EXPECT_FALSE(mqttBuildPublicationTopic(static_cast<MQTTTopicRouteStyle>(99),
                                         MQTT_PUBLICATION_STATUS, nullptr,
                                         IATA, DEVICE, TOKEN, topic, sizeof(topic)));
  EXPECT_FALSE(mqttBuildPublicationTopic(MQTT_ROUTE_MESHCORE, MQTT_PUBLICATION_STATUS,
                                         nullptr, IATA, DEVICE, TOKEN, nullptr, 64));
  EXPECT_FALSE(mqttBuildPublicationTopic(MQTT_ROUTE_MESHCORE, MQTT_PUBLICATION_STATUS,
                                         nullptr, IATA, DEVICE, TOKEN, topic, 0));

  EXPECT_FALSE(mqttTopicSlotIndexValid(-1, RUNTIME_MQTT_SLOTS));
  EXPECT_TRUE(mqttTopicSlotIndexValid(0, RUNTIME_MQTT_SLOTS));
  EXPECT_TRUE(mqttTopicSlotIndexValid(RUNTIME_MQTT_SLOTS - 1, RUNTIME_MQTT_SLOTS));
  EXPECT_FALSE(mqttTopicSlotIndexValid(RUNTIME_MQTT_SLOTS, RUNTIME_MQTT_SLOTS));
  EXPECT_FALSE(mqttTopicSlotIndexValid(0, 0));
}

TEST(MQTTTopicRouter, PublicationTypeEnumValuesAreFrozen) {
  // The bridge passes MQTTBridge::MQTTMessageType to mqttBuildPublicationTopic
  // as an int; a compile-time static_assert in the bridge ties the two enums
  // together. Freeze the router side here so its values can't drift on their own.
  EXPECT_EQ(0, MQTT_PUBLICATION_STATUS);
  EXPECT_EQ(1, MQTT_PUBLICATION_PACKETS);
  EXPECT_EQ(2, MQTT_PUBLICATION_RAW);
  EXPECT_EQ(3, MQTT_PUBLICATION_NEIGHBORS);
  EXPECT_STREQ("status", mqttPublicationTypeName(MQTT_PUBLICATION_STATUS));
  EXPECT_STREQ("packets", mqttPublicationTypeName(MQTT_PUBLICATION_PACKETS));
  EXPECT_STREQ("raw", mqttPublicationTypeName(MQTT_PUBLICATION_RAW));
  EXPECT_STREQ("neighbors", mqttPublicationTypeName(MQTT_PUBLICATION_NEIGHBORS));
}

// --- mqttBuildSerialTopic -------------------------------------------------
// The Observer-Probe tasking channel. This builder had no host coverage at all,
// so a regression in it could only ever surface on hardware. These tests pin the
// contract that the probe/v1 port must preserve: fail closed, and never leave a
// half-built topic in the caller's buffer.

// A real 64-hex device id: the probe channel is keyed on the node's own pubkey,
// and that length is what makes the buffer-boundary cases below meaningful.
constexpr const char* PUBKEY =
    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

TEST(MQTTSerialTopic, BuildsBothLeaves) {
  char topic[128];
  ASSERT_TRUE(mqttBuildSerialTopic(IATA, PUBKEY, true, topic, sizeof(topic)));
  EXPECT_EQ(std::string("meshcore/DEN/") + PUBKEY + "/serial/commands", topic);

  ASSERT_TRUE(mqttBuildSerialTopic(IATA, PUBKEY, false, topic, sizeof(topic)));
  EXPECT_EQ(std::string("meshcore/DEN/") + PUBKEY + "/serial/responses", topic);
}

TEST(MQTTSerialTopic, RejectsUnusableIata) {
  char topic[128];
  // Wrong length, topic separators and spaces would all corrupt the path.
  for (const char* bad : {"", "DE", "DENV", "D/N", "D N", "D-N"}) {
    EXPECT_FALSE(mqttBuildSerialTopic(bad, PUBKEY, true, topic, sizeof(topic)))
        << "iata=" << bad;
    EXPECT_STREQ("", topic) << "buffer not cleared for iata=" << bad;
  }
  EXPECT_FALSE(mqttBuildSerialTopic(nullptr, PUBKEY, true, topic, sizeof(topic)));
}

TEST(MQTTSerialTopic, RejectsTheXxxSentinel) {
  // "XXX" is a valid IATA by shape but is the unset sentinel, and it is what an
  // operator sets to take a node off the tasking channel. Keeping this behaviour
  // distinct from the shape check matters: the probe/v1 tree drops the IATA
  // segment, so this kill-switch does NOT carry over on its own.
  char topic[128];
  EXPECT_FALSE(mqttBuildSerialTopic("XXX", PUBKEY, true, topic, sizeof(topic)));
  EXPECT_STREQ("", topic);
}

TEST(MQTTSerialTopic, RejectsMissingDeviceId) {
  // Without this an unnamed device yields "meshcore/DEN//serial/commands" — an
  // empty path segment that is a legal MQTT topic and would silently subscribe
  // the node to a channel nobody publishes to.
  char topic[128];
  EXPECT_FALSE(mqttBuildSerialTopic(IATA, "", true, topic, sizeof(topic)));
  EXPECT_STREQ("", topic);
  EXPECT_FALSE(mqttBuildSerialTopic(IATA, nullptr, true, topic, sizeof(topic)));
  EXPECT_STREQ("", topic);
}

TEST(MQTTSerialTopic, RejectsUnusableBuffer) {
  char topic[128];
  EXPECT_FALSE(mqttBuildSerialTopic(IATA, PUBKEY, true, nullptr, sizeof(topic)));
  EXPECT_FALSE(mqttBuildSerialTopic(IATA, PUBKEY, true, topic, 0));
}

TEST(MQTTSerialTopic, OverflowFailsClosedAndClearsTheBuffer) {
  // "meshcore/" + "DEN" + "/" + 64 + "/serial/" + "commands" == 93 chars, so 94
  // bytes is the exact minimum. One short must fail rather than truncate: a
  // truncated topic is still a legal subscription that would never receive.
  const std::string full = std::string("meshcore/DEN/") + PUBKEY + "/serial/commands";
  ASSERT_EQ(93u, full.size());

  char exact[94];
  ASSERT_TRUE(mqttBuildSerialTopic(IATA, PUBKEY, true, exact, sizeof(exact)));
  EXPECT_EQ(full, exact);

  char one_short[93];
  EXPECT_FALSE(mqttBuildSerialTopic(IATA, PUBKEY, true, one_short, sizeof(one_short)));
  EXPECT_STREQ("", one_short);
}

// --- mqttBuildProbeTopic --------------------------------------------------
// The current control plane: probe/v1/{PUBKEY}/{cmd|rsp}, outside meshcore/.

TEST(MQTTProbeTopic, BuildsBothLeaves) {
  char topic[128];
  ASSERT_TRUE(mqttBuildProbeTopic(PUBKEY, true, topic, sizeof(topic)));
  EXPECT_EQ(std::string("probe/v1/") + PUBKEY + "/cmd", topic);

  ASSERT_TRUE(mqttBuildProbeTopic(PUBKEY, false, topic, sizeof(topic)));
  EXPECT_EQ(std::string("probe/v1/") + PUBKEY + "/rsp", topic);
}

TEST(MQTTProbeTopic, HasNoIataSegmentAndNoIataGate) {
  // Pins a deliberate behaviour CHANGE, not an oversight. The legacy builder
  // refuses when IATA is unset or "XXX", so `set mqtt.iata XXX` used to take a
  // node off the tasking channel. The probe tree has no IATA segment at all, so
  // that side effect is gone and `probe off` is the explicit control instead.
  char probe[128], serial[128];
  EXPECT_FALSE(mqttBuildSerialTopic("XXX", PUBKEY, true, serial, sizeof(serial)));
  EXPECT_TRUE(mqttBuildProbeTopic(PUBKEY, true, probe, sizeof(probe)));
  EXPECT_EQ(std::string("probe/v1/") + PUBKEY + "/cmd", probe);
  // Four levels exactly — the broker's parser rejects anything else. Bind the
  // string first: iterators taken from two separate temporaries are a dangling
  // pair, not a range.
  const std::string built(probe);
  EXPECT_EQ(3, std::count(built.begin(), built.end(), '/'));
}

TEST(MQTTProbeTopic, PreservesKeyCase) {
  // MQTT topic matching is case-sensitive and the broker's parser accepts ONLY
  // uppercase hex, so this builder must never fold the case it is handed.
  char topic[128];
  ASSERT_TRUE(mqttBuildProbeTopic(PUBKEY, true, topic, sizeof(topic)));
  EXPECT_NE(nullptr, strstr(topic, PUBKEY));
}

TEST(MQTTProbeTopic, RejectsMissingDeviceId) {
  char topic[128];
  EXPECT_FALSE(mqttBuildProbeTopic("", true, topic, sizeof(topic)));
  EXPECT_STREQ("", topic);
  EXPECT_FALSE(mqttBuildProbeTopic(nullptr, true, topic, sizeof(topic)));
  EXPECT_STREQ("", topic);
}

TEST(MQTTProbeTopic, RejectsUnusableBuffer) {
  char topic[128];
  EXPECT_FALSE(mqttBuildProbeTopic(PUBKEY, true, nullptr, sizeof(topic)));
  EXPECT_FALSE(mqttBuildProbeTopic(PUBKEY, true, topic, 0));
}

TEST(MQTTProbeTopic, OverflowFailsClosedAndClearsTheBuffer) {
  // "probe/v1/" + 64 + "/cmd" == 77 chars, so 78 bytes is the exact minimum.
  // Truncating instead would yield a legal topic that never receives anything —
  // and the firmware cannot see a denied SUBACK, so it would fail silently.
  const std::string full = std::string("probe/v1/") + PUBKEY + "/cmd";
  ASSERT_EQ(77u, full.size());

  char exact[78];
  ASSERT_TRUE(mqttBuildProbeTopic(PUBKEY, true, exact, sizeof(exact)));
  EXPECT_EQ(full, exact);

  char one_short[77];
  EXPECT_FALSE(mqttBuildProbeTopic(PUBKEY, true, one_short, sizeof(one_short)));
  EXPECT_STREQ("", one_short);
}

TEST(MQTTProbeTopic, IsShorterThanTheLegacyTopicItReplaces) {
  // Both callers pass a 128-byte buffer and the MQTT library truncates silently
  // at 127, so keep the margin visible in a test rather than in a comment.
  char probe[128], serial[128];
  ASSERT_TRUE(mqttBuildProbeTopic(PUBKEY, true, probe, sizeof(probe)));
  ASSERT_TRUE(mqttBuildSerialTopic(IATA, PUBKEY, true, serial, sizeof(serial)));
  EXPECT_LT(strlen(probe), strlen(serial));
  EXPECT_LT(strlen(probe), size_t(127));
}

}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
