#include <gtest/gtest.h>

#include "helpers/MQTTPacketFilter.h"

namespace Filter = MQTTPacketFilter;

TEST(MQTTPacketFilter, EmptyAndAllMeanEveryType) {
  for (const char* value : {"", " ", "\tall\r\n"}) {
    uint16_t mask = 0;
    ASSERT_TRUE(Filter::parse(value, &mask)) << value;
    EXPECT_EQ(Filter::kAllPacketTypes, mask);
  }
}

TEST(MQTTPacketFilter, NoneMeansNoTypes) {
  uint16_t mask = Filter::kAllPacketTypes;
  ASSERT_TRUE(Filter::parse(" none ", &mask));
  EXPECT_EQ(0u, mask);
}

TEST(MQTTPacketFilter, ParsesDecimalCsvWithWhitespaceAndDuplicates) {
  uint16_t mask = 0;
  ASSERT_TRUE(Filter::parse(" 2, 4,\t15,2 ", &mask));
  EXPECT_EQ(static_cast<uint16_t>((1u << 2) | (1u << 4) | (1u << 15)), mask);
}

TEST(MQTTPacketFilter, FullNumericListCanonicalizesToAll) {
  uint16_t mask = 0;
  ASSERT_TRUE(Filter::parse("0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15", &mask));
  EXPECT_EQ(Filter::kAllPacketTypes, mask);
  char output[Filter::kFilterTextSize];
  ASSERT_TRUE(Filter::format(mask, output, sizeof(output)));
  EXPECT_STREQ("all", output);
}

TEST(MQTTPacketFilter, RejectsMalformedOrOutOfRangeValuesWithoutChangingOutput) {
  const char* invalid[] = {
    ",", "1,", ",1", "1,,2", "1, ,2", "-1", "+1", "0x2", "16",
    "999999999999999999999", "ALL", "All", "all,2", "none,2", "2-4", "2x",
  };
  for (const char* value : invalid) {
    uint16_t mask = 0x1234;
    EXPECT_FALSE(Filter::parse(value, &mask)) << value;
    EXPECT_EQ(0x1234, mask) << value;
  }
  EXPECT_FALSE(Filter::parse(nullptr, nullptr));
}

TEST(MQTTPacketFilter, FormatsSubsetsInAscendingOrder) {
  const uint16_t mask = static_cast<uint16_t>(
      (1u << 15) | (1u << 2) | (1u << 10) | (1u << 0));
  char output[Filter::kFilterTextSize];
  ASSERT_TRUE(Filter::format(mask, output, sizeof(output)));
  EXPECT_STREQ("0,2,10,15", output);
}

TEST(MQTTPacketFilter, FormatsNoneAndHonorsExactBufferBoundaries) {
  char none[5];
  ASSERT_TRUE(Filter::format(0, none, sizeof(none)));
  EXPECT_STREQ("none", none);

  char too_small[4] = {'x', 'x', 'x', '\0'};
  EXPECT_FALSE(Filter::format(0, too_small, sizeof(too_small)));
  EXPECT_STREQ("", too_small);

  char all_types[Filter::kFilterTextSize];
  const uint16_t subset = static_cast<uint16_t>(Filter::kAllPacketTypes & ~(1u << 14));
  ASSERT_TRUE(Filter::format(subset, all_types, sizeof(all_types)));
  EXPECT_STREQ("0,1,2,3,4,5,6,7,8,9,10,11,12,13,15", all_types);
  char one_short[34];
  EXPECT_FALSE(Filter::format(subset, one_short, sizeof(one_short)));
  EXPECT_STREQ("", one_short);
}

TEST(MQTTPacketFilter, MembershipIsBoundedToFourBitTypes) {
  EXPECT_TRUE(Filter::allows(static_cast<uint16_t>(1u << 0), 0));
  EXPECT_TRUE(Filter::allows(static_cast<uint16_t>(1u << 15), 15));
  EXPECT_FALSE(Filter::allows(Filter::kAllPacketTypes, 16));
  EXPECT_FALSE(Filter::allows(0, 0));
}

TEST(MQTTPacketFilter, EligibilityIgnoresConnectionButRequiresTopicAndFilter) {
  const uint16_t only_advert = static_cast<uint16_t>(1u << 4);
  EXPECT_TRUE(Filter::slotEligible(true, true, only_advert, 4));
  EXPECT_FALSE(Filter::slotEligible(false, true, only_advert, 4));
  EXPECT_FALSE(Filter::slotEligible(true, false, only_advert, 4));
  EXPECT_FALSE(Filter::slotEligible(true, true, only_advert, 2));
}

TEST(MQTTPacketFilter, AllFilteredOrTopicIncompatibleTargetsCompleteIntentionally) {
  const uint16_t only_text = static_cast<uint16_t>(1u << 2);
  const bool filtered = Filter::slotEligible(true, true, only_text, 4);
  const bool topic_incompatible =
      Filter::slotEligible(true, false, Filter::kAllPacketTypes, 4);
  EXPECT_FALSE(filtered || topic_incompatible);
  EXPECT_TRUE(Filter::publishComplete(filtered || topic_incompatible, false));
}

TEST(MQTTPacketFilter, EligibleDisconnectedTargetStillRequiresRetry) {
  const uint16_t only_advert = static_cast<uint16_t>(1u << 4);
  // Connection state is intentionally absent from slotEligible(): the first
  // slot remains a target while disconnected. A second connected slot whose
  // filter rejects the advert cannot turn that into intentional completion.
  const bool disconnected_eligible =
      Filter::slotEligible(true, true, only_advert, 4);
  const bool connected_filtered =
      Filter::slotEligible(true, true, static_cast<uint16_t>(1u << 2), 4);
  ASSERT_TRUE(disconnected_eligible);
  ASSERT_FALSE(connected_filtered);
  EXPECT_FALSE(Filter::publishComplete(
      disconnected_eligible || connected_filtered, false));
}

TEST(MQTTPacketFilter, PublishFailureRetriesAndAnySuccessCompletes) {
  EXPECT_FALSE(Filter::publishComplete(true, false));
  EXPECT_TRUE(Filter::publishComplete(true, true));
  EXPECT_TRUE(Filter::publishComplete(false, true));  // defensive: success wins
}

TEST(MQTTPacketFilter, UnsupportedRawPathCannotHideEligiblePacketFailure) {
  const bool packet_eligible = true;
  const bool packet_published = false;
  const bool raw_eligible = false;  // e.g. MeshRank has no raw topic
  const bool raw_published = false;

  EXPECT_FALSE(Filter::publishComplete(
      packet_eligible || raw_eligible,
      packet_published || raw_published));
  EXPECT_TRUE(Filter::publishComplete(false, false));
}

TEST(MQTTPacketFilter, PacketAndRawCanShareTheSameMaskDecision) {
  const uint16_t text_and_advert = static_cast<uint16_t>((1u << 2) | (1u << 4));
  for (uint8_t type = 0; type <= 15; ++type) {
    const bool expected = type == 2 || type == 4;
    EXPECT_EQ(expected, Filter::allows(text_and_advert, type)) << unsigned(type);
  }
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
