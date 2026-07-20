#include <gtest/gtest.h>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "helpers/MQTTPrefsAtomicStore.h"

namespace AtomicStore = MQTTPrefsAtomicStore;

namespace {

enum class FailurePoint {
  None,
  Begin,
  HeaderWrite,
  PayloadWrite,
  ImageWrite,
  Finish,
  Commit,
};

class InMemoryStore {
public:
  explicit InMemoryStore(FailurePoint failure) : _failure(failure) {
    _files["/mqtt_prefs"] = {'o', 'l', 'd', '-', 'p', 'r', 'e', 'f', 's'};
  }

  bool begin() {
    ++begin_calls;
    _files.erase("/mqtt_prefs.tmp");
    _open = _failure != FailurePoint::Begin;
    return _open;
  }

  size_t write(const uint8_t* bytes, size_t size) {
    ++write_calls;
    if (!_open) return 0;
    const bool should_fail = (write_calls == 1 && _failure == FailurePoint::HeaderWrite) ||
        (write_calls == 2 && _failure == FailurePoint::PayloadWrite);
    const size_t written = should_fail && size > 0 ? size - 1 : size;
    _staging.insert(_staging.end(), bytes, bytes + written);
    return written;
  }

  bool finish() {
    ++finish_calls;
    _open = false;
    if (_failure == FailurePoint::Finish) return false;
    _files["/mqtt_prefs.tmp"] = _staging;
    return true;
  }

  bool commit() {
    ++commit_calls;
    if (_failure == FailurePoint::Commit) return false;
    _files["/mqtt_prefs"] = _files["/mqtt_prefs.tmp"];
    _files.erase("/mqtt_prefs.tmp");
    return true;
  }

  void abort() {
    ++abort_calls;
    _open = false;
    _staging.clear();
    _files.erase("/mqtt_prefs.tmp");
  }

  const std::vector<uint8_t>& source() const { return _files.at("/mqtt_prefs"); }
  bool tempExists() const { return _files.count("/mqtt_prefs.tmp") != 0; }

  int begin_calls = 0;
  int write_calls = 0;
  int finish_calls = 0;
  int commit_calls = 0;
  int abort_calls = 0;

private:
  FailurePoint _failure;
  bool _open = false;
  std::vector<uint8_t> _staging;
  std::map<std::string, std::vector<uint8_t>> _files;
};

AtomicStore::Result run(InMemoryStore* store) {
  const uint8_t header[] = {0xf5, 'M', 'Q', 'P', 1, 0, 0x09, 0x00};
  const uint8_t payload[] = {'n', 'e', 'w', '-', 'p', 'r', 'e', 'f', 's'};
  return AtomicStore::write(*store, header, sizeof(header), payload, sizeof(payload));
}

AtomicStore::Result runWithObserverTail(InMemoryStore* store) {
  const uint8_t header[] = {0xf5, 'M', 'Q', 'P', 1, 0, 0x0a, 0x00};
  // The final three bytes stand in for the observer tail transferred from a
  // legacy /com_prefs file. They must be committed before that source is compacted.
  const uint8_t payload[] = {'m', 'i', 'g', 'r', 'a', 't', 'e', 0x91, 0x7e, 0xa5};
  return AtomicStore::write(*store, header, sizeof(header), payload, sizeof(payload));
}

class LegacyComPrefs {
public:
  LegacyComPrefs() : bytes({'l', 'e', 'g', 'a', 'c', 'y', '-', 'c', 'o', 'm'}) {}

  void compactAfterMqttCommit(const std::vector<uint8_t>& mqtt_bytes) {
    const std::vector<uint8_t> observer_tail = {0x91, 0x7e, 0xa5};
    mqtt_tail_present_before_compaction = mqtt_bytes.size() >= observer_tail.size() &&
        std::equal(observer_tail.rbegin(), observer_tail.rend(), mqtt_bytes.rbegin());
    bytes = {'c', 'o', 'm', 'p', 'a', 'c', 't'};
    ++compact_calls;
  }

  std::vector<uint8_t> bytes;
  bool mqtt_tail_present_before_compaction = false;
  int compact_calls = 0;
};

class LegacyNodePrefs {
public:
  LegacyNodePrefs() : bytes({'l', 'e', 'g', 'a', 'c', 'y', '-', 'n', 'o', 'd', 'e'}) {}

  void migrateAfterMqttCommit(const std::vector<uint8_t>& mqtt_bytes) {
    const std::vector<uint8_t> observer_tail = {0x91, 0x7e, 0xa5};
    mqtt_tail_present_before_removal = mqtt_bytes.size() >= observer_tail.size() &&
        std::equal(observer_tail.rbegin(), observer_tail.rend(), mqtt_bytes.rbegin());
    bytes.clear();  // model removal after current-layout /com_prefs is written
    ++migration_calls;
  }

  std::vector<uint8_t> bytes;
  bool mqtt_tail_present_before_removal = false;
  int migration_calls = 0;
};

// Models the final old-name migration separately from the MQTT transaction:
// /com_prefs is absent while /node_prefs is authoritative. A failed temp write
// or rename must leave that source as the only usable preference image.
class InMemoryCommonPrefsStore {
public:
  explicit InMemoryCommonPrefsStore(FailurePoint failure) : _failure(failure) {
    _files["/node_prefs"] = {'l', 'e', 'g', 'a', 'c', 'y', '-', 'n', 'o', 'd', 'e'};
  }

  bool begin() {
    ++begin_calls;
    _files.erase("/com_prefs.tmp");
    _staging.clear();
    _open = _failure != FailurePoint::Begin;
    return _open;
  }

  size_t write(const uint8_t* bytes, size_t size) {
    ++write_calls;
    if (!_open) return 0;
    const bool should_fail = _failure == FailurePoint::ImageWrite && write_calls == 2;
    const size_t written = should_fail && size > 0 ? size - 1 : size;
    _staging.insert(_staging.end(), bytes, bytes + written);
    return written;
  }

  bool finish() {
    ++finish_calls;
    _open = false;
    if (_failure == FailurePoint::Finish) return false;
    _files["/com_prefs.tmp"] = _staging;
    return true;
  }

  bool commit() {
    ++commit_calls;
    if (_failure == FailurePoint::Commit) return false;
    _files["/com_prefs"] = _files["/com_prefs.tmp"];
    _files.erase("/com_prefs.tmp");
    return true;
  }

  void abort() {
    ++abort_calls;
    _open = false;
    _staging.clear();
    _files.erase("/com_prefs.tmp");
  }

  void removeNodeSource() { _files.erase("/node_prefs"); }
  const std::vector<uint8_t>& nodeSource() const { return _files.at("/node_prefs"); }
  const std::vector<uint8_t>& destination() const { return _files.at("/com_prefs"); }
  bool destinationExists() const { return _files.count("/com_prefs") != 0; }
  bool tempExists() const { return _files.count("/com_prefs.tmp") != 0; }
  bool nodeSourceIsPreferred() const {
    return _files.count("/node_prefs") != 0 && _files.count("/com_prefs") == 0;
  }
  bool nodeSourceExists() const { return _files.count("/node_prefs") != 0; }

  int begin_calls = 0;
  int write_calls = 0;
  int finish_calls = 0;
  int commit_calls = 0;
  int abort_calls = 0;

private:
  FailurePoint _failure;
  bool _open = false;
  std::vector<uint8_t> _staging;
  std::map<std::string, std::vector<uint8_t>> _files;
};

AtomicStore::ImageResult runCommonPrefsImage(InMemoryCommonPrefsStore* store) {
  const uint8_t core[] = {'c', 'o', 'm', '-', 'p', 'r', 'e', 'f', 's'};
  const uint8_t tail[] = {0x19, 0xa4, 0x7e};
  return AtomicStore::writeImage(*store, [&core, &tail](InMemoryCommonPrefsStore& target) {
    return target.write(core, sizeof(core)) == sizeof(core) &&
        target.write(tail, sizeof(tail)) == sizeof(tail);
  });
}

// Models ESP32 SPIFFS rename semantics: rename fails when the destination
// already exists (SPIFFS_ERR_CONFLICTING_NAME). Production MQTTPrefsFileStore
// must remove /mqtt_prefs before renaming the verified tmp into place.
class SpiffsLikeMqttPrefsStore {
public:
  SpiffsLikeMqttPrefsStore() {
    _files["/mqtt_prefs"] = {'o', 'l', 'd', '-', 'p', 'r', 'e', 'f', 's'};
  }

  bool begin() {
    _files.erase("/mqtt_prefs.tmp");
    _staging.clear();
    _open = true;
    return true;
  }

  size_t write(const uint8_t* bytes, size_t size) {
    if (!_open) return 0;
    _staging.insert(_staging.end(), bytes, bytes + size);
    return size;
  }

  bool finish() {
    _open = false;
    _files["/mqtt_prefs.tmp"] = _staging;
    _finished = true;
    return true;
  }

  // Naive POSIX-style replace — wrong for SPIFFS when dest exists.
  bool commitReplaceInPlace() {
    if (!_finished || _files.count("/mqtt_prefs.tmp") == 0) return false;
    if (_files.count("/mqtt_prefs") != 0) return false;  // CONFLICTING_NAME
    _files["/mqtt_prefs"] = _files["/mqtt_prefs.tmp"];
    _files.erase("/mqtt_prefs.tmp");
    return true;
  }

  // Matches CommonCLI MQTTPrefsFileStore::commit() on ESP32.
  bool commitRemoveThenRename() {
    if (!_finished || _files.count("/mqtt_prefs.tmp") == 0) return false;
    _files.erase("/mqtt_prefs");
    _files["/mqtt_prefs"] = _files["/mqtt_prefs.tmp"];
    _files.erase("/mqtt_prefs.tmp");
    return true;
  }

  void abort() {
    _open = false;
    _finished = false;
    _staging.clear();
    _files.erase("/mqtt_prefs.tmp");
  }

  const std::vector<uint8_t>& source() const { return _files.at("/mqtt_prefs"); }
  bool tempExists() const { return _files.count("/mqtt_prefs.tmp") != 0; }

private:
  bool _open = false;
  bool _finished = false;
  std::vector<uint8_t> _staging;
  std::map<std::string, std::vector<uint8_t>> _files;
};

}  // namespace

TEST(MQTTPrefsAtomicStore, CommitPublishesExactHeaderThenPayload) {
  InMemoryStore store(FailurePoint::None);

  EXPECT_EQ(AtomicStore::Result::Committed, run(&store));
  EXPECT_EQ((std::vector<uint8_t>{0xf5, 'M', 'Q', 'P', 1, 0, 0x09, 0x00,
                                  'n', 'e', 'w', '-', 'p', 'r', 'e', 'f', 's'}),
            store.source());
  EXPECT_FALSE(store.tempExists());
  EXPECT_EQ(1, store.begin_calls);
  EXPECT_EQ(2, store.write_calls);
  EXPECT_EQ(1, store.finish_calls);
  EXPECT_EQ(1, store.commit_calls);
  EXPECT_EQ(0, store.abort_calls);
}

TEST(MQTTPrefsAtomicStore, AnyFailureAbortsAndPreservesExistingSource) {
  const std::vector<uint8_t> source = {'o', 'l', 'd', '-', 'p', 'r', 'e', 'f', 's'};
  const struct {
    FailurePoint point;
    AtomicStore::Result expected;
    int writes;
    int finishes;
    int commits;
  } cases[] = {
      {FailurePoint::Begin, AtomicStore::Result::BeginFailed, 0, 0, 0},
      {FailurePoint::HeaderWrite, AtomicStore::Result::HeaderWriteFailed, 1, 0, 0},
      {FailurePoint::PayloadWrite, AtomicStore::Result::PayloadWriteFailed, 2, 0, 0},
      {FailurePoint::Finish, AtomicStore::Result::FinishFailed, 2, 1, 0},
      {FailurePoint::Commit, AtomicStore::Result::CommitFailed, 2, 1, 1},
  };

  for (const auto& test_case : cases) {
    InMemoryStore store(test_case.point);
    EXPECT_EQ(test_case.expected, run(&store));
    EXPECT_EQ(source, store.source());
    EXPECT_FALSE(store.tempExists());
    EXPECT_EQ(1, store.begin_calls);
    EXPECT_EQ(test_case.writes, store.write_calls);
    EXPECT_EQ(test_case.finishes, store.finish_calls);
    EXPECT_EQ(test_case.commits, store.commit_calls);
    EXPECT_EQ(1, store.abort_calls);
  }
}

TEST(MQTTPrefsAtomicStore, LegacyCrossFileUpgradeCommitsTailBeforeCompactingComPrefs) {
  InMemoryStore mqtt_store(FailurePoint::None);
  LegacyComPrefs com_prefs;
  AtomicStore::LegacyUpgradeGate gate(true);
  gate.requireMqttRewrite();

  const AtomicStore::Result result = runWithObserverTail(&mqtt_store);
  gate.recordMqttSave(AtomicStore::committed(result));
  ASSERT_TRUE(gate.mayRewriteComPrefs());

  com_prefs.compactAfterMqttCommit(mqtt_store.source());
  gate.recordComPrefsRewrite();

  EXPECT_TRUE(com_prefs.mqtt_tail_present_before_compaction);
  EXPECT_EQ(1, com_prefs.compact_calls);
  EXPECT_EQ((std::vector<uint8_t>{'c', 'o', 'm', 'p', 'a', 'c', 't'}), com_prefs.bytes);
  EXPECT_FALSE(gate.mayRewriteComPrefs());
}

TEST(MQTTPrefsAtomicStore, LegacyCrossFilePowerCutPreservesBothSources) {
  const std::vector<uint8_t> legacy_mqtt = {'o', 'l', 'd', '-', 'p', 'r', 'e', 'f', 's'};
  const std::vector<uint8_t> legacy_com = {'l', 'e', 'g', 'a', 'c', 'y', '-', 'c', 'o', 'm'};
  for (const FailurePoint point : {FailurePoint::Begin, FailurePoint::HeaderWrite,
                                   FailurePoint::PayloadWrite, FailurePoint::Finish,
                                   FailurePoint::Commit}) {
    InMemoryStore mqtt_store(point);
    LegacyComPrefs com_prefs;
    AtomicStore::LegacyUpgradeGate gate(true);
    gate.requireMqttRewrite();

    const AtomicStore::Result result = runWithObserverTail(&mqtt_store);
    gate.recordMqttSave(AtomicStore::committed(result));
    if (gate.mayRewriteComPrefs()) {
      com_prefs.compactAfterMqttCommit(mqtt_store.source());
      gate.recordComPrefsRewrite();
    }

    EXPECT_FALSE(AtomicStore::committed(result));
    EXPECT_EQ(legacy_mqtt, mqtt_store.source());
    EXPECT_EQ(legacy_com, com_prefs.bytes);
    EXPECT_EQ(0, com_prefs.compact_calls);
    EXPECT_TRUE(gate.blocksComPrefsRewrite());
  }
}

TEST(MQTTPrefsAtomicStore, LegacyNodePrefsMigrationWaitsForObserverTailCommit) {
  InMemoryStore mqtt_store(FailurePoint::None);
  LegacyNodePrefs node_prefs;
  AtomicStore::LegacyUpgradeGate gate(true);
  gate.requireMqttRewrite();

  const AtomicStore::Result result = runWithObserverTail(&mqtt_store);
  gate.recordMqttSave(AtomicStore::committed(result));
  ASSERT_TRUE(gate.mayRewriteComPrefs());

  node_prefs.migrateAfterMqttCommit(mqtt_store.source());
  gate.recordComPrefsRewrite();

  EXPECT_TRUE(node_prefs.mqtt_tail_present_before_removal);
  EXPECT_EQ(1, node_prefs.migration_calls);
  EXPECT_TRUE(node_prefs.bytes.empty());
}

TEST(MQTTPrefsAtomicStore, LegacyNodePrefsPowerCutPreservesSource) {
  const std::vector<uint8_t> legacy_mqtt = {'o', 'l', 'd', '-', 'p', 'r', 'e', 'f', 's'};
  const std::vector<uint8_t> legacy_node = {
      'l', 'e', 'g', 'a', 'c', 'y', '-', 'n', 'o', 'd', 'e'};
  for (const FailurePoint point : {FailurePoint::Begin, FailurePoint::HeaderWrite,
                                   FailurePoint::PayloadWrite, FailurePoint::Finish,
                                   FailurePoint::Commit}) {
    InMemoryStore mqtt_store(point);
    LegacyNodePrefs node_prefs;
    AtomicStore::LegacyUpgradeGate gate(true);
    gate.requireMqttRewrite();

    const AtomicStore::Result result = runWithObserverTail(&mqtt_store);
    gate.recordMqttSave(AtomicStore::committed(result));
    if (gate.mayRewriteComPrefs()) {
      node_prefs.migrateAfterMqttCommit(mqtt_store.source());
      gate.recordComPrefsRewrite();
    }

    EXPECT_FALSE(AtomicStore::committed(result));
    EXPECT_EQ(legacy_mqtt, mqtt_store.source());
    EXPECT_EQ(legacy_node, node_prefs.bytes);
    EXPECT_EQ(0, node_prefs.migration_calls);
    EXPECT_TRUE(gate.blocksComPrefsRewrite());
  }
}

TEST(MQTTPrefsAtomicStore, NodePrefsMigrationPublishesComPrefsBeforeRemovingSource) {
  InMemoryCommonPrefsStore store(FailurePoint::None);

  ASSERT_EQ(AtomicStore::ImageResult::Committed, runCommonPrefsImage(&store));
  EXPECT_TRUE(store.nodeSourceExists());  // caller removes it only after commit
  EXPECT_EQ((std::vector<uint8_t>{'c', 'o', 'm', '-', 'p', 'r', 'e', 'f', 's', 0x19, 0xa4, 0x7e}),
            store.destination());
  EXPECT_FALSE(store.tempExists());

  store.removeNodeSource();
  EXPECT_FALSE(store.nodeSourceExists());
  EXPECT_TRUE(store.destinationExists());
}

TEST(MQTTPrefsAtomicStore, NodePrefsMigrationFailurePreservesSourceAndNeverPrefersPartialDestination) {
  const std::vector<uint8_t> legacy_node = {
      'l', 'e', 'g', 'a', 'c', 'y', '-', 'n', 'o', 'd', 'e'};
  const struct {
    FailurePoint point;
    AtomicStore::ImageResult expected;
    int writes;
    int finishes;
    int commits;
  } cases[] = {
      {FailurePoint::Begin, AtomicStore::ImageResult::BeginFailed, 0, 0, 0},
      {FailurePoint::ImageWrite, AtomicStore::ImageResult::WriteFailed, 2, 0, 0},
      {FailurePoint::Finish, AtomicStore::ImageResult::FinishFailed, 2, 1, 0},
      {FailurePoint::Commit, AtomicStore::ImageResult::CommitFailed, 2, 1, 1},
  };

  for (const auto& test_case : cases) {
    InMemoryCommonPrefsStore store(test_case.point);
    EXPECT_EQ(test_case.expected, runCommonPrefsImage(&store));
    EXPECT_EQ(legacy_node, store.nodeSource());
    EXPECT_TRUE(store.nodeSourceIsPreferred());
    EXPECT_FALSE(store.destinationExists());
    EXPECT_FALSE(store.tempExists());
    EXPECT_EQ(1, store.begin_calls);
    EXPECT_EQ(test_case.writes, store.write_calls);
    EXPECT_EQ(test_case.finishes, store.finish_calls);
    EXPECT_EQ(test_case.commits, store.commit_calls);
    EXPECT_EQ(1, store.abort_calls);
  }
}

TEST(MQTTPrefsAtomicStore, SpiffsRenameRequiresRemoveBeforePublish) {
  const uint8_t header[] = {0xf5, 'M', 'Q', 'P', 1, 0, 0x09, 0x00};
  const uint8_t payload[] = {'n', 'e', 'w', '-', 'p', 'r', 'e', 'f', 's'};
  const std::vector<uint8_t> published = {0xf5, 'M', 'Q', 'P', 1, 0, 0x09, 0x00,
                                          'n', 'e', 'w', '-', 'p', 'r', 'e', 'f', 's'};
  const std::vector<uint8_t> previous = {'o', 'l', 'd', '-', 'p', 'r', 'e', 'f', 's'};

  {
    SpiffsLikeMqttPrefsStore store;
    ASSERT_TRUE(store.begin());
    ASSERT_EQ(sizeof(header), store.write(header, sizeof(header)));
    ASSERT_EQ(sizeof(payload), store.write(payload, sizeof(payload)));
    ASSERT_TRUE(store.finish());
    // Dest exists → SPIFFS-style rename must fail (the pre-fix production bug).
    EXPECT_FALSE(store.commitReplaceInPlace());
    EXPECT_EQ(previous, store.source());
    EXPECT_TRUE(store.tempExists());
    store.abort();
    EXPECT_FALSE(store.tempExists());
  }

  {
    SpiffsLikeMqttPrefsStore store;
    ASSERT_TRUE(store.begin());
    ASSERT_EQ(sizeof(header), store.write(header, sizeof(header)));
    ASSERT_EQ(sizeof(payload), store.write(payload, sizeof(payload)));
    ASSERT_TRUE(store.finish());
    EXPECT_TRUE(store.commitRemoveThenRename());
    EXPECT_EQ(published, store.source());
    EXPECT_FALSE(store.tempExists());
  }
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
