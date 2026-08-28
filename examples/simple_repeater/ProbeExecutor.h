#pragma once

// Echo Observer-Probe -- the probe executor.
//
// Drives a probe SESSION against one target node: an optional guest login
// (empty password) followed by the requested ver-ident / status / telemetry
// requests, or a single zero-hop anon owner request that needs no login at all.
//
// This is deliberately NOT a BaseChatMesh subclass. MyMesh already overrides the
// exact virtual set BaseChatMesh overrides (searchPeersByHash, getPeerSharedSecret,
// onPeerDataRecv, onPeerPathRecv, ...), BaseChatMesh::sendFloodScoped is UNSCOPED
// and would silently drop probe packets off this node's transport scope, and the
// contact table alone would cost roughly 8 KB on the non-PSRAM reference board.
// See DIRECTIONS-firmware.md section A.4.
//
// THREADING: everything here runs on the Arduino loop task (Core 1), which owns
// the radio, the packet pool and self_id. The MQTT mailbox is drained by MyMesh
// on that same task and handed in through onCommand(). Nothing in this class may
// be called from the MQTT bridge task or the esp-mqtt event task.
//
// Vocabulary: this node is an Observer in a mesh of nodes. The node roles are
// Repeater, Companion, Sensor, Observer.

#include <Arduino.h>
#include <Mesh.h>
#include <helpers/CommonCLI.h>
#include <helpers/ProbeProtocol.h>
#include <helpers/ProbePolicy.h>
#include <helpers/ProbeCodec.h>
#include <helpers/ProbeSecret.h>
#include "RateLimiter.h"

class MyMesh;

// Queue depth. Only ONE session is ever on the radio; the rest wait.
#ifndef MAX_PROBE_SESSIONS
  #define MAX_PROBE_SESSIONS 4
#endif

// Overlay index base for probe targets, kept clear of real ACL indices and of
// NEIGHBOR_DISCOVER_PEER_BASE (1000).
#define PROBE_PEER_BASE 2000

// Requested operations, a bitmask carried in the tasking command.
#define PROBE_OP_OWNER      0x01   // zero-hop anon owner request, no login
#define PROBE_OP_VER_IDENT  0x02   // guest login + REQ 0x07
#define PROBE_OP_STATUS     0x04   // guest login + REQ 0x01
#define PROBE_OP_TELEMETRY  0x08   // guest login + REQ 0x03
// Remote CLI command. Needs an ADMIN login: the target gates this on
// client->isAdmin() (MyMesh.cpp:890) and silently ignores a guest, so a command
// op without a sealed "pw" would time out with no explanation.
#define PROBE_OP_COMMAND    0x10
// Adopt a new controller key. Handled ON THIS NODE -- it never goes out over LoRa, so it
// takes no session and has no target beyond ourselves. Lets the controller move a node off
// the shared deployment key onto one issued just for it, so day-to-day tasking no longer
// depends on a key every node in the field shares.
#define PROBE_OP_SET_CONTROLLER 0x20
#define PROBE_OPS_NEED_LOGIN (PROBE_OP_VER_IDENT | PROBE_OP_STATUS | PROBE_OP_TELEMETRY                               | PROBE_OP_COMMAND)

#define PROBE_JOB_ID_LEN 16

// Inbound tasking command ceiling. Held as a MEMBER, never a stack local: the
// Arduino loop task has an 8 KB stack and the software Ed25519 verify path alone
// needs roughly 3 KB of it (src/Identity.cpp:25-28).
#define PROBE_CMD_MAX_LEN 1024
// Any clock reading below this (2023-11-14) is a node that has not learned the time
// yet, not a real timestamp. Used only to decide whether the boot epoch is usable.
#define PROBE_SANE_EPOCH 1700000000u

// DECODED claims budget -- the size of the _claims buffer below. The worst real case is a
// 160-char remote CLI command alongside a sealed admin password, measured at 503 decoded
// bytes; 512 would clear that by nine bytes, which is not headroom, it is a coincidence.
#define PROBE_CLAIMS_MAX_LEN 640
// The same budget expressed in BASE64URL characters, for the pre-filter that runs before
// we decode. These are different units and conflating them silently shrinks the usable
// claims by a quarter: comparing an ENCODED length against the DECODED cap left ~128 bytes
// of the buffer unreachable and capped a remote CLI command at about 44 characters, while
// Echo, this file and the protocol doc all advertised 160.
#define PROBE_CLAIMS_MAX_B64 (((PROBE_CLAIMS_MAX_LEN + 2) / 3) * 4)

enum ProbeStep : uint8_t {
  PS_IDLE = 0, PS_ANON, PS_LOGIN, PS_VER_IDENT, PS_STATUS, PS_TELEMETRY, PS_CLI, PS_DONE
};

enum ProbeState : uint8_t {
  PST_FREE = 0, PST_QUEUED, PST_ACTIVE, PST_OK, PST_TIMEOUT, PST_SEND_FAILED, PST_DENIED
};

enum ProbeRoute : uint8_t { PR_NONE = 0, PR_ZEROHOP, PR_DIRECT, PR_FLOOD };

// Why a command was refused. Reported back so Echo can tell "denied" from "lost".
enum ProbeReject : uint8_t {
  PRJ_NONE = 0, PRJ_DISABLED, PRJ_NO_CONTROLLER, PRJ_BAD_TOKEN, PRJ_BAD_SIG,
  PRJ_REPLAY, PRJ_CLOCK, PRJ_RATE, PRJ_QUEUE_FULL, PRJ_BAD_TARGET, PRJ_BAD_PW,
  PRJ_BAD_CMD, PRJ_NEED_ADMIN, PRJ_BAD_OBS, PRJ_PREBOOT
};

// A queued unit of work. Kept small: the bulky per-attempt state lives in the
// executor because only one session is ever active.
struct ProbeSession {
  mesh::Identity target;
  char     job_id[PROBE_JOB_ID_LEN + 1];
  uint8_t  ops_mask;
  uint8_t  state;
  uint8_t  reply_slot;      // MQTT slot the command arrived on; 0xFF = local CLI
  bool     from_mqtt;
  // Recovered admin password, empty for a guest login. Held only for the life of
  // the session and wiped in finishSession -- a field-readable node should not
  // carry a repeater admin password in RAM after it is done with it.
  char     password[PROBE_PW_MAX + 1];
  bool     is_admin;
  // Remote CLI command text for PROBE_OP_COMMAND. Not NUL-padded on the wire; the
  // stored length is authoritative.
  char     cli_cmd[PROBE_CLI_MAX_TEXT + 1];
  uint8_t  cli_len;
  // Admission-time deadline and arrival order. A session can sit QUEUED behind three
  // others, each of which may flood and retry for a minute or more, so by the time it
  // reaches the radio the command it carries can be long dead. exp is re-checked at
  // dispatch; seq makes the queue FIFO rather than "lowest free slot index wins".
  uint32_t exp;               // 0 = no deadline supplied (local CLI)
  uint32_t seq;               // monotonic admission counter
};

// Human-readable names for a finished session, used when MyMesh serialises the
// result token. Defined in ProbeExecutor.cpp.
const char* probeExecStateName(uint8_t state);
const char* probeExecRouteName(uint8_t route);

class ProbeExecutor {
public:
  ProbeExecutor();

  void begin(MyMesh* mesh, NodePrefs* prefs);

  // Re-arm both limiters from prefs. Must be called after loadPrefs(), because
  // the constructor runs before the stored prefs exist.
  void applyPrefs();

  void loop();

  // --- Admission ------------------------------------------------------------

  // A signed tasking command from Echo, already copied out of the MQTT mailbox
  // by MyMesh on Core 1. `len` must be strlen(token): the MQTT message callback
  // has no length parameter (see DIRECTIONS-firmware.md section B.5).
  bool onCommand(const char* token, size_t len, uint8_t reply_slot);

  // Local serial-CLI path (milestone M1). No signature, no MQTT.
  bool startLocal(const mesh::Identity& target, uint8_t ops_mask, char* err, size_t err_size);

  // --- Reply intake, called from MyMesh ------------------------------------

  int  overlayCount() const { return (_active >= 0 && _awaiting) ? 1 : 0; }
  bool overlayMatchesHash(const uint8_t* hash) const;
  bool overlayId(int overlay_idx, mesh::Identity& out) const;

  // `type` distinguishes a normal RESPONSE from a CLI reply, which arrives as
  // PAYLOAD_TYPE_TXT_MSG. Defaults keep the existing call sites working.
  bool handleResponse(int overlay_idx, const uint8_t* data, size_t len,
                      uint8_t type = PAYLOAD_TYPE_RESPONSE);
private:
  bool handleResponseInner(int overlay_idx, const uint8_t* data, size_t len);
public:
  bool handlePathReturn(int overlay_idx, const uint8_t* path, uint8_t path_len,
                        uint8_t extra_type, const uint8_t* extra, uint8_t extra_len);

  // True when this identity is the active target, for the case where the target
  // also happens to be an ACL client and resolves to a normal index.
  bool isActiveTarget(const mesh::Identity& id) const;

  // --- TX confirmation, called from MyMesh::logTx / logTxFail --------------
  void onPacketSent(mesh::Packet* pkt);
  void onPacketSendFailed(mesh::Packet* pkt);

  // --- Reporting ------------------------------------------------------------
  // The MQTT mailbox is drained straight into this buffer so no 1 KB temporary
  // ever lands on the mesh loop task stack.
  char*  commandBuffer() { return _cmd_buf; }
  size_t commandBufferSize() const { return sizeof(_cmd_buf); }

  bool getStatusLine(char* buf, size_t buf_size) const;
  void appendStatsJson(char* buf, size_t buf_size) const;
  bool isBusy() const { return _active >= 0; }

private:
  MyMesh*    _mesh;
  NodePrefs* _prefs;

  ProbeSession _sessions[MAX_PROBE_SESSIONS];
  int          _active;             // index of the running session, -1 when idle

  // --- Route cache -----------------------------------------------------------
  // Without this a learned path dies with the session, so EVERY login-based
  // session re-floods its first step -- polling 50 nodes hourly would be 50
  // mesh-wide flood cascades an hour, forever. Caching alone is only half the
  // fix; see the reciprocal teach in MyMesh::onPeerPathRecv, without which the
  // TARGET keeps flooding its replies and the flood merely moves out of sight of
  // our own counters.
  //
  // Full pubkey, not a prefix: a prefix collision would route a probe down
  // another node's path. The path is capped well below MAX_PATH_SIZE (see
  // PROBE_ROUTE_MAX_PATH) because real paths are a handful of 1-byte hops, so
  // 64 entries cost LESS than 24 full-width ones did.
  struct RouteEntry {
    uint8_t  pub_key[PUB_KEY_SIZE];
    uint8_t  out_path[PROBE_ROUTE_MAX_PATH];
    uint8_t  out_path_len;          // encoded, PROBE_OUT_PATH_UNKNOWN when empty
    uint32_t learned_at;            // epoch secs, 0 = free slot
  };
  RouteEntry _routes[PROBE_ROUTE_CACHE];

  // Per-target flood brake. Deliberately NOT persisted: after a reboot the mesh
  // may well have changed, and a node that has just come up should be allowed to
  // find its routes rather than inheriting an old grudge.
  struct FloodBackoff {
    uint8_t  pub_key[PUB_KEY_SIZE];
    uint32_t next_ok_at;          // epoch secs; 0 = free slot
    uint8_t  fails;               // consecutive failed floods
  };
  FloodBackoff _flood_backoff[PROBE_FLOOD_BACKOFF_SLOTS];
  bool     _session_flooded;      // this session actually put a flood on air
  bool     _route_from_cache;       // this session's path came from the cache
  bool     _flood_repaired;         // this session already spent its one repair flood
  unsigned long _next_session_at;    // self-pacing gate (probe.gap)
  bool     _routes_dirty;           // needs flushing to flash

  void  routeCacheStore(const uint8_t* pub_key, const uint8_t* path, uint8_t path_len);
  bool  routeCacheLookup(const uint8_t* pub_key);   // seeds _out_path on a hit

  // Open the sealed "pw" claim. Returns a ProbePwStatus; PROBE_PW_OK fills `out`.
  uint8_t openSealedPassword(const char* hex, size_t hex_len,
                             uint32_t nonce, uint32_t iat, ProbePasswordClaim* out);
  void  routeCacheDrop(const uint8_t* pub_key);
  // Mark a cached route as still good. A path in successful use must not expire on
  // a timer: without this, a mesh provisioned in one batch expires every route
  // together and re-floods all of them as a herd, every TTL, forever.
  void  routeCacheTouch(const uint8_t* pub_key);

  bool  floodHeldOff(const uint8_t* pub_key);    // still inside the backoff window
  void  floodFailed(const uint8_t* pub_key);     // advance the ladder
  void  floodSucceeded(const uint8_t* pub_key);  // clear it: the target answered

public:
  // Persistence. Without it every reboot costs a full sweep of floods to relearn
  // what the node already knew. Mirrors the lazy ACL write in MyMesh::loop().
  void routeCacheLoad(FILESYSTEM* fs);
  void routeCacheSave(FILESYSTEM* fs);
  bool routesDirty() const { return _routes_dirty; }

private:

  // Active-session working state.
  uint8_t  _out_path[MAX_PATH_SIZE];
  uint8_t  _out_path_len;
  uint8_t  _secret[PUB_KEY_SIZE];
  bool     _secret_valid;
  uint32_t _tag;
  uint8_t  _step;
  uint8_t  _route;
  uint8_t  _pending_ops;            // ops still to run in this session
  bool     _awaiting;               // a reply is outstanding
  unsigned long _deadline;
  mesh::Packet* _inflight;          // queued, not yet confirmed on air
  unsigned long _queue_deadline;
  uint8_t  _login_perms, _login_fw_level;
  bool     _logged_in;

  // Inbound command staging (members, not stack -- see PROBE_CMD_MAX_LEN).
  char    _cmd_buf[PROBE_CMD_MAX_LEN];
  uint8_t _claims[PROBE_CLAIMS_MAX_LEN];

  // Result accumulation for the active session (JSON claim fragment).
  char   _result[640];
  bool   _result_truncated;   // a fragment was dropped; the JSON stays valid
  uint32_t _boot_epoch;       // clock at first sane reading; 0 = not yet known
  uint32_t _seq_next;         // admission counter feeding ProbeSession::seq
  uint32_t _n_expired;        // sessions dropped at dispatch, deadline already passed
  // The build-time deployment key, if this image was compiled with one. Seeds an unset
  // pref so a factory-fresh node already trusts its controller, and is accepted as a
  // signer for PROBE_OP_SET_CONTROLLER *only* -- never for ordinary tasking. That is what
  // makes recovery possible: a node whose per-node key is lost can still be re-issued one,
  // without a serial cable, while a stolen deployment key still cannot poll anything.
  uint8_t  _deploy_key[PUB_KEY_SIZE];
  bool     _deploy_key_set;
  size_t _result_len;

  // Policy
  uint16_t       _applied_max;      // probe_max_per_hour the limiters were built from
  RateLimiter    _session_limiter;
  // Bounds how often an UNAUTHENTICATED message can cost us a full Ed25519
  // verify on the mesh loop task, independent of the session budget.
  RateLimiter    _verify_guard;
  RateLimiter    _packet_guard;
  ProbeNonceRing _nonces;

  // Counters, surfaced through the CLI and the WebConfig stats endpoint.
  uint32_t _n_accepted, _n_rejected, _n_ok, _n_timeout, _n_flood, _n_denied, _n_send_failed;
  uint8_t  _last_reject;

  // Status line for the display.
  char     _status[24];

  // --- internals ------------------------------------------------------------
  int  findFreeSession() const;
  void startNext();
  void advance();
  bool sendStep(uint8_t step);
  bool transmit(mesh::Packet* pkt);          // THE single path to the radio
  void finishSession(uint8_t state);
  void resetActive();

  bool verifyCommand(const char* token, size_t len, const char** payload,
                     size_t* payload_len, uint8_t* reject,
                     bool* via_deploy = nullptr);

  void resultBegin();
  void resultAppend(const char* fmt, ...);
  void resultAppendEscaped(const char* key, const char* val, size_t val_len);
  void publishResult(const ProbeSession& s, uint8_t state);
  void reportReject(uint8_t reason, uint8_t reply_slot, const char* job_id);

  uint32_t nowSecs() const;
  void setStatus(const char* fmt, ...);
};
