#include "ProbeExecutor.h"
#include "MyMesh.h"
#include <stdarg.h>

// How long a queued probe packet may sit in the outbound queue before we give
// up waiting for it to reach the air.
#define PROBE_QUEUE_TIMEOUT_MS 8000

// Same emergency-floor preflight the anon-regions client uses
// (examples/simple_repeater/MyMesh.cpp:1880). Re-declared here because
// NEIGHBOR_DISCOVER_MIN_FREE_PACKETS lives inside the WITH_MQTT_NEIGHBORS guard.
#define PROBE_MIN_FREE_PACKETS 5

// Unsigned-safe millis() deadline comparison; avoids depending on the protected
// futureMillis()/millisHasNowPassed() helpers.
static inline bool probeDeadlinePassed(unsigned long deadline) {
  return (long)(millis() - deadline) >= 0;
}

ProbeExecutor::ProbeExecutor()
  : _mesh(NULL), _prefs(NULL), _active(-1),
    _out_path_len(PROBE_OUT_PATH_UNKNOWN), _secret_valid(false), _tag(0),
    _step(PS_IDLE), _route(PR_NONE), _pending_ops(0), _awaiting(false),
    _deadline(0), _inflight(NULL), _queue_deadline(0),
    _login_perms(0), _login_fw_level(0), _logged_in(false), _result_len(0),
    _applied_max(0),
    _session_limiter(PROBE_DEFAULT_MAX_PER_HOUR, 3600),
    _verify_guard(30, 60),
    _packet_guard(PROBE_DEFAULT_MAX_PER_HOUR * PROBE_PACKET_GUARD_MULTIPLIER, 3600),
    _relay_limiter(PROBE_RELAY_MAX_PER_HOUR, 3600),
    _n_accepted(0), _n_rejected(0), _n_ok(0), _n_timeout(0), _n_flood(0), _n_denied(0),
    _n_send_failed(0), _n_relay_tx(0),
    _last_reject(PRJ_NONE)
{
  memset(_sessions, 0, sizeof(_sessions));
  memset(_routes, 0, sizeof(_routes));      // learned_at == 0 marks a slot free
  _route_from_cache = false;
  _flood_repaired = false;
  _session_flooded = false;
  memset(_flood_backoff, 0, sizeof(_flood_backoff));
  _routes_dirty = false;
  _next_session_at = 0;
  memset(_out_path, 0, sizeof(_out_path));
  memset(_secret, 0, sizeof(_secret));
  // Zeroed rather than left indeterminate: these hold an attacker-supplied token
  // and its decoded claims, so no stale bytes should ever survive between
  // commands even on a path that bails out early.
  memset(_cmd_buf, 0, sizeof(_cmd_buf));
  memset(_claims, 0, sizeof(_claims));
  _result[0] = 0;
  _status[0] = 0;
  probeNonceRingInit(&_nonces);
  _boot_epoch = 0;
  // Parse the build-time deployment key, if this image carries one. Done once here so the
  // hot paths only ever look at bytes.
  memset(_deploy_key, 0, sizeof(_deploy_key));
  _deploy_key_set = false;
#ifdef PROBE_CONTROLLER_PUBKEY
  {
    const char* hex = PROBE_CONTROLLER_PUBKEY;
    if (strlen(hex) == PUB_KEY_SIZE * 2 &&
        mesh::Utils::fromHex(_deploy_key, PUB_KEY_SIZE, hex)) {
      _deploy_key_set = probeControllerKeySet(_deploy_key, sizeof(_deploy_key));
    }
  }
#endif
  _seq_next = 0;
  _n_expired = 0;
}

void ProbeExecutor::begin(MyMesh* mesh, NodePrefs* prefs) {
  _mesh = mesh;
  _prefs = prefs;
  applyPrefs();
}

// The constructor runs before prefs are loaded, so both limiters are re-armed
// here from the stored values (called after CommonCLI::loadPrefs).
void ProbeExecutor::applyPrefs() {
  if (!_prefs) return;
  uint16_t per_hour = probeEffectiveMaxPerHour(_prefs->probe_max_per_hour);
  // Adjust in place rather than reconstructing: a rebuild zeroes the window and
  // hands back a full budget, so an operator editing probe.max -- or any code
  // path that re-applies prefs -- could refill it at will.
  // A node that has never been given a controller key trusts the one it was built with,
  // so a freshly flashed board is usable without anyone pasting 64 hex characters. An
  // explicitly set key always wins; this only fills the hole.
  if (_deploy_key_set &&
      !probeControllerKeySet(_prefs->probe_controller_pubkey,
                             sizeof(_prefs->probe_controller_pubkey))) {
    memcpy(_prefs->probe_controller_pubkey, _deploy_key, PUB_KEY_SIZE);
  }
  _session_limiter.setMaximum(per_hour);
  _packet_guard.setMaximum(probePacketGuardCeiling(_prefs->probe_max_per_hour));
  _applied_max     = _prefs->probe_max_per_hour;
}

uint32_t ProbeExecutor::nowSecs() const {
  if (!_mesh) return 0;
  return _mesh->getRTCClock()->getCurrentTime();
}

void ProbeExecutor::setStatus(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vsnprintf(_status, sizeof(_status), fmt, args);
  va_end(args);
}

int ProbeExecutor::findFreeSession() const {
  for (int i = 0; i < MAX_PROBE_SESSIONS; i++) {
    if (_sessions[i].state == PST_FREE) return i;
  }
  return -1;
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

bool ProbeExecutor::startLocal(const mesh::Identity& target, uint8_t ops_mask,
                               char* err, size_t err_size) {
  if (!_prefs || !_prefs->probe_enable) {
    if (err) snprintf(err, err_size, "probe disabled");
    _last_reject = PRJ_DISABLED; _n_rejected++;
    return false;
  }
  if (ops_mask == 0) {
    if (err) snprintf(err, err_size, "no ops requested");
    _last_reject = PRJ_BAD_TARGET; _n_rejected++;
    return false;
  }
  // The per-hour budget is charged ONCE here, at session admission -- never per
  // packet. A four-step session costs exactly one token.
  if (!_session_limiter.allow(nowSecs())) {
    if (err) snprintf(err, err_size, "rate limited (probe.max)");
    _last_reject = PRJ_RATE; _n_rejected++;
    return false;
  }
  int idx = findFreeSession();
  if (idx < 0) {
    if (err) snprintf(err, err_size, "probe queue full");
    _last_reject = PRJ_QUEUE_FULL; _n_rejected++;
    return false;
  }
  ProbeSession& s = _sessions[idx];
  memset(&s, 0, sizeof(s));
  s.target     = target;
  s.ops_mask   = ops_mask;
  s.state      = PST_QUEUED;
  s.reply_slot = 0xFF;               // local CLI, no MQTT reply
  s.from_mqtt  = false;
  s.exp        = 0;                  // operator at a console; no deadline to enforce
  s.seq        = _seq_next++;
  snprintf(s.job_id, sizeof(s.job_id), "cli-%d", idx);
  _n_accepted++;
  return true;
}

// Verify the Ed25519 controller signature over "header.payload". Runs on Core 1:
// the software Ed25519 path needs roughly 3 KB of stack (src/Identity.cpp:25-28),
// which is not available on the esp-mqtt event task.
bool ProbeExecutor::verifyCommand(const char* token, size_t len, const char** payload,
                                  size_t* payload_len, uint8_t* reject, bool* via_deploy) {
  // Fail closed FIRST, and before anything expensive.
  if (!probeControllerKeySet(_prefs->probe_controller_pubkey,
                             sizeof(_prefs->probe_controller_pubkey))) {
    *reject = PRJ_NO_CONTROLLER; return false;
  }

  const char *h, *p, *s;
  size_t hl, pl, sl;
  if (!probeTokenSplit(token, len, &h, &hl, &p, &pl, &s, &sl)) {
    *reject = PRJ_BAD_TOKEN; return false;
  }

  // Cheap structural pre-filters, so junk never reaches the ~3 KB-stack software
  // Ed25519 path. A raw 64-byte signature is exactly 86 unpadded base64url chars.
  // pl is the ENCODED payload length, so it is bounded by the base64 ceiling, not the
  // decoded one. The decode below is separately bounded by sizeof(_claims).
  if (sl != 86 || pl == 0 || pl > PROBE_CLAIMS_MAX_B64) {
    *reject = PRJ_BAD_TOKEN; return false;
  }

  uint8_t sig[SIGNATURE_SIZE];
  int siglen = probeB64UrlDecode(s, sl, sig, sizeof(sig));
  if (siglen != SIGNATURE_SIZE) { *reject = PRJ_BAD_TOKEN; return false; }

  // Only now spend the verify, and only at a bounded rate.
  if (!_verify_guard.allow(nowSecs())) { *reject = PRJ_RATE; return false; }

  // Signing input is the raw "header.payload" substring, verified in place.
  size_t signing_len = hl + 1 + pl;
  mesh::Identity controller(_prefs->probe_controller_pubkey);
  if (controller.verify(sig, (const uint8_t*)h, (int)signing_len)) {
    if (via_deploy) *via_deploy = false;
  } else if (_deploy_key_set &&
             memcmp(_deploy_key, _prefs->probe_controller_pubkey, PUB_KEY_SIZE) != 0 &&
             mesh::Identity(_deploy_key).verify(sig, (const uint8_t*)h, (int)signing_len)) {
    // Signed by the DEPLOYMENT key while this node is pinned to a different one. Accepted
    // only so the controller can re-issue a per-node key to a node whose key it has lost --
    // the caller restricts what this may actually do to PROBE_OP_SET_CONTROLLER. Without
    // this, losing Echo's key store would strand every field node behind a serial cable.
    if (via_deploy) *via_deploy = true;
  } else {
    *reject = PRJ_BAD_SIG; return false;
  }

  *payload = p;
  *payload_len = pl;
  return true;
}

bool ProbeExecutor::onCommand(const char* token, size_t len, uint8_t reply_slot, bool via_relay) {
  uint8_t reject = PRJ_NONE;
  char job[PROBE_JOB_ID_LEN + 1]; job[0] = 0;

  if (!_prefs) return false;                    // no config: silence, nothing to say

  // VERIFY BEFORE checking the master switch. Doing it the other way round makes
  // a disabled node answer ANY junk with a signed "disabled" token (empty jid),
  // which is a 1:1 amplification vector and an oracle for "this pubkey runs a
  // probe-capable Observer". The subscription only registers when probing is
  // enabled at boot, so this is reachable after `set probe off` at runtime --
  // narrow, but free to close. The verify spend on junk is bounded by
  // _verify_guard exactly as it is when probing is enabled.
  {
    const char* payload = NULL; size_t payload_len = 0;
    bool via_deploy = false;
    if (!verifyCommand(token, len, &payload, &payload_len, &reject, &via_deploy)) {
      // reject already set; the unauthenticated classes are silent in reportReject
    } else if (!_prefs->probe_enable) {
      reject = PRJ_DISABLED;                    // now only the real controller hears this
      // Recover just the jid so the controller can correlate this refusal to its
      // job. Safe to parse: these bytes carry a verified signature.
      int clen = probeB64UrlDecode(payload, payload_len, _claims, sizeof(_claims) - 1);
      if (clen > 0) {
        _claims[clen] = 0;
        const char* jid = NULL; size_t jid_len = 0;
        if (probeJsonGetString((const char*)_claims, (size_t)clen, "jid", &jid, &jid_len)) {
          size_t n = jid_len < PROBE_JOB_ID_LEN ? jid_len : PROBE_JOB_ID_LEN;
          memcpy(job, jid, n); job[n] = 0;
        }
      }
    } else {
      // Only authenticated bytes are parsed from here on.
      int clen = probeB64UrlDecode(payload, payload_len, _claims, sizeof(_claims) - 1);
      if (clen <= 0) {
        reject = PRJ_BAD_TOKEN;
      } else {
        _claims[clen] = 0;
        const char* js = (const char*)_claims;
        size_t jl = (size_t)clen;

        const char* jid = NULL; size_t jid_len = 0;
        if (probeJsonGetString(js, jl, "jid", &jid, &jid_len)) {
          size_t n = jid_len < PROBE_JOB_ID_LEN ? jid_len : PROBE_JOB_ID_LEN;
          memcpy(job, jid, n); job[n] = 0;
        }

        uint32_t iat = 0, exp = 0, nonce = 0, ops = 0;
        // iat and nonce are MANDATORY: defaulting them to 0 would leave the
        // freshness window and the replay ring disabled (fail-open) for any
        // command that simply omits them.
        bool have_iat   = probeJsonGetUInt(js, jl, "iat", &iat);
        bool have_nonce = probeJsonGetUInt(js, jl, "n",   &nonce);
        probeJsonGetUInt(js, jl, "exp", &exp);
        probeJsonGetUInt(js, jl, "ops", &ops);

        const char* tgt = NULL; size_t tgt_len = 0;
        uint8_t target_key[PUB_KEY_SIZE];
        bool have_target = probeJsonGetString(js, jl, "tgt", &tgt, &tgt_len)
                        && probeHexToBytes(tgt, tgt_len, target_key, sizeof(target_key));

        // "obs" binds this command to the observer it was addressed to, and is
        // MANDATORY. The signature proves WHAT was asked and by WHOM, but says
        // nothing about TO WHOM: without this, anyone who can place bytes on our
        // command topic -- a compromised or malicious broker, most obviously --
        // could lift a still-fresh command addressed to node A and replay it at
        // node B, which would verify the controller signature happily and execute
        // it. Absent or mismatched fails CLOSED, alongside iat/nonce below.
        const char* obs = NULL; size_t obs_len = 0;
        uint8_t obs_key[PUB_KEY_SIZE];
        bool obs_ok = probeJsonGetString(js, jl, "obs", &obs, &obs_len)
                   && probeHexToBytes(obs, obs_len, obs_key, sizeof(obs_key))
                   && memcmp(obs_key, _mesh->self_id.pub_key, PUB_KEY_SIZE) == 0;

        // ORDER MATTERS, and both naive orders are wrong.
        //
        // The nonce ring and the rate limiter each consume state, so whichever
        // goes first can be burned by commands the other would have refused:
        //   - nonce committed first  -> every rate-denied command evicts a ring
        //     slot, so a burst of refusals wipes the replay history.
        //   - rate charged first     -> a replayed command spends budget before
        //     being recognised as a replay, so replays can starve real work.
        //
        // Split the nonce check instead: PEEK (no state change), then charge the
        // rate, then COMMIT the nonce only once the command is actually going to
        // be accepted. Stateless checks come first so neither is spent on junk.
        if (!obs_ok) {
          // Stateless and first: a command not addressed to us must not spend a
          // nonce ring slot or rate budget.
          reject = PRJ_BAD_OBS;
        } else if (!have_iat || !have_nonce) {
          reject = PRJ_CLOCK;
        } else if (!probeTimestampOk(nowSecs(), iat, exp, PROBE_DEFAULT_CLOCK_SKEW_SECS)) {
          reject = PRJ_CLOCK;
        } else if (_boot_epoch >= PROBE_SANE_EPOCH &&
                   iat + PROBE_DEFAULT_CLOCK_SKEW_SECS < _boot_epoch) {
          // The nonce ring lives in RAM, so a reboot empties it and a token captured
          // before that reboot could be replayed once, any time inside its exp window.
          // Refusing anything ISSUED before we booted closes that window: after a
          // reboot the ring is gone but the clock is not, so iat is the one piece of
          // state that survives. Deliberately NOT persisted -- writing a counter to
          // flash on every command would wear the partition to close a hole that exp
          // already bounds. Skipped entirely while the clock is unknown (fail-open,
          // exactly as before), since a bogus floor would refuse every valid command.
          reject = PRJ_PREBOOT;
        } else if ((ops == PROBE_OP_RELAY_TX) != via_relay) {
          // Channel and op must agree, BOTH directions, and this has to sit ahead of
          // every op branch below -- SET_CONTROLLER and MANAGE are handled before the
          // relay branch, so a guard placed next to relay would let either of them run
          // when sent down the relay channel.
          //
          // A relay frame on the tasking channel would sidestep the broker's separate
          // relay gate; a tasking op on the relay channel would do the reverse. The
          // signature says WHO authorised this; the channel says which authority the
          // broker checked. A command that disagrees with itself is refused, not
          // reconciled.
          reject = PRJ_BAD_CMD;
        } else if (via_deploy && ops != PROBE_OP_SET_CONTROLLER) {
          // The deployment key is accepted ONLY to re-issue a controller key. It must not
          // be able to poll, log in, or run a CLI command on anything -- otherwise the
          // shared key every node ships with would remain a master key for the whole
          // field, which is the thing per-node keys exist to end.
          reject = PRJ_NEED_ADMIN;
        } else if (ops == PROBE_OP_SET_CONTROLLER) {
          // Self-directed: adopt a new controller key. Never goes out over LoRa, so it
          // takes no session and no target beyond ourselves. Everything that authorises it
          // has already been checked above -- signature, freshness, replay ring, and the
          // mandatory `obs` claim binding this token to THIS node, so a rotation cannot be
          // replayed against a different one.
          const char* ctl = NULL; size_t ctl_len = 0;
          uint8_t newkey[PUB_KEY_SIZE];
          char ctl_hex[PUB_KEY_SIZE * 2 + 1];
          if (!probeJsonGetString(js, jl, "ctl", &ctl, &ctl_len) ||
              ctl_len != PUB_KEY_SIZE * 2) {
            reject = PRJ_BAD_CMD;
          } else {
            memcpy(ctl_hex, ctl, ctl_len);
            ctl_hex[ctl_len] = 0;
            if (!mesh::Utils::fromHex(newkey, PUB_KEY_SIZE, ctl_hex) ||
                !probeControllerKeySet(newkey, sizeof(newkey))) {
              // Unparseable, or all-zero -- which would mean "trust nobody" and leave the
              // node unreachable until someone walks to it with a cable.
              reject = PRJ_BAD_CMD;
            } else {
              memcpy(_prefs->probe_controller_pubkey, newkey, PUB_KEY_SIZE);
              _mesh->savePrefs();            // survive the next reboot, or nothing changed
              _n_accepted++;

              // Answer through the ordinary result path so the controller can correlate
              // this like any other job. A throwaway session carries only what the result
              // needs; nothing is queued and nothing goes on air.
              ProbeSession ack;
              memset(&ack, 0, sizeof(ack));
              memcpy(ack.job_id, job, sizeof(job));
              ack.reply_slot = reply_slot;
              ack.from_mqtt  = true;
              ack.target     = _mesh->self_id;
              resultBegin();
              resultAppend(",\"ctl\":\"%s\"", ctl_hex);
              _mesh->publishProbeResult(ack, PST_OK, PR_NONE, _result, _result_len);
              return true;
            }
          }
        } else if (ops == PROBE_OP_MANAGE) {
          // Self-directed: do one named thing to ourselves. Like SET_CONTROLLER this never
          // goes on air, so it takes no session and no target. Authorisation was settled
          // above -- signature, freshness, replay ring, and the mandatory `obs` claim
          // binding this token to THIS node.
          //
          // THE SHARED KEY MUST NOT AUTHORISE THIS. Every published image ships trusting
          // the same deployment key, and applyPrefs() seeds an unset controller pref WITH
          // that key -- so on a node nobody has adopted, a deployment-key signature
          // satisfies the primary branch and via_deploy is never set. The restriction
          // higher up is therefore dead code exactly where it matters most. Refusing when
          // the key we trust IS the deployment key is what stops anyone holding it -- every
          // operator running the published controller -- from replacing our firmware.
          if (via_deploy
              || (_deploy_key_set
                  && memcmp(_prefs->probe_controller_pubkey, _deploy_key, PUB_KEY_SIZE) == 0)) {
            reject = PRJ_NEED_ADMIN;
          } else {
            const char* act = NULL; size_t act_len = 0;
            if (!probeJsonGetString(js, jl, "act", &act, &act_len)
                || act_len == 0 || act_len > 24) {
              reject = PRJ_BAD_CMD;
            } else {
              char act_s[25];
              memcpy(act_s, act, act_len);
              act_s[act_len] = 0;

              char detail[160] = {0};
              bool handled = false, ok = false;
              if (strcmp(act_s, "ota.check") == 0) {
                ok = _mesh->otaManage(false, detail, sizeof(detail));
                handled = true;
              } else if (strcmp(act_s, "ota.update") == 0) {
                // Schedules; it does NOT flash here. otaManage dry-runs first (bridge stays
                // up) and only arms the deferred update when a build actually applies, so
                // the acknowledgement below goes out over a live bridge BEFORE the teardown
                // that a flash requires. Answering afterwards would mean never answering.
                ok = _mesh->otaManage(true, detail, sizeof(detail));
                handled = true;
              }

              if (!handled) {
                // An action this firmware does not know. Refused rather than ignored: a
                // silent success is how a controller comes to believe an update landed on
                // a node that did nothing at all.
                reject = PRJ_BAD_CMD;
              } else {
                _n_accepted++;
                ProbeSession ack;
                memset(&ack, 0, sizeof(ack));
                memcpy(ack.job_id, job, sizeof(job));
                ack.reply_slot = reply_slot;
                ack.from_mqtt  = true;
                ack.target     = _mesh->self_id;
                resultBegin();
                // `mgmt` is the proof the controller looks for. Its ABSENCE is what tells a
                // newer controller that this firmware did not understand the request, so it
                // must never be omitted on a handled action.
                resultAppend(",\"mgmt\":\"%s\",\"ok\":%s", act_s, ok ? "true" : "false");
                resultAppendEscaped("detail", detail, strlen(detail));
                _mesh->publishProbeResult(ack, ok ? PST_OK : PST_DENIED, PR_NONE,
                                          _result, _result_len);
                return true;
              }
            }
          }
        } else if (ops == PROBE_OP_RELAY_TX) {
          // Transmit a frame the CONTROLLER built, verbatim. No session, no target, and
          // nothing here reads the payload: this node is a transport. Authorisation was
          // settled above (signature, freshness, replay ring, `obs` binding).
          //
          // Same shared-key refusal as MANAGE, and for a sharper reason. Every published
          // image trusts the same deployment key, and applyPrefs() seeds an unset
          // controller pref WITH it -- so on an unadopted node a deployment-key signature
          // satisfies the primary branch and via_deploy is never set. Without the second
          // half of this test, anyone holding a released binary could transmit arbitrary
          // frames from any unadopted node in the field, in that node's name.
          if (via_deploy
              || (_deploy_key_set
                  && memcmp(_prefs->probe_controller_pubkey, _deploy_key, PUB_KEY_SIZE) == 0)) {
            reject = PRJ_NEED_ADMIN;
          } else if (!_prefs->probe_relay_tx) {
            // Consent is per node and separate from probe_enable: probing is a bounded
            // set of named operations, relaying is arbitrary bytes on this node's radio.
            reject = PRJ_DISABLED;
          } else {
            const char* fr = NULL; size_t fr_len = 0;
            if (!probeJsonGetString(js, jl, "tx", &fr, &fr_len) || fr_len == 0) {
              reject = PRJ_BAD_CMD;
            } else {
              // Decode into a stack buffer bounded by the radio's own MTU: anything
              // larger cannot go on air, so refusing early costs nothing and keeps a
              // hostile length from reaching the parser.
              uint8_t raw[MAX_TRANS_UNIT];
              int raw_len = probeB64UrlDecode(fr, fr_len, raw, sizeof(raw));
              if (raw_len <= 0) {
                reject = PRJ_BAD_CMD;
              } else if (!_relay_limiter.allow(nowSecs())) {
                // Relay TX is airtime this node's operator did not individually approve,
                // so it carries its own budget on top of the session limiter.
                reject = PRJ_RATE;
              } else {
                mesh::Packet* pkt = _mesh->obtainNewPacket();
                if (pkt == NULL) {
                  reject = PRJ_QUEUE_FULL;
                } else if (!_mesh->tryParsePacket(pkt, raw, raw_len)) {
                  // Not a well-formed MeshCore frame. Refuse rather than key noise onto
                  // a shared channel -- the radio is the one resource we cannot take back.
                  _mesh->releasePacket(pkt);
                  reject = PRJ_BAD_CMD;
                } else {
                  // Queued through the NORMAL send path, not startSendRaw: that is what
                  // keeps CAD, the retransmit backoff and airtime accounting local to
                  // this node. The controller supplies the bytes; the LoRa MAC stays here.
                  _mesh->sendPacket(pkt, 0);
                  _n_relay_tx++;
                  ProbeSession ack;
                  memset(&ack, 0, sizeof(ack));
                  memcpy(ack.job_id, job, sizeof(job));
                  ack.reply_slot = reply_slot;
                  ack.from_mqtt  = true;
                  ack.target     = _mesh->self_id;
                  resultBegin();
                  // `relay` is the proof the controller looks for; its ABSENCE tells a
                  // newer controller this firmware did not understand the request. The
                  // ack means "queued on air", never "the far node answered" -- the reply
                  // reaches the controller through the observer uplink, not through us.
                  resultAppend(",\"relay\":true,\"len\":%d", raw_len);
                  _mesh->publishProbeResult(ack, PST_OK, PR_NONE, _result, _result_len);
                  return true;
                }
              }
            }
          }
        } else if (ops & ~PROBE_OPS_ALL) {
          // An op this firmware does not implement. Refused, not ignored -- see
          // PROBE_OPS_ALL. Silence here reads as success to the controller.
          reject = PRJ_BAD_CMD;
        } else if (!have_target || ops == 0 || ops > 0xFF) {
          reject = PRJ_BAD_TARGET;
        } else if (probeNonceSeen(&_nonces, nonce)) {
          reject = PRJ_REPLAY;                    // peek: ring untouched
        } else if (!_session_limiter.allow(nowSecs())) {
          // Charged once per SESSION, at admission. Nothing has transmitted, and
          // the nonce has NOT been consumed.
          reject = PRJ_RATE;
        } else if (!probeNonceAccept(&_nonces, nonce)) {
          reject = PRJ_REPLAY;                    // commit; races cannot reach here
        } else {
          // An optional sealed password promotes this session to an ADMIN login.
          // Opened only now, after the signature, the freshness window and the
          // replay ring have all passed -- decrypting earlier would spend an ECDH
          // and a SHA-256 on traffic we were going to refuse anyway.
          ProbePasswordClaim pw;
          bool have_pw = false;
          const char* pw_hex = NULL; size_t pw_hex_len = 0;
          if (probeJsonGetString(js, jl, "pw", &pw_hex, &pw_hex_len)) {
            uint8_t st = openSealedPassword(pw_hex, pw_hex_len, nonce, iat, &pw);
            if (st != PROBE_PW_OK) {
              probePwWipe(&pw);
              reject = PRJ_BAD_PW;                // a sealed field that will not open
            } else {
              have_pw = true;
            }
          }

          // A CLI command op: validate the text, and require an admin login. The
          // target gates remote CLI on client->isAdmin() (MyMesh.cpp:890) and
          // simply ignores a guest, so without this the session would sit there
          // and time out with nothing to explain why.
          const char* cli = NULL; size_t cli_len = 0;
          bool have_cli = probeJsonGetString(js, jl, "cmd", &cli, &cli_len);
          if (reject == PRJ_NONE && (ops & PROBE_OP_COMMAND)) {
            if (!have_cli || !probeCliTextValid(cli, cli_len)) {
              reject = PRJ_BAD_CMD;
            } else if (!have_pw) {
              reject = PRJ_NEED_ADMIN;
            }
          }

          int idx = (reject == PRJ_NONE) ? findFreeSession() : -1;
          if (reject != PRJ_NONE) {
            // already refused above
          } else if (idx < 0) {
            probePwWipe(&pw);
            reject = PRJ_QUEUE_FULL;
          } else {
            ProbeSession& sess = _sessions[idx];
            memset(&sess, 0, sizeof(sess));
            sess.target     = mesh::Identity(target_key);
            sess.ops_mask   = (uint8_t)ops;
            sess.state      = PST_QUEUED;
            sess.reply_slot = reply_slot;
            sess.from_mqtt  = true;
            sess.exp        = exp;   // re-checked at dispatch, not just at admission
            sess.seq        = _seq_next++;
            memcpy(sess.job_id, job, sizeof(job));
            if (have_pw) {
              memcpy(sess.password, pw.password, sizeof(sess.password));
              sess.is_admin = true;
            }
            if ((ops & PROBE_OP_COMMAND) && have_cli) {
              size_t n = cli_len < PROBE_CLI_MAX_TEXT ? cli_len : PROBE_CLI_MAX_TEXT;
              memcpy(sess.cli_cmd, cli, n);
              sess.cli_cmd[n] = 0;
              sess.cli_len = (uint8_t)n;
            }
            probePwWipe(&pw);                     // the session owns it now
            _n_accepted++;
            return true;
          }
        }
      }
    }
  }

  _last_reject = reject;
  _n_rejected++;
  reportReject(reject, reply_slot, job);
  return false;
}

// ---------------------------------------------------------------------------
// Session driving
// ---------------------------------------------------------------------------

void ProbeExecutor::resetActive() {
  _active = -1;
  _step = PS_IDLE;
  _awaiting = false;
  _inflight = NULL;
  _secret_valid = false;
  _logged_in = false;
  _out_path_len = PROBE_OUT_PATH_UNKNOWN;
  _route = PR_NONE;
  _pending_ops = 0;
  _result_len = 0;
  _result[0] = 0;
  _result_truncated = false;
}

void ProbeExecutor::startNext() {
  // Drop anything whose deadline passed while it waited. Admission checked exp against
  // the clock at ARRIVAL; a queued session can wait behind three others that each flood
  // and retry, so re-check here or we spend airtime transmitting a command Echo gave up
  // on long ago. Reported, not silently discarded.
  uint32_t now = nowSecs();
  if (now >= PROBE_SANE_EPOCH) {
    for (int i = 0; i < MAX_PROBE_SESSIONS; i++) {
      ProbeSession& q = _sessions[i];
      if (q.state != PST_QUEUED || q.exp == 0) continue;
      if (now > (uint32_t)(q.exp + PROBE_DEFAULT_CLOCK_SKEW_SECS)) {
        _n_expired++;
        if (q.from_mqtt) _mesh->publishProbeReject(q.reply_slot, q.job_id, "expired");
        // memset frees the slot (PST_FREE == 0) AND wipes the recovered admin
        // password, which finishSession would otherwise have been responsible for.
        memset(&q, 0, sizeof(q));
      }
    }
  }

  // FIFO. Scanning for the lowest free slot index meant a session could be starved
  // indefinitely by later arrivals landing in lower slots.
  int pick = -1;
  for (int i = 0; i < MAX_PROBE_SESSIONS; i++) {
    if (_sessions[i].state != PST_QUEUED) continue;
    if (pick < 0 || _sessions[i].seq < _sessions[pick].seq) pick = i;
  }
  if (pick >= 0) {
    int i = pick;
    _active = i;
    ProbeSession& s = _sessions[i];
    s.state = PST_ACTIVE;

    _pending_ops = s.ops_mask;
    _logged_in = false;
    // Seed from the cache: without this the session floods its first login-based
    // step even when this target was probed moments ago.
    _out_path_len = PROBE_OUT_PATH_UNKNOWN;
    _route_from_cache = routeCacheLookup(s.target.pub_key);
    _flood_repaired = false;
    _session_flooded = false;
    _route = PR_NONE;
    _awaiting = false;
    _inflight = NULL;

    _mesh->self_id.calcSharedSecret(_secret, s.target);
    _secret_valid = true;

    resultBegin();
    setStatus("PROBE %02X%02X", s.target.pub_key[0], s.target.pub_key[1]);
    advance();
    return;
  }
}

// Pick the next step for the active session.
void ProbeExecutor::advance() {
  if (_active < 0) return;

  uint8_t next = PS_DONE;
  if (_pending_ops & PROBE_OP_OWNER) {
    next = PS_ANON;
  } else if ((_pending_ops & PROBE_OPS_NEED_LOGIN)
             && !probeRouteIsDirect(_out_path_len)
             && (!_prefs->probe_allow_flood
                 || (_active >= 0 && floodHeldOff(_sessions[_active].target.pub_key)))) {
    // Either flooding is switched off entirely, or this specific target is inside
    // its backoff window after consecutive floods that went unanswered. The two
    // are reported separately: "no_route" is a policy setting the operator chose,
    // "flood_backoff" is us protecting the mesh from a target that is not there.
    if (_prefs->probe_allow_flood) {
      resultAppend(",\"reason\":\"flood_backoff\"");
      finishSession(PST_DENIED);
      return;
    }
    // THE FLOOD VETO COVERS THE REPLY DIRECTION TOO.
    //
    // Our zero-hop login/REQ cannot propagate, but the target has no return path
    // to us, so it answers by FLOODING its response: onAnonDataRecv/onPeerDataRecv
    // fall through to mesh::chooseReplyRoute(false, false, false) == REPLY_ROUTE_FLOOD
    // and call sendFloodReply(). Each step of the session would induce another
    // mesh-wide flood, which is louder than enabling probe.flood (a flooded
    // request draws one PATH return that teaches the route, after which the rest
    // of the session is direct).
    //
    // PROBE_OP_OWNER is exempt and handled above: its body carries
    // reply_path_len = 0, so the target replies zero-hop.
    resultAppend(",\"reason\":\"no_route\"");
    finishSession(PST_DENIED);
    return;
  } else if ((_pending_ops & PROBE_OPS_NEED_LOGIN) && !_logged_in) {
    next = PS_LOGIN;
  } else if (_pending_ops & PROBE_OP_VER_IDENT) {
    next = PS_VER_IDENT;
  } else if (_pending_ops & PROBE_OP_STATUS) {
    next = PS_STATUS;
  } else if (_pending_ops & PROBE_OP_TELEMETRY) {
    next = PS_TELEMETRY;
  } else if (_pending_ops & PROBE_OP_COMMAND) {
    // Last, so a session that also reads status/telemetry captures the node's
    // state BEFORE the command changes it.
    next = PS_CLI;
  }

  if (next == PS_DONE) { finishSession(PST_OK); return; }
  if (!sendStep(next)) { finishSession(PST_SEND_FAILED); return; }
}

bool ProbeExecutor::sendStep(uint8_t step) {
  ProbeSession& s = _sessions[_active];
  mesh::Packet* pkt = NULL;
  _step = step;

  if (step == PS_ANON) {
    // Zero-hop anon owner request: needs no login and physically cannot flood.
    // The target's handler requires isRouteDirect() (MyMesh.cpp:676-680).
    uint8_t body[PROBE_ANON_BODY_LEN];
    _tag = _mesh->getRTCClock()->getCurrentTimeUnique();
    probeBuildAnonBody(body, sizeof(body), _tag, PROBE_ANON_REQ_TYPE_OWNER, 0x00);
    pkt = _mesh->createAnonDatagram(PAYLOAD_TYPE_ANON_REQ, _mesh->self_id, s.target,
                                    _secret, body, sizeof(body));
  } else if (step == PS_LOGIN) {
    // Guest login is the empty-password case: the body is exactly {now u32} and
    // the target reads data[4] == 0 as "blank password" (MyMesh.cpp:674, :103).
    // With a sealed password the same builder produces an ADMIN login, which is
    // what unlocks privileged CLI commands and external-sensor telemetry (a guest
    // is forced to perm_mask 0x00 by the target).
    uint8_t body[24];
    uint32_t now = _mesh->getRTCClock()->getCurrentTimeUnique();
    int blen = probeBuildLoginBody(body, sizeof(body), now, s.password);
    if (blen < 0) return false;
    _tag = now;
    pkt = _mesh->createAnonDatagram(PAYLOAD_TYPE_ANON_REQ, _mesh->self_id, s.target,
                                    _secret, body, (size_t)blen);
  } else if (step == PS_CLI) {
    ProbeSession& s = _sessions[_active];
    uint8_t body[PROBE_CLI_HEADER_LEN + PROBE_CLI_MAX_TEXT];
    uint32_t now = _mesh->getRTCClock()->getCurrentTimeUnique();
    int blen = probeBuildCliBody(body, sizeof(body), now, s.cli_cmd, s.cli_len);
    if (blen < 0) return false;
    // The reply is matched by the target's own timestamp echo, not by a tag: a
    // CLI reply carries no request tag (MyMesh.cpp:936-938), so correlation rests
    // on there being exactly one command in flight -- which the single-session
    // executor guarantees.
    _tag = now;
    pkt = _mesh->createDatagram(PAYLOAD_TYPE_TXT_MSG, s.target, _secret, body, (size_t)blen);
  } else {
    uint8_t req_type = (step == PS_VER_IDENT) ? PROBE_REQ_TYPE_GET_OWNER_INFO
                     : (step == PS_STATUS)    ? PROBE_REQ_TYPE_GET_STATUS
                                              : PROBE_REQ_TYPE_GET_TELEMETRY_DATA;
    uint8_t body[PROBE_REQ_BODY_LEN];
    uint8_t rnd[4];
    _mesh->getRNG()->random(rnd, 4);
    _tag = _mesh->getRTCClock()->getCurrentTimeUnique();
    probeBuildReqBody(body, sizeof(body), _tag, req_type, rnd);
    pkt = _mesh->createDatagram(PAYLOAD_TYPE_REQ, s.target, _secret, body, sizeof(body));
  }

  if (!pkt) return false;
  return transmit(pkt);
}

// ---------------------------------------------------------------------------
// THE ONLY PLACE A PROBE PACKET REACHES THE RADIO. Core 1 only.
// ---------------------------------------------------------------------------
bool ProbeExecutor::transmit(mesh::Packet* pkt) {
  if (pkt == NULL) return false;

  // 1. master switch
  if (!_prefs->probe_enable) { _mesh->releasePacket(pkt); return false; }

  // 2. packet-level runaway backstop ONLY -- the per-hour SESSION budget is
  //    charged at admission, not here. If this ever fires it is a bug.
  if (!_packet_guard.allow(nowSecs())) {
    _mesh->releasePacket(pkt);
    return false;
  }

  // 3. pool preflight: RxReservePacketManager keeps an emergency floor, and its
  //    queue API is void, so it could otherwise silently shed this request.
  if (_mesh->getFreePacketCount() < PROBE_MIN_FREE_PACKETS) {
    _mesh->releasePacket(pkt);
    return false;
  }

  // 4. FLOOD VETO -- the hard safety rule. A probe to a target with no learned
  //    path would otherwise FLOOD a login/request datagram. It is never a
  //    PAYLOAD_TYPE_ADVERT, but it is still a flood, so it stays behind an
  //    explicitly enabled switch that defaults OFF.
  //
  //    Anon requests are ALWAYS zero-hop regardless: the target's handler
  //    requires isRouteDirect() (MyMesh.cpp:676-680), so a flooded anon request
  //    would simply be ignored.
  if (_step == PS_ANON || probeShouldVetoFlood(_prefs->probe_allow_flood != 0, _out_path_len)) {
    _mesh->sendZeroHop(pkt);
    _route = PR_ZEROHOP;
  } else if (!probeRouteIsDirect(_out_path_len)) {
    _mesh->sendFloodScoped(_mesh->getDefaultScope(), pkt, 0, _prefs->path_hash_mode + 1);
    _route = PR_FLOOD;
    _n_flood++;
    _session_flooded = true;
  } else {
    _mesh->sendDirect(pkt, _out_path, _out_path_len, 0);
    _route = PR_DIRECT;
  }

  _inflight = pkt;
  _queue_deadline = millis() + PROBE_QUEUE_TIMEOUT_MS;
  _awaiting = false;                 // set once the packet is confirmed on air
  return true;
}

void ProbeExecutor::onPacketSent(mesh::Packet* pkt) {
  if (_active < 0 || pkt == NULL || pkt != _inflight) return;
  _inflight = NULL;
  _awaiting = true;
  // Size the listen window to how far the reply must travel. _route was set for this
  // step in sendStep(): a DIRECT send has a known hop count in _out_path_len; a FLOOD
  // reaches an unknown distance, so assume a conservative multi-hop reach; a ZEROHOP
  // send is a direct neighbour, so the zero-hop base is correct.
  uint8_t hops = 0;
  if (_route == PR_DIRECT) {
    hops = probeRoutePathCount(_out_path_len);
  } else if (_route == PR_FLOOD) {
    hops = PROBE_FLOOD_ASSUMED_HOPS;
  }
  _deadline = millis() + _mesh->getProbeQueryTimeoutMs(hops);
}

void ProbeExecutor::onPacketSendFailed(mesh::Packet* pkt) {
  if (_active < 0 || pkt == NULL || pkt != _inflight) return;
  _inflight = NULL;
  _awaiting = false;
  finishSession(PST_SEND_FAILED);
}

void ProbeExecutor::loop() {
  if (!_mesh || !_prefs) return;

  // Latch the boot epoch the FIRST time the clock reads sane. An observer boots before
  // it associates and runs NTP, so nowSecs() during begin() is pre-epoch garbage; by
  // latching here instead we capture the clock within a tick of it becoming valid,
  // which is close enough to boot to be usable as a replay floor. See the PRJ_PREBOOT
  // check for what it is for.
  if (_boot_epoch == 0) {
    uint32_t t = nowSecs();
    if (t >= PROBE_SANE_EPOCH) _boot_epoch = t;
  }

  // `set probe.max` writes the pref directly, so re-arm both limiters when it
  // changes rather than plumbing a dedicated callback through CommonCLI.
  if (_prefs->probe_max_per_hour != _applied_max) applyPrefs();

  if (_active < 0) {
    // Self-pacing. Without this the executor starts the next queued session the
    // instant the previous one ends, so a controller that batches would put
    // back-to-back sessions on the radio with no gap at all.
    if (_next_session_at == 0 || probeDeadlinePassed(_next_session_at)) {
      startNext();
    }
    return;
  }
  if (_inflight) {
    if (probeDeadlinePassed(_queue_deadline)) {
      // Take the packet back out of the outbound queue. Merely detaching
      // _inflight left it queued, so it still went on air later -- airtime spent
      // for a session already torn down and reported send_failed. If it has
      // already left, withdraw returns false and there is nothing to undo.
      if (_mesh) _mesh->withdrawOutboundPacket(_inflight);
      _inflight = NULL;
      finishSession(PST_SEND_FAILED);
    }
    return;
  }
  if (_awaiting && probeDeadlinePassed(_deadline)) {
    _n_timeout++;
    // A cached route that goes unanswered is most likely stale: the mesh moved.
    // Drop it so the next attempt re-floods once and re-learns, rather than
    // failing silently against a dead path for the whole TTL.
    if (_route_from_cache && _active >= 0) {
      routeCacheDrop(_sessions[_active].target.pub_key);
      resultAppend(",\"stale_route\":true");
    }

    // REPAIR IN THIS SESSION rather than making the caller poll again.
    //
    // A direct path that stops answering is the normal way a mesh says it moved.
    // Ending here means every repair costs a wasted poll: the scheduler gets a
    // useless "timeout", the node looks down when it is not, and the NEXT poll is
    // the one that floods and succeeds. Retrying once here costs no more airtime
    // than that -- the second poll would have flooded anyway -- and turns a
    // two-poll repair into one.
    //
    // THE PATH'S PROVENANCE MUST NOT DECIDE THIS. The repair used to sit inside the
    // cache branch above, so it ran only for a path read from the cache and never for
    // one learned from a PATH return earlier in this same session. That split the
    // behaviour of two identical failures and made a marginal target alternate,
    // measured against w9jz.org Pine Bluff (RSSI -99, SNR 5, ~16s round trip):
    //
    //   session A  no cache -> flood login -> learn path P -> status over P times out
    //              -> _route_from_cache is false -> NO repair -> reported timeout,
    //                 while P is left in the cache by handlePathReturn
    //   session B  reads P from cache -> times out -> stale -> repairs -> succeeds
    //
    // Every other poll was thrown away to re-discover what the previous one had just
    // been told. A direct step that went unanswered has earned exactly one re-flood
    // either way -- what differs is only whether the cache entry was also wrong, which
    // is what the drop above still handles on its own.
    //
    // Deliberately NOT extended to a step that already FLOODED: re-flooding a flood
    // that nobody answered buys nothing and doubles the airtime on a mesh-wide send.
    //
    // Bounded to one repair per session by _flood_repaired, so a target that is
    // genuinely gone cannot loop. The login is deliberately NOT reset: the target
    // keys its session on our pubkey, not on the path. The re-flood's PATH return
    // overwrites the cached entry through handlePathReturn, so a fresh path that was
    // genuinely bad corrects itself without being dropped on one lost packet.
    if (_route == PR_DIRECT && _active >= 0
        && _prefs && _prefs->probe_allow_flood && !_flood_repaired) {
      _flood_repaired = true;
      _route_from_cache = false;
      _out_path_len = PROBE_OUT_PATH_UNKNOWN;   // forces the flood path
      _awaiting = false;
      _inflight = NULL;
      resultAppend(",\"route_repaired\":true");
      advance();                                 // re-issue the failed step
      return;
    }
    finishSession(PST_TIMEOUT);
  }
}

void ProbeExecutor::finishSession(uint8_t state) {
  if (_active < 0) return;
  ProbeSession& s = _sessions[_active];

  // A path that just carried a whole session is demonstrably alive, so restart its
  // TTL. Without this the cache expires purely on age, and a batch-provisioned mesh
  // re-floods every node together on the same schedule, forever.
  if (state == PST_OK && _route_from_cache) routeCacheTouch(s.target.pub_key);

  // Flood brake bookkeeping. Only sessions that actually put a flood on air move
  // the ladder: a timeout on a direct route says nothing about whether flooding
  // this target is worthwhile.
  if (_session_flooded) {
    if (state == PST_OK) floodSucceeded(s.target.pub_key);
    else if (state == PST_TIMEOUT) floodFailed(s.target.pub_key);
  }

  if (state == PST_OK) _n_ok++;
  if (state == PST_DENIED) _n_denied++;
  if (state == PST_SEND_FAILED) _n_send_failed++;

  // Local CLI probes have no MQTT reply path, so print the outcome to the
  // console. _result is a leading-comma JSON fragment; wrap it into an object.
  if (!s.from_mqtt) {
    // Full target key, not a prefix: the MQTT tasking path requires the whole
    // 64-hex key, and the neighbours table only ever shows a prefix -- so without
    // this there is no way to learn a node's full key from the bench. This goes
    // to Serial, not the fixed CLI reply buffer, so the length is safe.
    char tgt_hex[PUB_KEY_SIZE * 2 + 1];
    probeBytesToHex(s.target.pub_key, PUB_KEY_SIZE, tgt_hex, sizeof(tgt_hex));
    Serial.printf("PROBE: st=%s route=%s tgt=%s {%s}\n",
                  probeExecStateName(state), probeExecRouteName(_route),
                  tgt_hex, _result_len ? _result + 1 : "");
  }

  publishResult(s, state);

  // Do not leave a repeater admin password in RAM once the session is done.
  memset(s.password, 0, sizeof(s.password));
  s.is_admin = false;

  s.state = PST_FREE;
  setStatus("%s", state == PST_OK ? "PROBE ok" : "PROBE fail");
  {
    uint8_t gap = _prefs ? _prefs->probe_gap_secs : PROBE_DEFAULT_GAP_SECS;
    _next_session_at = gap ? (millis() + (unsigned long)gap * 1000UL) : 0;
  }
  resetActive();
}

// ---------------------------------------------------------------------------
// Reply intake
// ---------------------------------------------------------------------------

bool ProbeExecutor::overlayMatchesHash(const uint8_t* hash) const {
  if (_active < 0 || !_awaiting) return false;
  return _sessions[_active].target.isHashMatch(hash);
}

bool ProbeExecutor::overlayId(int overlay_idx, mesh::Identity& out) const {
  if (_active < 0 || overlay_idx != 0) return false;
  out = _sessions[_active].target;
  return true;
}

bool ProbeExecutor::isActiveTarget(const mesh::Identity& id) const {
  if (_active < 0 || !_awaiting) return false;
  return _sessions[_active].target.matches(id);
}

bool ProbeExecutor::handleResponse(int overlay_idx, const uint8_t* data, size_t len,
                                   uint8_t type) {
  // A CLI reply is a TXT_MSG carrying text, not a tagged RESPONSE. It has no
  // request tag to match on (MyMesh.cpp:936-938), so correlation rests on there
  // being exactly one command in flight -- which the single-session executor
  // guarantees.
  if (type == PAYLOAD_TYPE_TXT_MSG) {
    if (_active < 0 || _step != PS_CLI) return false;
    const char* text = NULL; size_t text_len = 0;
    if (!probeParseCliReply(data, len, &text, &text_len)) return false;
    resultAppendEscaped("cmd_reply", text, text_len);
    _pending_ops &= (uint8_t)~PROBE_OP_COMMAND;
    _awaiting = false;
    advance();
    return true;
  }
  return handleResponseInner(overlay_idx, data, len);
}

bool ProbeExecutor::handleResponseInner(int overlay_idx, const uint8_t* data, size_t len) {
  if (_active < 0 || !_awaiting) return false;

  if (_step == PS_LOGIN) {
    ProbeLoginReply lr;
    if (!probeParseLoginReply(data, len, &lr)) return false;
    _logged_in = true;
    _login_perms = lr.permissions;
    _login_fw_level = lr.firmware_ver_level;
    resultAppend(",\"fw_level\":%u,\"perms\":%u", lr.firmware_ver_level, lr.permissions);
    // Whether the login was ATTEMPTED as admin. `perms` above is what the target
    // actually granted, so Echo can tell "we sent a password" from "the target
    // accepted it" -- a wrong password still logs in, as a guest.
    if (_sessions[_active].is_admin) {
      resultAppend(",\"admin\":%s", lr.is_admin ? "true" : "false");
    }
    // REQ_TYPE_GET_OWNER_INFO (0x07) only exists at FIRMWARE_VER_LEVEL >= 2
    // (examples/simple_repeater/MyMesh.cpp:56). Asking an older node just burns a
    // step and times the session out, so drop it and let status/telemetry run.
    if (lr.firmware_ver_level < 2 && (_pending_ops & PROBE_OP_VER_IDENT)) {
      _pending_ops &= (uint8_t)~PROBE_OP_VER_IDENT;
      resultAppend(",\"ver_ident_skipped\":\"fw_level<2\"");
    }
    _awaiting = false;
    advance();
    return true;
  }

  if (_step == PS_ANON) {
    uint32_t tag = 0, clk = 0;
    const uint8_t* body = NULL; size_t body_len = 0;
    if (!probeParseAnonReply(data, len, &tag, &clk, &body, &body_len)) return false;
    if (tag != _tag) return false;
    // {node_name}\n{owner_info}
    body_len = probeTrimPadding(body, body_len);      // strip cipher padding
    const char* txt = (const char*)body;
    size_t nl = 0; while (nl < body_len && txt[nl] != '\n') nl++;
    resultAppend(",\"clock\":%lu", (unsigned long)clk);
    // Namespaced so a session that also runs ver-ident does not emit duplicate
    // "name"/"owner" keys (matching "clock", which is already anon-only).
    resultAppendEscaped("anon_name", txt, nl);
    if (nl < body_len) resultAppendEscaped("anon_owner", txt + nl + 1, body_len - nl - 1);
    _pending_ops &= (uint8_t)~PROBE_OP_OWNER;
    _awaiting = false;
    advance();
    return true;
  }

  // REQ replies echo the sender timestamp as a tag (MyMesh.cpp:258).
  uint32_t tag = 0;
  if (!probeParseReplyTag(data, len, &tag) || tag != _tag) return false;

  if (_step == PS_VER_IDENT) {
    ProbeOwnerInfo oi;
    if (!probeParseOwnerInfo(data, len, NULL, &oi)) return false;
    resultAppendEscaped("fw", oi.firmware_version, oi.firmware_version_len);
    resultAppendEscaped("name", oi.node_name, oi.node_name_len);
    resultAppendEscaped("owner", oi.owner_info, oi.owner_info_len);
    _pending_ops &= (uint8_t)~PROBE_OP_VER_IDENT;
  } else if (_step == PS_STATUS) {
    ProbeRepeaterStats st;
    if (!probeParseStatusReply(data, len, NULL, &st)) return false;
    resultAppend(",\"stats\":{\"batt_mv\":%u,\"q\":%u,\"noise\":%d,\"rssi\":%d,"
                 "\"rx\":%lu,\"tx\":%lu,\"air\":%lu,\"up\":%lu,"
                 "\"sf\":%lu,\"sd\":%lu,\"rf\":%lu,\"rd\":%lu,"
                 "\"err\":%u,\"snr\":%d,\"ddup\":%u,\"fdup\":%u,"
                 "\"rxair\":%lu,\"rxerr\":%lu}",
                 st.batt_milli_volts, st.curr_tx_queue_len, st.noise_floor, st.last_rssi,
                 (unsigned long)st.n_packets_recv, (unsigned long)st.n_packets_sent,
                 (unsigned long)st.total_air_time_secs, (unsigned long)st.total_up_time_secs,
                 (unsigned long)st.n_sent_flood, (unsigned long)st.n_sent_direct,
                 (unsigned long)st.n_recv_flood, (unsigned long)st.n_recv_direct,
                 st.err_events, st.last_snr, st.n_direct_dups, st.n_flood_dups,
                 (unsigned long)st.total_rx_air_time_secs, (unsigned long)st.n_recv_errors);
    _pending_ops &= (uint8_t)~PROBE_OP_STATUS;
  } else if (_step == PS_TELEMETRY) {
    const uint8_t* lpp = NULL; size_t lpp_len = 0;
    if (!probeParseTelemetryReply(data, len, NULL, &lpp, &lpp_len)) return false;
    // Ship the raw Cayenne LPP bytes; Echo decodes them with its existing lib.
    //
    // A GUEST login is forced to perm_mask 0x00 (MyMesh.cpp:291-293), so it can
    // only ever see channel-1 base telemetry. An admin login is not, so the flag
    // has to follow the permissions the target ACTUALLY granted -- reporting it
    // unconditionally would tell Echo that admin telemetry was base-only and have
    // it discard external sensor channels it did receive.
    //
    // Note the flag describes the LOGIN, not the payload: a node with no external
    // sensors returns channel-1 data to an admin too, and that is not the same
    // thing as having been restricted.
    char hex[2 * 64 + 1];
    size_t n = lpp_len > 64 ? 64 : lpp_len;
    probeBytesToHex(lpp, n, hex, sizeof(hex));
    bool base_only = (_login_perms == 0);
    resultAppend(",\"lpp\":\"%s\",\"lpp_guest_base_only\":%s", hex,
                 base_only ? "true" : "false");
    _pending_ops &= (uint8_t)~PROBE_OP_TELEMETRY;
  } else {
    return false;
  }

  _awaiting = false;
  advance();
  return true;
}

// A flooded request is answered with a PATH return that CARRIES the response as
// `extra`. Without handling it here, every flooded probe would have its answer
// thrown away (MyMesh::onPeerPathRecv ignored extra_* before this feature).
// --- Route cache -------------------------------------------------------------
// A learned path used to die with the session, so every login-based session
// re-flooded its first step. See ProbeExecutor.h for why caching is only half
// the fix -- the reciprocal teach in MyMesh::onPeerPathRecv is the other half.

void ProbeExecutor::routeCacheStore(const uint8_t* pub_key, const uint8_t* path, uint8_t path_len) {
  if (!pub_key) return;
  // A path too long to store is simply not cached: that target keeps flooding,
  // which is graceful. Storing a truncated path would be worse than none -- it
  // would route down a wrong, silently-failing route.
  if (!probeRoutePathCacheable(path_len)) return;
  uint32_t now = nowSecs();
  int slot = -1, oldest = -1;
  uint32_t oldest_at = 0xFFFFFFFFu;

  for (int i = 0; i < PROBE_ROUTE_CACHE; i++) {
    RouteEntry& e = _routes[i];
    if (e.learned_at != 0 && memcmp(e.pub_key, pub_key, PUB_KEY_SIZE) == 0) {
      slot = i; break;                            // refresh in place
    }
    if (e.learned_at == 0) { if (slot < 0) slot = i; }
    else if (e.learned_at < oldest_at) { oldest_at = e.learned_at; oldest = i; }
  }
  if (slot < 0) slot = (oldest >= 0) ? oldest : 0;  // evict the oldest

  RouteEntry& e = _routes[slot];
  memcpy(e.pub_key, pub_key, PUB_KEY_SIZE);
  e.out_path_len = mesh::Packet::copyPath(e.out_path, path, path_len);
  e.learned_at = now;
  _routes_dirty = true;
}

// Open the sealed "pw" claim. See ProbeSecret.h for why the password is sealed at
// all: the tasking token is signed but NOT encrypted, so a plain claim would put a
// repeater admin password in front of the broker operator and every admin-role
// subscriber.
uint8_t ProbeExecutor::openSealedPassword(const char* hex, size_t hex_len,
                                          uint32_t nonce, uint32_t iat,
                                          ProbePasswordClaim* out) {
  if (!hex || hex_len != PROBE_PW_HEX_LEN) return PROBE_PW_BAD_LEN;

  uint8_t blob[PROBE_PW_BLOB_LEN];
  if (!probeHexToBytes(hex, hex_len, blob, sizeof(blob))) return PROBE_PW_BAD_LEN;

  const uint8_t *salt = NULL, *mac_ct = NULL; size_t mac_ct_len = 0;
  if (!probePwSplitBlob(blob, sizeof(blob), &salt, &mac_ct, &mac_ct_len)) {
    return PROBE_PW_BAD_LEN;
  }

  // K = SHA256(ECDH(us, controller) || salt). The per-command salt is folded into
  // the KEY, not used as a nonce beside it: MeshCore's cipher is AES-128-ECB, so a
  // fixed key would give byte-identical ciphertext for a repeated password and
  // leak equality across commands.
  uint8_t S[PUB_KEY_SIZE];
  _mesh->self_id.calcSharedSecret(S, _prefs->probe_controller_pubkey);
  uint8_t K[32];
  mesh::Utils::sha256(K, sizeof(K), S, PUB_KEY_SIZE, salt, PROBE_PW_SALT_LEN);
  memset(S, 0, sizeof(S));

  uint8_t pt[PROBE_PW_CT_LEN + CIPHER_BLOCK_SIZE];
  int n = mesh::Utils::MACThenDecrypt(K, pt, mac_ct, (int)mac_ct_len);
  memset(K, 0, sizeof(K));
  if (n <= 0) { memset(pt, 0, sizeof(pt)); return PROBE_PW_BAD_MAC; }

  uint8_t st = probePwParsePlaintext(pt, (size_t)n, nonce, iat, out);
  memset(pt, 0, sizeof(pt));
  return st;
}

bool ProbeExecutor::routeCacheLookup(const uint8_t* pub_key) {
  if (!pub_key) return false;
  uint32_t now = nowSecs();
  for (int i = 0; i < PROBE_ROUTE_CACHE; i++) {
    RouteEntry& e = _routes[i];
    if (e.learned_at == 0 || memcmp(e.pub_key, pub_key, PUB_KEY_SIZE) != 0) continue;
    if (!probeRouteFresh(now, e.learned_at, PROBE_ROUTE_TTL_SECS)) {
      e.learned_at = 0;                           // expired: drop it
      return false;
    }
    _out_path_len = mesh::Packet::copyPath(_out_path, e.out_path, e.out_path_len);
    return true;
  }
  return false;
}

bool ProbeExecutor::floodHeldOff(const uint8_t* pub_key) {
  if (!pub_key) return false;
  uint32_t now = nowSecs();
  for (int i = 0; i < PROBE_FLOOD_BACKOFF_SLOTS; i++) {
    FloodBackoff& b = _flood_backoff[i];
    if (b.next_ok_at != 0 && memcmp(b.pub_key, pub_key, PUB_KEY_SIZE) == 0) {
      return probeFloodHeldOff(now, b.next_ok_at);
    }
  }
  return false;
}

void ProbeExecutor::floodFailed(const uint8_t* pub_key) {
  if (!pub_key) return;
  uint32_t now = nowSecs();
  if (now < PROBE_MIN_VALID_EPOCH) return;   // cannot schedule against an untrusted clock
  int free_slot = -1, oldest = 0;
  for (int i = 0; i < PROBE_FLOOD_BACKOFF_SLOTS; i++) {
    FloodBackoff& b = _flood_backoff[i];
    if (b.next_ok_at != 0 && memcmp(b.pub_key, pub_key, PUB_KEY_SIZE) == 0) {
      if (b.fails < 0xFF) b.fails++;
      b.next_ok_at = now + probeFloodBackoffSecs(b.fails);
      return;
    }
    if (b.next_ok_at == 0 && free_slot < 0) free_slot = i;
    if (_flood_backoff[i].next_ok_at < _flood_backoff[oldest].next_ok_at) oldest = i;
  }
  // Full: evict whichever entry frees up soonest, so the longest holds survive.
  FloodBackoff& b = _flood_backoff[free_slot >= 0 ? free_slot : oldest];
  memcpy(b.pub_key, pub_key, PUB_KEY_SIZE);
  b.fails = 1;
  b.next_ok_at = now + probeFloodBackoffSecs(1);
}

void ProbeExecutor::floodSucceeded(const uint8_t* pub_key) {
  if (!pub_key) return;
  for (int i = 0; i < PROBE_FLOOD_BACKOFF_SLOTS; i++) {
    FloodBackoff& b = _flood_backoff[i];
    if (b.next_ok_at != 0 && memcmp(b.pub_key, pub_key, PUB_KEY_SIZE) == 0) {
      b.next_ok_at = 0;   // answered: forget the grudge entirely
      b.fails = 0;
      return;
    }
  }
}

void ProbeExecutor::routeCacheTouch(const uint8_t* pub_key) {
  if (!pub_key) return;
  uint32_t now = nowSecs();
  if (now < PROBE_MIN_VALID_EPOCH) return;   // pre-NTP: a bogus stamp is worse than none
  for (int i = 0; i < PROBE_ROUTE_CACHE; i++) {
    RouteEntry& e = _routes[i];
    if (e.learned_at != 0 && memcmp(e.pub_key, pub_key, PUB_KEY_SIZE) == 0) {
      e.learned_at = now;      // still good -- restart its TTL
      _routes_dirty = true;
      return;
    }
  }
}

void ProbeExecutor::routeCacheDrop(const uint8_t* pub_key) {
  if (!pub_key) return;
  for (int i = 0; i < PROBE_ROUTE_CACHE; i++) {
    RouteEntry& e = _routes[i];
    if (e.learned_at != 0 && memcmp(e.pub_key, pub_key, PUB_KEY_SIZE) == 0) {
      e.learned_at = 0;
      _routes_dirty = true;
      return;
    }
  }
}

// --- Persistence -------------------------------------------------------------
// A reboot would otherwise cost a full sweep of floods to relearn routes the node
// already had. Written lazily on a dirty flag (see MyMesh::loop) rather than on
// every learn, to spare the flash.

#define PROBE_ROUTES_FILE  "/probe_routes"
#define PROBE_ROUTES_MAGIC 0x50524F31UL   // "PRO1"

// Same platform split ClientACL.cpp:3-12 and RegionMap.cpp:61 each keep their own
// copy of. This file compiles for every repeater target, not just ESP32, so the
// bare open(path, "w", true) form is not portable enough on its own.
static File probeOpenWrite(FILESYSTEM* fs, const char* filename) {
  #if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
    fs->remove(filename);
    return fs->open(filename, FILE_O_WRITE);
  #elif defined(RP2040_PLATFORM)
    return fs->open(filename, "w");
  #else
    return fs->open(filename, "w", true);
  #endif
}

void ProbeExecutor::routeCacheLoad(FILESYSTEM* fs) {
  if (!fs || !fs->exists(PROBE_ROUTES_FILE)) return;
#if defined(RP2040_PLATFORM)
  File file = fs->open(PROBE_ROUTES_FILE, "r");
#else
  File file = fs->open(PROBE_ROUTES_FILE);
#endif
  if (!file) return;

  uint32_t magic = 0; uint16_t entry_size = 0, count = 0;
  bool ok = (file.read((uint8_t*)&magic, 4) == 4)
         && (file.read((uint8_t*)&entry_size, 2) == 2)
         && (file.read((uint8_t*)&count, 2) == 2);
  // entry_size guards against a layout change (a different PROBE_ROUTE_MAX_PATH
  // or key size) silently loading garbage as routes.
  if (!ok || magic != PROBE_ROUTES_MAGIC || entry_size != (uint16_t)sizeof(RouteEntry)) {
    file.close();
    return;
  }
  int loaded = 0;
  for (uint16_t i = 0; i < count && loaded < PROBE_ROUTE_CACHE; i++) {
    RouteEntry e;
    if (file.read((uint8_t*)&e, sizeof(e)) != (int)sizeof(e)) break;   // truncated
    if (e.learned_at == 0) continue;
    _routes[loaded++] = e;
  }
  file.close();
  _routes_dirty = false;
}

void ProbeExecutor::routeCacheSave(FILESYSTEM* fs) {
  if (!fs) return;
  File file = probeOpenWrite(fs, PROBE_ROUTES_FILE);
  if (!file) { _routes_dirty = false; return; }   // don't spin retrying

  uint16_t count = 0;
  for (int i = 0; i < PROBE_ROUTE_CACHE; i++) if (_routes[i].learned_at != 0) count++;

  uint32_t magic = PROBE_ROUTES_MAGIC;
  uint16_t entry_size = (uint16_t)sizeof(RouteEntry);
  file.write((const uint8_t*)&magic, 4);
  file.write((const uint8_t*)&entry_size, 2);
  file.write((const uint8_t*)&count, 2);
  for (int i = 0; i < PROBE_ROUTE_CACHE; i++) {
    if (_routes[i].learned_at == 0) continue;
    file.write((const uint8_t*)&_routes[i], sizeof(RouteEntry));
  }
  file.close();
  _routes_dirty = false;
}

bool ProbeExecutor::handlePathReturn(int overlay_idx, const uint8_t* path, uint8_t path_len,
                                     uint8_t extra_type, const uint8_t* extra, uint8_t extra_len) {
  if (_active < 0) return false;

  // path_len is an ENCODED value (hash count in the low bits, hash size in the
  // high bits), not a raw byte count -- copying it verbatim corrupted the path
  // handed to sendDirect(). isValidPathLen() already bounds the decoded length.
  //
  // path_len == 0 is DELIBERATELY accepted: it means a zero-hop return path,
  // i.e. the target is a direct neighbour. That is the best case, not an absent
  // path. Rejecting it left out_path_len UNKNOWN and made every later step of a
  // session re-flood -- measured as 4 floods for a 4-step probe against a direct
  // neighbour, where 1 (the login) is enough.
  if (path && mesh::Packet::isValidPathLen(path_len)) {
    _out_path_len = mesh::Packet::copyPath(_out_path, path, path_len);
    _route_from_cache = false;              // learned fresh, not from the cache
    if (_active >= 0) {
      routeCacheStore(_sessions[_active].target.pub_key, path, path_len);
    }
  }
  if (extra_type == PAYLOAD_TYPE_RESPONSE && extra && extra_len > 0) {
    return handleResponse(overlay_idx, extra, extra_len);
  }
  return true;
}

// ---------------------------------------------------------------------------
// Result reporting
// ---------------------------------------------------------------------------

void ProbeExecutor::resultBegin() {
  _result_len = 0;
  _result[0] = 0;
  _result_truncated = false;
}

// ALL-OR-NOTHING. vsnprintf truncates at the buffer edge, and a clipped append lands
// mid-JSON -- often mid-STRING -- so the node would sign and publish a perfectly valid
// token carrying malformed JSON. Echo verifies that signature happily and then fails to
// parse the claims, which reads as a corrupt node rather than as "the result did not fit".
// Dropping the whole fragment instead keeps the JSON parseable and loses only detail.
void ProbeExecutor::resultAppend(const char* fmt, ...) {
  // Reserve room for the truncation marker and the closing brace, so a session that runs
  // out of space still emits parseable JSON that SAYS it is short.
  const size_t lim = sizeof(_result) - 18;
  if (_result_len >= lim) return;

  char tmp[256];
  va_list args;
  va_start(args, fmt);
  int n = vsnprintf(tmp, sizeof(tmp), fmt, args);
  va_end(args);
  if (n <= 0) return;

  bool fits = (size_t)n < sizeof(tmp) && _result_len + (size_t)n < lim;
  if (!fits) {
    if (!_result_truncated) {
      _result_truncated = true;
      if (_result_len + 13 < sizeof(_result)) {
        memcpy(_result + _result_len, ",\"trunc\":true", 13);
        _result_len += 13;
        _result[_result_len] = 0;
      }
    }
    return;
  }
  memcpy(_result + _result_len, tmp, (size_t)n);
  _result_len += (size_t)n;
  _result[_result_len] = 0;
}

// Minimal JSON string escaping: quote, backslash and control characters. Node
// names and owner strings are operator-supplied, so they cannot be trusted to be
// JSON-safe.
void ProbeExecutor::resultAppendEscaped(const char* key, const char* val, size_t val_len) {
  if (!key) return;
  // Escape into scratch FIRST, then emit the key and value as ONE atomic append. Writing
  // into _result directly meant that once resultAppend started dropping fragments, the
  // opening key could be dropped while raw value bytes were still written after it --
  // precisely the malformed JSON the all-or-nothing rule exists to prevent. Truncating
  // the VALUE here is safe: it stops on a whole-character boundary and the string still
  // gets closed.
  char esc[128];
  size_t e = 0;
  for (size_t i = 0; i < val_len && e + 8 < sizeof(esc); i++) {
    unsigned char c = (unsigned char)val[i];
    if (c == '"' || c == '\\') {
      esc[e++] = '\\';
      esc[e++] = (char)c;
    } else if (c < 0x20) {
      e += (size_t)snprintf(esc + e, sizeof(esc) - e, "\\u%04x", c);
    } else {
      esc[e++] = (char)c;
    }
  }
  esc[e] = 0;
  resultAppend(",\"%s\":\"%s\"", key, esc);
}

static const char* probeStateName(uint8_t st) {
  switch (st) {
    case PST_OK:          return "ok";
    case PST_TIMEOUT:     return "timeout";
    case PST_SEND_FAILED: return "send_failed";
    case PST_DENIED:      return "denied";
    default:              return "unknown";
  }
}

static const char* probeRouteName(uint8_t r) {
  switch (r) {
    case PR_ZEROHOP: return "zerohop";
    case PR_DIRECT:  return "direct";
    case PR_FLOOD:   return "flood";
    default:         return "none";
  }
}

void ProbeExecutor::publishResult(const ProbeSession& s, uint8_t state) {
  if (!s.from_mqtt) return;                 // local CLI prints its own output
  _mesh->publishProbeResult(s, state, _route, _result, _result_len);
}

void ProbeExecutor::reportReject(uint8_t reason, uint8_t reply_slot, const char* job_id) {
  if (reply_slot == 0xFF) return;           // local CLI
  // Never answer unauthenticated junk: a token we could not parse or whose
  // signature failed carries no usable job id anyway (jid is only readable after
  // verification), so replying would just amplify an attacker 1:1 and put a
  // signed message on a broker we may not control.
  if (reason == PRJ_BAD_TOKEN || reason == PRJ_BAD_SIG || reason == PRJ_NO_CONTROLLER) return;
  static const char* names[] = {
    "none", "disabled", "no_controller", "bad_token", "bad_sig",
    "replay", "clock", "rate", "queue_full", "bad_target", "bad_pw",
    "bad_cmd", "need_admin", "bad_obs", "preboot"
  };
  const char* rn = (reason < (sizeof(names) / sizeof(names[0]))) ? names[reason] : "unknown";
  _mesh->publishProbeReject(reply_slot, job_id, rn);
}

// ---------------------------------------------------------------------------
// Reporting helpers
// ---------------------------------------------------------------------------

bool ProbeExecutor::getStatusLine(char* buf, size_t buf_size) const {
  if (!buf || buf_size == 0 || _status[0] == 0) return false;
  snprintf(buf, buf_size, "%s", _status);
  return true;
}

void ProbeExecutor::appendStatsJson(char* buf, size_t buf_size) const {
  // KEYS ARE DELIBERATELY SHORT. This lands in the serial CLI's reply buffer,
  // which is a fixed char[160] (examples/simple_repeater/main.cpp:153) passed
  // without a size, so anything longer smashes the caller's stack. The verbose
  // spelling plus the two mailbox counters came to ~161 bytes and did exactly
  // that. Keep any new field short, and keep this comment.
  snprintf(buf, buf_size,
           "{\"en\":%s,\"busy\":%s,\"acc\":%lu,\"rej\":%lu,"
           "\"ok\":%lu,\"den\":%lu,\"tmo\":%lu,\"sfail\":%lu,"
           "\"flood\":%lu,\"lrej\":%u}",
           (_prefs && _prefs->probe_enable) ? "true" : "false",
           (_active >= 0) ? "true" : "false",
           (unsigned long)_n_accepted, (unsigned long)_n_rejected,
           (unsigned long)_n_ok, (unsigned long)_n_denied,
           (unsigned long)_n_timeout, (unsigned long)_n_send_failed,
           (unsigned long)_n_flood, _last_reject);
}

// Route/state names are referenced by MyMesh when it serialises a result.
const char* probeExecStateName(uint8_t st) { return probeStateName(st); }
const char* probeExecRouteName(uint8_t r)  { return probeRouteName(r); }
