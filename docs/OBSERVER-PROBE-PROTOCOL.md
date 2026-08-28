# Echo Observer-Probe — wire contract

This is the **authoritative** description of what the firmware actually implements.
Anyone writing the Echo side should implement against this document, not against
an earlier design draft.

Vocabulary: an Observer is one node role in a **mesh of nodes**; the roles are
Repeater, Companion, Sensor, Observer.

---

## 1. What the feature is

A repeater-observer keeps doing its normal job (repeating, adverts, MQTT uplink)
and additionally accepts **signed tasking commands over MQTT** telling it to
interrogate a nearby node that Echo's own radios cannot reach. It performs a
guest login and the requested requests, then returns a **signed result**.

The feature is **off by default**. With `probe_enable = 0` the node behaves
exactly like a stock repeater-observer and transmits nothing extra.

---

## 2. MQTT topics

| Direction | Topic | QoS | Retain |
|---|---|---|---|
| Echo → Observer | `meshcore/{IATA}/{PUBKEY}/serial/commands` | 1 | false |
| Observer → Echo | `meshcore/{IATA}/{PUBKEY}/serial/responses` | 1 | **false** |

**Publish commands with `retain: false`.** The Observer drops any command
delivered with the MQTT retain flag set, which stops a retained command being
re-executed every time the node reconnects.

> Note the MQTT subtlety, because it is easy to test wrongly: a live publish
> with `retain=true` is delivered to **already-subscribed** clients with the
> retain flag **cleared**, so it still executes. The flag is only set when the
> broker replays the message from its retained store on a **fresh subscribe**.
> That reconnect case is what the check defends, and it is the case to test —
> publish retained, restart the node, and confirm the command does not run a
> second time. Verified on hardware: exactly one execution.

**The Observer connects with a clean session**, so QoS 1 from Echo is safe. It
never calls `setCleanSession`, and the client library defaults it to true, which
means the broker keeps no persistent session and **no queue of commands can build
up while the node is offline and then burst on reconnect** — a burst of queued
commands would be a burst of RF probe transmissions. The trade is that a command
published while the Observer is offline is simply **dropped, not queued**: Echo
owns retry, and a retry must carry a fresh `n` and `iat` or it will be refused as
a replay or as stale.

`{PUBKEY}` is the Observer's own 64-hex device public key, uppercase, exactly as
it already appears in its `status` / `packets` topics. `{IATA}` is the Observer's
configured IATA.

Built by `mqttBuildSerialTopic()` in `src/helpers/MQTTTopicRouter.h`.

**A result is never retained.** A retained result would be replayed to the next
subscriber as though it were fresh.

### Subscription scope

The Observer subscribes to its command topic on **exactly one operator-designated
control slot** (`probe.slot`), never on every connected broker. `serial/*` is
private only on the operator's own broker; other slots are public presets.

---

## 3. Token format — **standards-correct EdDSA compact token**

Both directions use the same envelope:

```
base64url(header) "." base64url(payload) "." base64url(signature)
```

* `header` = `{"alg":"EdDSA","typ":"JWT"}`
* `signature` = raw 64-byte Ed25519 signature over the ASCII bytes of
  `base64url(header) + "." + base64url(payload)`
* base64url is **unpadded** (RFC 4648 §5). Padding (`=`) is rejected.

> ### This is deliberately NOT the format `JWTHelper` produces
>
> `JWTHelper::createAuthToken` (used for **broker authentication**) hex-encodes
> the signature and advertises `alg: "Ed25519"`. No stock JWT library verifies
> that. It is untouched, and the probe channel uses the standard form above
> instead, so the Echo side can use an ordinary Ed25519/JWT verifier.

Implemented by `probeB64UrlEncode` / `probeB64UrlDecode` / `probeTokenSplit` in
`src/helpers/ProbeCodec.h`, and `probeSignToken()` in
`examples/simple_repeater/MyMesh.cpp`.

### Verifying a result, Echo side

```python
import base64, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

h, p, s = token.split(".")
Ed25519PublicKey.from_public_bytes(observer_pubkey_bytes).verify(
    b64u(s), (h + "." + p).encode("ascii")
)
claims = json.loads(b64u(p))
```

---

## 4. Command claims (Echo → Observer)

```jsonc
{
  "jid": "job-1234",     // opaque job id, <= 16 chars, echoed back
  "tgt": "<64 hex>",     // target node public key
  "ops": 6,              // bitmask, see below
  "n":   918273,         // nonce, must be unique
  "iat": 1735000000,     // issued-at, epoch seconds
  "exp": 1735000300      // expiry, epoch seconds (0 = no expiry)
}
```

### `ops` bitmask

| Bit | Value | Operation | Login required |
|---|---|---|---|
| 0 | `0x01` | anon owner request (`ANON_REQ_TYPE_OWNER`) | no — always zero-hop |
| 1 | `0x02` | ver-ident (`REQ_TYPE_GET_OWNER_INFO`, `0x07`) | yes |
| 2 | `0x04` | status (`REQ_TYPE_GET_STATUS`, `0x01`) | yes |
| 3 | `0x08` | telemetry (`REQ_TYPE_GET_TELEMETRY_DATA`, `0x03`) | yes |
| 4 | `0x10` | remote CLI command (`TXT_MSG` / `TXT_TYPE_CLI_DATA`) | yes — **admin** |

Bits may be combined. One guest login is performed for the whole session,
then each requested request runs in order — **one session costs one rate-limit
token, not one per step.**

### `cmd` — the remote CLI command (with `ops` bit `0x10`)

Runs a CLI command on the target and returns its reply in `cmd_reply`. This is
what lets Echo retire the locally-attached companion radios: it is the same
command surface a companion drives today.

**It requires a sealed `pw`.** The target gates remote CLI on `client->isAdmin()`
and simply ignores a guest, so a command op without a password would sit there and
time out with nothing to explain why — the Observer refuses it up front with
`reason: "need_admin"` instead.

The text must be **printable ASCII, no `"` and no `\`**, at most 160 characters.
The claim scanner does not unescape, so rather than half-handle escaping the
firmware refuses anything that could have needed it (`reason: "bad_cmd"`). 160 is
the target's own ceiling: it builds replies in a 166-byte buffer with the text at
offset 5.

The command runs **last** in a session, after any ver-ident/status/telemetry, so a
combined session captures the node's state *before* the command changes it.

A CLI reply comes back as `PAYLOAD_TYPE_TXT_MSG`, not a tagged `RESPONSE`, and
carries no request tag — correlation rests on there being exactly one command in
flight, which the single-session executor guarantees.

**Verified against a live repeater:** `get freq` returned `> 910.5250244`.

### `pw` — the sealed admin password (optional)

Present it and the session logs in as **admin** instead of guest, which is what
unlocks privileged operations and external-sensor telemetry. Omit it for a guest
login.

**It must never be a plain claim.** The token is *signed*, not *encrypted*, so a
password in clear would be readable by the broker operator and by every
admin-role subscriber. It rides sealed to the Observer's own device key:

```
"pw": hex( salt[16] || mac[2] || ciphertext[32] )      // exactly 100 hex chars

S = X25519(controller_prv, observer_ed_pub)   // raw, unhashed (MeshCore's ECDH)
K = SHA256(S || salt)                         // fresh per command
ciphertext = AES-128-ECB(K[:16], plaintext), mac = HMAC-SHA256(K[:32], ct)[:2]

plaintext, zero-padded to 32 bytes:
  [0]      0x01      version
  [1..4]   nonce     u32 LE  -- MUST equal the signed "n"
  [5..8]   iat       u32 LE  -- MUST equal the signed "iat"
  [9]      pw_len    1..15   (NodePrefs::password is char[16])
  [10..]   password
```

The salt is folded into the **key**, not used as a nonce beside it. MeshCore's
cipher is AES-128-ECB, so a fixed key would produce byte-identical ciphertext for
a repeated password and leak equality across commands; a fresh `K` per command
removes that.

Binding `n` and `iat` *inside* the ciphertext is what stops a captured blob being
pasted into a different command — and the outer Ed25519 signature means an
attacker cannot re-sign a command to match one. A blob that fails to open is
refused with `reason: "bad_pw"`.

Echo needs no new crypto: `backend/app/meshcrypto.py` already implements
`shared_secret()` and `encrypt_then_mac()` byte-compatibly. See
`seal_password()` in `tools/echo_probe_sim.py` for a working reference.

**Verified against a live repeater:** the same probe returned `perms: 0` as a
guest and `perms: 3` with a sealed password.

### Admission rules (all must pass, else the command is refused)

1. `probe_enable` is on.
2. `probe_controller_pubkey` is set — an all-zero key **fails closed**, refusing
   everything.
3. Signature verifies against that controller key.
4. `iat`/`exp` are within ±300 s of the Observer clock. **Before the first NTP
   sync the node refuses every command** rather than guessing.
5. `n` has not been seen recently (8-entry nonce ring). **`iat` and `n` are
   mandatory** — a command that omits either is refused, so a missing claim can
   never silently disable the freshness window or the replay ring.
6. The session rate limit (`probe.max`, sessions/hour) allows it.
7. A session slot is free (queue depth 4).

Claims are parsed **only after the signature verifies**. The only operations
performed on unauthenticated bytes are the token split and base64url decode.

---

## 5. Result claims (Observer → Echo)

```jsonc
{
  "jid":   "job-1234",
  "tgt":   "<64 hex>",
  "st":    "ok",              // ok | timeout | send_failed | denied | unknown
  "route": "zerohop",         // zerohop | direct | flood | none
  "iat":   1735000012,

  // present according to which ops ran and succeeded
  "fw_level": 2,              // from the login reply
  "perms":    2,
  "fw":       "v1.17.1",      // ver-ident
  "name":     "Lake Edge",
  "owner":    "...",
  "clock":      1735000000,   // anon owner request only
  "anon_name":  "Lake Edge",  // anon owner request only (namespaced so a session
  "anon_owner": "...",        //   that also runs ver-ident has no duplicate keys)
  "ver_ident_skipped": "fw_level<2",   // target too old for REQ 0x07
  "truncated": true,          // result did not fit; re-probe with fewer ops
  "stats": {                  // status
    "batt_mv": 4123, "q": 0, "noise": -97, "rssi": -80,
    "rx": 123, "tx": 45, "air": 10, "up": 99999,
    "sf": 1, "sd": 2, "rf": 3, "rd": 4,
    "err": 0, "snr": -20, "ddup": 0, "fdup": 0,
    "rxair": 5, "rxerr": 0
  },
  "admin":     true,          // login was ATTEMPTED as admin; `perms` is what was granted
  "cmd_reply": "> 910.52",    // remote CLI command output
  "lpp": "0167011002...",             // telemetry, RAW Cayenne LPP as hex
  "lpp_guest_base_only": true
}
```

A refusal is reported as its own token so Echo can distinguish **denied** from
**lost**:

```jsonc
{ "jid": "job-1234", "st": "denied", "reason": "rate", "iat": 1735000012 }
```

`reason` is one of `disabled`, `replay`, `clock`, `rate`, `queue_full`,
`bad_target`, `bad_pw` (a sealed password that would not open), `bad_cmd` (command
text that is empty, too long, or would have needed JSON escaping), `need_admin`
(a command op with no sealed password), or `no_route` (login-based ops refused because flooding is off and
the target has no known route — see section 6).

**`disabled` is answered only after the signature verifies.** The master switch is
checked *after* verification, not before, so a node whose probing was turned off
at runtime does not answer arbitrary junk with a signed `disabled` token — that
would be a 1:1 amplification vector and an oracle for "this pubkey runs a
probe-capable Observer". The legitimate controller still gets the refusal, with
its `jid` echoed so it can be correlated. (With probing off at *boot* the node
never subscribes at all, so the question only arises after `set probe off` at
runtime.) Verified on hardware: junk drew no reply, a valid command drew
`denied`/`disabled` carrying its jid.

**Unauthenticated failures are deliberately silent.** `bad_token`, `bad_sig` and
`no_controller` produce **no reply at all**: such a token carries no usable job id
anyway (`jid` is only readable after verification), so answering would amplify an
attacker one-for-one and put a signed message on a broker we may not control.
Echo should treat a command that draws no response within its own timeout as
either lost or rejected-as-unauthenticated.

### Two caveats worth carrying into Echo

* **`lpp` is base telemetry only for a GUEST login.** The target forces
  `perm_mask = 0x00` for guests, so a guest probe never sees external sensors —
  only channel-1 battery and MCU temperature. Send a sealed `pw` to log in as
  admin and lift that. `lpp_guest_base_only` reports which applied, and it
  describes the **login**, not the payload: a node with no external sensors
  returns channel-1 data to an admin too, which is not the same as being
  restricted.
* **`stats` is a raw 56-byte struct** read little-endian. `snr` is multiplied by
  4 (divide to get dB).

---

## 6. Flood safety

The project rule is that this feature must never cause repeated flood traffic.

* Reaching a target with no learned path floods a **login/request datagram** —
  it is **never** a `PAYLOAD_TYPE_ADVERT`. The Observer emits no flood adverts
  because of this feature.
* **The veto covers the reply direction too, which is the non-obvious half.** A
  zero-hop request cannot propagate, but a target that has no return path to us
  answers a login or `REQ` by **flooding its response** (`chooseReplyRoute` with
  no supplied path and no stored `out_path` returns `REPLY_ROUTE_FLOOD`). Naively
  probing zero-hop is therefore *louder* than flooding: a flooded request draws
  one PATH return that teaches the route, after which the rest of the session is
  direct.
  So with `probe.flood` **off**, login-based ops (ver-ident / status / telemetry)
  against a target with no known route are **refused** — the result comes back
  `st: "denied"`, `reason: "no_route"`, and nothing is transmitted. Enable
  `probe.flood` to run them.

  > **`no_route` is unconditional, not per-target — do not read it as reachability
  > data.** A session never inherits a route: `ProbeExecutor::startNext()` resets
  > `_out_path_len` to unknown for every session, and the only writer is
  > `handlePathReturn()`, which fires mid-session and only after a packet was
  > flooded. So with `probe.flood` off, *every* login-based op against *every*
  > target is refused. The refusal describes the node's configuration, not the
  > target. Ranking Observers by it, or rotating to a "better" one, just collects
  > the same instant refusal from each.
  >
  > The same fact costs something with flooding **on**: because the learned path
  > dies with the session, every login-based session pays exactly **one flood** on
  > its first login step — even re-probing the same target seconds later. Budget a
  > scheduled sweep of N nodes at N floods, and prefer the `owner` op wherever it
  > suffices, since it is exempt and always zero-hop.
* **A flooded login teaches the route, so only the FIRST step of a session can
  flood.** The target answers a flooded request with a PATH return; the executor
  stores that path (including a zero-length one, which means the target is a
  direct neighbour) and every later step of the session goes direct. Measured on
  hardware against a direct neighbour: a 4-step `all` session costs **1 flood +
  3 zero-hop sends**. Treating a zero-length return path as "no path" is what
  makes it cost 4 floods instead -- that regressed once and is worth a test.
* Anon owner requests are **always** allowed and always zero-hop: their body
  carries `reply_path_len = 0`, so the target replies zero-hop as well. This is
  the one operation that is quiet against a completely unknown node.
* Every probe packet passes through exactly one function, `ProbeExecutor::transmit()`,
  which holds the master switch, the runaway packet backstop, the packet-pool
  preflight and the flood veto. There is no second path to the radio.
* The session budget is charged **once at admission**, so a multi-step session can
  never be denied half-way and strand a login on the target.

Operators should also run `set flood.advert.interval 0` on probe-capable nodes.
The compiled default only helps a fresh install: stored prefs are loaded over it.

---

## 7. Settings

| CLI | Web key | Meaning |
|---|---|---|
| `set probe on\|off` | `probe` | master switch (restart to apply) |
| `set probe.controller <64 hex>\|none` | `probe.controller` | the only key whose commands are accepted |
| `set probe.max <n>` | `probe.max` | probe **sessions** per hour (0 = default 12) |
| `set probe.flood on\|off` | `probe.flood` | allow flooding to no-route targets (default off) |
| `set probe.slot <n>\|off` | `probe.slot` | the one MQTT slot allowed to task this node |

`get probe`, `get probe.controller`, `get probe.max`, `get probe.flood`,
`get probe.slot` read them back; `probe.status` reports live counters.

Stored in `NodePrefs` (`/prefs.json`), which is key-addressed JSON and therefore
append-safe — no version dance, and the WiFi credentials in `/mqtt_prefs` are
untouched.

Local testing without MQTT:

```
probe <pubkey-hex> [owner|ver|status|telemetry|all]
probe.status
```

---

## 8. Threading

| Runs on | What |
|---|---|
| esp-mqtt event task | `offerProbeCommand()` — copy into the mailbox and set a flag. Nothing else. |
| Arduino loop task (Core 1) | everything else: signature verify, session state machine, all radio operations |
| MQTT bridge task (Core 0) | `publishProbeResult()` |

The Core 0 → Core 1 mailbox is an acquire/release single-slot handoff mirroring
`requestPublishNeighbors`. Signature verification runs on Core 1 because the
software Ed25519 path needs ~3 KB of stack, which the esp-mqtt event task does
not have. The command and claim buffers are class members, never stack locals,
for the same reason.
