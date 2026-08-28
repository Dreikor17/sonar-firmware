#pragma once

// Echo Observer-Probe -- the encrypted-password envelope.
//
// WHY THIS EXISTS: the tasking command is Ed25519-SIGNED but NOT ENCRYPTED. A
// repeater admin password placed in a plain claim would travel readable (base64url
// of JSON) through the broker, visible to the broker operator and to every
// admin-role subscriber. Signing proves who sent it; it hides nothing.
//
// So the password rides in its own sealed field, encrypted to the Observer's
// device key. Echo ECDHs its controller private key against the Observer public
// key it already knows (it is the {PUBKEY} in the MQTT topic and the key Echo
// verifies results with), and only that Observer can open it.
//
// KEY DERIVATION -- the part that matters. MeshCore's symmetric primitive is
// AES-128-ECB, which leaks equality: the same password under the same key gives
// byte-identical ciphertext every time, so an observer of the topic could tell
// "same password as last time" and build a codebook. A per-command SALT folded
// into the key defeats that:
//
//     S = X25519(controller_prv, observer_pub)      // raw, unhashed (MeshCore's ECDH)
//     K = SHA256(S || salt)                         // fresh 32 bytes per command
//
// A salt used only as a nonce alongside a fixed key would NOT be enough under
// ECB; the key itself has to change.
//
// REPLAY: the plaintext carries the command's own nonce and issued-at, and the
// caller must check they match the SIGNED claims. That binds the sealed blob to
// exactly one command, which the nonce ring and the freshness window already
// police. Lifting the blob into a different command fails because the Ed25519
// signature covers the whole payload.
//
// Deliberately free of Arduino/radio dependencies so it is exercised host-side by
// test/test_probe_secret. Convention follows ProbePolicy.h / ProbeCodec.h.
//
// Vocabulary: this node is an Observer in a mesh of nodes. The node roles are
// Repeater, Companion, Sensor, Observer.

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Wire layout of the "pw" claim, hex-encoded (so 2x these bytes as characters):
//     salt[16] || mac[2] || ciphertext[32]
#define PROBE_PW_SALT_LEN    16
#define PROBE_PW_MAC_LEN     2
#define PROBE_PW_CT_LEN      32
#define PROBE_PW_BLOB_LEN    (PROBE_PW_SALT_LEN + PROBE_PW_MAC_LEN + PROBE_PW_CT_LEN)   // 50
#define PROBE_PW_HEX_LEN     (PROBE_PW_BLOB_LEN * 2)                                    // 100

// Plaintext inside the ciphertext. 25 bytes used, zero-padded to one 32-byte
// span so the block cipher has whole blocks.
//     [0]      version
//     [1..4]   nonce  (LE u32) -- must equal the signed "n"
//     [5..8]   iat    (LE u32) -- must equal the signed "iat"
//     [9]      pw_len (1..15)
//     [10..24] password bytes
#define PROBE_PW_VERSION     0x01
#define PROBE_PW_MAX         15    // NodePrefs::password is char[16]
#define PROBE_PW_PT_LEN      (10 + PROBE_PW_MAX)   // 25

// Parsed result. `password` is NUL-terminated for the login builder.
struct ProbePasswordClaim {
  uint32_t nonce;
  uint32_t iat;
  char     password[PROBE_PW_MAX + 1];
  uint8_t  pw_len;
};

// Why a sealed password was refused. Reported only to the authenticated
// controller; never to unauthenticated traffic.
enum ProbePwStatus : uint8_t {
  PROBE_PW_OK = 0,
  PROBE_PW_BAD_LEN,        // blob is not exactly PROBE_PW_BLOB_LEN
  PROBE_PW_BAD_MAC,        // wrong key, or tampered
  PROBE_PW_BAD_VERSION,
  PROBE_PW_BAD_FIELDS,     // implausible pw_len
  PROBE_PW_BINDING,        // nonce/iat do not match the signed claims
};

// Little-endian reads, written out rather than memcpy'd so the wire format does
// not depend on the host's endianness.
static inline uint32_t probePwReadU32(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void probePwWriteU32(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xFF);
  p[1] = (uint8_t)((v >> 8) & 0xFF);
  p[2] = (uint8_t)((v >> 16) & 0xFF);
  p[3] = (uint8_t)((v >> 24) & 0xFF);
}

// Build the 32-byte plaintext span. Exposed so the host tests can construct a
// blob exactly as Echo would, rather than trusting a hand-written fixture.
static inline bool probePwBuildPlaintext(uint8_t* out, size_t out_size,
                                         uint32_t nonce, uint32_t iat,
                                         const char* password) {
  if (!out || out_size < PROBE_PW_CT_LEN || !password) return false;
  size_t n = strlen(password);
  if (n == 0 || n > PROBE_PW_MAX) return false;
  memset(out, 0, PROBE_PW_CT_LEN);
  out[0] = PROBE_PW_VERSION;
  probePwWriteU32(&out[1], nonce);
  probePwWriteU32(&out[5], iat);
  out[9] = (uint8_t)n;
  memcpy(&out[10], password, n);
  return true;
}

// Validate a DECRYPTED plaintext span and extract the password.
//
// `expect_nonce`/`expect_iat` come from the SIGNED claims. Checking them here is
// what stops a sealed blob captured from one command being pasted into another.
static inline uint8_t probePwParsePlaintext(const uint8_t* pt, size_t pt_len,
                                            uint32_t expect_nonce, uint32_t expect_iat,
                                            ProbePasswordClaim* out) {
  if (!pt || !out || pt_len < PROBE_PW_PT_LEN) return PROBE_PW_BAD_LEN;
  if (pt[0] != PROBE_PW_VERSION) return PROBE_PW_BAD_VERSION;

  uint8_t n = pt[9];
  if (n == 0 || n > PROBE_PW_MAX) return PROBE_PW_BAD_FIELDS;

  uint32_t nonce = probePwReadU32(&pt[1]);
  uint32_t iat   = probePwReadU32(&pt[5]);
  if (nonce != expect_nonce || iat != expect_iat) return PROBE_PW_BINDING;

  memset(out, 0, sizeof(*out));
  out->nonce  = nonce;
  out->iat    = iat;
  out->pw_len = n;
  memcpy(out->password, &pt[10], n);
  out->password[n] = 0;
  return PROBE_PW_OK;
}

// Split a decoded blob into its salt and the MAC+ciphertext span that
// MACThenDecrypt expects. No crypto here -- the caller owns the key schedule,
// which keeps this header free of the mesh crypto dependencies.
static inline bool probePwSplitBlob(const uint8_t* blob, size_t blob_len,
                                    const uint8_t** salt, const uint8_t** mac_ct,
                                    size_t* mac_ct_len) {
  if (!blob || blob_len != PROBE_PW_BLOB_LEN) return false;
  if (salt) *salt = blob;
  if (mac_ct) *mac_ct = blob + PROBE_PW_SALT_LEN;
  if (mac_ct_len) *mac_ct_len = PROBE_PW_MAC_LEN + PROBE_PW_CT_LEN;
  return true;
}

// Wipe a recovered password. Called on every exit path that touched one --
// leaving a repeater admin password sitting in RAM after the session is over is
// exactly the kind of residue a field-readable node should not carry.
static inline void probePwWipe(ProbePasswordClaim* c) {
  if (!c) return;
  memset(c, 0, sizeof(*c));
}
