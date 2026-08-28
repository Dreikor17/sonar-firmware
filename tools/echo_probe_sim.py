#!/usr/bin/env python3
"""
Echo Observer-Probe -- stand-in controller for bench testing.

Mints, signs and publishes tasking commands to an Observer, and verifies the
signed results it sends back. Lets you exercise the whole MQTT tasking path
without Echo or the production broker existing yet.

This is also the REFERENCE IMPLEMENTATION of the token contract in
docs/OBSERVER-PROBE-PROTOCOL.md -- the Echo side should match it.

Requires: cryptography    (pip install cryptography)
Optional: paho-mqtt       (pip install paho-mqtt)  -- only for publish/listen

Typical bench session:

    # 1. make a controller key, paste the pubkey into the node
    python tools/echo_probe_sim.py keygen
    #    on the node:  set probe.controller <PUBKEY>
    #                  set probe on
    #                  set probe.slot 1

    # 2. mint a token offline and eyeball it (no broker needed)
    python tools/echo_probe_sim.py mint --target <64-hex> --ops owner

    # 3. with a broker running, task the node and watch for the result
    python tools/echo_probe_sim.py listen --host 127.0.0.1 --iata TST \\
        --observer <OBSERVER-64-hex>
    python tools/echo_probe_sim.py task   --host 127.0.0.1 --iata TST \\
        --observer <OBSERVER-64-hex> --target <TARGET-64-hex> --ops owner
"""

import argparse
import base64
import json
import os
import secrets
import sys
import time

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.hazmat.primitives import serialization
except ImportError:
    sys.exit("need 'cryptography': pip install cryptography")

KEYFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "probe_controller.key")

OPS = {"owner": 0x01, "ver": 0x02, "status": 0x04, "telemetry": 0x08, "command": 0x10}


# ---------------------------------------------------------------------------
# base64url, unpadded (RFC 4648 section 5) -- matches src/helpers/ProbeCodec.h
# ---------------------------------------------------------------------------

def b64u_enc(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------

def load_key() -> Ed25519PrivateKey:
    if not os.path.exists(KEYFILE):
        sys.exit("no controller key yet -- run: %s keygen" % sys.argv[0])
    with open(KEYFILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def pubkey_hex(priv: Ed25519PrivateKey) -> str:
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return raw.hex().upper()


def cmd_keygen(args):
    if os.path.exists(KEYFILE) and not args.force:
        priv = load_key()
        print("existing controller key (use --force to replace)")
    else:
        priv = Ed25519PrivateKey.generate()
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
        with open(KEYFILE, "wb") as f:
            f.write(pem)
        try:
            os.chmod(KEYFILE, 0o600)
        except Exception:
            pass
        print("wrote %s" % KEYFILE)
    print("")
    print("controller public key (paste into the node):")
    print("    set probe.controller %s" % pubkey_hex(priv))


# ---------------------------------------------------------------------------
# Token minting
# ---------------------------------------------------------------------------

HEADER = '{"alg":"EdDSA","typ":"JWT"}'

# ---------------------------------------------------------------------------
# Sealed admin password (the "pw" claim)
# ---------------------------------------------------------------------------
# The token is SIGNED but NOT ENCRYPTED, so a repeater admin password in a plain
# claim would be readable by the broker operator and every admin-role subscriber.
# It rides sealed to the Observer's device key instead.
#
# This mirrors Echo's backend/app/meshcrypto.py byte for byte (shared_secret and
# encrypt_then_mac); Echo can call that module directly rather than copying this.

_P = 2 ** 255 - 19


def ed25519_pub_to_x25519(ed_pub: bytes) -> bytes:
    """Ed25519 public key -> X25519 Montgomery-u, via u = (1+y)/(1-y) mod p."""
    if len(ed_pub) != 32:
        raise ValueError("ed_pub must be 32 bytes")
    y = int.from_bytes(ed_pub, "little") & ((1 << 255) - 1)   # clear the x-sign bit
    u = ((1 + y) % _P) * pow((1 - y) % _P, _P - 2, _P) % _P
    return u.to_bytes(32, "little")


def _x25519_scalar(priv: Ed25519PrivateKey) -> bytes:
    """MeshCore's ECDH scalar for an Ed25519 identity: clamp(sha512(seed)[:32])."""
    import hashlib
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return bytes(h)


def seal_password(priv: Ed25519PrivateKey, observer_pub_hex: str,
                  password: str, nonce: int, iat: int) -> str:
    """Return the hex "pw" claim: salt[16] || mac[2] || ciphertext[32]."""
    import hashlib, hmac as _hmac, os
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    pw = password.encode()
    if not 1 <= len(pw) <= 15:
        sys.exit("password must be 1-15 chars (NodePrefs::password is char[16])")

    # S = raw X25519, unhashed -- MeshCore uses it directly.
    sk = X25519PrivateKey.from_private_bytes(_x25519_scalar(priv))
    pk = X25519PublicKey.from_public_bytes(
        ed25519_pub_to_x25519(bytes.fromhex(observer_pub_hex)))
    S = sk.exchange(pk)

    # K = SHA256(S || salt). The salt goes into the KEY, not beside it: the cipher
    # is AES-128-ECB, so a fixed key would give identical ciphertext for a repeated
    # password and leak equality across commands.
    salt = os.urandom(16)
    K = hashlib.sha256(S + salt).digest()

    # [ver][nonce u32 LE][iat u32 LE][pw_len][password], zero-padded to 32.
    pt = bytearray(32)
    pt[0] = 0x01
    pt[1:5] = (nonce & 0xFFFFFFFF).to_bytes(4, "little")
    pt[5:9] = (iat & 0xFFFFFFFF).to_bytes(4, "little")
    pt[9] = len(pw)
    pt[10:10 + len(pw)] = pw

    enc = Cipher(algorithms.AES(K[:16]), modes.ECB()).encryptor()
    ct = enc.update(bytes(pt)) + enc.finalize()
    mac = _hmac.new(K[:32], ct, hashlib.sha256).digest()[:2]
    return (salt + mac + ct).hex()


def mint_token(priv: Ed25519PrivateKey, target_hex: str, ops: int,
               jid: str, iat: int, exp_in: int, nonce: int,
               password: str = None, observer_hex: str = None,
               cli_cmd: str = None) -> str:
    # Key order is irrelevant to the firmware's scanner, but keep it stable so
    # the tokens are easy to eyeball.
    claims = {
        "jid": jid,
        # Which observer this command is FOR. Mandatory: the node refuses anything
        # whose obs is absent or not its own key. The signature proves what was
        # asked and by whom, not TO WHOM -- without this binding a compromised
        # broker could lift a still-fresh command for node A and replay it at node
        # B, which would verify the controller signature happily and execute it.
        "obs": (observer_hex or "").upper(),
        "tgt": target_hex.upper(),
        "ops": ops,
        "n": nonce,
        "iat": iat,
        "exp": iat + exp_in if exp_in else 0,
    }
    if not claims["obs"]:
        sys.exit("--observer is required: it binds the command to one node")
    # A remote CLI command. The firmware refuses anything that would have needed
    # JSON escaping, so reject it here too rather than sending a doomed token.
    if cli_cmd:
        forbidden = ('"', chr(92))    # quote and backslash: would need escaping
        if any(ord(c) < 0x20 or ord(c) > 0x7E or c in forbidden for c in cli_cmd):
            sys.exit("--cmd must be printable ASCII with no quote or backslash")
        if not 1 <= len(cli_cmd) <= 160:
            sys.exit("--cmd must be 1-160 chars")
        claims["cmd"] = cli_cmd

    # An optional sealed admin password. Bound to this command's nonce and iat, so
    # a blob captured from one command cannot be pasted into another.
    if password:
        if not observer_hex:
            sys.exit("--password needs --observer (the key it is sealed to)")
        claims["pw"] = seal_password(priv, observer_hex, password, claims["n"], claims["iat"])

    payload = json.dumps(claims, separators=(",", ":"))
    signing_input = (b64u_enc(HEADER.encode()) + "." + b64u_enc(payload.encode()))
    sig = priv.sign(signing_input.encode("ascii"))
    return signing_input + "." + b64u_enc(sig)


def parse_ops(spec: str) -> int:
    if spec.lower() == "all":
        return OPS["ver"] | OPS["status"] | OPS["telemetry"]
    total = 0
    for part in spec.split(","):
        part = part.strip().lower()
        if part not in OPS:
            sys.exit("unknown op %r (choose from %s, or 'all')" % (part, ", ".join(OPS)))
        total |= OPS[part]
    return total


def build_token(args) -> str:
    priv = load_key()
    # --cmd implies the command op, so the caller does not have to say both.
    if getattr(args, "cli_cmd", None) and "command" not in args.ops:
        args.ops = (args.ops + ",command") if args.ops else "command"
    tgt = args.target.strip().upper()
    if len(tgt) != 64 or any(c not in "0123456789ABCDEF" for c in tgt):
        sys.exit("--target must be 64 hex chars")
    return mint_token(
        priv, tgt, parse_ops(args.ops),
        args.jid, args.iat or int(time.time()), args.ttl,
        args.nonce if args.nonce is not None else secrets.randbits(31),
        password=getattr(args, "password_for_target", None),
        observer_hex=getattr(args, "observer", None),
        cli_cmd=getattr(args, "cli_cmd", None))


def cmd_mint(args):
    token = build_token(args)
    print(token)
    print("", file=sys.stderr)
    print("len=%d  (firmware accepts up to 1023; signature segment must be 86 chars)"
          % len(token), file=sys.stderr)
    h, p, s = token.split(".")
    print("claims: %s" % b64u_dec(p).decode(), file=sys.stderr)
    print("sig segment len: %d" % len(s), file=sys.stderr)


# ---------------------------------------------------------------------------
# MQTT
# ---------------------------------------------------------------------------

def need_paho():
    try:
        import paho.mqtt.client as mqtt   # noqa: F401
        return mqtt
    except ImportError:
        sys.exit("need 'paho-mqtt' for this subcommand: pip install paho-mqtt")


def make_client(mqtt, client_id, username=None, password=None):
    """Build a client under either paho 1.x or 2.x.

    paho 2.x made the callback API version a required first argument. Asking for
    VERSION1 keeps the on_connect/on_message signatures used below working on
    both major versions.
    """
    try:
        cli = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1,
                          client_id=client_id, clean_session=True)
    except AttributeError:                      # paho 1.x
        cli = mqtt.Client(client_id=client_id, clean_session=True)
    if username:
        cli.username_pw_set(username, password or "")
    return cli


# Leaf names differ per tree, so callers pass a DIRECTION and this maps it.
# Keeping both runnable matters: the legacy tree is the rollback path, and the
# node stays subscribed to it through the transition.
_LEAVES = {
    "serial": {"cmd": "commands", "rsp": "responses"},
    "probe":  {"cmd": "cmd",      "rsp": "rsp"},
}


def topic_for(tree: str, iata: str, observer: str, direction: str) -> str:
    # Uppercase pubkey: broker authorization is case-insensitive but MQTT ROUTING
    # is not, and the probe tree's parser accepts ONLY uppercase hex.
    leaf = _LEAVES[tree][direction]
    if tree == "probe":
        # No IATA segment by design -- it is node-mutable, so keying a mailbox on
        # it would let a node silently relocate its own command topic. --iata is
        # accepted and ignored on this tree.
        return "probe/v1/%s/%s" % (observer.upper(), leaf)
    return "meshcore/%s/%s/serial/%s" % (iata.upper(), observer.upper(), leaf)


def cmd_task(args):
    mqtt = need_paho()
    token = build_token(args)
    topic = topic_for(args.tree, args.iata, args.observer, "cmd")

    cli = make_client(mqtt, args.client_id, args.username, args.password)
    cli.connect(args.host, args.port, keepalive=30)
    cli.loop_start()
    # retain=False on purpose: the firmware drops retained commands unread.
    info = cli.publish(topic, token, qos=1, retain=False)
    info.wait_for_publish(timeout=10)
    cli.loop_stop()
    cli.disconnect()
    print("published %d bytes -> %s" % (len(token), topic))
    print("claims: %s" % b64u_dec(token.split(".")[1]).decode())


def verify_result(token: str, observer_hex: str):
    """Verify a result token exactly as Echo should."""
    try:
        h, p, s = token.split(".")
    except ValueError:
        return None, "not a 3-segment token"
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(observer_hex))
        pub.verify(b64u_dec(s), (h + "." + p).encode("ascii"))
    except Exception as e:
        return None, "SIGNATURE INVALID (%s)" % type(e).__name__
    try:
        return json.loads(b64u_dec(p).decode()), None
    except Exception as e:
        return None, "claims not valid JSON: %s" % e


def cmd_listen(args):
    mqtt = need_paho()
    if args.observer:
        topic = topic_for(args.tree, args.iata, args.observer, "rsp")
    else:
        # ONE wildcard level on the probe tree, TWO on the legacy one.
        topic = "probe/v1/+/rsp" if args.tree == "probe" else "meshcore/+/+/serial/responses"

    def on_connect(client, userdata, flags, rc):
        print("connected rc=%s, subscribing to %s" % (rc, topic))
        client.subscribe(topic, qos=1)

    def on_message(client, userdata, msg):
        raw = msg.payload.decode("utf-8", "replace")
        print("")
        print("--- %s (%d bytes) ---" % (msg.topic, len(raw)))
        if not args.observer:
            print(raw)
            return
        claims, err = verify_result(raw, args.observer)
        if err:
            print("  !! %s" % err)
            print("  raw: %s" % raw[:200])
            return
        print("  signature OK")
        for k in ("jid", "st", "reason", "route", "tgt", "fw", "name", "owner",
                  "anon_name", "anon_owner", "fw_level", "perms", "admin", "clock",
                  "cmd_reply", "lpp", "lpp_guest_base_only", "ver_ident_skipped",
                  "truncated", "stale_route"):
            if k in claims:
                print("  %-20s %s" % (k, claims[k]))
        if "stats" in claims:
            print("  stats:")
            for k, v in claims["stats"].items():
                print("      %-8s %s" % (k, v))

    cli = make_client(mqtt, args.client_id + "-listen", args.username, args.password)
    cli.on_connect = on_connect
    cli.on_message = on_message
    cli.connect(args.host, args.port, keepalive=30)
    print("listening (ctrl-c to stop)")
    try:
        cli.loop_forever()
    except KeyboardInterrupt:
        print("")


def cmd_verify(args):
    token = args.token or sys.stdin.read().strip()
    claims, err = verify_result(token, args.observer)
    if err:
        sys.exit(err)
    print("signature OK")
    print(json.dumps(claims, indent=2))


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_mqtt(p):
        p.add_argument("--host", default="127.0.0.1")
        p.add_argument("--port", type=int, default=1883)
        p.add_argument("--username")
        p.add_argument("--password")
        p.add_argument("--client-id", default="echo-probe-sim")
        p.add_argument("--iata", default="TST",
                       help="legacy tree only; accepted and ignored with --tree probe")
        p.add_argument("--observer", help="observer device pubkey, 64 hex (get public.key)")
        # Default legacy so an existing invocation keeps working, and so the
        # rollback path stays runnable for as long as nodes are subscribed to it.
        p.add_argument("--tree", choices=("serial", "probe"), default="serial",
                       help="which tasking topic tree to use (default: serial/legacy)")

    def add_token(p):
        p.add_argument("--target", required=True, help="target node pubkey, 64 hex")
        p.add_argument("--ops", default="owner",
                       help="owner,ver,status,telemetry or 'all' (default: owner)")
        p.add_argument("--jid", default="bench-1")
        p.add_argument("--ttl", type=int, default=120, help="exp = iat + ttl (0 = no expiry)")
        p.add_argument("--iat", type=int, help="override issued-at (for clock-window tests)")
        p.add_argument("--nonce", type=int, help="override nonce (for replay tests)")
        p.add_argument("--cmd", dest="cli_cmd",
                       help="remote CLI command text (implies ops=command); needs "
                            "--password-for-target, since the target requires admin")
        p.add_argument("--password-for-target", dest="password_for_target",
                       help="repeater ADMIN password; sealed to the Observer key, "
                            "never sent in clear. Needs --observer.")

    p = sub.add_parser("keygen", help="create/show the controller keypair")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("mint", help="print a signed command token (no broker)")
    add_token(p)
    # Only needed when sealing a password: the blob is encrypted TO this key.
    p.add_argument("--observer", help="observer device pubkey, 64 hex "
                                      "(required with --password-for-target)")
    p.set_defaults(func=cmd_mint)

    p = sub.add_parser("task", help="sign and publish a command")
    add_mqtt(p); add_token(p)
    p.set_defaults(func=cmd_task)

    p = sub.add_parser("listen", help="subscribe to results and verify them")
    add_mqtt(p)
    p.set_defaults(func=cmd_listen)

    p = sub.add_parser("verify", help="verify one result token from argv or stdin")
    p.add_argument("--observer", required=True)
    p.add_argument("token", nargs="?")
    p.set_defaults(func=cmd_verify)

    args = ap.parse_args()
    if getattr(args, "cmd", None) == "task" and not args.observer:
        sys.exit("--observer is required to build the command topic")
    args.func(args)


if __name__ == "__main__":
    main()
