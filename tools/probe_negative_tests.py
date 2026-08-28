"""Negative-path tests for the Observer-Probe tasking channel.

Every case here must produce SILENCE from the node -- an unauthenticated or
malformed command draws no reply by design, since the token carries no usable
job id and answering would amplify an attacker one-for-one.

Silence is only meaningful if the channel is otherwise alive, so the run ends
with a POSITIVE CONTROL: a valid command that must draw a response. If the
control is silent too, the whole run is inconclusive rather than passing.
"""

import base64
import json
import secrets
import sys
import time

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

HOST = "127.0.0.1"
PORT = 1883
IATA = "TST"
OBS = "20B69583B659A576C03299E5D1B849C29635BB9C069C024088FE8DB889C281DB"
TGT = "DEADBEEF00112233445566778899AABBCCDDEEFF00112233445566778899AABB"
KEYFILE = (r"C:\Users\tvolk\OneDrive\Desktop\Claude Wokspace"
           r"\meshcore-observer-probe\tools\probe_controller.key")

CMD_TOPIC = "meshcore/%s/%s/serial/commands" % (IATA, OBS)
RSP_TOPIC = "meshcore/%s/%s/serial/responses" % (IATA, OBS)

HEADER = '{"alg":"EdDSA","typ":"JWT"}'


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def mint(priv, jid, iat=None, nonce=None, ops=1):
    claims = {
        "jid": jid, "tgt": TGT, "ops": ops,
        "n": nonce if nonce is not None else secrets.randbits(31),
        "iat": iat if iat is not None else int(time.time()),
        "exp": 0,
    }
    si = b64u(HEADER.encode()) + "." + b64u(json.dumps(claims, separators=(",", ":")).encode())
    return si + "." + b64u(priv.sign(si.encode("ascii")))


def main():
    with open(KEYFILE, "rb") as f:
        good = serialization.load_pem_private_key(f.read(), password=None)
    rogue = Ed25519PrivateKey.generate()

    got = []

    def on_msg(c, u, m):
        try:
            claims = json.loads(base64.urlsafe_b64decode(
                m.payload.decode().split(".")[1] + "=="))
            got.append(claims.get("jid", "?") + "/" + str(claims.get("st")))
        except Exception:
            got.append("unparseable")

    try:
        cli = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id="negtest")
    except AttributeError:
        cli = mqtt.Client(client_id="negtest")
    cli.on_message = on_msg
    cli.connect(HOST, PORT, 30)
    cli.subscribe(RSP_TOPIC, qos=1)
    cli.loop_start()
    time.sleep(1.5)

    # --- build the cases -------------------------------------------------
    valid = mint(good, "neg-valid")
    h, p, s = valid.split(".")
    flipped = "A" if s[0] != "A" else "B"
    tampered_sig = h + "." + p + "." + flipped + s[1:]

    h2, p2, s2 = mint(good, "neg-payload").split(".")
    other = b64u(json.dumps({"jid": "swapped", "tgt": TGT, "ops": 1,
                             "n": 1, "iat": int(time.time()), "exp": 0},
                            separators=(",", ":")).encode())
    swapped_payload = h2 + "." + other + "." + s2

    cases = [
        ("tampered signature",     tampered_sig,                  False),
        ("payload swapped, old sig", swapped_payload,             False),
        ("signed by ROGUE key",    mint(rogue, "neg-rogue"),      False),
        ("not a token at all",     "hello world",                 False),
        ("empty payload",          "",                            False),
        ("two segments only",      h + "." + p,                   False),
        ("padded base64url",       h + "." + p + "." + s + "==",  False),
        ("RETAINED valid command", mint(good, "neg-retained"),    False),
        ("POSITIVE CONTROL",       mint(good, "neg-control"),     True),
    ]

    results = []
    for name, payload, expect_reply in cases:
        got.clear()
        retain = (name == "RETAINED valid command")
        cli.publish(CMD_TOPIC, payload, qos=1, retain=retain)
        time.sleep(7)
        replied = len(got) > 0
        ok = (replied == expect_reply)
        results.append((name, expect_reply, replied, got[:], ok))
        print("%-26s expect_reply=%-5s got=%-5s %s %s" % (
            name, expect_reply, replied, "PASS" if ok else "*** FAIL ***",
            got[:] if got else ""), flush=True)

    # clear any retained command we may have left on the broker
    cli.publish(CMD_TOPIC, "", qos=1, retain=True)
    time.sleep(1)
    cli.loop_stop()
    cli.disconnect()

    print("")
    failed = [r for r in results if not r[4]]
    control = [r for r in results if r[0] == "POSITIVE CONTROL"][0]
    if not control[2]:
        print("INCONCLUSIVE: positive control drew no reply -- channel may be dead")
        sys.exit(2)
    print("%d/%d passed" % (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
