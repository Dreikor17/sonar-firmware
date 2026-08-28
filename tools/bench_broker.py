"""Minimal local MQTT broker for Observer-Probe bench testing.

Stands in for mosquitto: same MQTT 3.1.1 the ESP32 client speaks, but installs
via pip with no admin rights. Anonymous, no TLS, no ACLs -- deliberately, so the
only thing under test is the probe tasking contract itself. The probe's security
is the Ed25519 controller signature at the application layer, which does not
depend on the broker being trusted.

  python bench_broker.py [--bind 0.0.0.0] [--port 1883]
"""

import argparse
import asyncio
import logging
import sys

from amqtt.broker import Broker

# amqtt 0.12 validates config against dataclasses (via dacite), so listener and
# top-level keys use UNDERSCORES (max_connections, topic_check) -- hyphens raise
# UnexpectedDataError. Plugins must be given as DOTTED CLASS PATHS; the
# entry-point short names ("auth_anonymous") fail to import, and omitting the
# section entirely falls back to entry points with a deprecation warning and
# drags in the psutil-dependent $SYS plugin. Naming just the one plugin we need
# keeps the broker quiet and dependency-free.
ANON_AUTH = "amqtt.plugins.authentication.AnonymousAuthPlugin"


def build_config(bind: str, port: int) -> dict:
    return {
        "listeners": {
            "default": {
                "type": "tcp",
                "bind": "%s:%d" % (bind, port),
                "max_connections": 50,
            },
        },
        "sys_interval": 0,
        "auth": {"allow-anonymous": True},
        "plugins": {ANON_AUTH: {}},
        "topic_check": {"enabled": False},
    }


async def run(bind: str, port: int):
    broker = Broker(build_config(bind, port))
    await broker.start()
    print("BROKER LISTENING on %s:%d" % (bind, port), flush=True)
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass
    finally:
        await broker.shutdown()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    try:
        asyncio.run(run(args.bind, args.port))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
