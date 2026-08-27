# Sonar

Firmware releases for **Sonar** — the [rflab.io](https://rflab.io) MeshCore observer build.

Sonar is a MeshCore **observer** that also acts as a remote **probe**. It does what an
observer normally does — sit on the mesh, hear packets, and uplink what it hears to an
MQTT broker — and adds the ability to be *asked a question*: interrogate a specific node
over LoRa on command and return a signed answer.

The name is the behaviour. Sonar works by echo, and it has two modes:

| Sonar | Node |
|---|---|
| **passive** — listen, report what you hear | observer: packet/status uplink, neighbour reports |
| **active** — transmit, then listen for the return | probe: query a node and return the result |

## Why

A monitoring station can only poll what its own radio can reach. Nodes behind a ridge, or
in another town, are simply invisible to it — and asking louder doesn't help, it just
spends airtime transmitting into silence.

Sonar nodes are the ears in those places. A manager picks the Sonar node that can actually
*hear* the node in question and asks that one, which means the query goes out from
somewhere it can succeed, rather than being flooded across the whole mesh from somewhere
it can't.

## Airtime

This is a monitoring tool that transmits, so restraint is built in rather than optional:

- Queries prefer a **direct** path and fall back to a flood only when there is no route.
- Every node enforces a **per-hour budget** on how often it can be tasked.
- A node that stops answering earns an increasing **backoff** instead of being retried
  forever.
- Neighbour reports are collected with a **zero-hop** discovery (it never propagates), at
  most once every 12 hours.
- Sonar never sends repeated adverts.

## Updates

Sonar can update itself. On the device:

    ota check     # report the available build, change nothing
    ota update    # download, flash, reboot

The release channel *is* the manifest URL the firmware was built with, so a Sonar node
only ever sees Sonar builds — never stock observer builds, and vice versa. Manifests are
served from `rflab.io`; the firmware images themselves come from the Releases on this
repository.

`ota update` verifies the download against the certificate bundle embedded in the
firmware, so images are only ever fetched over HTTPS from a publicly trusted host.

## Versions

    v1.17.1.3-observer-sonar-a1b2c3d
    │        │ │        │     └─ commit
    │        │ │        └─ this build (Sonar)
    │        │ └─ upstream variant
    │        └─ Sonar build number, increases every release
    └─ upstream MeshCore version

The upstream version is kept deliberately, so it is always obvious which MeshCore release
a Sonar build is based on.

## Flashing

Attach the `.bin` from a release. For a first install use the merged image
(`*-merged.bin`) written at offset `0x0`; afterwards the device can update itself over the
air. A build whose partition layout changed cannot be applied over the air — the release
notes will say so, and those need a cable.

## Credit and license

Sonar is built on [MeshCore](https://meshcore.io) by Scott Powell, and on the
observer/MQTT work in [agessaman/MeshCore](https://github.com/agessaman/MeshCore).

MeshCore is MIT licensed; see [`license.txt`](license.txt), which applies to the firmware
images published here.
