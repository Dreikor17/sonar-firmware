# Sonar

Source and firmware releases for **Sonar** — the [rflab.io](https://rflab.io) MeshCore
observer build.

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

Each release carries two images. Which one you want depends on whether the board has
ever run Sonar before.

**A new or unknown board — `*-merged.bin`, written at offset `0x0`:**

```
esptool.py --chip esp32s3 write_flash 0x0 <name>-merged.bin
```

This carries the bootloader, partition table, OTA selector and application together. A
first flash has to be over USB — there is no way onto a blank board over the network.

**Updating a board already running Sonar — let it update itself:**

```
ota check     # report what is available, change nothing
ota update    # download, flash, reboot
```

The plain `.bin` (no `-merged`) is the application image the device fetches for itself.
You can write it at `0x10000` over a cable if you prefer, but it will not boot a board
that has never been flashed.

A release whose partition layout changed cannot be applied over the air — OTA cannot
rewrite a partition table. The firmware checks this itself and refuses rather than
bricking; those releases say so in the notes and need a cable.

## First-time setup

A freshly flashed board knows nothing: no network, no broker, no controller. Configure it
over USB serial (or the built-in config portal), at minimum:

```
set wifi.ssid <ssid>
set wifi.pwd <password>
set mqtt.iata <code>            # its slot in the broker topic tree
set mqtt.origin <name>          # how it identifies itself
```

To let a manager task it as a probe, it also needs the controller key it will accept
commands from — anything not signed by that key is refused, so a compromised broker
still cannot task it:

```
set probe.controller <64-hex controller public key>
set probe on
```

Neighbour reporting (`set mqtt.neighbors on`) is on by default on a fresh install. A board
carried over from an earlier build keeps whatever it had, so it may need setting once.

Being reachable is not the same as being permitted: the manager and the broker each keep
their own list of which nodes may be tasked, and both have to allow it.

## The source

This repository holds the full firmware, not just the binaries, so anyone running a Sonar
node — or hearing one on the mesh — can read exactly what it does. It is a fork of
MeshCore's observer build; the Sonar work is a handful of commits on top, and the upstream
history is kept intact rather than squashed away.

| Branch | Points at | Use |
|---|---|---|
| `main` | the production manifest | what field nodes run |
| `dev` | the development manifest | what is being worked on |

The two differ only in which release channel a build is bound to, and `dev` additionally
carries a broker preset for the development environment. The channel is compiled in, so a
node only ever sees updates from the branch it was built from — the two populations cannot
cross-update.

Worth knowing before you flash a release:

- The image carries the controller's **public** key, so a node trusts one specific
  controller out of the box. Without the private half it cannot be tasked, and it still
  has to be approved on the controller side before anything reaches it.
- The admin password is MeshCore's stock default. **Change it during setup** — a
  repeater accepts an admin login over the radio from anyone in range who knows it.
- OTA manifests are signed with that same controller key, so a node will not install
  firmware named by a manifest it cannot verify.

Building needs [PlatformIO](https://platformio.org/). `release-sonar.sh` pins the
environment variables a releasable build depends on; a plain `pio run` produces a working
node with over-the-air updates disarmed, which is the safe default for a local build.

## Credit and license

Sonar is built on [MeshCore](https://meshcore.io) by Scott Powell, and on the
observer/MQTT work in [agessaman/MeshCore](https://github.com/agessaman/MeshCore).

MeshCore is MIT licensed; see [`license.txt`](license.txt), which applies to the firmware
images published here.
