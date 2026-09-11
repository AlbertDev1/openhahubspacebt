# openhahubspacebt

Working toward fully local control of Hubspace ceiling fans from Home Assistant,
over Bluetooth Low Energy, with the Afero cloud cut out entirely.

**Status: reverse engineering, nothing decoded yet.** The recon tooling works.
The protocol is still unknown. See [docs/protocol.md](docs/protocol.md) for what
is established and what is still open.

## Why this can work

Hubspace runs on Afero's cloud and the existing Home Assistant integration is
cloud-only. Afero puts a "softhub" inside the phone app to relay device traffic,
and Afero's documentation says that softhub must be associated with an account
before it will talk to any device at all.

The fans this project targets never reliably joined Wi-Fi, and **the app still
controls them with the internet disconnected.** So the association already
happened and the credentials are cached on the phone. The traffic is probably
still encrypted, because the radio module has a hardware security element, but
the key is in local storage rather than issued per session.

That turns an intractable problem, breaking cryptography, into two tractable
ones: find the key, and re-implement the framing.

## What is here

| Path | What it is |
| --- | --- |
| `tools/scan.py` | Find the fan among every Bluetooth advertiser nearby |
| `tools/enumerate.py` | Dump a device's entire attribute table |
| `tools/listen.py` | Subscribe to notifications and watch state change |
| `tools/btsnoop_parse.py` | Pull the attribute layer out of an Android capture |
| `docs/protocol.md` | Living record of findings and dead ends |
| `docs/capture-guide.md` | How to capture Bluetooth traffic from the app |
| `tests/` | Tests for the capture parser, runnable without pytest |

The eventual deliverable is a HACS custom integration, not an add-on. An add-on
is a container and cannot create entities or reach Home Assistant's Bluetooth
stack, including remote Bluetooth proxies.

## Running the tools on Home Assistant

The Bluetooth adapter is on the Home Assistant machine, so the tools run there.

**1. Get a shell.** Install the **Advanced SSH & Web Terminal** add-on. It
already declares the host D-Bus access that BlueZ needs. In its configuration
set:

```yaml
packages:
  - python3
  - py3-pip
  - bluez
  - gcc
  - python3-dev
  - musl-dev
  - linux-headers
```

The compiler packages are there because one of bleak's dependencies may need to
build from source on Alpine. If **Protection mode** is on and BlueZ turns out to
be unreachable, switch it off.

**2. Confirm the adapter is alive.**

```sh
bluetoothctl list          # should name at least one adapter
bluetoothctl --timeout 10 scan on
```

If that lists nothing, stop here. Nothing else will work until it does.

**3. Install this repository.** Drop `-b recon-tooling` once that branch is
merged into `main`.

```sh
cd /config
git clone -b recon-tooling https://github.com/AlbertDev1/openhahubspacebt.git
cd openhahubspacebt
python3 -m venv .venv
.venv/bin/pip install -r requirements-tools.txt
```

**4. Find the fan.** Run this once from as close to the fan as the machine can
get, then again from far away. The fan is the advertiser whose signal strength
collapses between the two runs. Do not trust the name, which may be generic or
absent.

```sh
.venv/bin/python tools/scan.py --seconds 30 --label near
.venv/bin/python tools/scan.py --seconds 30 --label far
```

**5. Map it.** Once you have an address, dump everything it exposes:

```sh
.venv/bin/python tools/enumerate.py AA:BB:CC:DD:EE:FF
```

A vendor-specific service holding one characteristic that accepts writes and one
that sends notifications is the command pipe. That is the target.

**6. Watch it.** Subscribe, then operate the fan from the app or the wall switch:

```sh
.venv/bin/python tools/listen.py AA:BB:CC:DD:EE:FF --seconds 120
```

Output lands in `captures/`, which is deliberately excluded from git because it
contains account and device identifiers.

### A conflict to expect

Bluetooth Low Energy generally allows one connected central at a time, and three
things want this fan: the phone app, Home Assistant's own Bluetooth integration,
and these tools. If connections keep dropping, close the app, and consider
disabling the Home Assistant Bluetooth integration while doing connection-level
work.

## Capturing traffic from the app

The highest-value evidence comes from the phone, not from Home Assistant.
Android logs every Bluetooth packet with no extra hardware.

Follow [docs/capture-guide.md](docs/capture-guide.md), then:

```sh
python tools/btsnoop_parse.py captures/fan-on.log --summary
```

The summary view groups payloads by attribute handle and marks which byte
positions change. Capture "fan on" twice: if the two payloads differ in only a
byte or two, those bytes are a counter and the rest is readable structure. If
they share nothing, the payload is encrypted and the work moves to finding the
key.

`btsnoop_parse.py` uses the standard library only, so it runs anywhere with no
install.

## Development

```sh
python -m venv .venv
.venv/bin/pip install -r requirements-tools.txt
python tests/test_btsnoop_parse.py     # no pytest needed
```

Tested against Python 3.12 and bleak 3.0.2.

## Licence

Apache 2.0.
