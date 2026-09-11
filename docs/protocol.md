# Hubspace Bluetooth protocol notes

A living record. Add findings as they land, including the ones that go nowhere.
Several people have started this work and left nothing behind, which is why
every attempt so far has begun from zero.

Status: **nothing decoded yet.** Everything below is background and open
questions.

---

## What is known about the platform

Hubspace is Home Depot's brand on top of Afero's IoT platform. The Android app
is published as `io.afero.partner.hubspace`.

| Piece | What it is | Open? |
| --- | --- | --- |
| AferoJavaSDK | Android client library, drives the softhub | Yes |
| AferoSwiftSDK | iOS equivalent | Yes |
| Softhub (`hubby`) | Relays device traffic, holds the Bluetooth logic | **No**, binary only |
| afLib | Library for a microcontroller talking to the radio module over serial | Yes |
| ASR-1 / ASR-2KL | The radio module inside the device | Hardware |

Devices are built around an Afero Secure Radio module. Afero's model is that
each device exposes numbered **attributes**, and control means writing a value
to an attribute. The cloud API exposes the same thing under friendlier names,
keyed by function class and function instance, for example `power` with instance
`fan-power` versus `light-power` on a fan that also has a light.

The phone app contains a **softhub**, which relays traffic between the device
and Afero's cloud over Bluetooth. Afero's own documentation states the softhub
"attaches to an Afero account by acting as a logical Afero device, and therefore
must be associated with an account before it is able to communicate with
physical Afero peripheral devices."

Afero does not publish the Bluetooth service or characteristic identifiers
anywhere, including in the radio module's regulatory filings.

## Why this project is viable

**The fans here never reliably joined Wi-Fi, and the app still controls them
with the internet disconnected.**

That is the whole basis for the project. The softhub must be associated with an
account before it will talk to a device, so if it works offline then the
association already happened and the credentials are cached on the phone. The
traffic is probably still encrypted, since the radio module has a hardware
security element, but the key is sitting in local storage rather than being
issued per session.

This turns an intractable problem, breaking cryptography, into two tractable
ones: find the key, and re-implement the framing.

### To confirm rigorously

- [ ] Phone in airplane mode with Bluetooth switched back on, so cellular cannot
      quietly carry the traffic.
- [ ] Fan's access point powered down.
- [ ] Change speed, toggle light, note exactly what works and for how long.

Record the result here.

## Prior art

- `jdeath/Hubspace-Homeassistant` plus the `aioafero` library. Cloud only. Auth
  is OAuth2 with PKCE against a Keycloak server. Useful for the capability model
  and for a possible one-time key fetch, not for local control.
- `jdeath/hubspace_ble`. Aimed at Hubspace locks. Three commits. Recovers a
  device identifier and nothing further.
- Home Assistant discussion 1344, on Hubspace Bluetooth bulbs. A capture was
  posted, no analysis followed, still unanswered.

No working decode exists publicly.

## Open questions

1. Which Bluetooth service and characteristics does the fan expose? Answer with
   `tools/enumerate.py`.
2. Does the fan advertise continuously, or only when unprovisioned or awake?
   Answer with `tools/scan.py` at different times.
3. Is the payload encrypted? Answer by capturing the same action twice and
   comparing. `tools/btsnoop_parse.py --summary` does the comparison.
4. If encrypted, where does the key live? Three candidates, cheapest first:
   the app's private storage, a one-time cloud association performed from
   Python, the softhub binary.
5. Does a session handshake happen on every connection, and does it need
   anything the cloud has to supply?
6. What happens when two things try to connect at once, the phone and Home
   Assistant? Low Energy generally permits one central at a time.

## Findings

### Advertisements

_Nothing recorded yet. Run `tools/scan.py` beside a fan and again far from it._

| Address | Name | Service UUIDs | Manufacturer data | Notes |
| --- | --- | --- | --- | --- |
| | | | | |

### Attribute table

_Nothing recorded yet. Run `tools/enumerate.py <address>`._

| Service UUID | Characteristic UUID | Properties | Guessed role |
| --- | --- | --- | --- |
| | | | |

### Payload framing

_Nothing decoded yet._

### Dead ends

_Record anything ruled out here, with enough detail that nobody repeats it._
