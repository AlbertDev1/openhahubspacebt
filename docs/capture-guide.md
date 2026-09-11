# Capturing Bluetooth traffic from the Hubspace app

Android records every Bluetooth packet the phone sends or receives, with no
extra hardware. This is the highest-value evidence the project can gather.

Because these fans work with the internet disconnected, captures taken offline
are unusually clean. There is no cloud chatter mixed in, so close to every
packet is the protocol being studied.

## Turning the log on

1. Settings, About phone, tap Build number seven times to unlock Developer
   options.
2. Settings, System, Developer options, enable **Enable Bluetooth HCI snoop
   log**.
3. Toggle Bluetooth off and on. On many builds the log only starts on a fresh
   Bluetooth stack.

The log is written to a path that varies by manufacturer. Common ones:

```
/sdcard/Android/data/btsnoop_hci.log
/data/misc/bluetooth/logs/btsnoop_hci.log
/sdcard/btsnoop_hci.log
```

## Getting the log off the phone

The reliable route on a phone without root is a bug report, which bundles the
snoop log and needs no special access:

1. Developer options, **Bug report**, choose Full report.
2. Wait for the notification, then share it to yourself.
3. Unzip it. The log is under `FS/data/misc/bluetooth/logs/`.

With `adb` available:

```sh
adb bugreport bugreport.zip
# or, if the path is readable directly
adb pull /sdcard/btsnoop_hci.log
```

## What to capture

Take each of these as its own separate log, clearing the log between runs by
toggling Bluetooth off and on. Small, isolated captures are far more useful than
one long one.

| Capture | Why it matters |
| --- | --- |
| Adding a fan from scratch | Where key material is exchanged. Worth factory resetting one fan to get it. |
| App startup while offline | Shows the session handshake with no cloud involved. |
| Fan on, nothing else | The simplest possible command. |
| Fan on a second time | Compared against the first, this reveals counters and nonces. |
| Fan off | Should differ from "on" in very few bytes. |
| One speed step | Isolates the speed field. |
| Light on, light off | Separates the light from the fan. |
| Idle for two minutes, no interaction | Exposes heartbeats and polling. |

Keep a note of the wall-clock time of each button press. Matching a press to a
packet is much easier with a timestamp than by guesswork.

**Airplane mode on the phone, with Bluetooth switched back on.** Otherwise
cellular carries traffic to the cloud and the capture is no longer offline.

## Reading a capture

Wireshark opens these files natively and is the right tool for exploring one.
Filter with `btatt` to see just the attribute layer.

For comparing captures, use the script in this repository:

```sh
# every payload-carrying packet, in order
python tools/btsnoop_parse.py captures/fan-on.log

# group by handle and show which byte positions change
python tools/btsnoop_parse.py captures/fan-on.log --summary

# narrow to one attribute handle once you know which one matters
python tools/btsnoop_parse.py captures/fan-on.log --handle 0x0012
```

The summary view is the one that matters. Capture "fan on" twice, and if the two
payloads differ only in a byte or two, those bytes are a counter and the rest is
readable structure. If they share nothing at all, the payload is encrypted and
the project moves to hunting for the key.

## Handle with care

These logs contain account identifiers, device identifiers and possibly key
material. `captures/` is in `.gitignore` for that reason. Sanitise anything
before putting it in `tests/fixtures/` or pasting it into an issue.
