"""Compare two scans and show what changed between them.

The decisive way to identify a mains-powered device is to cut its power and see
which advertiser disappears. Names and manufacturer prefixes are guesswork;
this is proof.

    # fan powered on
    python tools/scan.py --seconds 45 --label powered
    # kill the fan at the wall switch or breaker, wait a minute
    python tools/scan.py --seconds 45 --label unpowered

    python tools/diff_scans.py captures/*-powered.json captures/*-unpowered.json

Anything listed as gone is a device that stopped advertising when the power
went. On a quiet night that should be a very short list.

Addresses that rotate belong to phones and are hidden by default, because they
churn between any two scans and drown out the signal. Pass --all to see them.

Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import address_kind, random_flavour  # noqa: E402

ROTATING = "random-rotating"


def load(path: Path) -> dict[str, dict[str, Any]]:
    entries = json.loads(path.read_text(encoding="utf-8"))
    return {entry["address"]: entry for entry in entries}


def kind_of(entry: dict[str, Any]) -> str:
    """Prefer what the OS reported, and fall back to a flagged guess.

    Only an OS-confirmed random address gets classified as rotating, because
    hiding a device on the strength of a guess could hide the fan itself.
    """
    declared = entry.get("address_type")
    if declared == "public":
        return "public"
    if declared == "random":
        return random_flavour(entry["address"])
    return declared or address_kind(entry["address"])


def describe(entry: dict[str, Any]) -> str:
    names = entry.get("names") or []
    name = names[0] if names else "(no name)"
    rssi = entry.get("rssi") or {}
    mean = rssi.get("mean")
    signal = f"{mean:.0f} dBm" if isinstance(mean, (int, float)) else "?"
    return f"{entry['address']:<20} {signal:>9}  {kind_of(entry):<16} {name}"


def detail(entry: dict[str, Any]) -> list[str]:
    lines = []
    if entry.get("service_uuids"):
        lines.append(f"      services: {', '.join(entry['service_uuids'])}")
    for company, payloads in (entry.get("manufacturer_data") or {}).items():
        lines.append(f"      company {company}: {'; '.join(payloads)}")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path, help="the earlier scan, e.g. powered")
    parser.add_argument("after", type=Path, help="the later scan, e.g. unpowered")
    parser.add_argument(
        "--all",
        action="store_true",
        help="include rotating addresses, which are phones and always churn",
    )
    parser.add_argument(
        "--rssi-shift",
        type=float,
        default=15.0,
        help="flag devices whose signal moved by at least this many dB",
    )
    args = parser.parse_args()

    try:
        before, after = load(args.before), load(args.after)
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    def keep(entry: dict[str, Any]) -> bool:
        return args.all or kind_of(entry) != ROTATING

    gone = [e for a, e in before.items() if a not in after and keep(e)]
    new = [e for a, e in after.items() if a not in before and keep(e)]
    both = [a for a in before if a in after and keep(before[a])]

    hidden = sum(1 for e in before.values() if not keep(e))

    print(f"before: {args.before.name}  ({len(before)} advertisers)")
    print(f"after:  {args.after.name}  ({len(after)} advertisers)")
    if hidden and not args.all:
        print(f"hiding {hidden} rotating address(es); pass --all to include them")

    print()
    print(f"GONE  present before, absent after  ({len(gone)})")
    print("-" * 76)
    if gone:
        for entry in sorted(gone, key=lambda e: e["address"]):
            print(f"  {describe(entry)}")
            for line in detail(entry):
                print(line)
    else:
        print("  nothing")

    print()
    print(f"NEW  absent before, present after  ({len(new)})")
    print("-" * 76)
    if new:
        for entry in sorted(new, key=lambda e: e["address"]):
            print(f"  {describe(entry)}")
    else:
        print("  nothing")

    moved = []
    for address in both:
        old = (before[address].get("rssi") or {}).get("mean")
        now = (after[address].get("rssi") or {}).get("mean")
        if old is None or now is None:
            continue
        if abs(now - old) >= args.rssi_shift:
            moved.append((address, old, now))

    print()
    print(f"MOVED  signal shifted by {args.rssi_shift:.0f} dB or more  ({len(moved)})")
    print("-" * 76)
    if moved:
        for address, old, now in sorted(moved, key=lambda m: -abs(m[2] - m[1])):
            names = before[address].get("names") or []
            label = names[0] if names else "(no name)"
            print(f"  {address:<20} {old:>6.0f} -> {now:<6.0f} dBm   {label}")
    else:
        print("  nothing")

    print()
    if len(gone) == 1:
        print("One device disappeared. That is almost certainly your fan.")
        print(f"Run: python tools/enumerate.py {gone[0]['address']}")
    elif gone:
        print("Several disappeared. Repeat the test to see which drops out every")
        print("time; the others are devices that happened to go quiet.")
    else:
        print("Nothing disappeared. Either the power did not actually drop, or the")
        print("fan keeps advertising on standby power. Try a longer scan.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
