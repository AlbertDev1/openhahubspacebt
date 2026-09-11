"""Print the full detail of a saved scan, including advertisement payloads.

The scan table shows only what fits on a line. This shows everything, which is
where identification actually happens: a manufacturer payload begins with a
registered company identifier, and a service identifier is often unique to one
product family.

    python tools/show_scan.py captures/20260911-161516-powered.json
    python tools/show_scan.py captures/*.json --address CC:DB:A7:2E:B8:72
    python tools/show_scan.py captures/*.json --with-payload

Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Bluetooth SIG company identifiers seen so far, or likely to turn up here.
# The full registry is large; this covers enough to recognise the usual suspects
# and anything unlisted is printed raw for looking up.
COMPANY_IDS = {
    0x0006: "Microsoft",
    0x004C: "Apple",
    0x0075: "Samsung",
    0x00E0: "Google",
    0x0087: "Garmin",
    0x0157: "Anhui Huami",
    0x02E5: "Espressif",
    0x0499: "Ruuvi",
    0x059B: "Nordic Semiconductor",
}


def company_name(raw: str) -> str:
    try:
        value = int(raw, 16)
    except ValueError:
        return "unparseable"
    return COMPANY_IDS.get(value, "not in local table, look up this id")


def show(entry: dict[str, Any]) -> None:
    names = entry.get("names") or []
    rssi = entry.get("rssi") or {}
    print(f"{entry['address']}   {names[0] if names else '(no name)'}")
    if len(names) > 1:
        print(f"  all names:     {', '.join(names)}")
    print(f"  address type:  {entry.get('address_type', 'unrecorded')}")
    mean = rssi.get("mean")
    if mean is not None:
        print(
            f"  signal:        {mean} dBm mean, "
            f"{rssi.get('min')} to {rssi.get('max')}, "
            f"{entry.get('packets')} packets"
        )
    if entry.get("tx_power"):
        print(f"  tx power:      {entry['tx_power']}")

    services = entry.get("service_uuids") or []
    print(f"  services:      {', '.join(services) if services else 'none advertised'}")

    service_data = entry.get("service_data") or {}
    if service_data:
        print("  service data:")
        for uuid, payloads in service_data.items():
            print(f"    {uuid}")
            for payload in payloads:
                print(f"      {payload}")

    mfr = entry.get("manufacturer_data") or {}
    if mfr:
        print("  manufacturer data:")
        for company, payloads in mfr.items():
            print(f"    company {company}  ({company_name(company)})")
            for payload in payloads:
                print(f"      {payload}")
    else:
        print("  manufacturer data: none")
    print()


def has_payload(entry: dict[str, Any]) -> bool:
    return bool(entry.get("service_uuids") or entry.get("manufacturer_data")
                or entry.get("service_data"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", type=Path, nargs="+", help="scan JSON files")
    parser.add_argument(
        "--address",
        action="append",
        help="only this address; repeatable",
    )
    parser.add_argument(
        "--with-payload",
        action="store_true",
        help="only devices that advertise a service or manufacturer payload",
    )
    args = parser.parse_args()

    wanted = {a.upper() for a in args.address} if args.address else None
    total = 0

    for path in args.captures:
        try:
            entries = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error reading {path}: {exc}", file=sys.stderr)
            continue

        selected = [
            e
            for e in entries
            if (wanted is None or e["address"].upper() in wanted)
            and (not args.with_payload or has_payload(e))
        ]
        print("=" * 76)
        print(f"{path.name}   {len(selected)} of {len(entries)} shown")
        print("=" * 76)
        for entry in selected:
            show(entry)
        total += len(selected)

    if total == 0:
        print("Nothing matched. Drop --address or --with-payload to widen it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
