"""Scan for Bluetooth Low Energy advertisers and summarise what each one sends.

Run this twice: once standing next to the fan, once as far from it as you can
get. The fan is the advertiser whose signal strength collapses between the two
runs. Signal strength is the only reliable way to identify it, because the name
may be generic or absent.

    python tools/scan.py --seconds 30
    python tools/scan.py --seconds 30 --name-filter hub

Output goes to captures/ as JSON.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from collections import defaultdict
from statistics import mean
from typing import Any

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from common import (
    address_kind,
    address_type,
    hexdump,
    looks_interesting,
    save_json,
    setup_logging,
)


class Observation:
    """Everything seen from one advertiser across a scan."""

    def __init__(self, address: str) -> None:
        self.address = address
        self.names: set[str] = set()
        self.rssis: list[int] = []
        self.service_uuids: set[str] = set()
        self.service_data: dict[str, set[bytes]] = defaultdict(set)
        self.manufacturer_data: dict[int, set[bytes]] = defaultdict(set)
        self.tx_power: set[int] = set()
        self.address_type: str | None = None

    def record(self, device: BLEDevice, adv: AdvertisementData) -> None:
        if self.address_type is None:
            self.address_type = address_type(device)
        if adv.local_name:
            self.names.add(adv.local_name)
        if device.name:
            self.names.add(device.name)
        if adv.rssi is not None:
            self.rssis.append(adv.rssi)
        self.service_uuids.update(adv.service_uuids)
        for uuid, data in adv.service_data.items():
            self.service_data[uuid].add(bytes(data))
        for company, data in adv.manufacturer_data.items():
            self.manufacturer_data[company].add(bytes(data))
        if adv.tx_power is not None:
            self.tx_power.add(adv.tx_power)

    @property
    def best_name(self) -> str | None:
        return sorted(self.names)[0] if self.names else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "names": sorted(self.names),
            "address_type": self.address_type or address_kind(self.address),
            "packets": len(self.rssis),
            "rssi": {
                "min": min(self.rssis),
                "max": max(self.rssis),
                "mean": round(mean(self.rssis), 1),
            }
            if self.rssis
            else None,
            "service_uuids": sorted(self.service_uuids),
            # Multiple distinct payloads from one source means the advertisement
            # carries changing state, which is worth investigating on its own.
            "service_data": {
                uuid: [hexdump(v) for v in sorted(vals)]
                for uuid, vals in self.service_data.items()
            },
            "manufacturer_data": {
                f"0x{company:04x}": [hexdump(v) for v in sorted(vals)]
                for company, vals in self.manufacturer_data.items()
            },
            "tx_power": sorted(self.tx_power),
        }


async def scan(seconds: float, name_filter: str | None) -> list[Observation]:
    seen: dict[str, Observation] = {}

    def on_detection(device: BLEDevice, adv: AdvertisementData) -> None:
        obs = seen.get(device.address)
        if obs is None:
            obs = seen[device.address] = Observation(device.address)
            logging.debug("new advertiser %s (%s)", device.address, adv.local_name)
        obs.record(device, adv)

    scanner = BleakScanner(detection_callback=on_detection)
    logging.info("scanning for %.0f seconds", seconds)
    await scanner.start()
    try:
        await asyncio.sleep(seconds)
    finally:
        await scanner.stop()

    results = list(seen.values())
    if name_filter:
        needle = name_filter.lower()
        results = [
            o for o in results if o.best_name and needle in o.best_name.lower()
        ]
    # Strongest signal first: the fan should be near the top when you stand
    # under it.
    results.sort(key=lambda o: mean(o.rssis) if o.rssis else -999, reverse=True)
    return results


def report(results: list[Observation]) -> None:
    if not results:
        logging.warning("nothing found. Is Bluetooth enabled and in range?")
        return

    print()
    print(f"{'address':<20} {'rssi':>6} {'pkts':>5} {'type':<16} name")
    print("-" * 86)
    for obs in results:
        avg = f"{mean(obs.rssis):.0f}" if obs.rssis else "-"
        flag = "*" if looks_interesting(obs.best_name, {
            k: next(iter(v)) for k, v in obs.manufacturer_data.items()
        }) else " "
        kind = obs.address_type or address_kind(obs.address)
        print(
            f"{obs.address:<20} {avg:>6} {len(obs.rssis):>5} {kind:<16}{flag} "
            f"{obs.best_name or '(no name)'}"
        )
    print()
    print("* = worth a closer look. Run tools/enumerate.py against its address.")
    print("A rotating address is a phone or similar and is never the fan.")


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=20.0)
    parser.add_argument("--name-filter", help="only report names containing this")
    parser.add_argument("--label", default="scan", help="tag for the capture file")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)
    results = await scan(args.seconds, args.name_filter)
    report(results)
    save_json(args.label, [o.as_dict() for o in results])


if __name__ == "__main__":
    asyncio.run(main())
