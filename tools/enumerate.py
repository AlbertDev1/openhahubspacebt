"""Connect to one device and dump its entire attribute table.

This is the single most informative thing you can do to an unknown Bluetooth
device. What we are hunting for is a vendor-specific service holding a small
number of characteristics, typically one that accepts writes and one that sends
notifications. That pair is the command pipe.

    python tools/enumerate.py AA:BB:CC:DD:EE:FF
    python tools/enumerate.py AA:BB:CC:DD:EE:FF --no-read

Reading every characteristic occasionally upsets a device badly enough to drop
the link. If that happens, re-run with --no-read to get the structure alone.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from typing import Any

from bleak import BleakClient
from bleak.uuids import uuidstr_to_str

from common import (
    ConnectFailed,
    DeviceNotFound,
    connected,
    hexdump,
    printable,
    save_json,
    setup_logging,
)

# Characteristics whose contents are identifying rather than interesting. We
# still read them, because model and firmware strings pin down the hardware.
DEVICE_INFO_SERVICE = "0000180a-0000-1000-8000-00805f9b34fb"


def is_vendor_uuid(uuid: str) -> bool:
    """True for anything outside the Bluetooth SIG's assigned 16-bit range.

    SIG UUIDs all share the 0000xxxx-0000-1000-8000-00805f9b34fb base. A UUID
    that does not is one the manufacturer invented, and that is where custom
    protocols live.
    """
    return not uuid.lower().endswith("-0000-1000-8000-00805f9b34fb")


async def read_value(client: BleakClient, char: Any) -> dict[str, Any] | None:
    if "read" not in char.properties:
        return None
    try:
        data = bytes(await client.read_gatt_char(char))
    except Exception as exc:  # noqa: BLE001 - any failure here is just "no value"
        return {"error": str(exc)}
    return {"hex": hexdump(data), "ascii": printable(data), "length": len(data)}


async def dump(
    address: str,
    do_read: bool,
    *,
    scan_timeout: float,
    connect_timeout: float,
    retries: int,
) -> dict[str, Any]:
    async with connected(
        address,
        scan_timeout=scan_timeout,
        connect_timeout=connect_timeout,
        retries=retries,
    ) as client:
        logging.info("connected, mtu=%s", getattr(client, "mtu_size", "unknown"))
        services: list[dict[str, Any]] = []

        for service in client.services:
            entry: dict[str, Any] = {
                "uuid": service.uuid,
                "handle": service.handle,
                "description": uuidstr_to_str(service.uuid),
                "vendor_specific": is_vendor_uuid(service.uuid),
                "characteristics": [],
            }
            for char in service.characteristics:
                char_entry: dict[str, Any] = {
                    "uuid": char.uuid,
                    "handle": char.handle,
                    "description": uuidstr_to_str(char.uuid),
                    "properties": sorted(char.properties),
                    "vendor_specific": is_vendor_uuid(char.uuid),
                    "descriptors": [
                        {
                            "uuid": d.uuid,
                            "handle": d.handle,
                            "description": uuidstr_to_str(d.uuid),
                        }
                        for d in char.descriptors
                    ],
                }
                if do_read:
                    value = await read_value(client, char)
                    if value is not None:
                        char_entry["value"] = value
                entry["characteristics"].append(char_entry)
            services.append(entry)

        return {
            "address": address,
            "mtu": getattr(client, "mtu_size", None),
            "services": services,
        }


def report(dumped: dict[str, Any]) -> None:
    print()
    for service in dumped["services"]:
        marker = "VENDOR" if service["vendor_specific"] else "      "
        label = service["description"] or "unknown service"
        print(f"{marker}  {service['uuid']}  {label}")
        for char in service["characteristics"]:
            props = ",".join(char["properties"])
            print(f"          {char['uuid']}  [{props}]")
            value = char.get("value")
            if value and "hex" in value:
                print(f"              = {value['hex']}   |{value['ascii']}|")
            elif value:
                print(f"              ! {value['error']}")
        print()

    vendor = [s for s in dumped["services"] if s["vendor_specific"]]
    if vendor:
        print(f"{len(vendor)} vendor-specific service(s) found. These are the target.")
        for service in vendor:
            writable = [
                c["uuid"]
                for c in service["characteristics"]
                if {"write", "write-without-response"} & set(c["properties"])
            ]
            notifying = [
                c["uuid"]
                for c in service["characteristics"]
                if {"notify", "indicate"} & set(c["properties"])
            ]
            print(f"  {service['uuid']}")
            print(f"    accepts writes:  {', '.join(writable) or 'none'}")
            print(f"    sends notifies:  {', '.join(notifying) or 'none'}")
    else:
        print("No vendor-specific services. If this is the fan, the protocol may")
        print("hide behind a standard-looking UUID, so check the capture instead.")


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address", help="device address from tools/scan.py")
    parser.add_argument(
        "--no-read",
        action="store_true",
        help="skip reading values, just map the structure",
    )
    parser.add_argument(
        "--scan-timeout",
        type=float,
        default=20.0,
        help="how long to look for the device before giving up",
    )
    parser.add_argument("--connect-timeout", type=float, default=30.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)
    try:
        dumped = await dump(
            args.address,
            do_read=not args.no_read,
            scan_timeout=args.scan_timeout,
            connect_timeout=args.connect_timeout,
            retries=args.retries,
        )
    except (DeviceNotFound, ConnectFailed) as exc:
        logging.error("%s", exc)
        raise SystemExit(1) from None
    report(dumped)
    save_json(f"gatt-{args.address.replace(':', '')}", dumped)


if __name__ == "__main__":
    asyncio.run(main())
