"""Subscribe to every notifying characteristic and log what the device sends.

Connect this, then operate the fan from the Hubspace app or the wall switch and
watch what arrives. Anything that changes when the fan changes is state, and
anything that arrives unprompted on a timer is a heartbeat.

    python tools/listen.py AA:BB:CC:DD:EE:FF --seconds 120

Bluetooth Low Energy usually allows a single connection at a time, so this tool
and the phone app will compete for the fan. If the device keeps dropping, close
the app first.

Output is JSON lines under captures/, one object per notification.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import time
from typing import Any

from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic

from common import (
    ConnectFailed,
    DeviceNotFound,
    capture_path,
    connected,
    hexdump,
    printable,
    setup_logging,
)


async def listen(
    address: str,
    seconds: float | None,
    *,
    scan_timeout: float = 20.0,
    connect_timeout: float = 30.0,
    retries: int = 3,
) -> None:
    path = capture_path("notifications", ".jsonl")
    started = time.time()
    count = 0
    disconnected = asyncio.Event()

    def on_disconnect(_client: BleakClient) -> None:
        logging.warning("device disconnected")
        disconnected.set()

    with path.open("w", encoding="utf-8") as sink:

        def on_notify(char: BleakGATTCharacteristic, data: bytearray) -> None:
            nonlocal count
            count += 1
            payload = bytes(data)
            offset = time.time() - started
            record: dict[str, Any] = {
                "offset": round(offset, 4),
                "handle": char.handle,
                "uuid": char.uuid,
                "length": len(payload),
                "hex": hexdump(payload),
                "ascii": printable(payload),
            }
            sink.write(json.dumps(record) + "\n")
            sink.flush()
            print(
                f"[{offset:8.3f}] h{char.handle:<4} {len(payload):>3}B  "
                f"{hexdump(payload)}"
            )

        async with connected(
            address,
            scan_timeout=scan_timeout,
            connect_timeout=connect_timeout,
            retries=retries,
            disconnected_callback=on_disconnect,
        ) as client:
            subscribed = []
            for service in client.services:
                for char in service.characteristics:
                    if not {"notify", "indicate"} & set(char.properties):
                        continue
                    try:
                        await client.start_notify(char, on_notify)
                    except Exception as exc:  # noqa: BLE001
                        logging.warning("cannot subscribe to %s: %s", char.uuid, exc)
                        continue
                    subscribed.append(char.uuid)

            if not subscribed:
                logging.error("no notifying characteristics, nothing to listen to")
                return

            logging.info("subscribed to %d characteristic(s)", len(subscribed))
            for uuid in subscribed:
                logging.info("  %s", uuid)
            logging.info("operate the fan now. Ctrl-C to stop.")

            try:
                if seconds is None:
                    await disconnected.wait()
                else:
                    await asyncio.wait_for(disconnected.wait(), timeout=seconds)
            except asyncio.TimeoutError:
                pass
            except KeyboardInterrupt:
                pass

    logging.info("captured %d notification(s) to %s", count, path)


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address", help="device address from tools/scan.py")
    parser.add_argument(
        "--seconds",
        type=float,
        default=120.0,
        help="how long to listen, or 0 to run until disconnected",
    )
    parser.add_argument("--scan-timeout", type=float, default=20.0)
    parser.add_argument("--connect-timeout", type=float, default=30.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)
    try:
        await listen(
            args.address,
            args.seconds or None,
            scan_timeout=args.scan_timeout,
            connect_timeout=args.connect_timeout,
            retries=args.retries,
        )
    except (DeviceNotFound, ConnectFailed) as exc:
        logging.error("%s", exc)
        raise SystemExit(1) from None


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print()
