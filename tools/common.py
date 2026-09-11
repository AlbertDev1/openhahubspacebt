"""Shared helpers for the recon tools.

Every tool writes its output under captures/ with a timestamped name so repeated
runs can be diffed against each other rather than overwriting evidence.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
CAPTURES_DIR = REPO_ROOT / "captures"

# Substrings that suggest an advertiser is worth a closer look. Afero does not
# publish its identifiers, so this is a starting hint and not a filter.
NAME_HINTS = ("hubspace", "afero", "asr", "fan", "hd-", "hb-")


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )
    # bleak's backend chatter drowns out our own output at debug level.
    logging.getLogger("bleak.backends").setLevel(logging.INFO)


def capture_path(stem: str, suffix: str = ".json") -> Path:
    """Return a timestamped path under captures/, creating the directory."""
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return CAPTURES_DIR / f"{stamp}-{stem}{suffix}"


def save_json(stem: str, payload: Any) -> Path:
    path = capture_path(stem)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    logging.info("wrote %s", path)
    return path


def hexdump(data: bytes) -> str:
    """Space-separated hex, which diffs far better than a solid run of digits."""
    return " ".join(f"{b:02x}" for b in data)


def printable(data: bytes) -> str:
    """ASCII rendering with non-printables as dots, for spotting embedded text."""
    return "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in data)


def looks_interesting(name: str | None, manufacturer_data: dict[int, bytes]) -> bool:
    """Rough triage for the scan output. Deliberately loose."""
    if name and any(hint in name.lower() for hint in NAME_HINTS):
        return True
    # A device advertising a lot of manufacturer payload is doing something
    # custom, which is what we are hunting for.
    return any(len(v) >= 8 for v in manufacturer_data.values())


# --- address types ----------------------------------------------------------
#
# Separating fixed devices from phones is most of the triage. Phones use
# resolvable private addresses that rotate every few minutes, so an address
# that survives two scans an hour apart belongs to something that stays put.


def address_type(device: object) -> str | None:
    """Ask the OS for the address type. BlueZ knows; other backends may not."""
    details = getattr(device, "details", None)
    if isinstance(details, dict):
        props = details.get("props")
        if isinstance(props, dict):
            value = props.get("AddressType")
            if isinstance(value, str):
                return value
    return None


def top_bits(address: str) -> int | None:
    """The two most significant bits of an address, which type a random one."""
    try:
        return int(address.split(":")[0], 16) >> 6
    except (ValueError, IndexError):
        return None


def random_flavour(address: str) -> str:
    """Which sort of random address this is. Only valid once you know it is one.

    BlueZ reports an address as "random" without saying which kind, and the top
    bits answer that reliably for an address already known to be random.
    """
    return "random-static" if top_bits(address) == 0b11 else "random-rotating"


def address_kind(address: str) -> str:
    """Guess the address type from its bits, for when the OS will not say.

    Only one pattern is conclusive. A public address carries no type bits at
    all, so it can begin with anything, and a guess of "static?" or "rotating?"
    may really be a public address. Espressif's CC:DB:A7 prefix is exactly that
    trap: the bits say random, the registry says Espressif.

    Prefer address_type(), which asks the operating system, wherever possible.
    """
    top = top_bits(address)
    if top is None:
        return "unknown"
    if top == 0b10:
        return "public"          # no random address can start with these bits
    if top == 0b11:
        return "static?"         # random-static, or a public address
    return "rotating?"           # resolvable or not, or a public address


# --- connecting -------------------------------------------------------------
#
# BlueZ will not connect to a bare address it does not currently know about,
# because it needs the address type that only discovery can tell it. Scanning
# for the device first and connecting to the object that comes back avoids a
# timeout that otherwise looks like the device being out of range.

import asyncio  # noqa: E402
from contextlib import asynccontextmanager  # noqa: E402
from typing import TYPE_CHECKING, AsyncIterator, Callable  # noqa: E402

# bleak is imported where it is used, so that the helpers above stay usable
# from tools that need no radio, such as diff_scans.py.
if TYPE_CHECKING:
    from bleak import BleakClient
    from bleak.backends.device import BLEDevice


class DeviceNotFound(Exception):
    """The address never appeared during discovery."""


class ConnectFailed(Exception):
    """The device was found but would not accept a connection."""


async def resolve_device(address: str, timeout: float = 15.0) -> "BLEDevice":
    from bleak import BleakScanner

    logging.info("looking for %s (up to %.0fs)", address, timeout)
    device = await BleakScanner.find_device_by_address(address, timeout=timeout)
    if device is None:
        raise DeviceNotFound(
            f"{address} did not appear in {timeout:.0f}s of scanning. It may be "
            "out of range, asleep, or already connected to something else."
        )
    logging.info("found %s (%s)", address, device.name or "no name")
    return device


@asynccontextmanager
async def connected(
    address: str,
    *,
    scan_timeout: float = 15.0,
    connect_timeout: float = 30.0,
    retries: int = 3,
    disconnected_callback: Callable[["BleakClient"], None] | None = None,
) -> AsyncIterator["BleakClient"]:
    """Connect to a device, retrying, and always disconnect on the way out."""
    from bleak import BleakClient

    device = await resolve_device(address, scan_timeout)

    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        client = BleakClient(
            device,
            timeout=connect_timeout,
            disconnected_callback=disconnected_callback,
        )
        try:
            await client.connect()
        except Exception as exc:  # noqa: BLE001 - retry regardless of cause
            last_error = exc
            logging.warning(
                "connect attempt %d/%d failed: %s: %s",
                attempt,
                retries,
                type(exc).__name__,
                exc or "timed out",
            )
            if attempt < retries:
                await asyncio.sleep(2.0)
            continue

        logging.info("connected to %s", address)
        try:
            yield client
        finally:
            try:
                await client.disconnect()
            except Exception:  # noqa: BLE001 - already going away
                pass
        return

    raise ConnectFailed(
        f"could not connect to {address} after {retries} attempts. The device "
        "advertises but refuses connections, which usually means it is already "
        "connected to a phone, or the signal is too weak to hold a link."
    ) from last_error
