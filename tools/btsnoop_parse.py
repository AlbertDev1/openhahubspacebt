"""Extract the Bluetooth attribute layer from an Android HCI snoop log.

Wireshark opens these logs natively and is the right tool for exploring one.
This script exists for the other job: comparing captures mechanically. Capture
"fan on" twice and the payloads should differ only in a counter or a nonce.
Finding which bytes those are is what reveals the framing.

    python tools/btsnoop_parse.py captures/fan-on.log
    python tools/btsnoop_parse.py captures/fan-on.log --summary
    python tools/btsnoop_parse.py captures/fan-on.log --handle 0x0012

Standard library only, so it runs anywhere without installing anything.

See docs/capture-guide.md for how to produce the log.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator, NamedTuple

BTSNOOP_MAGIC = b"btsnoop\x00"

# Datalink types we know how to unwrap.
DATALINK_HCI_UNENCAPSULATED = 1001
DATALINK_HCI_UART = 1002  # what Android writes

HCI_ACL_PACKET = 0x02

L2CAP_CID_ATT = 0x0004

# Timestamps are microseconds since 0000-01-01 in the proleptic Gregorian
# calendar. Python's datetime starts at 0001-01-01, so year zero, which is a
# leap year, has to be added back by hand.
_YEAR_ZERO_DAYS = 366
_EPOCH_OFFSET_US = (
    ((datetime(1970, 1, 1) - datetime.min).days + _YEAR_ZERO_DAYS) * 86_400 * 1_000_000
)

ATT_OPCODES = {
    0x01: "error_response",
    0x02: "exchange_mtu_request",
    0x03: "exchange_mtu_response",
    0x04: "find_information_request",
    0x05: "find_information_response",
    0x06: "find_by_type_value_request",
    0x07: "find_by_type_value_response",
    0x08: "read_by_type_request",
    0x09: "read_by_type_response",
    0x0A: "read_request",
    0x0B: "read_response",
    0x0C: "read_blob_request",
    0x0D: "read_blob_response",
    0x0E: "read_multiple_request",
    0x0F: "read_multiple_response",
    0x10: "read_by_group_type_request",
    0x11: "read_by_group_type_response",
    0x12: "write_request",
    0x13: "write_response",
    0x16: "prepare_write_request",
    0x17: "prepare_write_response",
    0x18: "execute_write_request",
    0x19: "execute_write_response",
    0x1B: "notification",
    0x1D: "indication",
    0x1E: "confirmation",
    0x52: "write_command",
    0xD2: "signed_write_command",
}

# The opcodes that actually carry application payload. Everything else is
# discovery and housekeeping.
PAYLOAD_OPCODES = {0x12, 0x52, 0x1B, 0x1D, 0x0B, 0xD2}


class AttPacket(NamedTuple):
    index: int
    timestamp: datetime
    offset: float
    outgoing: bool
    conn_handle: int
    opcode: int
    att_handle: int | None
    value: bytes

    @property
    def opcode_name(self) -> str:
        return ATT_OPCODES.get(self.opcode, f"unknown_0x{self.opcode:02x}")

    @property
    def direction(self) -> str:
        return "phone->device" if self.outgoing else "device->phone"

    def as_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "time": self.timestamp.isoformat(),
            "offset": round(self.offset, 6),
            "direction": self.direction,
            "conn_handle": f"0x{self.conn_handle:04x}",
            "opcode": self.opcode_name,
            "att_handle": f"0x{self.att_handle:04x}"
            if self.att_handle is not None
            else None,
            "length": len(self.value),
            "hex": self.value.hex(" "),
        }


def read_records(path: Path) -> Iterator[tuple[int, datetime, bytes]]:
    """Yield (flags, timestamp, packet_data) for every record in the log."""
    with path.open("rb") as handle:
        header = handle.read(16)
        if len(header) < 16 or header[:8] != BTSNOOP_MAGIC:
            raise ValueError(f"{path} is not a btsnoop file")
        _version, datalink = struct.unpack(">II", header[8:16])
        if datalink not in (DATALINK_HCI_UART, DATALINK_HCI_UNENCAPSULATED):
            raise ValueError(f"unsupported datalink type {datalink}")

        while True:
            record_header = handle.read(24)
            if len(record_header) < 24:
                return
            _original, included, flags, _drops, stamp = struct.unpack(
                ">IIIIq", record_header
            )
            data = handle.read(included)
            if len(data) < included:
                return

            when = datetime(1970, 1, 1) + timedelta(
                microseconds=stamp - _EPOCH_OFFSET_US
            )
            if datalink == DATALINK_HCI_UART:
                if not data:
                    continue
                packet_type, data = data[0], data[1:]
                if packet_type != HCI_ACL_PACKET:
                    continue
            else:
                # Unencapsulated logs mark commands and events in the flags, so
                # anything not flagged as such is ACL data.
                if flags & 0x02:
                    continue
            yield flags, when, data


def parse(path: Path) -> list[AttPacket]:
    """Reassemble fragmented L2CAP frames and pull out attribute packets."""
    # Keyed by (connection handle, direction) because both sides can have a
    # partially received frame at the same time.
    pending: dict[tuple[int, bool], tuple[int, bytearray]] = {}
    packets: list[AttPacket] = []
    first_time: datetime | None = None

    for index, (flags, when, acl) in enumerate(read_records(path)):
        if len(acl) < 4:
            continue
        # btsnoop flag bit 0: 0 means the host sent it, 1 means it received it.
        outgoing = not (flags & 0x01)
        header, _length = struct.unpack("<HH", acl[:4])
        conn_handle = header & 0x0FFF
        pb_flag = (header >> 12) & 0x03
        body = acl[4:]
        key = (conn_handle, outgoing)

        if pb_flag == 0x01:  # continuing fragment
            held = pending.get(key)
            if held is None:
                continue
            expected, buffer = held
            buffer.extend(body)
        else:  # start of a new L2CAP frame
            if len(body) < 4:
                continue
            expected, cid = struct.unpack("<HH", body[:4])
            if cid != L2CAP_CID_ATT:
                pending.pop(key, None)
                continue
            buffer = bytearray(body[4:])

        if len(buffer) < expected:
            pending[key] = (expected, buffer)
            continue

        pending.pop(key, None)
        frame = bytes(buffer[:expected])
        if not frame:
            continue

        opcode = frame[0]
        rest = frame[1:]
        att_handle: int | None = None
        value = rest
        if opcode in PAYLOAD_OPCODES and opcode != 0x0B and len(rest) >= 2:
            att_handle = struct.unpack("<H", rest[:2])[0]
            value = rest[2:]

        if first_time is None:
            first_time = when
        packets.append(
            AttPacket(
                index=index,
                timestamp=when,
                offset=(when - first_time).total_seconds(),
                outgoing=outgoing,
                conn_handle=conn_handle,
                opcode=opcode,
                att_handle=att_handle,
                value=value,
            )
        )

    return packets


def variance_report(packets: list[AttPacket]) -> None:
    """Group identical-shaped payloads and show which byte positions move.

    This is the point of the whole script. Within one group, a byte that never
    changes is structure and a byte that always changes is a counter, a nonce or
    the thing being commanded.
    """
    groups: dict[tuple[str, str, str, int], list[bytes]] = defaultdict(list)
    for packet in packets:
        if packet.opcode not in PAYLOAD_OPCODES or not packet.value:
            continue
        att = f"0x{packet.att_handle:04x}" if packet.att_handle is not None else "-"
        groups[(packet.direction, att, packet.opcode_name, len(packet.value))].append(
            packet.value
        )

    if not groups:
        print("No payload-carrying attribute packets found.")
        return

    for (direction, att, opcode, length), values in sorted(groups.items()):
        print()
        print(f"{direction}  handle {att}  {opcode}  {length} bytes  "
              f"x{len(values)} ({len(set(values))} distinct)")
        print("-" * 76)

        varying = [
            i for i in range(length) if len({v[i] for v in values}) > 1
        ]
        positions = "".join(
            "^" if i in varying else "." for i in range(length)
        )
        for value in sorted(set(values))[:12]:
            print(f"  {value.hex(' ')}")
        if len(set(values)) > 12:
            print(f"  ... {len(set(values)) - 12} more distinct payload(s)")
        print(f"  {' '.join(positions)}")
        if varying:
            print(f"  varying byte offsets: {varying}")
        else:
            print("  every payload identical, so this carries no state")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logfile", type=Path)
    parser.add_argument(
        "--summary",
        action="store_true",
        help="group payloads and show which bytes vary",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="include discovery traffic, not just payload-carrying packets",
    )
    parser.add_argument("--handle", help="only this attribute handle, e.g. 0x0012")
    parser.add_argument("--json", type=Path, help="also write parsed packets here")
    args = parser.parse_args()

    try:
        packets = parse(args.logfile)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not args.all:
        packets = [p for p in packets if p.opcode in PAYLOAD_OPCODES]
    if args.handle:
        wanted = int(args.handle, 16)
        packets = [p for p in packets if p.att_handle == wanted]

    if not packets:
        print("No matching attribute packets. Try --all to see discovery traffic.")
        return 0

    if args.summary:
        variance_report(packets)
    else:
        for packet in packets:
            att = (
                f"0x{packet.att_handle:04x}" if packet.att_handle is not None else "  -   "
            )
            print(
                f"[{packet.offset:9.4f}] {packet.direction:<14} {att} "
                f"{packet.opcode_name:<24} {packet.value.hex(' ')}"
            )
        print()
        print(f"{len(packets)} packet(s)")

    if args.json:
        args.json.write_text(
            json.dumps([p.as_dict() for p in packets], indent=2), encoding="utf-8"
        )
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
