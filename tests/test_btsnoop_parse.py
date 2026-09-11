"""Tests for the capture parser, built on a synthetic log.

Runs under pytest, and also standalone with plain `python` so it can be checked
on the Home Assistant box where pytest may not be installed:

    python tests/test_btsnoop_parse.py
"""

from __future__ import annotations

import struct
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import btsnoop_parse as bsp  # noqa: E402

HCI_ACL = 0x02
CONN_HANDLE = 0x0040

PB_START = 0b10
PB_CONTINUE = 0b01


def acl_fragment(payload: bytes, pb_flag: int) -> bytes:
    """Wrap a payload as one ACL fragment, with the H4 type byte in front."""
    header = CONN_HANDLE | (pb_flag << 12)
    return bytes([HCI_ACL]) + struct.pack("<HH", header, len(payload)) + payload


def l2cap(att: bytes, cid: int = bsp.L2CAP_CID_ATT) -> bytes:
    return struct.pack("<HH", len(att), cid) + att


def record(packet: bytes, *, outgoing: bool, seconds: float) -> bytes:
    # btsnoop flag bit 0 is set on packets the host received.
    flags = 0 if outgoing else 0x01
    stamp = bsp._EPOCH_OFFSET_US + int(seconds * 1_000_000)
    return (
        struct.pack(">IIIIq", len(packet), len(packet), flags, 0, stamp) + packet
    )


def build_log(records: list[bytes]) -> Path:
    body = b"btsnoop\x00" + struct.pack(">II", 1, bsp.DATALINK_HCI_UART)
    body += b"".join(records)
    handle = tempfile.NamedTemporaryFile(suffix=".log", delete=False)
    handle.write(body)
    handle.close()
    return Path(handle.name)


def test_parses_write_and_notification() -> None:
    write = bytes([0x12]) + struct.pack("<H", 0x0012) + b"\x01\x02\x03"
    notify = bytes([0x1B]) + struct.pack("<H", 0x0014) + b"\xaa\xbb"

    path = build_log(
        [
            record(acl_fragment(l2cap(write), PB_START), outgoing=True, seconds=10.0),
            record(acl_fragment(l2cap(notify), PB_START), outgoing=False, seconds=10.5),
        ]
    )
    try:
        packets = bsp.parse(path)
    finally:
        path.unlink()

    assert len(packets) == 2

    first, second = packets
    assert first.opcode_name == "write_request"
    assert first.direction == "phone->device"
    assert first.att_handle == 0x0012
    assert first.value == b"\x01\x02\x03"
    assert first.offset == 0.0

    assert second.opcode_name == "notification"
    assert second.direction == "device->phone"
    assert second.att_handle == 0x0014
    assert second.value == b"\xaa\xbb"
    assert abs(second.offset - 0.5) < 1e-6


def test_reassembles_fragmented_frame() -> None:
    """A payload larger than one ACL fragment must be stitched back together."""
    value = bytes(range(40))
    att = bytes([0x52]) + struct.pack("<H", 0x0020) + value
    frame = l2cap(att)
    split = 16

    path = build_log(
        [
            record(acl_fragment(frame[:split], PB_START), outgoing=True, seconds=1.0),
            record(
                acl_fragment(frame[split:], PB_CONTINUE), outgoing=True, seconds=1.01
            ),
        ]
    )
    try:
        packets = bsp.parse(path)
    finally:
        path.unlink()

    assert len(packets) == 1
    assert packets[0].opcode_name == "write_command"
    assert packets[0].att_handle == 0x0020
    assert packets[0].value == value


def test_ignores_non_attribute_channels() -> None:
    """Signalling on other L2CAP channels must not be mistaken for attributes."""
    signalling = l2cap(b"\x01\x02\x03\x04", cid=0x0005)
    path = build_log(
        [record(acl_fragment(signalling, PB_START), outgoing=True, seconds=1.0)]
    )
    try:
        assert bsp.parse(path) == []
    finally:
        path.unlink()


def test_read_response_has_no_handle() -> None:
    """A read response carries a value but no handle, so it must not eat two bytes."""
    att = bytes([0x0B]) + b"\xde\xad\xbe\xef"
    path = build_log(
        [record(acl_fragment(l2cap(att), PB_START), outgoing=False, seconds=1.0)]
    )
    try:
        packets = bsp.parse(path)
    finally:
        path.unlink()

    assert len(packets) == 1
    assert packets[0].att_handle is None
    assert packets[0].value == b"\xde\xad\xbe\xef"


def test_rejects_a_file_that_is_not_a_capture() -> None:
    handle = tempfile.NamedTemporaryFile(suffix=".log", delete=False)
    handle.write(b"this is not a capture")
    handle.close()
    path = Path(handle.name)
    try:
        raised = False
        try:
            bsp.parse(path)
        except ValueError:
            raised = True
        assert raised, "expected a ValueError for a non-btsnoop file"
    finally:
        path.unlink()


def test_epoch_offset_matches_a_known_timestamp() -> None:
    """Guard the calendar arithmetic, which is easy to get quietly wrong.

    A record stamped exactly at the offset must decode to the Unix epoch.
    """
    att = bytes([0x12]) + struct.pack("<H", 0x0001) + b"\x00"
    path = build_log(
        [record(acl_fragment(l2cap(att), PB_START), outgoing=True, seconds=0.0)]
    )
    try:
        packets = bsp.parse(path)
    finally:
        path.unlink()

    decoded = packets[0].timestamp.replace(tzinfo=timezone.utc)
    assert decoded == datetime(1970, 1, 1, tzinfo=timezone.utc)


def test_variance_report_runs(capsys=None) -> None:
    """The summary view is the tool's whole point, so make sure it works."""
    payloads = [b"\x01\x00\x05", b"\x01\x01\x05", b"\x01\x02\x05"]
    records = [
        record(
            acl_fragment(
                l2cap(bytes([0x12]) + struct.pack("<H", 0x0012) + payload), PB_START
            ),
            outgoing=True,
            seconds=float(i),
        )
        for i, payload in enumerate(payloads)
    ]
    path = build_log(records)
    try:
        packets = bsp.parse(path)
        bsp.variance_report(packets)
    finally:
        path.unlink()

    assert len(packets) == 3
    # Byte 1 is the only one that moves across the three payloads.
    varying = [i for i in range(3) if len({p.value[i] for p in packets}) > 1]
    assert varying == [1]


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failures = 0
    for test in tests:
        try:
            test()
        except AssertionError as exc:
            failures += 1
            print(f"FAIL  {test.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"ERROR {test.__name__}: {type(exc).__name__}: {exc}")
        else:
            print(f"ok    {test.__name__}")
    print()
    print(f"{len(tests) - failures} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
