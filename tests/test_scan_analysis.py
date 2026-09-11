"""Tests for address classification and the scan comparison tool.

Runs under pytest, and standalone with plain `python`:

    python tests/test_scan_analysis.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import common  # noqa: E402


def test_only_one_bit_pattern_is_conclusive() -> None:
    # 0b10 leading bits cannot occur in a random address, so this one is certain.
    assert common.address_kind("8C:26:AA:F0:01:C3") == "public"

    # Everything else is a guess, and must be marked as one. CC:DB:A7 is a
    # registered Espressif prefix whose bits nonetheless look random.
    assert common.address_kind("CC:DB:A7:2E:B8:72") == "static?"
    assert common.address_kind("52:BB:03:B0:53:BA") == "rotating?"
    assert common.address_kind("0A:26:0A:A8:06:00") == "rotating?"
    assert common.address_kind("nonsense") == "unknown"


def test_random_flavour_splits_static_from_rotating() -> None:
    assert common.random_flavour("CC:DB:A7:2E:B8:72") == "random-static"
    assert common.random_flavour("52:BB:03:B0:53:BA") == "random-rotating"


def test_common_imports_without_a_radio() -> None:
    """diff_scans depends on this, so keep bleak out of module scope."""
    source = (ROOT / "tools" / "common.py").read_text(encoding="utf-8")
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith(("import bleak", "from bleak")):
            assert line.startswith("    "), f"bleak imported at module scope: {line}"


def entry(address: str, rssi: float, *, name: str = "", kind: str = "public") -> dict:
    return {
        "address": address,
        "names": [name] if name else [],
        "address_type": kind,
        "packets": 50,
        "rssi": {"min": rssi - 2, "max": rssi + 2, "mean": rssi},
        "service_uuids": [],
        "service_data": {},
        "manufacturer_data": {},
        "tx_power": [],
    }


def write(entries: list[dict]) -> Path:
    handle = tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False)
    json.dump(entries, handle)
    handle.close()
    return Path(handle.name)


def run_diff(before: Path, after: Path, *extra: str) -> str:
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "diff_scans.py"),
         str(before), str(after), *extra],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_diff_names_the_device_that_vanished() -> None:
    fan = entry("CC:DB:A7:2E:B8:72", -81.0, kind="public")
    lamp = entry("BE:59:B6:00:01:0B", -40.0, name="ELK-BLEDOM")

    before = write([fan, lamp])
    after = write([lamp])
    try:
        out = run_diff(before, after)
    finally:
        before.unlink()
        after.unlink()

    assert "CC:DB:A7:2E:B8:72" in out
    assert "almost certainly your fan" in out
    assert "tools/enumerate.py CC:DB:A7:2E:B8:72" in out


def test_diff_hides_confirmed_rotating_addresses_only() -> None:
    """A phone that churns is noise. A guess must not be treated as confirmed."""
    phone = entry("52:BB:03:B0:53:BA", -60.0, kind="random")
    guessed = entry("6F:26:EB:32:8F:C0", -62.0, kind="")
    keeper = entry("BE:59:B6:00:01:0B", -40.0, name="ELK-BLEDOM")

    before = write([phone, guessed, keeper])
    after = write([keeper])
    try:
        out = run_diff(before, after)
    finally:
        before.unlink()
        after.unlink()

    # The phone is confirmed random and rotating, so it is suppressed.
    assert "52:BB:03:B0:53:BA" not in out
    # The unconfirmed one only *looks* rotating, so it must still be reported.
    assert "6F:26:EB:32:8F:C0" in out


def test_diff_reports_a_large_signal_shift() -> None:
    before = write([entry("AA:BB:CC:DD:EE:FF", -45.0, name="thing")])
    after = write([entry("AA:BB:CC:DD:EE:FF", -78.0, name="thing")])
    try:
        out = run_diff(before, after)
    finally:
        before.unlink()
        after.unlink()

    assert "MOVED" in out
    assert "-45" in out and "-78" in out


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
