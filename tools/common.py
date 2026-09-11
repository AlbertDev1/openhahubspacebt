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
