#!/usr/bin/env python3
"""Regenerate tests/fixtures/golden_digest.txt from the fixed sample aggregate.

Run this after deliberately changing the template digest wording:
    python tools/regen_golden.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

from helpers import sample_aggregate  # noqa: E402

from logkompass.digest import format_message, make_digest  # noqa: E402


def main() -> int:
    result = make_digest(sample_aggregate(), client=None)
    target = ROOT / "tests" / "fixtures" / "golden_digest.txt"
    target.write_text(format_message(result) + "\n")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
