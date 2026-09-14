from __future__ import annotations

import sys


def send(text: str, stream=None) -> dict:
    handle = stream or sys.stdout
    handle.write(text.rstrip() + "\n")
    return {"ok": True, "sink": "stdout", "chunks": 1}
