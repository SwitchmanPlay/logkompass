"""tools/reparse.py replays stored sshd lines through the current parser."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from helpers import make_event

from logkompass.store import Store

_SPEC = importlib.util.spec_from_file_location(
    "reparse", Path(__file__).resolve().parents[1] / "tools" / "reparse.py"
)
reparse_tool = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(reparse_tool)


def _seed(path: Path) -> None:
    store = Store.open(path)
    store.insert_events(
        [
            make_event(kind="other", raw="Started OpenSSH server daemon.", ip=None, username=None),
            make_event(
                kind="other",
                raw="Connection reset by authenticating user root 62.60.130.0 port 62114 [preauth]",
                ip=None,
                username=None,
            ),
            make_event(kind="cowrie_command", raw='{"eventid": "cowrie.command.input"}'),
        ]
    )
    store.close()


def test_dry_run_reports_without_writing(tmp_path):
    db = tmp_path / "lk.db"
    _seed(db)
    result = reparse_tool.reparse(str(db), only_other=True, dry_run=True)
    assert result["changed"] == 2
    assert result["kinds"]["other"] == 2


def test_rewrites_other_rows_and_never_touches_cowrie(tmp_path):
    db = tmp_path / "lk.db"
    _seed(db)
    result = reparse_tool.reparse(str(db), only_other=False, dry_run=False)
    assert result["moves"] == {"other -> ignored": 1, "other -> preauth_disconnect": 1}
    assert result["kinds"] == {"ignored": 1, "preauth_disconnect": 1, "cowrie_command": 1}
