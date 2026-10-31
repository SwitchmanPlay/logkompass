from __future__ import annotations

from logkompass.config import Config
from logkompass.probe import check_log_source


def cowrie_config(path):
    return Config.from_dict({"collect": {"source": "cowrie", "cowrie_json_path": str(path)}}, env={})


def test_cowrie_source_checks_the_json_log_not_auth_log(tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_text('{"eventid": "cowrie.session.connect"}\n')
    check = check_log_source(cowrie_config(log))
    assert check.ok
    assert "cowrie JSON" in check.detail


def test_missing_cowrie_log_fails(tmp_path):
    check = check_log_source(cowrie_config(tmp_path / "nope.json"))
    assert not check.ok
    assert "cowrie" in check.detail
