from __future__ import annotations

import json

from helpers import make_event

from logkompass.cli import main
from logkompass.store import Store

CONFIG = (
    'host = "canary-01"\n'
    "[paths]\n"
    'db = "{db}"\n'
    "[collect]\n"
    'source = "authlog"\n'
    'authlog_path = "{log}"\n'
    "[[llm.providers]]\n"
    'name = "local"\n'
    'base_url = "http://127.0.0.1:8081/v1"\n'
    'model = "qwen3-27b"\n'
)


def setup_workspace(tmp_path, seed=True):
    db = tmp_path / "lk.db"
    log = tmp_path / "auth.log"
    log.write_text(
        "Sep 20 10:00:01 canary-01 sshd[1]: Failed password for root from "
        "198.51.100.7 port 41022 ssh2\n"
    )
    config = tmp_path / "config.toml"
    config.write_text(CONFIG.format(db=db, log=log))
    if seed:
        store = Store.open(str(db))
        store.insert_events(
            [make_event(ts="2026-09-20T10:00:00Z") for _ in range(3)],
            geo=lambda ip: ("NL", 1, "Example Hosting"),
        )
        store.close()
    return config, db


def test_stats_runs_on_a_seeded_database(tmp_path, capsys):
    config, _ = setup_workspace(tmp_path)
    assert main(["--config", str(config), "stats"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["events"] == 3
    assert payload["parse_rate"] == 1.0


def test_collect_then_rules_then_aggregate(tmp_path, capsys):
    config, _ = setup_workspace(tmp_path, seed=False)
    assert main(["--config", str(config), "collect"]) == 0
    assert json.loads(capsys.readouterr().out)["inserted"] == 1

    assert main(["--config", str(config), "rules", "--since", "36500d"]) == 0
    rules_out = json.loads(capsys.readouterr().out)
    assert rules_out["events"] == 1
    assert any(f["rule_id"] == "R03_high_value_user" for f in rules_out["findings"])

    out = tmp_path / "agg.json"
    assert main(
        ["--config", str(config), "aggregate", "--day", "today", "--out", str(out)]
    ) == 0
    assert json.loads(out.read_text())["host"] == "canary-01"


def test_digest_from_a_file_without_a_database(tmp_path, capsys):
    config, _ = setup_workspace(tmp_path)
    agg = tmp_path / "agg.json"
    assert main(
        ["--config", str(config), "aggregate", "--day", "2026-09-20", "--out", str(agg)]
    ) == 0
    assert main(
        [
            "--config", str(config), "digest", "--input", str(agg),
            "--no-model", "--notify", "stdout", "--mask",
        ]
    ) == 0
    text = capsys.readouterr().out
    assert "LogKompass canary-01, 2026-09-20" in text
    assert "198.51.100.x" in text


def test_prune_reports_what_it_deleted(tmp_path, capsys):
    config, _ = setup_workspace(tmp_path)
    assert main(["--config", str(config), "prune", "--days", "1"]) == 0
    assert "cutoff" in json.loads(capsys.readouterr().out)


def test_probe_returns_nonzero_when_something_is_broken(tmp_path):
    config, _ = setup_workspace(tmp_path)
    assert main(["--config", str(config), "probe", "--skip-model"]) in (0, 1)


def test_missing_config_is_reported_as_exit_code_two(tmp_path):
    assert main(["--config", str(tmp_path / "nope.toml"), "stats"]) == 2
