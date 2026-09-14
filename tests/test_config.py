from __future__ import annotations

import pytest

from logkompass.config import Config, ConfigError, resolve_secret

BASE = {
    "paths": {"db": "/tmp/lk.db"},
    "collect": {"source": "journald", "unit": "ssh"},
    "rules": {"burst_threshold": 30},
    "llm": {
        "providers": [
            {"name": "local", "base_url": "http://127.0.0.1:8081/v1", "model": "qwen3-27b"},
            {
                "name": "openrouter-free",
                "base_url": "https://openrouter.ai/api/v1",
                "model": "free",
                "api_key": "env:OPENROUTER_API_KEY",
            },
        ]
    },
    "notify": {"telegram_token": "env:TG_TOKEN", "chat_id": "env:TG_CHAT"},
    "host": "canary-01",
}
ENV = {"TG_TOKEN": "123:abc", "TG_CHAT": "42", "OPENROUTER_API_KEY": "or-key"}


def test_full_config_loads():
    cfg = Config.from_dict(BASE, env=ENV)
    assert cfg.paths.db == "/tmp/lk.db"
    assert cfg.rules.burst_threshold == 30
    assert cfg.rules.spray_distinct_users == 8  # default survives
    assert cfg.notify.telegram_token == "123:abc"
    assert cfg.host == "canary-01"
    assert len(cfg.available_providers()) == 2


def test_missing_cloud_key_disables_only_that_provider():
    env = dict(ENV)
    env.pop("OPENROUTER_API_KEY")
    cfg = Config.from_dict(BASE, env=env)
    names = [p.name for p in cfg.available_providers()]
    assert names == ["local"]
    assert cfg.providers[1].unavailable_reason == "api key env var not set"


def test_missing_telegram_secret_is_fatal():
    env = dict(ENV)
    env.pop("TG_TOKEN")
    with pytest.raises(ConfigError):
        Config.from_dict(BASE, env=env)


def test_literal_secret_is_refused():
    data = dict(BASE)
    data["notify"] = {"telegram_token": "123:abc", "chat_id": "env:TG_CHAT"}
    with pytest.raises(ConfigError):
        Config.from_dict(data, env=ENV)


def test_typo_in_a_threshold_is_an_error_not_a_silent_default():
    data = dict(BASE)
    data["rules"] = {"burst_treshold": 30}
    with pytest.raises(ConfigError):
        Config.from_dict(data, env=ENV)


def test_unknown_section_is_rejected():
    data = dict(BASE)
    data["nope"] = {}
    with pytest.raises(ConfigError):
        Config.from_dict(data, env=ENV)


def test_invalid_collect_source_is_rejected():
    data = dict(BASE)
    data["collect"] = {"source": "syslog-ng"}
    with pytest.raises(ConfigError):
        Config.from_dict(data, env=ENV)


def test_defaults_apply_to_an_empty_config():
    cfg = Config.from_dict({}, env={})
    assert cfg.collect.source == "journald"
    assert cfg.retention_days == 90
    assert len(cfg.providers) == 1
    assert cfg.quiet_hours == (23, 7)


def test_resolve_secret_requires_the_env_prefix():
    assert resolve_secret("env:A", env={"A": "x"}) == "x"
    with pytest.raises(ConfigError):
        resolve_secret("plain", env={})


def test_toml_file_round_trip(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        "host = \"canary-01\"\n"
        "[paths]\ndb = \"/tmp/x.db\"\n"
        "[[llm.providers]]\n"
        "name = \"local\"\n"
        "base_url = \"http://127.0.0.1:8081/v1\"\n"
        "model = \"qwen3-27b\"\n"
        "extra_body = { chat_template_kwargs = { enable_thinking = false } }\n"
    )
    cfg = Config.load(path, env={})
    assert cfg.providers[0].extra_body == {"chat_template_kwargs": {"enable_thinking": False}}


def test_missing_file_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError):
        Config.load(tmp_path / "nope.toml", env={})
