import pytest
from pydantic import ValidationError

from src.config_errors import load_settings_or_exit
from src.settings import Settings

from tests.conftest import TEST_SECRET


def _factory():
    # A factory for load_settings_or_exit that never reads the on-disk .env, so
    # each test depends only on the env vars it sets.
    return Settings(_env_file=None)


def _set_valid(monkeypatch):
    monkeypatch.setenv("FASTMAIL_API_TOKEN", "tok")
    monkeypatch.setenv("MAIL2RSS_SECRET", TEST_SECRET)
    monkeypatch.setenv("BASE_URL", "https://rss.example.com")


def test_loads_from_env(monkeypatch):
    _set_valid(monkeypatch)
    s = Settings(_env_file=None)
    assert s.fastmail_api_token == "tok"
    assert s.mail2rss_secret == TEST_SECRET
    assert s.base_url == "https://rss.example.com"
    # Defaults for third-party API and tuning knobs.
    assert s.jmap_session_url == "https://api.fastmail.com/jmap/session"
    assert s.cache_ttl == 600
    assert s.max_limit == 100


def test_missing_credentials_exit_naming_each_var(capsys, monkeypatch):
    for var in ("FASTMAIL_API_TOKEN", "MAIL2RSS_SECRET", "BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(SystemExit) as ei:
        load_settings_or_exit(_factory)
    assert ei.value.code == 1
    err = capsys.readouterr().err
    # Each missing variable is named; no pydantic traceback leaks through.
    assert "FASTMAIL_API_TOKEN" in err
    assert "MAIL2RSS_SECRET" in err
    assert "BASE_URL" in err
    assert "Traceback" not in err


def test_weak_secret_refuses_to_start(capsys, monkeypatch):
    monkeypatch.setenv("FASTMAIL_API_TOKEN", "tok")
    monkeypatch.setenv("BASE_URL", "https://rss.example.com")
    monkeypatch.setenv("MAIL2RSS_SECRET", "hunter2")
    with pytest.raises(SystemExit) as ei:
        load_settings_or_exit(_factory)
    assert ei.value.code == 1
    err = capsys.readouterr().err
    assert "MAIL2RSS_SECRET" in err
    assert "Invalid" in err
    # The rejected secret value is NEVER echoed back into the message.
    assert "hunter2" not in err


def test_weak_secret_raises_validation_error(monkeypatch):
    monkeypatch.setenv("FASTMAIL_API_TOKEN", "tok")
    monkeypatch.setenv("BASE_URL", "https://rss.example.com")
    monkeypatch.setenv("MAIL2RSS_SECRET", "hunter2")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_base_url_trailing_slash_stripped(monkeypatch):
    _set_valid(monkeypatch)
    monkeypatch.setenv("BASE_URL", "https://rss.example.com/")
    s = Settings(_env_file=None)
    assert s.base_url == "https://rss.example.com"


def test_base_url_http_localhost_allowed(monkeypatch):
    _set_valid(monkeypatch)
    monkeypatch.setenv("BASE_URL", "http://localhost:8000")
    s = Settings(_env_file=None)
    assert s.base_url == "http://localhost:8000"


def test_base_url_http_non_localhost_rejected(monkeypatch):
    _set_valid(monkeypatch)
    monkeypatch.setenv("BASE_URL", "http://rss.example.com")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_base_url_not_a_url_rejected(monkeypatch):
    _set_valid(monkeypatch)
    monkeypatch.setenv("BASE_URL", "not-a-url")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_epochs_property_parses_map(monkeypatch):
    _set_valid(monkeypatch)
    monkeypatch.setenv("MAIL2RSS_EPOCH", "M9f3ac21b:2,M77bb01c:5")
    s = Settings(_env_file=None)
    assert s.epochs == {"M9f3ac21b": "2", "M77bb01c": "5"}
    assert s.epoch_for("M9f3ac21b") == "2"
    assert s.epoch_for("unknown") == ""


def test_epochs_empty_by_default(monkeypatch):
    _set_valid(monkeypatch)
    monkeypatch.delenv("MAIL2RSS_EPOCH", raising=False)
    s = Settings(_env_file=None)
    assert s.epochs == {}


def test_epoch_malformed_rejected(monkeypatch):
    _set_valid(monkeypatch)
    monkeypatch.setenv("MAIL2RSS_EPOCH", "not-a-pair")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_media_cache_bytes_derived(monkeypatch):
    _set_valid(monkeypatch)
    monkeypatch.setenv("MEDIA_CACHE_MAX_MB", "10")
    s = Settings(_env_file=None)
    assert s.media_cache_max_bytes == 10 * 1024 * 1024
