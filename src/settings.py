"""Configuration — ENV only, no config file (SPEC.md §10.2).

This is a direct consequence of §4: feeds are described by their URLs, so there
is nothing left to put in a config file. Credentials and the address of our own
service have NO defaults: a missing variable must fail at startup with a readable
message, not silently degrade (a `http://localhost:8000` default for BASE_URL
would ship broken links into every feed).
"""

from __future__ import annotations

import fnmatch
import re
from urllib.parse import urlparse

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.config_errors import load_settings_or_exit
from src.crypto import validate_secret

# "M9f3ac21b:2" — a JMAP Id (F4: only [A-Za-z0-9_-]) and a counter.
_EPOCH_ENTRY_RE = re.compile(r"\A([A-Za-z0-9_-]+):([A-Za-z0-9._-]+)\Z")

# http:// is tolerated only for these hosts, so local development works without TLS.
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


class Settings(BaseSettings):
    # Credentials — no defaults. Missing in env -> fail at startup (§10.2).
    fastmail_api_token: str
    mail2rss_secret: str  # 128-bit base32; format is validated at startup (§4.4 p.1)

    # Address of our OWN service — no default either: it depends on the deployment,
    # and a wrong value ends up baked into permalinks and media URLs inside the feed.
    base_url: str

    # Public third-party API — a default is fine here.
    jmap_session_url: str = "https://api.fastmail.com/jmap/session"

    # Non-secret tuning.
    cache_ttl: int = 600  # seconds; min interval between JMAP round-trips per feed (§6.3)
    max_limit: int = 100  # server-forced ceiling on ?limit, regardless of the MAC (§4.3)
    mailbox_tree_ttl: int = 3600  # seconds (§6.1)
    media_cache_max_mb: int = 500  # LRU cap for the on-disk blob cache (§3.2)
    mail2rss_epoch: str = ""  # "M9f3ac21b:2,M77bb01c:5" — per-folder revocation (§4.7)
    mail2rss_allowed_folders: str = ""  # "Newsletters,Newsletters/*" — hard folder allowlist (§4.8)
    log_level: str = "INFO"
    cache_db_path: str = "data/cache.db"  # all mutable state lives under data/

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @field_validator("mail2rss_secret")
    @classmethod
    def _check_secret(cls, value: str) -> str:
        # A weak secret must PREVENT STARTUP (SPEC.md §4.4 p.1). The secret is
        # validated here once, at startup; nothing else ever re-checks it (the
        # link-calculator page computes MACs in the browser and never sends the
        # secret to the server). The message never echoes the value back.
        if not validate_secret(value):
            raise ValueError(
                "must be a machine-generated 128-bit base32 secret "
                "(26 chars, a-z2-7) — run `make gen-secret`"
            )
        return value

    @field_validator("base_url")
    @classmethod
    def _check_base_url(cls, value: str) -> str:
        url = value.strip().rstrip("/")
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("must be an absolute https:// URL, e.g. https://rss.example.com")
        if parsed.scheme == "http" and (parsed.hostname or "") not in _LOCAL_HOSTS:
            # Capability URLs live in this address: plaintext is not an option (§5.2 p.1).
            raise ValueError("must use https:// (http:// is allowed only for localhost)")
        return url

    @field_validator("mail2rss_epoch")
    @classmethod
    def _check_epoch(cls, value: str) -> str:
        # Fail loudly on a malformed entry: silently ignoring it would mean a
        # revocation the operator believes is in effect is not, in fact, applied.
        seen: set[str] = set()
        for entry in _split_csv(value):
            match = _EPOCH_ENTRY_RE.match(entry)
            if not match:
                raise ValueError(
                    f"malformed entry {entry!r}; expected 'mailboxId:counter' "
                    "pairs separated by commas, e.g. 'M9f3ac21b:2,M77bb01c:5'"
                )
            mailbox_id = match.group(1)
            if mailbox_id in seen:
                raise ValueError(f"duplicate mailbox id {mailbox_id!r}")
            seen.add(mailbox_id)
        return value

    @field_validator("mail2rss_allowed_folders")
    @classmethod
    def _check_allowed_folders(cls, value: str) -> str:
        # Fail loudly: a non-blank value that parses to ZERO patterns (e.g. " , ,")
        # would silently mean "allow everything" while the operator believes a
        # restriction is in effect — refuse to start instead (same rule as epoch).
        if value.strip() and not _split_csv(value):
            raise ValueError(
                "is non-empty but contains no patterns; expected comma-separated "
                "fnmatch globs over folder paths, e.g. 'Newsletters,Newsletters/*'"
            )
        return value

    @property
    def epochs(self) -> dict[str, str]:
        """Parsed MAIL2RSS_EPOCH: {mailbox_id: counter} (§4.7).

        Flat ENV, parsed in a property — house rule for lists/maps in config.
        """
        result: dict[str, str] = {}
        for entry in _split_csv(self.mail2rss_epoch):
            match = _EPOCH_ENTRY_RE.match(entry)
            if match:
                result[match.group(1)] = match.group(2)
        return result

    def epoch_for(self, mailbox_id: str) -> str:
        """Epoch of one mailbox; "" when it was never bumped (the 99% case)."""
        return self.epochs.get(mailbox_id, "")

    @property
    def allowed_folder_patterns(self) -> list[str]:
        """Parsed MAIL2RSS_ALLOWED_FOLDERS: fnmatch globs over folder paths (§4.8).

        Flat ENV, parsed in a property — house rule for lists/maps in config.
        """
        return _split_csv(self.mail2rss_allowed_folders)

    def folder_allowed(self, path: str) -> bool:
        """True iff the folder path passes MAIL2RSS_ALLOWED_FOLDERS.

        The allowlist caps the blast radius of a leaked feed URL or even a leaked
        MAIL2RSS_SECRET: even a valid MAC for a non-matching folder serves nothing
        (SPEC.md §4.8; complements the per-folder epoch revocation, §4.7).

        An empty allowlist means no restriction. Matching is fnmatch.fnmatchcase
        (deterministic, case-sensitive; fnmatch.fnmatch would fold case on macOS):
        '*' crosses '/' (fnmatch is not path-aware), so 'Newsletters/*' covers the
        whole subtree; add 'Newsletters' itself as a separate pattern if needed.
        """
        patterns = self.allowed_folder_patterns
        if not patterns:
            return True
        return any(fnmatch.fnmatchcase(path, p) for p in patterns)

    @property
    def media_cache_max_bytes(self) -> int:
        return self.media_cache_max_mb * 1024 * 1024


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


# Build settings with clear startup errors: a missing/invalid variable prints a
# readable message naming the env var and exits(1), instead of a raw pydantic
# traceback (which would also print the offending value — never do that with a secret).
settings = load_settings_or_exit(Settings)
