"""CLI subcommands (SPEC.md §4.5) — the same computations as the service, offline.

Everything is derived from the secret without touching the service; Fastmail is
contacted only where folders are enumerated. Dispatched from main.py.

    gen-secret  print a fresh MAIL2RSS_SECRET (no network, no settings)
    folders     list Fastmail folders with ids and paths (JMAP)
    url         print a feed URL for a mailbox id — OFFLINE (no Fastmail call)
    feeds       table of path -> mailbox_id -> feed URL (JMAP)
    opml        print the OPML of all user folders (JMAP)
    check       verify the token, the session and that BASE_URL looks https (JMAP)

``gen-secret`` deliberately avoids importing settings so it works before an env is
configured — it is what you run to create the secret in the first place.
"""

from __future__ import annotations

import argparse
import asyncio
from html import escape

import httpx

from src.crypto import feed_mac, feed_url, gen_secret, slugify
from src.jmap import JmapClient, JmapError, JmapNotFound
from src.mailbox_tree import MailboxTree
from src.models import DEFAULT_LIMIT, FeedParams

# The slug is cosmetic and never verified (SPEC.md §4.1 p.2); offline we have no
# folder name, so we use a neutral placeholder.
_OFFLINE_SLUG = "feed"


def run_cli(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="mail2rss", description="mail2rss CLI (SPEC.md §4.5)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("gen-secret", help="print a fresh MAIL2RSS_SECRET")
    sub.add_parser("folders", help="list Fastmail folders with ids and paths")

    p_url = sub.add_parser("url", help="print a feed URL for a mailbox id (offline)")
    p_url.add_argument("--mailbox", required=True, help="JMAP mailbox id")
    p_url.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="entries in the feed")
    p_url.add_argument("--children", action="store_true", help="include subfolders")

    sub.add_parser("feeds", help="table of path -> mailbox_id -> feed URL")
    sub.add_parser("opml", help="print the OPML of all user folders")
    sub.add_parser("check", help="verify the token, the session and BASE_URL")

    args = parser.parse_args(argv)

    if args.cmd == "gen-secret":
        return _cmd_gen_secret()
    if args.cmd == "url":
        return _cmd_url(args)
    if args.cmd == "folders":
        return asyncio.run(_cmd_folders())
    if args.cmd == "feeds":
        return asyncio.run(_cmd_feeds())
    if args.cmd == "opml":
        return asyncio.run(_cmd_opml())
    if args.cmd == "check":
        return asyncio.run(_cmd_check())
    return 2


# --- Offline commands --------------------------------------------------------


def _cmd_gen_secret() -> int:
    # No settings import here: this runs before an env exists.
    print(gen_secret())
    return 0


def _cmd_url(args: argparse.Namespace) -> int:
    from src.settings import settings

    params = FeedParams(limit=args.limit, children=args.children)
    epoch = settings.epoch_for(args.mailbox)
    mac = feed_mac(args.mailbox, params, epoch)
    print(feed_url(settings.base_url, _OFFLINE_SLUG, args.mailbox, mac, params))
    return 0


# --- JMAP-backed commands ----------------------------------------------------


async def _load_tree(include_system: bool = True) -> MailboxTree:
    from src.settings import settings

    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0)) as client:
        jmap = JmapClient(settings.fastmail_api_token, settings.jmap_session_url, client)
        tree = MailboxTree(jmap, settings.mailbox_tree_ttl)
        await tree.ensure_fresh()
        return tree


async def _cmd_folders() -> int:
    from src.settings import settings

    try:
        tree = await _load_tree()
    except (JmapError, JmapNotFound) as exc:
        print(f"error: could not list folders: {exc}")
        return 1
    # `folders` is a raw-tree inspection tool: it lists EVERYTHING, but marks the
    # rows the server would silently 404 (SPEC.md §4.8) so the operator can debug
    # the allowlist patterns.
    mark_excluded = bool(settings.allowed_folder_patterns)
    for mailbox, path in tree.list_folders(include_system=True):
        tag = f" [{mailbox.role}]" if mailbox.role else ""
        if mark_excluded and not settings.folder_allowed(path):
            tag += " [excluded by MAIL2RSS_ALLOWED_FOLDERS]"
        print(f"{mailbox.id}\t{path}{tag}\t({mailbox.total_emails} emails)")
    return 0


async def _cmd_feeds() -> int:
    from src.settings import settings

    try:
        tree = await _load_tree()
    except (JmapError, JmapNotFound) as exc:
        print(f"error: could not list folders: {exc}")
        return 1
    for mailbox, path in tree.list_folders(include_system=False):
        # Emitting a URL the server will silently 404 would be a lie (§4.8).
        if not settings.folder_allowed(path):
            continue
        epoch = settings.epoch_for(mailbox.id)
        mac = feed_mac(mailbox.id, FeedParams(), epoch)
        url = feed_url(settings.base_url, slugify(mailbox.name), mailbox.id, mac, FeedParams())
        print(f"{path}\t{mailbox.id}\t{url}")
    return 0


def build_opml(folders) -> str:
    """OPML 2.0 of the listed folders' default feed URLs (SPEC.md §4.5).

    Folders excluded by MAIL2RSS_ALLOWED_FOLDERS are skipped: emitting a URL the
    server will silently 404 would be a lie (SPEC.md §4.8).
    """
    # Local import: keep `gen-secret` runnable before any env exists (see module docstring).
    from src.settings import settings

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<opml version="2.0">',
        "<head><title>mail2rss</title></head>",
        "<body>",
    ]
    for mailbox, path in folders:
        if not settings.folder_allowed(path):
            continue
        epoch = settings.epoch_for(mailbox.id)
        url = feed_url(
            settings.base_url,
            slugify(mailbox.name),
            mailbox.id,
            feed_mac(mailbox.id, FeedParams(), epoch),
            FeedParams(),
        )
        text = escape(path, quote=True)
        lines.append(
            f'  <outline text="{text}" title="{text}" type="rss" '
            f'xmlUrl="{escape(url, quote=True)}"/>'
        )
    lines += ["</body>", "</opml>"]
    return "\n".join(lines)


async def _cmd_opml() -> int:
    try:
        tree = await _load_tree()
    except (JmapError, JmapNotFound) as exc:
        print(f"error: could not list folders: {exc}")
        return 1
    print(build_opml(tree.list_folders(include_system=False)))
    return 0


async def _cmd_check() -> int:
    from src.settings import settings

    ok = True

    base = settings.base_url
    if base.startswith("https://"):
        print(f"base_url: ok ({base})")
    elif base.startswith("http://") and ("localhost" in base or "127.0.0.1" in base):
        print(f"base_url: ok, local ({base})")
    else:
        print(f"base_url: NOT https ({base})")
        ok = False

    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0)) as client:
        jmap = JmapClient(settings.fastmail_api_token, settings.jmap_session_url, client)
        try:
            session = await jmap.get_session()
            print(f"jmap session: ok (account {session.account_id})")
        except (JmapError, JmapNotFound) as exc:
            print(f"jmap session: FAILED ({exc})")
            ok = False

    return 0 if ok else 1
