# mail2rss

Turns Fastmail folders into Atom feeds. **One Atom feed per Fastmail folder**, read over the
JMAP API, served to a self-hosted [Miniflux](https://miniflux.app/) (or any reader). Access to
the mailbox is **read-only** — messages are never marked as seen, moved or deleted — and
**nothing is stored**: there is no email database and no feed config file. The feed URL itself
carries the folder id and an HMAC signature, so the whole service is stateless.

The full design rationale is in [`SPEC.md`](SPEC.md) (Russian).

## Requirements

- **A paid Fastmail plan.** API tokens are **not available on the Basic plan**.
- Docker + Traefik for deployment (or just Python 3.12 to run it locally).
- Miniflux (recommended) — see the [`MEDIA_PROXY_MODE`](#miniflux-media_proxy_modeall-required) requirement below.

## Setup

### 1. Create the Fastmail API token

In Fastmail: **Settings → Privacy & Security → Connected apps & API tokens →
Manage API tokens → New API token**.

- **Type:** JMAP
- **Scopes:** *Read-only access* + *Email*

The token is **shown only once** — copy it right away. These scopes make the service read-only
*by construction*: mutating the mailbox is physically impossible, not merely avoided by
careful code.

### 2. Generate the secret

```bash
make gen-secret     # prints a 128-bit base32 secret
```

### 3. Configure

```bash
make env            # or: cp .env.example .env
```

Fill in `FASTMAIL_API_TOKEN`, `MAIL2RSS_SECRET` and `BASE_URL`. All three are required; the
service refuses to start if any is missing, and it also rejects a `MAIL2RSS_SECRET` that is not
a machine-generated 128-bit base32 value.

### 4. Get your feed URLs

List your folders and their mailbox ids with the CLI:

```bash
make folders                                  # folder tree with mailbox ids
make feeds                                    # the feed URL table (one signed URL per folder)
.venv/bin/python main.py opml > feeds.opml    # OPML with all folders — Miniflux imports it in one go
```

The service root (`BASE_URL/`) is a client-side link calculator: paste a mailbox id (from
`make folders`) and the secret, and the feed URL is computed right in the browser — nothing is
ever sent to the server, and the server reveals no mailbox data. A new folder in Fastmail needs
no config change, no restart and no deploy: grab its id from `make folders` and compute the link.

## Miniflux: `MEDIA_PROXY_MODE=all` (required)

Set this in your Miniflux deployment:

```yaml
MEDIA_PROXY_MODE: all
```

**Why it matters.** By default Miniflux uses `http-only` and does **not** proxy https images. A
newsletter is full of https images hosted by the sender, so with the default every image is
fetched by *your browser* — handing the sender your IP address and the exact moment you opened
the mail. With `MEDIA_PROXY_MODE=all`, Miniflux fetches them from its own server instead. See
`SPEC.md` §8.2. (mail2rss strips tracking pixels itself, but it deliberately does not rewrite
the sender's real images — that part is Miniflux's job.)

A commented-out Miniflux service block is included in `docker-compose.yml`.

## Environment variables

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `FASTMAIL_API_TOKEN` | yes | — | Fastmail JMAP API token (scopes: Read-only access + Email). |
| `MAIL2RSS_SECRET` | yes | — | 128-bit base32 secret; every feed and media URL is derived from it. `make gen-secret`. |
| `BASE_URL` | yes | — | Public https URL of this service, e.g. `https://rss.example.com`. Baked into the links inside the feed, so it has no default. |
| `JMAP_SESSION_URL` | no | `https://api.fastmail.com/jmap/session` | Fastmail JMAP session endpoint. |
| `CACHE_TTL` | no | `600` | Seconds a rendered feed is served from cache before JMAP is queried again. |
| `MAX_LIMIT` | no | `100` | Server-side ceiling on `?limit=`, forced regardless of the URL signature. |
| `MAILBOX_TREE_TTL` | no | `3600` | Seconds the folder tree is cached; a new folder appears without a restart. |
| `MAIL2RSS_EPOCH` | no | *(empty)* | Per-folder URL revocation counters, e.g. `M9f3ac21b:2,M77bb01c:5`. Bumping one changes only that folder's URL. |
| `MAIL2RSS_ALLOWED_FOLDERS` | no | *(empty)* | Hard server-side allowlist: comma-separated glob patterns over folder paths, e.g. `Newsletters,Newsletters/*`. Empty = all folders. Non-matching folders silently 404, even with a valid URL. |
| `LOG_LEVEL` | no | `INFO` | Log level. |
| `CACHE_DB_PATH` | no | `data/cache.db` | SQLite cache file; keep it under `data/`. |

The full list also lives in `.env.example`, and `docker-compose.yml` documents each variable inline.

## Deployment

Production does not build the image — CI does. Push to `main` → tests run → the image is built
and pushed to `ghcr.io/vvzvlad/mail2rss:latest` → watchtower picks it up. Red tests physically
cannot produce an image (`build` has `needs: test`).

```bash
cp docker-compose.yml /path/on/server/
# fill in FASTMAIL_API_TOKEN / MAIL2RSS_SECRET / BASE_URL and the Traefik Host rule
docker compose up -d
```

The container listens on port 8000 and is published over HTTPS by Traefik (compose labels); the
app itself terminates no TLS and has no `EXPOSE`. The named volume at `/app/data` holds only a
disposable SQLite cache — feed bodies, media blobs, the folder tree. Deleting it loses nothing.

## ⚠️ Back up `MAIL2RSS_SECRET`

Every feed and media URL is derived from this one value. **Lose it and every feed URL changes**:
all your Miniflux subscriptions break at once and you have to re-import the OPML. It is not
stored anywhere except your `.env` / compose file — the service keeps no copy, by design.

Conversely, this is also the recovery story: move the service to another host, keep the secret,
and all the old URLs keep working. `data/` does not need to come along.

## How it works

**The URL is the config.**

```text
/f/{slug}/{mailboxId}/{mac}/atom.xml
   └─┬──┘ └────┬────┘ └─┬─┘
     │         │        └── HMAC-SHA256 over the folder id + params; the only thing checked
     │         └── what to fetch from JMAP (immutable, survives renames)
     └── cosmetic, for humans; ignored by the server
```

- Nothing is persisted: there is no feed list, no config file, no email database. The signature
  in the URL proves it was issued by the holder of `MAIL2RSS_SECRET`.
- A bad signature is a `404` — the service never confirms whether a folder exists.
- Rename a folder or move it under another parent and the feed keeps working: the signature
  covers the immutable `mailboxId`, not the name.
- Entry ids are derived from the message's `Message-ID`, so entries stay read in Miniflux and
  never resurface as new.
- Inline `cid:` images are served through a signed media proxy on this service; tracking pixels
  are stripped, and the mail's HTML is sanitized (nh3) before it goes into the feed.

## Development

```bash
make install    # create .venv + install dev/test deps
make test       # pytest
make run        # run the service
make help       # all targets
```
