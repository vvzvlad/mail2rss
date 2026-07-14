# Agent Instructions — mail2rss

Stateless service: Fastmail folders (JMAP, read-only) → Atom feeds for Miniflux. No email
database, no feed config — the feed URL carries the folder id and an HMAC signature.

**`SPEC.md` (Russian) is authoritative.** Read it before changing behaviour; cite sections in
code comments (`see SPEC.md §7.5 p. 6`) the way the existing code does.

## Project structure

- `src/` — application code (`settings.py` is the single config entry point)
- `tests/` — pytest
- `data/` — runtime state: the disposable SQLite cache (gitignored, mounted as a docker volume)
- `templates/` — static assets that ship inside the image
- `main.py` — thin entry point over `src/`; also hosts the CLI subcommands

## Setup

All routine actions go through the `Makefile` — run `make help` to list targets.

```bash
make install           # create .venv and install dev/test deps
cp .env.example .env   # then fill in the values  (shortcut: make env)
make gen-secret        # generate MAIL2RSS_SECRET for that .env
```

## Running tests

```bash
make test              # runs .venv/bin/pytest
```

## Running the app

```bash
make run               # runs .venv/bin/python main.py
make folders           # CLI: Fastmail folders + mailbox ids
make feeds             # CLI: the feed URL table
```

## Conventions

- All mutable state goes under `data/`, and it is **disposable**: deleting `data/cache.db` must
  never lose anything. Static assets belong in `templates/` — on prod `data/` is shadowed by the
  volume, so anything shipped there disappears.
- All config comes from ENV / `.env` (see `.env.example`). There is no config file, by design.
- Credentials go ONLY into `.env` — never into code, never into tests, never into
  `docker-compose.yml` (placeholders there), never as inline env vars on the command line.
  Read them through `Settings`.
- No default/example credentials in code; a missing ENV var → fail at startup naming the
  variable. `BASE_URL` has no default on purpose: a `localhost` default would ship broken links
  inside the feed.
- **Never log secrets.** Not `MAIL2RSS_SECRET`, not `FASTMAIL_API_TOKEN`, not the `mac` from a
  feed URL — and on an auth failure never log the *expected* value of a token or MAC. Log the
  `mailboxId` and the first 6 chars of a hash of the `mac`. Compare secrets with
  `hmac.compare_digest` only.
- Code comments are in English. So are `README.md` and this file. `SPEC.md` stays Russian.
- All repeated actions (env setup, tests, run, CLI) go through `make` targets — add or extend a
  target instead of running ad-hoc commands.
- Python always runs inside a local `.venv`, created automatically by `make` on first use
  (`make test` / `make run` bootstrap it) — never the system Python.
- Tests are mandatory for new code; in CI `build` depends on `test`, so red tests physically
  cannot produce an image. Fastmail HTTP is mocked with `respx` — no test touches the network.
- No `EXPOSE` in the Dockerfile — Traefik publishes the service via compose labels. The
  container runs as non-root.
