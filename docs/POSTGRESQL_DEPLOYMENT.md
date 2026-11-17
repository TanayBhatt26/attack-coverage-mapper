# Deploying with PostgreSQL (Streamlit Community Cloud)

The repository ships with a working SQLite database, which is right for local
development and wrong for Streamlit Community Cloud: the platform mounts the
repository **read-only**, so every write to `db/coverage.db` fails with

```
sqlite3.OperationalError: attempt to write a readonly database
```

The app reads fine and then breaks the first time a visitor runs a simulation.
This document describes the supported production setup: **SQLite for
development, managed PostgreSQL for the deployed app**, plus the one-time
migration that moves the existing data across.

---

## 1. The contract: `APP_ENV`

`src/database/session.py` resolves the database URL differently per environment.

| `APP_ENV` | `DATABASE_URL` | Behaviour |
|---|---|---|
| `development` (default) | unset | `sqlite:///db/coverage.db` — zero-install local dev |
| `development` | set | used as given (SQLite or PostgreSQL) |
| `production` | unset | **refuses to start** (`RuntimeError`) |
| `production` | SQLite | **refuses to start** (`RuntimeError`) |
| `production` | `postgresql+psycopg://…` | used |

Failing loudly is the point. A silent SQLite fallback on a read-only host
produces a deploy that looks healthy until the first write — and, if the file
were absent, would quietly create an empty database and render a blank
dashboard.

`verify_schema(engine)` is the second guard. `SELECT 1` succeeds against any
live server, so the app also checks that all ten application tables exist and
that `techniques` is populated, and says which migration to run otherwise.

Both are unit-tested in `tests/test_postgres_migration.py`.

---

## 2. Provision PostgreSQL

Any PostgreSQL 14+ works. For Streamlit Community Cloud the convenient choice is
a managed serverless instance (Neon, Supabase, RDS, Cloud SQL) — something with
a public endpoint and a connection string of the form:

```
postgresql+psycopg://user:password@host:5432/dbname
```

Two things to decide at provisioning time:

* **Create an empty database.** The migration refuses to write into a database
  that already holds application tables, so point it at a fresh one.
* **Use a dedicated, least-privilege user** for the app rather than the server
  superuser. The database must allow `CREATE` on its schema the first time the
  app starts (the schema is created with `create_all(checkfirst=True)`), and
  `SELECT/INSERT/UPDATE/DELETE` afterwards. `docker/initdb/01-app-role.sql` is
  the local reference for that role split.

---

## 3. Migrate the existing SQLite database

Run from the repository root:

```bash
cd attack-coverage-mapper

# 1. Plan the copy without writing anything
PYTHONPATH=src ./.venv/Scripts/python.exe scripts/migrate_sqlite_to_postgres.py \
    --postgres-url "postgresql+psycopg://user:password@host:5432/dbname" \
    --dry-run

# 2. Copy, then verify every row (ids and timestamps included)
PYTHONPATH=src ./.venv/Scripts/python.exe scripts/migrate_sqlite_to_postgres.py \
    --postgres-url "postgresql+psycopg://user:password@host:5432/dbname" \
    --deep-verify
```

Expected result for the current dataset: **8,850 rows across 10 tables**
(858 techniques, 699 detection strategies, 1,758 analytics, 191 groups,
4,628 group-technique links, 8 data sources, 104 coverage rows, 9 simulation
runs, 594 simulation-technique rows, 1 ingest snapshot).

Re-check at any time without copying:

```bash
PYTHONPATH=src ./.venv/Scripts/python.exe scripts/migrate_sqlite_to_postgres.py \
    --postgres-url "..." --verify-only
```

### What the migration guarantees

* **Non-destructive.** Only `create_all(checkfirst=True)`; nothing is dropped,
  truncated or reset. The SQLite source is only read.
* **Atomic.** Schema creation, the copy, the sequence resynchronisation and the
  verification run in one transaction that commits only after verification
  passes. A failure leaves the target untouched.
* **No duplicate imports.** A target that already holds application rows is
  refused with exit code `3`.
* **Verbatim data.** Primary keys (including surrogate `id`s), foreign keys,
  JSON values and timestamps are copied as-is. Naive SQLite datetimes are
  interpreted as UTC so they match PostgreSQL `timestamptz` exactly.
* **Working sequences.** `setval` advances every serial primary key past the
  imported rows, so the next simulation gets `max(id) + 1` rather than
  colliding with id 1.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success (or `--dry-run` / `--verify-only` passed) |
| 1 | operational failure (unreachable backend, bad arguments) |
| 2 | verification failure (counts or row signatures differ) |
| 3 | refused — target already contains application data |

---

## 4. Configure Streamlit Community Cloud

In the app's **Secrets** (three-dot menu → Settings → Secrets), add TOML
equivalent to:

```toml
APP_ENV = "production"
DATABASE_URL = "postgresql+psycopg://user:password@host:5432/dbname"
```

Then redeploy. On startup the sidebar should read:

```
Database connected and schema verified: postgresql+psycopg://user:***@host/dbname
```

### Required Neon setting

Serverless PostgreSQL pools connections. Set the pooler to **session mode** (or
use the direct connection endpoint) rather than transaction mode — the app holds
a session across a render, and transaction-mode pooling can hand a session back
before its write lands. Enable **IPv4** on Neon if the app otherwise cannot
reach the endpoint from Streamlit's network.

---

## 5. Verify the deployment

Work through the same checks the migration and test suite encode:

1. Sidebar reports the schema as verified (not just "connected").
2. **Coverage Overview** shows 606 in-scope / 31 detectable / 5.12%.
3. **APT Simulation** → pick a group → **Run simulation** → the run appears.
4. **Hunt Queries** lists 58 gaps for the new run and expands to SPL.
5. **Gap Analysis** shows 575 total gaps and the remediation bundles.
6. **Anomaly Detection** renders its metrics and chart.
7. Reload the page: the simulation run is still there (it was committed, not
   just rendered).

The local equivalent, against `docker compose up -d postgres`:

```bash
TEST_POSTGRES_URL="postgresql+psycopg://attack_mapper:attack_mapper@localhost:5432/attack_coverage" \
    PYTHONPATH=src ./.venv/Scripts/python.exe -m pytest tests/test_postgres_migration.py -q
```

---

## 6. Local development is unchanged

Nothing about the dev workflow moves: with `APP_ENV` unset the app still opens
`db/coverage.db`, and `docker-compose.yml` still provides PostgreSQL for
checkpoint parity runs (`scripts/checkpoint_a_parity.py`). The committed
`db/coverage.db` stays in the repository as the zero-install default; the
production database is a *copy*, and the two can diverge as soon as anyone runs
a simulation. Re-run the migration (into a fresh database) if you need to
re-seed production from local data.

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `APP_ENV=production requires DATABASE_URL…` | secret missing | add `DATABASE_URL` to Streamlit Secrets |
| `refusing to fall back to SQLite` | `DATABASE_URL` still points at SQLite | set the PostgreSQL URL |
| `missing application tables: …` | pointed at an empty database | run the migration |
| `the "techniques" table is empty` | schema created but never populated | run the migration, or the ATT&CK ingest |
| exit code 3 on migration | target already has data | point at a fresh database, or use `--verify-only` |
| `attempt to write a readonly database` | `APP_ENV` not set in production | set `APP_ENV="production"` and the PostgreSQL secret |
| connection timeouts from Streamlit | pooler in transaction mode / IPv4 off | use session mode or the direct endpoint; enable IPv4 |
