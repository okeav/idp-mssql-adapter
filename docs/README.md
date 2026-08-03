# @okeav/idp-core-mssql Documentation

Reference documentation and a runnable example for [`@okeav/idp-core-mssql`](..) — a Microsoft SQL
Server storage adapter for [`@okeav/idp-core`](https://github.com/okeav/idp), implementing all
eight of its storage repository interfaces against a plain relational schema using nothing but the
`mssql` driver (no ORM). This is a light doc set compared to idp-core's own — the package is thin,
implementing one plug-in seam (`config.storage.factory`) behind eight already-documented
interfaces.

## Layout

```
docs/
  api/         one file per concept area — purpose, full signatures, config, errors, return shapes
  examples/    one working, runnable scenario per file
```

Every file carries the same YAML frontmatter (`title`, `package`, `category`, `tags`,
`description`) as idp-core's own docs tree, so both can be indexed together — `category` is
`api-reference` or `example`.

## API reference (`api/`)

| File | Covers |
|---|---|
| [storage-adapter.md](api/storage-adapter.md) | What the adapter is, the `config.storage.factory` wiring, its own connection/config shape, migrations, and the schema at a glance |

## Examples (`examples/`)

| File | Scenario |
|---|---|
| [mssql-storage-adapter.md](examples/mssql-storage-adapter.md) | Running the migration, then setting up idp-core with this adapter end-to-end |

## Source of truth

Written directly against this package's own source (`src/index.js`, `src/pool.js`,
`src/migrations/run-migrations.js`, `src/migrations/sql/0001_init.sql`, `src/repositories/*.js`,
`src/util/*.js`) and cross-referenced against `@okeav/idp-core`'s
`docs/api/repository-adapters.md` for the interface contract this adapter implements, kept in sync
as the package evolves.
