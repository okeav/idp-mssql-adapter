---
title: "Set Up idp-core with the MSSQL Storage Adapter"
package: "@okeav/idp-core-mssql"
category: "example"
tags: ["storage-adapter", "mssql", "sql-server"]
description: "Run the migration, then wire @okeav/idp-core-mssql into initIdentityProvider() via config.storage.factory."
---

# Set Up idp-core with the MSSQL Storage Adapter

This walks through standing up `@okeav/idp-core` against a SQL Server database instead of the
default MongoDB adapter: running the bundled migration once, then wiring the adapter in via
`config.storage.factory`. See [MSSQL Storage Adapter](../api/storage-adapter.md) for the full
config shape and schema reference.

## Prerequisites

- A reachable SQL Server instance (the package repo's `docker-compose.yml` includes one for local
  dev/testing).
- `npm install @okeav/idp-core-mssql mssql`

## Step 1 — run the migration once, at deploy time

`createMssqlStorage()` does **not** run migrations itself — run them explicitly, before the app
starts serving traffic, so you don't have multiple booting instances racing to apply DDL:

```js
// migrate.js — run once per deploy, separately from the app process
import sql from 'mssql';
import { runMigrations } from '@okeav/idp-core-mssql';

const poolConfig = {
  server: process.env.MSSQL_HOST,
  user: process.env.MSSQL_USER,
  password: process.env.MSSQL_PASSWORD,
  database: process.env.MSSQL_DATABASE,
  options: { encrypt: true },
};

const pool = new sql.ConnectionPool(poolConfig);
await pool.connect();
const applied = await runMigrations(pool);
console.log('Applied migrations:', applied); // e.g. ['0001_init.sql'] on first run, [] thereafter
await pool.close();
```

`runMigrations()` is idempotent — it tracks applied filenames in `dbo.idp_schema_migrations` and
only runs new ones, so re-running this script on every deploy is safe and cheap once the schema is
current.

## Step 2 — wire the adapter into `initIdentityProvider()`

```js
// server.js
import express from 'express';
import { initIdentityProvider } from '@okeav/idp-core';
import { createMssqlStorage } from '@okeav/idp-core-mssql';

const poolConfig = {
  server: process.env.MSSQL_HOST,
  user: process.env.MSSQL_USER,
  password: process.env.MSSQL_PASSWORD,
  database: process.env.MSSQL_DATABASE,
  options: { encrypt: true },
};

const idp = await initIdentityProvider({
  issuer: 'https://idp.example.com',
  // No config.mongo — storage.factory replaces the built-in Mongo adapter entirely.
  storage: {
    factory: (resolvedConfig, emailDeps) => createMssqlStorage({ pool: poolConfig }, emailDeps),
  },
  signingKeys: { keys: { /* ... */ } },
  security: {
    emailHashPepper: process.env.EMAIL_HASH_PEPPER,
    tokenHashSecret: process.env.TOKEN_HASH_SECRET,
  },
});

const app = express();
app.use(idp.router);
app.listen(3000, () => console.log('idp listening on :3000'));
```

`initIdentityProvider()` calls your `storage.factory(resolvedConfig, { hashEmail, normalizeEmail })`
in place of its built-in `createMongoStorage()` — `createMssqlStorage()` opens its own `mssql`
`ConnectionPool` from `poolConfig`, then runs a cheap read-only check that this database has the
migrations the installed package version expects (throwing an actionable error naming any missing
migration file if not — the most common cause is forgetting Step 1). Everything else — routes,
handlers, token issuance, MFA, WebAuthn, OAuth2 — behaves identically to the Mongo-backed
quickstart; only the storage layer underneath changed.

## Skipping the startup check in CI

If a CI job reuses a database it already knows is fully migrated, skip the extra round trip:

```js
storage: {
  factory: (resolvedConfig, emailDeps) =>
    createMssqlStorage({ pool: poolConfig, skipMigrationCheck: true }, emailDeps),
},
```

## Related

- [MSSQL Storage Adapter](../api/storage-adapter.md) — full config shape, migration mechanics, and
  schema reference for this adapter.
- [Repository Adapters (Storage)](https://github.com/okeav/idp/blob/main/docs/api/repository-adapters.md)
  in the `@okeav/idp-core` repo — the eight-interface contract this adapter implements.
