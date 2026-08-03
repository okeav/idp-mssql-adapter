---
title: "MSSQL Storage Adapter"
package: "@okeav/idp-core-mssql"
category: "api-reference"
tags: ["storage-adapter", "mssql", "sql-server"]
description: "The SQL Server implementation of idp-core's eight storage repository interfaces, its connection/config shape, migrations, and schema."
---

# MSSQL Storage Adapter

`@okeav/idp-core-mssql` implements all eight of idp-core's storage repository interfaces
(`UserRepository`, `SessionRepository`, `AuthorizationCodeRepository`, `ConsentRepository`,
`OAuthClientRepository`, `VerificationTokenRepository`, `ServiceKeyRepository`,
`CredentialRepository` — see idp-core's own
[Repository Adapters](#related) doc for the exact per-repository method contract) against a plain
relational schema on Microsoft SQL Server, using nothing but the [`mssql`](https://www.npmjs.com/package/mssql)
driver — no ORM, no query builder.

idp-core itself never imports this package. It's wired in entirely through the
`config.storage.factory` seam idp-core exposes for exactly this purpose.

## Wiring it in — `config.storage.factory`

```js
import { initIdentityProvider } from '@okeav/idp-core';
import { createMssqlStorage } from '@okeav/idp-core-mssql';

await initIdentityProvider({
  issuer: 'https://idp.example.com',
  // No config.mongo at all — storage.factory replaces it entirely.
  storage: {
    factory: (resolvedConfig, emailDeps) => createMssqlStorage({ pool: poolConfig }, emailDeps),
  },
  signingKeys: { keys: { /* ... */ } },
  security: { emailHashPepper: '...', tokenHashSecret: '...' },
});
```

`createMssqlStorage(config, emailDeps)` matches the exact `factory(resolvedConfig, { hashEmail,
normalizeEmail })` signature idp-core calls — `initIdentityProvider()` invokes
`resolved.storage.factory(resolved, { hashEmail, normalizeEmail })` in place of its built-in Mongo
adapter whenever a factory is provided. `hashEmail`/`normalizeEmail` are the same email
blind-index helpers the Mongo adapter uses; `MssqlUserRepository.findByEmail` uses them to query
`WHERE email_hash = @emailHash OR email = @email`, the same blind-index-plus-plaintext pattern
described in idp-core's repository-adapters doc.

## Config shape

`createMssqlStorage(config, emailDeps)` takes:

```ts
{
  pool: import('mssql').config;   // required — e.g. { server, user, password, database, options: { encrypt: true } }
  skipMigrationCheck?: boolean;    // default false
}
```

Internally, `config.pool` is passed straight to `new sql.ConnectionPool(poolConfig)` (`src/pool.js`)
and `.connect()`ed — it's a plain `mssql` connection config, not an adapter-specific shape. Either
`server` or `connectionString` must be present or `createPool` throws immediately.

The returned storage object also exposes the raw `pool` (an `mssql` `ConnectionPool`) alongside
`close()` and the eight repositories, in case a consuming app wants to run its own queries against
the same connection.

## Migrations — not automatic

Raw `.sql` files live under `src/migrations/sql/` (currently just `0001_init.sql`), applied in
filename order by `runMigrations(pool, opts?)`, each file inside its own transaction, tracked by
filename in a `dbo.idp_schema_migrations` table.

**`createMssqlStorage()` does not run migrations itself.** You call `runMigrations()` explicitly,
at your own deploy/startup step, once, before `initIdentityProvider()` ever wires up the factory —
running DDL automatically from every booting instance would be a real concurrent-DDL risk
otherwise:

```js
import { runMigrations } from '@okeav/idp-core-mssql';
import sql from 'mssql';

const migrationPool = new sql.ConnectionPool(poolConfig);
await migrationPool.connect();
await runMigrations(migrationPool);
await migrationPool.close();
```

What `createMssqlStorage()` *does* do on every call (unless `skipMigrationCheck: true`) is a cheap,
read-only startup check: it reads `dbo.idp_schema_migrations` and compares the applied filenames
against the migration files bundled with the installed package version
(`expectedMigrationFilenames()`). If the table doesn't exist, or any expected migration is missing,
it throws an actionable `Error` naming the missing file(s) rather than letting it surface later as
a confusing query failure. Set `skipMigrationCheck: true` to skip this round trip (e.g. a CI job
reusing a known-good database).

## Schema at a glance

All tables live in the `dbo` schema, primary keys are application-generated `UNIQUEIDENTIFIER`
GUIDs (`crypto.randomUUID()`, no `NEWID()` defaults):

| Table | Backs | Notes |
|---|---|---|
| `idp_users` | `UserRepository` | flat profile/MFA/lockout columns; `metadata` as `NVARCHAR(MAX)` JSON |
| `idp_user_external_providers` | — | join table for SSO-linked identities; unique on `(provider, provider_id)` |
| `idp_user_recovery_codes` | — | join table for MFA recovery codes; unique on `(user_id, position)`, consumed positionally |
| `idp_sessions` | `SessionRepository` | `user_id` is a real `FOREIGN KEY` into `idp_users(id)` |
| `idp_access_token_audit` | — | write-only audit trail, one row per issued access token |
| `idp_authorization_codes` | `AuthorizationCodeRepository` | `code` column stores a hash despite the name |
| `idp_consents` | `ConsentRepository` | unique on `(user_id, client_id)` |
| `idp_oauth_clients` | `OAuthClientRepository` | `client_secret_hash` only returned when a query explicitly asks for it |
| `idp_verification_tokens` | `VerificationTokenRepository` | one table backs `password_reset`/`email_verification`/`magic_link` via a `kind` check constraint |
| `idp_service_keys` | `ServiceKeyRepository` | unique on `kid` |
| `idp_credentials` | `CredentialRepository` | WebAuthn credentials; unique on `credential_id` |

Two notable schema behaviors worth knowing before you rely on this adapter:

- **GUID casing**: `mssql` renders `UNIQUEIDENTIFIER` values back as uppercase strings, while every
  ID this package generates is lowercase. Every ID field read back from a row is passed through a
  `lowerGuid()` normalizer before reaching callers, so string equality against a
  `crypto.randomUUID()` value always holds.
- **No native TTL**: unlike MongoDB, SQL Server has no TTL index, so `pruneExpired()` on sessions,
  authorization codes, and verification tokens is a real `DELETE`, not a no-op. idp-core never
  calls it automatically — schedule it yourself.
- **No native JSON/array column type**: `metadata`, `claims`, `scopes`, `redirectUris`,
  `allowedScopes`, `allowedGrants`, and `transports` are stored as `NVARCHAR(MAX)` JSON text, with
  the repository layer doing `JSON.stringify()`/`JSON.parse()` manually.

## Related

- [Repository Adapters (Storage)](https://github.com/okeav/idp/blob/main/docs/api/repository-adapters.md)
  in the `@okeav/idp-core` repo — the canonical eight-interface contract and the
  `config.storage.factory` seam this adapter plugs into.
- [Set up idp-core with the MSSQL adapter](../examples/mssql-storage-adapter.md) — a full worked
  example, including running the migration.
