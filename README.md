# @okeav/idp-core-mssql

A Microsoft SQL Server storage adapter for [`@okeav/idp-core`](../identity) — implements all 8 storage repository interfaces (users, sessions, OAuth2 authorization codes/clients/consents, verification tokens, service keys, WebAuthn credentials) against a plain relational schema, using nothing but [`mssql`](https://www.npmjs.com/package/mssql) (no ORM).

## Install

```bash
npm install @okeav/idp-core-mssql mssql
```

## Usage

`@okeav/idp-core` doesn't know this package exists — you wire it in yourself via `config.storage.factory`, a small seam idp-core exposes specifically so non-Mongo adapters can plug in without idp-core ever importing them:

```js
import { initIdentityProvider } from '@okeav/idp-core';
import { createMssqlStorage, runMigrations } from '@okeav/idp-core-mssql';
import sql from 'mssql';

const poolConfig = {
  server: process.env.MSSQL_HOST,
  user: process.env.MSSQL_USER,
  password: process.env.MSSQL_PASSWORD,
  database: process.env.MSSQL_DATABASE,
  options: { encrypt: true },
};

// Run once, at deploy time — NOT automatically by createMssqlStorage().
const migrationPool = new sql.ConnectionPool(poolConfig);
await migrationPool.connect();
await runMigrations(migrationPool);
await migrationPool.close();

await initIdentityProvider({
  issuer: 'https://idp.example.com',
  // No config.mongo at all — storage.factory replaces it entirely.
  storage: {
    factory: (resolvedConfig, emailDeps) => createMssqlStorage({ pool: poolConfig }, emailDeps),
  },
  signingKeys: { keys: { /* ... */ } },
  security: { emailHashPepper: '...', tokenHashSecret: '...' },
  // ...everything else is identical to the Mongo-backed quickstart.
});
```

## Migrations

Raw `.sql` files under `src/migrations/sql/`, applied in order by `runMigrations(pool)`, tracked in an `idp_schema_migrations` table. **Not** run automatically by `createMssqlStorage()` — call it explicitly at your own deploy/startup step (concurrent DDL from multiple instances booting at once is a real risk otherwise). `createMssqlStorage()` does a cheap read-only check on startup that the expected migrations have actually been applied, and throws an actionable error if not; set `config.skipMigrationCheck: true` to skip that round trip (e.g. a CI job reusing a known-good database).

## Schema notes

- Primary keys are application-generated GUIDs (`crypto.randomUUID()`), stored as `UNIQUEIDENTIFIER` — no `NEWID()`/`NEWSEQUENTIALID()` column defaults, consistent with the Postgres/DynamoDB adapters.
- **GUID casing**: SQL Server's `UNIQUEIDENTIFIER` is a 16-byte binary value — the `mssql` driver renders it back to a string in UPPERCASE, while every ID this package family generates is lowercase. Every `id`/`user`/`userId` field read back from a row goes through a `lowerGuid()` normalizer (`src/util/row-mappers.js`) before reaching callers, so string equality against a `crypto.randomUUID()` value always holds.
- No native array or JSON column type — `metadata`, `claims`, `scopes`, `redirectUris`, `allowedScopes`, `allowedGrants`, `transports` are stored as `NVARCHAR(MAX)` JSON text, with the repository layer doing `JSON.stringify()`/`JSON.parse()` manually (unlike Postgres's JSONB, which `pg` auto-parses).
- Two of idp-core's Mongo-shaped embedded arrays became real join tables here, matching the Postgres adapter's design: `idp_user_external_providers` (SSO-linked identities, looked up by `provider`+`providerId`) and `idp_user_recovery_codes` (MFA recovery codes, consumed by positional index — reconstructed in `position` order).
- `idp_oauth_clients.client_secret_hash` has no database-level "hide by default" — every query lists its columns explicitly and only includes the secret hash when asked (`{ includeSecret: true }`). Don't change any repository query to `SELECT *`.
- Upserts (`ServiceKeyRepository.upsertByKid`, `ConsentRepository.upsert`) use T-SQL's `UPDATE ... WITH (UPDLOCK, HOLDLOCK)` then `INSERT` if `@@ROWCOUNT = 0`, inside an explicit transaction — T-SQL has no `ON CONFLICT DO UPDATE`, and the locking hints prevent two concurrent upserts of the same key both seeing zero rows and both attempting the INSERT.
- Pagination (`listMany`, `findMany`) uses native `OFFSET ... ROWS FETCH NEXT ... ROWS ONLY` — a direct equivalent of Postgres's `OFFSET/LIMIT`.
- Unlike MongoDB, SQL Server has no native TTL index — `pruneExpired()` on sessions/authorization-codes/verification-tokens is a **real** delete here, not a no-op. Schedule it yourself (a job/interval); idp-core never calls it automatically.
- `createSessionForLogin` (the composite write every login flow uses) runs as a real SQL Server transaction via `mssql`'s `Transaction`/`Request` classes. `idp_sessions.user_id` carries a real `FOREIGN KEY` against `idp_users(id)`, so this adapter's test suite verifies actual rollback behavior on a forced failure — no emulator-gap caveat, unlike the DynamoDB adapter's `TransactWriteItems` limitation.

## Testing

**No pure-JS/embeddable SQL Server emulator exists** (it's proprietary — unlike Postgres/DynamoDB, nobody has legally reimplemented it), so this is the one adapter in the family whose test suite needs a real SQL Server instance:

```bash
docker compose up -d   # or: podman compose up -d
npm test
```

Each test **file** gets its own freshly-created, uniquely-named database (`test/helpers/build-test-db.js`), migrated and dropped per run — `node --test` runs files concurrently by default, and a shared database would let one file's `truncateAll()` wipe out another file's in-progress rows mid-run. Connection defaults match `docker-compose.yml` (`127.0.0.1:14330`, `sa` / `IdpCore_Test_Pass123!`) and can be overridden via `MSSQL_TEST_HOST`, `MSSQL_TEST_PORT`, `MSSQL_TEST_USER`, `MSSQL_TEST_PASSWORD`.

## What this package does not do

- No connection pooling tuning beyond whatever you pass in `config.pool` (a plain `mssql` `ConnectionPool` config).
- No automatic migrations, no automatic `pruneExpired()` scheduling — both are your app's responsibility.
- No RBAC/authorization decisioning — same as idp-core itself; this package only implements storage.

## License

MIT © Okeav
