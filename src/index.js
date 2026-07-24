import { createPool } from './pool.js';
import { expectedMigrationFilenames } from './migrations/run-migrations.js';
import { MssqlUserRepository } from './repositories/mssql-user.repository.js';
import { MssqlSessionRepository } from './repositories/mssql-session.repository.js';
import { MssqlAuthorizationCodeRepository } from './repositories/mssql-authorization-code.repository.js';
import { MssqlConsentRepository } from './repositories/mssql-consent.repository.js';
import { MssqlOAuthClientRepository } from './repositories/mssql-oauth-client.repository.js';
import { MssqlVerificationTokenRepository } from './repositories/mssql-verification-token.repository.js';
import { MssqlServiceKeyRepository } from './repositories/mssql-service-key.repository.js';
import { MssqlCredentialRepository } from './repositories/mssql-credential.repository.js';

export { runMigrations } from './migrations/run-migrations.js';

/**
 * SQL Server storage adapter for @okeav/idp-core. Wire it in via
 * `config.storage.factory` — see README.md.
 *
 * Does NOT run migrations itself (call `runMigrations()` explicitly at your
 * own deploy/startup step — see README.md for why) but DOES do a cheap
 * read-only check that the migrations this package version expects have
 * actually been applied, failing loudly with an actionable error if not,
 * mirroring the Postgres/DynamoDB adapters' startup checks. Set
 * `config.skipMigrationCheck: true` to skip this (e.g. a CI job reusing a
 * known-good database) and shave the round trip off startup.
 *
 * @param {{ pool: import('mssql').config, skipMigrationCheck?: boolean }} config
 * @param {{ hashEmail: (email: string) => string, normalizeEmail: (email: string) => string }} emailDeps
 */
export async function createMssqlStorage(config, emailDeps) {
    const pool = await createPool(config.pool);

    if (!config.skipMigrationCheck) {
        await assertMigrationsApplied(pool);
    }

    return {
        pool,
        close: () => pool.close(),
        userRepository: new MssqlUserRepository(pool, emailDeps),
        sessionRepository: new MssqlSessionRepository(pool),
        authorizationCodeRepository: new MssqlAuthorizationCodeRepository(pool),
        consentRepository: new MssqlConsentRepository(pool),
        oauthClientRepository: new MssqlOAuthClientRepository(pool),
        verificationTokenRepository: new MssqlVerificationTokenRepository(pool),
        serviceKeyRepository: new MssqlServiceKeyRepository(pool),
        credentialRepository: new MssqlCredentialRepository(pool),
    };
}

async function assertMigrationsApplied(pool) {
    const expected = await expectedMigrationFilenames();
    let appliedRows;
    try {
        ({ recordset: appliedRows } = await pool.request().query('SELECT filename FROM dbo.idp_schema_migrations'));
    } catch (err) {
        throw new Error(
            'idp-core-mssql: idp_schema_migrations table not found — have you run runMigrations() against this ' +
            'database yet? See README.md "Migrations". Set config.skipMigrationCheck:true to skip this check.',
            { cause: err }
        );
    }
    const applied = new Set(appliedRows.map((r) => r.filename));
    const missing = expected.filter((f) => !applied.has(f));
    if (missing.length > 0) {
        throw new Error(
            `idp-core-mssql: this database is missing migration(s) this package version expects: ${missing.join(', ')}. ` +
            'Run runMigrations() against it first. Set config.skipMigrationCheck:true to skip this check.'
        );
    }
}
