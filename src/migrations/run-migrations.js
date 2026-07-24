import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import sql from 'mssql';

const DEFAULT_SQL_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'sql');

/**
 * Applies every not-yet-applied `NNNN_description.sql` file in `dir` (default:
 * this package's own bundled migrations) against `pool`, in filename order,
 * each inside its own transaction, tracked in `idp_schema_migrations`.
 *
 * Deliberately NOT called automatically by `createMssqlStorage()` — the
 * consuming app calls this explicitly at its own deploy/startup step, same
 * as the Postgres/DynamoDB adapters.
 *
 * @param {import('mssql').ConnectionPool} pool
 * @param {{ dir?: string }} [opts]
 * @returns {Promise<string[]>} filenames newly applied this run
 */
export async function runMigrations(pool, { dir = DEFAULT_SQL_DIR } = {}) {
    await pool.request().batch(`
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'idp_schema_migrations')
        BEGIN
            CREATE TABLE dbo.idp_schema_migrations (
                filename NVARCHAR(255) PRIMARY KEY,
                applied_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
            );
        END
    `);

    const { recordset: appliedRows } = await pool.request().query('SELECT filename FROM dbo.idp_schema_migrations');
    const applied = new Set(appliedRows.map((r) => r.filename));

    const files = (await fs.readdir(dir)).filter((f) => f.endsWith('.sql')).sort();
    const newlyApplied = [];

    for (const filename of files) {
        if (applied.has(filename)) continue;

        const sqlText = await fs.readFile(path.join(dir, filename), 'utf8');
        const transaction = new sql.Transaction(pool);
        await transaction.begin();
        try {
            await new sql.Request(transaction).batch(sqlText);
            await new sql.Request(transaction)
                .input('filename', sql.NVarChar, filename)
                .query('INSERT INTO dbo.idp_schema_migrations (filename) VALUES (@filename)');
            await transaction.commit();
            newlyApplied.push(filename);
        } catch (err) {
            await transaction.rollback();
            throw new Error(`Migration ${filename} failed: ${err.message}`, { cause: err });
        }
    }

    return newlyApplied;
}

/** Names of every migration file bundled with this package version — used by createMssqlStorage's startup check. */
export async function expectedMigrationFilenames({ dir = DEFAULT_SQL_DIR } = {}) {
    return (await fs.readdir(dir)).filter((f) => f.endsWith('.sql')).sort();
}
