import { test } from 'node:test';
import assert from 'node:assert/strict';
import sql from 'mssql';
import { buildTestDb } from './helpers/build-test-db.js';

test('buildTestDb: migrations apply and the pool can query real SQL Server', async () => {
    const db = await buildTestDb();
    try {
        const { recordset } = await db.pool.request().query('SELECT COUNT(*) AS count FROM dbo.idp_schema_migrations');
        assert.equal(recordset[0].count, 1);

        const { recordset: tables } = await db.pool.request().query('SELECT name FROM sys.tables ORDER BY name');
        const names = tables.map((r) => r.name);
        assert.ok(names.includes('idp_users'));
        assert.ok(names.includes('idp_sessions'));
        assert.ok(names.includes('idp_credentials'));

        await db.pool.request()
            .input('id', sql.UniqueIdentifier, '11111111-1111-1111-1111-111111111111')
            .query("INSERT INTO dbo.idp_users (id, email, email_hash) VALUES (@id, 'a@example.com', 'hash1')");

        const { recordset: users } = await db.pool.request().query('SELECT * FROM dbo.idp_users');
        assert.equal(users.length, 1);
        assert.equal(users[0].email, 'a@example.com');

        await db.truncateAll();
        const { recordset: afterTruncate } = await db.pool.request().query('SELECT * FROM dbo.idp_users');
        assert.equal(afterTruncate.length, 0);
    } finally {
        await db.stop();
    }
});
