import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import sql from 'mssql';
import { buildTestDb } from './helpers/build-test-db.js';
import { MssqlConsentRepository } from '../src/repositories/mssql-consent.repository.js';

let db, repo, userId;

before(async () => {
    db = await buildTestDb();
    repo = new MssqlConsentRepository(db.pool);
});
after(async () => db.stop());
beforeEach(async () => {
    await db.truncateAll();
    userId = crypto.randomUUID();
    await db.pool.request().input('id', sql.UniqueIdentifier, userId).input('email', sql.NVarChar, 'a@example.com')
        .query('INSERT INTO dbo.idp_users (id, email) VALUES (@id, @email)');
});

test('upsert creates, then re-upsert updates scopes in place (no duplicate row)', async () => {
    const first = await repo.upsert(userId, 'client-1', ['openid']);
    assert.deepEqual(first.scopes, ['openid']);

    const second = await repo.upsert(userId, 'client-1', ['openid', 'profile', 'email']);
    assert.deepEqual(second.scopes, ['openid', 'profile', 'email']);

    const list = await repo.listForUser(userId);
    assert.equal(list.length, 1);
});

test('find only returns non-revoked consent', async () => {
    await repo.upsert(userId, 'client-2', ['openid']);
    assert.ok(await repo.find(userId, 'client-2'));

    await repo.revoke(userId, 'client-2');
    assert.equal(await repo.find(userId, 'client-2'), null);
});

test('re-upsert after revoke clears the revoked flag', async () => {
    await repo.upsert(userId, 'client-3', ['openid']);
    await repo.revoke(userId, 'client-3');
    assert.equal(await repo.find(userId, 'client-3'), null);

    await repo.upsert(userId, 'client-3', ['openid']);
    assert.ok(await repo.find(userId, 'client-3'));
});

test('listForUser lists only non-revoked consents', async () => {
    await repo.upsert(userId, 'client-a', ['openid']);
    await repo.upsert(userId, 'client-b', ['openid']);
    await repo.revoke(userId, 'client-b');

    const list = await repo.listForUser(userId);
    assert.equal(list.length, 1);
    assert.equal(list[0].clientId, 'client-a');
});
