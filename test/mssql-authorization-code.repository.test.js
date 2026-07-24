import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import sql from 'mssql';
import { buildTestDb } from './helpers/build-test-db.js';
import { MssqlAuthorizationCodeRepository } from '../src/repositories/mssql-authorization-code.repository.js';

let db, repo, userId;

before(async () => {
    db = await buildTestDb();
    repo = new MssqlAuthorizationCodeRepository(db.pool);
});
after(async () => db.stop());
beforeEach(async () => {
    await db.truncateAll();
    userId = crypto.randomUUID();
    await db.pool.request().input('id', sql.UniqueIdentifier, userId).input('email', sql.NVarChar, 'a@example.com')
        .query('INSERT INTO dbo.idp_users (id, email) VALUES (@id, @email)');
});

function sampleInput(overrides = {}) {
    return {
        code: 'hashed-code-1', clientId: 'client-1', userId, redirectUri: 'https://app.example.com/cb',
        scopes: ['openid', 'profile'], codeChallenge: null, codeChallengeMethod: null,
        expiresAt: new Date(Date.now() + 60_000), used: false,
        ...overrides,
    };
}

test('create + consumeByCodeHash marks used exactly once', async () => {
    await repo.create(sampleInput());

    const consumed = await repo.consumeByCodeHash('hashed-code-1');
    assert.ok(consumed);
    assert.equal(consumed.used, true);
    assert.equal(consumed.clientId, 'client-1');
    assert.deepEqual(consumed.scopes, ['openid', 'profile']);

    const secondAttempt = await repo.consumeByCodeHash('hashed-code-1');
    assert.equal(secondAttempt, null, 'a code must not be exchangeable twice');
});

test('consumeByCodeHash rejects an expired code', async () => {
    await repo.create(sampleInput({ code: 'expired-code', expiresAt: new Date(Date.now() - 1000) }));
    const result = await repo.consumeByCodeHash('expired-code');
    assert.equal(result, null);
});

test('pruneExpired deletes only expired rows', async () => {
    await repo.create(sampleInput({ code: 'fresh', expiresAt: new Date(Date.now() + 60_000) }));
    await repo.create(sampleInput({ code: 'stale', expiresAt: new Date(Date.now() - 60_000) }));

    const { deletedCount } = await repo.pruneExpired();
    assert.equal(deletedCount, 1);
});
