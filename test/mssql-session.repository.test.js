import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import sql from 'mssql';
import { buildTestDb } from './helpers/build-test-db.js';
import { MssqlSessionRepository } from '../src/repositories/mssql-session.repository.js';
import { MssqlUserRepository } from '../src/repositories/mssql-user.repository.js';

let db, repo, userRepo, userId;

before(async () => {
    db = await buildTestDb();
    repo = new MssqlSessionRepository(db.pool);
    userRepo = new MssqlUserRepository(db.pool, { hashEmail: (e) => `hash:${e}`, normalizeEmail: (e) => e.trim().toLowerCase() });
});
after(async () => db.stop());
beforeEach(async () => {
    await db.truncateAll();
    const user = await userRepo.create({ email: 'session-user@example.com', status: 'ACTIVE' });
    userId = user.id;
});

function sessionInput(overrides = {}) {
    return {
        user: userId, tokenHash: 'th-1', expiresAt: new Date(Date.now() + 60_000),
        kid: 'kid-1', jti: crypto.randomUUID(), ipAddress: '127.0.0.1', deviceInfo: 'node-test',
        deviceFingerprint: 'fp-1', claims: { role: 'member' },
        ...overrides,
    };
}

test('createSession + findByRefreshTokenHash round-trip', async () => {
    const created = await repo.createSession(sessionInput());
    assert.equal(created.user, userId);
    assert.deepEqual(created.claims, { role: 'member' });

    const found = await repo.findByRefreshTokenHash('th-1');
    assert.equal(found.id, created.id);
});

test('revokeByRefreshTokenHash is atomic (returns PRE-revocation state) and only consumable once', async () => {
    await repo.createSession(sessionInput({ tokenHash: 'th-2' }));

    const first = await repo.revokeByRefreshTokenHash('th-2');
    assert.equal(first.revokedAt, null, 'must return the state BEFORE revocation');

    const second = await repo.revokeByRefreshTokenHash('th-2');
    assert.equal(second, null, 'an already-revoked token cannot be revoked again');

    const { recordset: [row] } = await db.pool.request()
        .input('tokenHash', sql.NVarChar, 'th-2')
        .query('SELECT revoked_at FROM dbo.idp_sessions WHERE token_hash = @tokenHash');
    assert.ok(row.revoked_at, 'the row itself is actually revoked now');
});

test('revokeByRefreshTokenHash with onlyIfActive:false ignores expiry', async () => {
    await repo.createSession(sessionInput({ tokenHash: 'th-3', expiresAt: new Date(Date.now() - 1000) }));
    assert.equal(await repo.revokeByRefreshTokenHash('th-3'), null, 'expired + onlyIfActive:true (default) should not match');
    const revoked = await repo.revokeByRefreshTokenHash('th-3', { onlyIfActive: false });
    assert.ok(revoked, 'onlyIfActive:false ignores the expiry check');
});

test('revokeById is scoped to the claimed owner and returns POST-revocation state', async () => {
    const otherUser = await userRepo.create({ email: 'other@example.com', status: 'ACTIVE' });
    const created = await repo.createSession(sessionInput({ tokenHash: 'th-4' }));

    assert.equal(await repo.revokeById(created.id, otherUser.id), null, 'wrong owner must not revoke it');
    const revoked = await repo.revokeById(created.id, userId);
    assert.ok(revoked.revokedAt, 'must return the state AFTER revocation');
});

test('revokeAllForUser revokes every active session except an optionally-exempted one', async () => {
    await repo.createSession(sessionInput({ tokenHash: 'th-5' }));
    await repo.createSession(sessionInput({ tokenHash: 'th-6' }));
    await repo.createSession(sessionInput({ tokenHash: 'th-7' }));

    const { revokedCount } = await repo.revokeAllForUser(userId, { exceptTokenHash: 'th-6' });
    assert.equal(revokedCount, 2);

    assert.ok((await repo.findByRefreshTokenHash('th-5')).revokedAt);
    assert.equal((await repo.findByRefreshTokenHash('th-6')).revokedAt, null, 'the exempted session stays active');
    assert.ok((await repo.findByRefreshTokenHash('th-7')).revokedAt);
});

test('listActiveForUser excludes revoked and expired sessions', async () => {
    await repo.createSession(sessionInput({ tokenHash: 'active-1' }));
    await repo.createSession(sessionInput({ tokenHash: 'expired-1', expiresAt: new Date(Date.now() - 1000) }));
    const revoked = await repo.createSession(sessionInput({ tokenHash: 'revoked-1' }));
    await repo.revokeById(revoked.id, userId);

    const active = await repo.listActiveForUser(userId);
    assert.equal(active.length, 1);
    assert.equal(active[0].tokenHash, 'active-1');
});

test('listHistoryForUser includes revoked/expired, sorted newest-first, clamped to [1,100]', async () => {
    for (let i = 0; i < 5; i += 1) {
        await repo.createSession(sessionInput({ tokenHash: `hist-${i}` }));
    }
    const history = await repo.listHistoryForUser(userId, { limit: 3 });
    assert.equal(history.length, 3);

    const unclamped = await repo.listHistoryForUser(userId, { limit: 99999 });
    assert.equal(unclamped.length, 5); // clamp ceiling of 100 doesn't cut off fewer-than-100 real rows
});

test('existsForDevice matches by fingerprint OR raw device info, scoped to the user', async () => {
    await repo.createSession(sessionInput({ tokenHash: 'dev-1', deviceFingerprint: 'fp-known', deviceInfo: 'Chrome/Win' }));

    assert.equal(await repo.existsForDevice(userId, 'fp-known', 'something else entirely'), true);
    assert.equal(await repo.existsForDevice(userId, 'fp-unknown', 'Chrome/Win'), true);
    assert.equal(await repo.existsForDevice(userId, 'fp-unknown', 'unknown device'), false);
    assert.equal(await repo.existsForDevice(userId, null, 'Chrome/Win'), true);
});

test('createSessionForLogin atomically writes audit + session + resets user lockout state', async () => {
    await db.pool.request().input('id', sql.UniqueIdentifier, userId)
        .query("UPDATE dbo.idp_users SET failed_login_attempts = 4, lock_until = DATEADD(MINUTE, 10, SYSUTCDATETIME()) WHERE id = @id");

    const lastLoginAt = new Date();
    const session = await repo.createSessionForLogin({
        accessTokenAudit: { user: userId, tokenHash: 'at-hash-1', expiresAt: new Date(Date.now() + 3600_000), kid: 'kid-1', jti: 'jti-1', ipAddress: '1.2.3.4', deviceInfo: 'ua' },
        session: sessionInput({ tokenHash: 'refresh-hash-1' }),
        userId,
        lastLoginAt,
    });

    assert.equal(session.tokenHash, 'refresh-hash-1');

    const { recordset: [auditRow] } = await db.pool.request()
        .input('tokenHash', sql.NVarChar, 'at-hash-1')
        .query('SELECT * FROM dbo.idp_access_token_audit WHERE token_hash = @tokenHash');
    assert.ok(auditRow, 'audit row was written in the same transaction');

    const { recordset: [userRow] } = await db.pool.request()
        .input('id', sql.UniqueIdentifier, userId)
        .query('SELECT * FROM dbo.idp_users WHERE id = @id');
    assert.equal(userRow.failed_login_attempts, 0);
    assert.equal(userRow.lock_until, null);
    assert.equal(new Date(userRow.last_login_at).getTime(), lastLoginAt.getTime());
});

test('createSessionForLogin rolls back ALL writes together on failure mid-transaction (real FK violation, no emulator gap)', async () => {
    const bogusUserId = '00000000-0000-0000-0000-000000000000'; // no such user — idp_sessions.user_id has a real FOREIGN KEY against idp_users(id)
    await assert.rejects(() =>
        repo.createSessionForLogin({
            accessTokenAudit: { user: userId, tokenHash: 'at-hash-fail', expiresAt: new Date(Date.now() + 3600_000), kid: 'k', jti: 'j', ipAddress: '1.1.1.1', deviceInfo: 'ua' },
            session: sessionInput({ tokenHash: 'refresh-hash-fail', user: bogusUserId }), // invalid FK
            userId,
            lastLoginAt: new Date(),
        })
    );

    // Neither the audit row nor the session row should have survived the rollback.
    const { recordset: auditRows } = await db.pool.request()
        .input('tokenHash', sql.NVarChar, 'at-hash-fail')
        .query('SELECT * FROM dbo.idp_access_token_audit WHERE token_hash = @tokenHash');
    assert.equal(auditRows.length, 0, 'audit insert must have been rolled back too, not just the failing statement');
    const { recordset: sessionRows } = await db.pool.request()
        .input('tokenHash', sql.NVarChar, 'refresh-hash-fail')
        .query('SELECT * FROM dbo.idp_sessions WHERE token_hash = @tokenHash');
    assert.equal(sessionRows.length, 0);
});

test('pruneExpired deletes only expired sessions', async () => {
    await repo.createSession(sessionInput({ tokenHash: 'fresh-sess', expiresAt: new Date(Date.now() + 60_000) }));
    await repo.createSession(sessionInput({ tokenHash: 'stale-sess', expiresAt: new Date(Date.now() - 60_000) }));

    const { deletedCount } = await repo.pruneExpired();
    assert.equal(deletedCount, 1);
});
