import crypto from 'node:crypto';
import sql from 'mssql';
import { mapSessionRow, lowerGuid } from '../util/row-mappers.js';

const LIST_COLUMNS = 'id, user_id, ip_address, device_info, device_fingerprint, created_at, expires_at, revoked_at, token_hash';

function mapListRow(row) {
    if (!row) return null;
    return {
        id: lowerGuid(row.id), user: lowerGuid(row.user_id), ipAddress: row.ip_address, deviceInfo: row.device_info,
        deviceFingerprint: row.device_fingerprint, createdAt: row.created_at, expiresAt: row.expires_at,
        revokedAt: row.revoked_at, tokenHash: row.token_hash,
    };
}

/** @implements {import('@okeav/idp-core/src/storage/interfaces.js').SessionRepository} */
export class MssqlSessionRepository {
    constructor(pool) {
        this.pool = pool;
    }

    async createSession(input) {
        const { recordset: [row] } = await this.pool.request()
            .input('id', sql.UniqueIdentifier, crypto.randomUUID())
            .input('userId', sql.UniqueIdentifier, input.user)
            .input('tokenHash', sql.NVarChar, input.tokenHash)
            .input('expiresAt', sql.DateTime2, input.expiresAt)
            .input('kid', sql.NVarChar, input.kid)
            .input('jti', sql.NVarChar, input.jti)
            .input('ipAddress', sql.NVarChar, input.ipAddress || null)
            .input('deviceInfo', sql.NVarChar, input.deviceInfo || null)
            .input('deviceFingerprint', sql.NVarChar, input.deviceFingerprint || null)
            .input('claims', sql.NVarChar(sql.MAX), JSON.stringify(input.claims || {}))
            .query(`
                INSERT INTO dbo.idp_sessions (id, user_id, token_hash, expires_at, kid, jti, ip_address, device_info, device_fingerprint, claims)
                OUTPUT INSERTED.*
                VALUES (@id, @userId, @tokenHash, @expiresAt, @kid, @jti, @ipAddress, @deviceInfo, @deviceFingerprint, @claims)
            `);
        return mapSessionRow(row);
    }

    async findByRefreshTokenHash(hash) {
        const { recordset: [row] } = await this.pool.request()
            .input('tokenHash', sql.NVarChar, hash)
            .query('SELECT * FROM dbo.idp_sessions WHERE token_hash = @tokenHash');
        return mapSessionRow(row);
    }

    /** Atomic find+revoke — a single UPDATE...OUTPUT means only one concurrent caller can successfully consume a given refresh token. Returns the PRE-revocation row (Mongo's returnDocument:'before' equivalent) — the WHERE clause required revoked_at IS NULL to match, so it's known to have been null going in. */
    async revokeByRefreshTokenHash(hash, { onlyIfActive = true } = {}) {
        const expiryClause = onlyIfActive ? 'AND expires_at > SYSUTCDATETIME()' : '';
        const { recordset: [row] } = await this.pool.request()
            .input('tokenHash', sql.NVarChar, hash)
            .query(`
                UPDATE dbo.idp_sessions SET revoked_at = SYSUTCDATETIME(), updated_at = SYSUTCDATETIME()
                OUTPUT DELETED.*
                WHERE token_hash = @tokenHash AND revoked_at IS NULL ${expiryClause}
            `);
        // OUTPUT DELETED.* on an UPDATE yields the pre-update row image, and
        // the WHERE clause required revoked_at IS NULL to match, so this
        // already IS the pre-revocation state — no override needed (unlike a
        // driver that only returns the post-update row).
        return mapSessionRow(row);
    }

    async revokeById(id, userId) {
        const { recordset: [row] } = await this.pool.request()
            .input('id', sql.UniqueIdentifier, id)
            .input('userId', sql.UniqueIdentifier, userId)
            .query(`
                UPDATE dbo.idp_sessions SET revoked_at = SYSUTCDATETIME(), updated_at = SYSUTCDATETIME()
                OUTPUT INSERTED.*
                WHERE id = @id AND user_id = @userId AND revoked_at IS NULL
            `);
        return mapSessionRow(row);
    }

    async revokeAllForUser(userId, { exceptTokenHash } = {}) {
        const request = this.pool.request().input('userId', sql.UniqueIdentifier, userId);
        let exceptClause = '';
        if (exceptTokenHash) {
            request.input('exceptTokenHash', sql.NVarChar, exceptTokenHash);
            exceptClause = 'AND token_hash != @exceptTokenHash';
        }
        const { rowsAffected } = await request.query(
            `UPDATE dbo.idp_sessions SET revoked_at = SYSUTCDATETIME(), updated_at = SYSUTCDATETIME() WHERE user_id = @userId AND revoked_at IS NULL ${exceptClause}`
        );
        return { revokedCount: rowsAffected[0] };
    }

    async listActiveForUser(userId) {
        const { recordset } = await this.pool.request()
            .input('userId', sql.UniqueIdentifier, userId)
            .query(`SELECT ${LIST_COLUMNS} FROM dbo.idp_sessions WHERE user_id = @userId AND revoked_at IS NULL AND expires_at > SYSUTCDATETIME() ORDER BY created_at DESC`);
        return recordset.map(mapListRow);
    }

    async listHistoryForUser(userId, { limit = 20 } = {}) {
        const clamped = Math.min(Math.max(limit, 1), 100);
        const { recordset } = await this.pool.request()
            .input('userId', sql.UniqueIdentifier, userId)
            .input('limit', sql.Int, clamped)
            .query(`SELECT TOP (@limit) ${LIST_COLUMNS} FROM dbo.idp_sessions WHERE user_id = @userId ORDER BY created_at DESC`);
        return recordset.map(mapListRow);
    }

    async existsForDevice(userId, fingerprint, rawDeviceInfo) {
        const request = this.pool.request().input('userId', sql.UniqueIdentifier, userId);
        let query;
        if (fingerprint) {
            request.input('fingerprint', sql.NVarChar, fingerprint).input('deviceInfo', sql.NVarChar, rawDeviceInfo);
            query = 'SELECT TOP 1 1 AS hit FROM dbo.idp_sessions WHERE user_id = @userId AND (device_fingerprint = @fingerprint OR device_info = @deviceInfo)';
        } else {
            request.input('deviceInfo', sql.NVarChar, rawDeviceInfo);
            query = 'SELECT TOP 1 1 AS hit FROM dbo.idp_sessions WHERE user_id = @userId AND device_info = @deviceInfo';
        }
        const { recordset } = await request.query(query);
        return recordset.length > 0;
    }

    /** Optional — write-only audit trail. */
    async recordIssuedAccessToken(entry) {
        await this.pool.request()
            .input('id', sql.UniqueIdentifier, crypto.randomUUID())
            .input('userId', sql.UniqueIdentifier, entry.user)
            .input('tokenHash', sql.NVarChar, entry.tokenHash)
            .input('expiresAt', sql.DateTime2, entry.expiresAt)
            .input('kid', sql.NVarChar, entry.kid)
            .input('jti', sql.NVarChar, entry.jti)
            .input('ipAddress', sql.NVarChar, entry.ipAddress || null)
            .input('deviceInfo', sql.NVarChar, entry.deviceInfo || null)
            .query(`
                INSERT INTO dbo.idp_access_token_audit (id, user_id, token_hash, expires_at, kid, jti, ip_address, device_info)
                VALUES (@id, @userId, @tokenHash, @expiresAt, @kid, @jti, @ipAddress, @deviceInfo)
            `);
    }

    /**
     * Composite, atomic "create a login session" operation — the 3-row write
     * (access-token audit + session + user.lastLoginAt/lockout-reset) that
     * password/MFA-verify/SSO/magic-link/WebAuthn login flows each need,
     * wrapped in a real SQL Server transaction via mssql's Transaction/Request
     * classes. `idp_sessions.user_id` has a real FOREIGN KEY against
     * `idp_users(id)`, so an invalid userId fails the session INSERT and
     * triggers a genuine rollback — no emulator-gap workaround needed here,
     * unlike the DynamoDB adapter.
     */
    async createSessionForLogin({ accessTokenAudit, session, userId, lastLoginAt }) {
        const transaction = new sql.Transaction(this.pool);
        await transaction.begin();
        try {
            if (accessTokenAudit) {
                await new sql.Request(transaction)
                    .input('id', sql.UniqueIdentifier, crypto.randomUUID())
                    .input('userId', sql.UniqueIdentifier, accessTokenAudit.user)
                    .input('tokenHash', sql.NVarChar, accessTokenAudit.tokenHash)
                    .input('expiresAt', sql.DateTime2, accessTokenAudit.expiresAt)
                    .input('kid', sql.NVarChar, accessTokenAudit.kid)
                    .input('jti', sql.NVarChar, accessTokenAudit.jti)
                    .input('ipAddress', sql.NVarChar, accessTokenAudit.ipAddress || null)
                    .input('deviceInfo', sql.NVarChar, accessTokenAudit.deviceInfo || null)
                    .query(`
                        INSERT INTO dbo.idp_access_token_audit (id, user_id, token_hash, expires_at, kid, jti, ip_address, device_info)
                        VALUES (@id, @userId, @tokenHash, @expiresAt, @kid, @jti, @ipAddress, @deviceInfo)
                    `);
            }

            const { recordset: [sessionRow] } = await new sql.Request(transaction)
                .input('id', sql.UniqueIdentifier, crypto.randomUUID())
                .input('userId', sql.UniqueIdentifier, session.user)
                .input('tokenHash', sql.NVarChar, session.tokenHash)
                .input('expiresAt', sql.DateTime2, session.expiresAt)
                .input('kid', sql.NVarChar, session.kid)
                .input('jti', sql.NVarChar, session.jti)
                .input('ipAddress', sql.NVarChar, session.ipAddress || null)
                .input('deviceInfo', sql.NVarChar, session.deviceInfo || null)
                .input('deviceFingerprint', sql.NVarChar, session.deviceFingerprint || null)
                .input('claims', sql.NVarChar(sql.MAX), JSON.stringify(session.claims || {}))
                .query(`
                    INSERT INTO dbo.idp_sessions (id, user_id, token_hash, expires_at, kid, jti, ip_address, device_info, device_fingerprint, claims)
                    OUTPUT INSERTED.*
                    VALUES (@id, @userId, @tokenHash, @expiresAt, @kid, @jti, @ipAddress, @deviceInfo, @deviceFingerprint, @claims)
                `);

            await new sql.Request(transaction)
                .input('id', sql.UniqueIdentifier, userId)
                .input('lastLoginAt', sql.DateTime2, lastLoginAt)
                .query(`
                    UPDATE dbo.idp_users SET last_login_at = @lastLoginAt, failed_login_attempts = 0, lock_until = NULL, updated_at = SYSUTCDATETIME()
                    WHERE id = @id
                `);

            await transaction.commit();
            return mapSessionRow(sessionRow);
        } catch (err) {
            await transaction.rollback();
            throw err;
        }
    }

    /** No native TTL in SQL Server (unlike Mongo) — a real delete, not a no-op. Schedule it yourself. */
    async pruneExpired() {
        const { rowsAffected } = await this.pool.request()
            .query('DELETE FROM dbo.idp_sessions WHERE expires_at < SYSUTCDATETIME()');
        return { deletedCount: rowsAffected[0] };
    }
}
