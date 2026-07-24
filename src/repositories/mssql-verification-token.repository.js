import crypto from 'node:crypto';
import sql from 'mssql';
import { mapVerificationTokenRow } from '../util/row-mappers.js';

const DELETE_ON_CONSUME_KINDS = new Set(['email_verification', 'magic_link']);

/** @implements {import('@okeav/idp-core/src/storage/interfaces.js').VerificationTokenRepository} */
export class MssqlVerificationTokenRepository {
    constructor(pool) {
        this.pool = pool;
    }

    async create(kind, input) {
        await this.pool.request()
            .input('id', sql.UniqueIdentifier, crypto.randomUUID())
            .input('kind', sql.NVarChar, kind)
            .input('userId', sql.UniqueIdentifier, input.user)
            .input('tokenHash', sql.NVarChar, input.tokenHash)
            .input('verificationCode', sql.NVarChar, input.verificationCode || null)
            .input('expiresAt', sql.DateTime2, input.expiresAt)
            .query(`
                INSERT INTO dbo.idp_verification_tokens (id, kind, user_id, token_hash, verification_code, expires_at)
                VALUES (@id, @kind, @userId, @tokenHash, @verificationCode, @expiresAt)
            `);
    }

    /**
     * `userId`, when given, scopes the consume to the claimed identity
     * (password reset). email_verification/magic_link are single-use-by-
     * deletion (matching idp-core's Mongo adapter); password_reset instead
     * flags `used_at`, keeping the row.
     */
    async consumeByHash(kind, hash, userId) {
        const request = this.pool.request().input('kind', sql.NVarChar, kind).input('hash', sql.NVarChar, hash);
        let userClause = '';
        if (userId) { request.input('userId', sql.UniqueIdentifier, userId); userClause = 'AND user_id = @userId'; }

        if (DELETE_ON_CONSUME_KINDS.has(kind)) {
            const { recordset } = await request.query(`
                DELETE FROM dbo.idp_verification_tokens
                OUTPUT DELETED.*
                 WHERE kind = @kind AND token_hash = @hash AND used_at IS NULL AND expires_at > SYSUTCDATETIME() ${userClause}
            `);
            return mapVerificationTokenRow(recordset[0]);
        }

        const { recordset } = await request.query(`
            UPDATE dbo.idp_verification_tokens
               SET used_at = SYSUTCDATETIME(), updated_at = SYSUTCDATETIME()
            OUTPUT INSERTED.*
             WHERE kind = @kind AND token_hash = @hash AND used_at IS NULL AND expires_at > SYSUTCDATETIME() ${userClause}
        `);
        return mapVerificationTokenRow(recordset[0]);
    }

    async consumeByCode(kind, code, userId) {
        const { recordset } = await this.pool.request()
            .input('kind', sql.NVarChar, kind)
            .input('code', sql.NVarChar, code)
            .input('userId', sql.UniqueIdentifier, userId)
            .query(`
                DELETE FROM dbo.idp_verification_tokens
                OUTPUT DELETED.*
                 WHERE kind = @kind AND verification_code = @code AND user_id = @userId AND expires_at > SYSUTCDATETIME()
            `);
        return mapVerificationTokenRow(recordset[0]);
    }

    async deleteAllForUser(kind, userId) {
        await this.pool.request()
            .input('kind', sql.NVarChar, kind)
            .input('userId', sql.UniqueIdentifier, userId)
            .query('DELETE FROM dbo.idp_verification_tokens WHERE kind = @kind AND user_id = @userId');
    }

    /** No native TTL sweep in SQL Server — a real delete, not a no-op. */
    async pruneExpired() {
        const { recordset } = await this.pool.request().query(`
            DELETE FROM dbo.idp_verification_tokens OUTPUT DELETED.id WHERE expires_at < SYSUTCDATETIME()
        `);
        return { deletedCount: recordset.length };
    }
}
