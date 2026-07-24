import crypto from 'node:crypto';
import sql from 'mssql';
import { mapAuthorizationCodeRow } from '../util/row-mappers.js';

/** @implements {import('@okeav/idp-core/src/storage/interfaces.js').AuthorizationCodeRepository} */
export class MssqlAuthorizationCodeRepository {
    constructor(pool) {
        this.pool = pool;
    }

    async create(input) {
        await this.pool.request()
            .input('id', sql.UniqueIdentifier, crypto.randomUUID())
            .input('code', sql.NVarChar, input.code)
            .input('clientId', sql.NVarChar, input.clientId)
            .input('userId', sql.UniqueIdentifier, input.userId)
            .input('redirectUri', sql.NVarChar, input.redirectUri)
            .input('scopes', sql.NVarChar(sql.MAX), JSON.stringify(input.scopes || []))
            .input('codeChallenge', sql.NVarChar, input.codeChallenge || null)
            .input('codeChallengeMethod', sql.NVarChar, input.codeChallengeMethod || null)
            .input('expiresAt', sql.DateTime2, input.expiresAt)
            .input('used', sql.Bit, input.used ?? false)
            .query(`
                INSERT INTO dbo.idp_authorization_codes (id, code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at, used)
                VALUES (@id, @code, @clientId, @userId, @redirectUri, @scopes, @codeChallenge, @codeChallengeMethod, @expiresAt, @used)
            `);
    }

    /** Atomic find+mark-used via UPDATE...OUTPUT — the OAuth2 spec requires a code be exchangeable exactly once. */
    async consumeByCodeHash(hash) {
        const { recordset } = await this.pool.request()
            .input('code', sql.NVarChar, hash)
            .query(`
                UPDATE dbo.idp_authorization_codes
                   SET used = 1, used_at = SYSUTCDATETIME(), updated_at = SYSUTCDATETIME()
                OUTPUT INSERTED.*
                 WHERE code = @code AND used = 0 AND expires_at > SYSUTCDATETIME()
            `);
        return mapAuthorizationCodeRow(recordset[0]);
    }

    /** No native TTL sweep in SQL Server — a real delete, not a no-op. Schedule it yourself. */
    async pruneExpired() {
        const { recordset } = await this.pool.request().query(`
            DELETE FROM dbo.idp_authorization_codes OUTPUT DELETED.id WHERE expires_at < SYSUTCDATETIME()
        `);
        return { deletedCount: recordset.length };
    }
}
