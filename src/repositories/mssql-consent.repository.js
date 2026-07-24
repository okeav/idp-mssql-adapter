import crypto from 'node:crypto';
import sql from 'mssql';
import { mapConsentRow } from '../util/row-mappers.js';

/** @implements {import('@okeav/idp-core/src/storage/interfaces.js').ConsentRepository} */
export class MssqlConsentRepository {
    constructor(pool) {
        this.pool = pool;
    }

    /** Same UPDATE-then-INSERT-if-zero upsert pattern as ServiceKeyRepository, with UPDLOCK+HOLDLOCK to avoid a race on the same (user_id, client_id) pair. */
    async upsert(userId, clientId, scopes) {
        const transaction = new sql.Transaction(this.pool);
        await transaction.begin();
        try {
            const updateResult = await new sql.Request(transaction)
                .input('userId', sql.UniqueIdentifier, userId)
                .input('clientId', sql.NVarChar, clientId)
                .input('scopes', sql.NVarChar(sql.MAX), JSON.stringify(scopes || []))
                .query(`
                    UPDATE dbo.idp_consents WITH (UPDLOCK, HOLDLOCK)
                       SET scopes = @scopes, granted_at = SYSUTCDATETIME(), is_revoked = 0, revoked_at = NULL, updated_at = SYSUTCDATETIME()
                     WHERE user_id = @userId AND client_id = @clientId
                `);

            if (updateResult.rowsAffected[0] === 0) {
                await new sql.Request(transaction)
                    .input('id', sql.UniqueIdentifier, crypto.randomUUID())
                    .input('userId', sql.UniqueIdentifier, userId)
                    .input('clientId', sql.NVarChar, clientId)
                    .input('scopes', sql.NVarChar(sql.MAX), JSON.stringify(scopes || []))
                    .query(`
                        INSERT INTO dbo.idp_consents (id, user_id, client_id, scopes, granted_at, is_revoked)
                        VALUES (@id, @userId, @clientId, @scopes, SYSUTCDATETIME(), 0)
                    `);
            }
            await transaction.commit();
        } catch (err) {
            await transaction.rollback();
            throw err;
        }

        return this.find(userId, clientId);
    }

    async find(userId, clientId) {
        const { recordset } = await this.pool.request()
            .input('userId', sql.UniqueIdentifier, userId)
            .input('clientId', sql.NVarChar, clientId)
            .query('SELECT * FROM dbo.idp_consents WHERE user_id = @userId AND client_id = @clientId AND is_revoked = 0');
        return mapConsentRow(recordset[0]);
    }

    async listForUser(userId) {
        const { recordset } = await this.pool.request()
            .input('userId', sql.UniqueIdentifier, userId)
            .query('SELECT * FROM dbo.idp_consents WHERE user_id = @userId AND is_revoked = 0');
        return recordset.map(mapConsentRow);
    }

    async revoke(userId, clientId) {
        await this.pool.request()
            .input('userId', sql.UniqueIdentifier, userId)
            .input('clientId', sql.NVarChar, clientId)
            .query(`
                UPDATE dbo.idp_consents SET is_revoked = 1, revoked_at = SYSUTCDATETIME(), updated_at = SYSUTCDATETIME()
                WHERE user_id = @userId AND client_id = @clientId
            `);
    }
}
