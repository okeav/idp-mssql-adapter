import crypto from 'node:crypto';
import sql from 'mssql';
import { mapCredentialRow } from '../util/row-mappers.js';

/** @implements {import('@okeav/idp-core/src/storage/interfaces.js').CredentialRepository} */
export class MssqlCredentialRepository {
    constructor(pool) {
        this.pool = pool;
    }

    async create({ userId, credentialId, publicKey, counter, transports, deviceType, backedUp, name }) {
        const id = crypto.randomUUID();
        await this.pool.request()
            .input('id', sql.UniqueIdentifier, id)
            .input('userId', sql.UniqueIdentifier, userId)
            .input('credentialId', sql.NVarChar, credentialId)
            .input('publicKey', sql.NVarChar(sql.MAX), publicKey)
            .input('counter', sql.BigInt, counter ?? 0)
            .input('transports', sql.NVarChar(sql.MAX), JSON.stringify(transports || []))
            .input('deviceType', sql.NVarChar, deviceType || 'singleDevice')
            .input('backedUp', sql.Bit, backedUp ?? false)
            .input('name', sql.NVarChar, name ?? null)
            .query(`
                INSERT INTO dbo.idp_credentials (id, user_id, credential_id, public_key, counter, transports, device_type, backed_up, name)
                VALUES (@id, @userId, @credentialId, @publicKey, @counter, @transports, @deviceType, @backedUp, @name)
            `);
        return this.findByCredentialId(credentialId);
    }

    async findByCredentialId(credentialId) {
        const { recordset } = await this.pool.request()
            .input('credentialId', sql.NVarChar, credentialId)
            .query('SELECT * FROM dbo.idp_credentials WHERE credential_id = @credentialId');
        return mapCredentialRow(recordset[0]);
    }

    async findByUserId(userId) {
        const { recordset } = await this.pool.request()
            .input('userId', sql.UniqueIdentifier, userId)
            .query('SELECT * FROM dbo.idp_credentials WHERE user_id = @userId');
        return recordset.map(mapCredentialRow);
    }

    async updateCounter(credentialId, newCounter) {
        await this.pool.request()
            .input('credentialId', sql.NVarChar, credentialId)
            .input('counter', sql.BigInt, newCounter)
            .query(`
                UPDATE dbo.idp_credentials SET counter = @counter, last_used_at = SYSUTCDATETIME(), updated_at = SYSUTCDATETIME()
                WHERE credential_id = @credentialId
            `);
    }

    async deleteByCredentialId(credentialId, userId) {
        await this.pool.request()
            .input('credentialId', sql.NVarChar, credentialId)
            .input('userId', sql.UniqueIdentifier, userId)
            .query('DELETE FROM dbo.idp_credentials WHERE credential_id = @credentialId AND user_id = @userId');
    }

    async countForUser(userId) {
        const { recordset } = await this.pool.request()
            .input('userId', sql.UniqueIdentifier, userId)
            .query('SELECT COUNT(*) AS count FROM dbo.idp_credentials WHERE user_id = @userId');
        return recordset[0].count;
    }
}
