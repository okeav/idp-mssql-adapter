import crypto from 'node:crypto';
import sql from 'mssql';
import { mapServiceKeyRow } from '../util/row-mappers.js';

const PUBLISHABLE_STATUSES = ['ACTIVE', 'ROTATING'];

/** @implements {import('@okeav/idp-core/src/storage/interfaces.js').ServiceKeyRepository} */
export class MssqlServiceKeyRepository {
    constructor(pool) {
        this.pool = pool;
    }

    /**
     * Idempotent upsert by kid. T-SQL has no `ON CONFLICT DO UPDATE` — this
     * is the standard "UPDATE, check @@ROWCOUNT, INSERT if zero" pattern,
     * wrapped in a transaction with UPDLOCK+HOLDLOCK table hints so two
     * concurrent upserts of the SAME kid can't both see zero rows affected
     * and both attempt the INSERT (a well-known T-SQL upsert race).
     */
    async upsertByKid({ kid, name, publicKey, region }) {
        const transaction = new sql.Transaction(this.pool);
        await transaction.begin();
        try {
            const updateResult = await new sql.Request(transaction)
                .input('kid', sql.NVarChar, kid)
                .input('name', sql.NVarChar, name)
                .input('publicKey', sql.NVarChar(sql.MAX), publicKey)
                .input('region', sql.NVarChar, region || 'global')
                .query(`
                    UPDATE dbo.idp_service_keys WITH (UPDLOCK, HOLDLOCK)
                       SET name = @name, public_key = @publicKey, status = 'ACTIVE', region = @region, last_seen_at = SYSUTCDATETIME()
                     WHERE kid = @kid
                `);

            if (updateResult.rowsAffected[0] === 0) {
                await new sql.Request(transaction)
                    .input('id', sql.UniqueIdentifier, crypto.randomUUID())
                    .input('kid', sql.NVarChar, kid)
                    .input('name', sql.NVarChar, name)
                    .input('publicKey', sql.NVarChar(sql.MAX), publicKey)
                    .input('region', sql.NVarChar, region || 'global')
                    .query(`
                        INSERT INTO dbo.idp_service_keys (id, kid, name, public_key, status, region)
                        VALUES (@id, @kid, @name, @publicKey, 'ACTIVE', @region)
                    `);
            }
            await transaction.commit();
        } catch (err) {
            await transaction.rollback();
            throw err;
        }

        const { recordset } = await this.pool.request().input('kid', sql.NVarChar, kid).query('SELECT * FROM dbo.idp_service_keys WHERE kid = @kid');
        return mapServiceKeyRow(recordset[0]);
    }

    async listPublishable() {
        const { recordset } = await this.pool.request()
            .input('active', sql.NVarChar, PUBLISHABLE_STATUSES[0])
            .input('rotating', sql.NVarChar, PUBLISHABLE_STATUSES[1])
            .query('SELECT * FROM dbo.idp_service_keys WHERE status IN (@active, @rotating)');
        return recordset.map(mapServiceKeyRow);
    }
}
