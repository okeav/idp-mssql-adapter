import crypto from 'node:crypto';
import sql from 'mssql';
import { mapOAuthClientRow, OAUTH_CLIENT_PUBLIC_COLUMNS } from '../util/row-mappers.js';

const COLUMN_FOR = {
    name: 'name', redirectUris: 'redirect_uris', allowedScopes: 'allowed_scopes', allowedGrants: 'allowed_grants',
    clientType: 'client_type', accessTokenTTL: 'access_token_ttl', refreshTokenTTL: 'refresh_token_ttl', idTokenTTL: 'id_token_ttl',
    logoUrl: 'logo_url', websiteUrl: 'website_url', privacyPolicyUrl: 'privacy_policy_url', termsOfServiceUrl: 'terms_of_service_url',
    supportEmail: 'support_email', metadata: 'metadata', status: 'status', clientSecretHash: 'client_secret_hash',
};
const JSON_KEYS = new Set(['redirectUris', 'allowedScopes', 'allowedGrants', 'metadata']);
const INT_KEYS = new Set(['accessTokenTTL', 'refreshTokenTTL', 'idTokenTTL']);

/**
 * `client_secret_hash` has no DB-level "hide by default" — every SELECT
 * lists the public columns explicitly, only including the secret column
 * when `{ includeSecret: true }` is passed. Don't change any query here to
 * `SELECT *`.
 *
 * @implements {import('@okeav/idp-core/src/storage/interfaces.js').OAuthClientRepository}
 */
export class MssqlOAuthClientRepository {
    constructor(pool) {
        this.pool = pool;
    }

    async create(input) {
        const id = crypto.randomUUID();
        await this.pool.request()
            .input('id', sql.UniqueIdentifier, id)
            .input('name', sql.NVarChar, input.name)
            .input('slug', sql.NVarChar, input.slug)
            .input('clientId', sql.NVarChar, input.clientId)
            .input('clientSecretHash', sql.NVarChar, input.clientSecretHash)
            .input('clientType', sql.NVarChar, input.clientType)
            .input('redirectUris', sql.NVarChar(sql.MAX), JSON.stringify(input.redirectUris || []))
            .input('allowedScopes', sql.NVarChar(sql.MAX), JSON.stringify(input.allowedScopes || []))
            .input('allowedGrants', sql.NVarChar(sql.MAX), JSON.stringify(input.allowedGrants || []))
            .input('status', sql.NVarChar, input.status)
            .input('metadata', sql.NVarChar(sql.MAX), JSON.stringify(input.metadata || {}))
            .query(`
                INSERT INTO dbo.idp_oauth_clients (id, name, slug, client_id, client_secret_hash, client_type, redirect_uris, allowed_scopes, allowed_grants, status, metadata)
                VALUES (@id, @name, @slug, @clientId, @clientSecretHash, @clientType, @redirectUris, @allowedScopes, @allowedGrants, @status, @metadata)
            `);
        return this.findByClientId(input.clientId);
    }

    async findByClientId(clientId, { includeSecret = false } = {}) {
        const columns = includeSecret ? `${OAUTH_CLIENT_PUBLIC_COLUMNS}, client_secret_hash` : OAUTH_CLIENT_PUBLIC_COLUMNS;
        const { recordset } = await this.pool.request()
            .input('clientId', sql.NVarChar, clientId)
            .query(`SELECT ${columns} FROM dbo.idp_oauth_clients WHERE client_id = @clientId`);
        return mapOAuthClientRow(recordset[0]);
    }

    async findBySlug(slug) {
        const { recordset } = await this.pool.request()
            .input('slug', sql.NVarChar, slug)
            .query(`SELECT ${OAUTH_CLIENT_PUBLIC_COLUMNS} FROM dbo.idp_oauth_clients WHERE slug = @slug`);
        return mapOAuthClientRow(recordset[0]);
    }

    async updateByClientId(clientId, patch) {
        const request = this.pool.request().input('clientId', sql.NVarChar, clientId);
        const setClauses = [];
        let i = 0;
        for (const [key, value] of Object.entries(patch)) {
            const column = COLUMN_FOR[key];
            if (!column) continue;
            const paramName = `p${i}`;
            const paramValue = JSON_KEYS.has(key) ? JSON.stringify(value) : value;
            const paramType = JSON_KEYS.has(key) ? sql.NVarChar(sql.MAX) : INT_KEYS.has(key) ? sql.Int : sql.NVarChar;
            request.input(paramName, paramType, paramValue);
            setClauses.push(`${column} = @${paramName}`);
            i += 1;
        }
        setClauses.push('updated_at = SYSUTCDATETIME()');

        await request.query(`UPDATE dbo.idp_oauth_clients SET ${setClauses.join(', ')} WHERE client_id = @clientId`);
        return this.findByClientId(clientId);
    }

    async listMany({ skip = 0, limit = 20 } = {}) {
        const { recordset } = await this.pool.request()
            .input('skip', sql.Int, skip)
            .input('limit', sql.Int, limit)
            .query(`
                SELECT ${OAUTH_CLIENT_PUBLIC_COLUMNS} FROM dbo.idp_oauth_clients
                ORDER BY created_at DESC OFFSET @skip ROWS FETCH NEXT @limit ROWS ONLY
            `);
        return recordset.map(mapOAuthClientRow);
    }

    async countAll() {
        const { recordset } = await this.pool.request().query('SELECT COUNT(*) AS count FROM dbo.idp_oauth_clients');
        return recordset[0].count;
    }
}
