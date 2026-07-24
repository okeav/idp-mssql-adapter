import crypto from 'node:crypto';
import sql from 'mssql';
import { resolveUserSelect, applyUserSelect, splitUserPatch, assembleUser } from '../util/user-mapping.js';

// updateById's column-set values arrive as plain JS values (string/boolean/
// Date/number/null) and mssql, unlike pg, needs an explicit sql.* type per
// bound parameter — it will not infer BIT/DATETIME2/INT from the JS value
// the way pg infers timestamp/boolean/int from a $n placeholder.
const SQL_TYPE_FOR_COLUMN = {
    email: sql.NVarChar,
    password_hash: sql.NVarChar,
    status: sql.NVarChar,
    last_login_at: sql.DateTime2,
    password_changed_at: sql.DateTime2,
    failed_login_attempts: sql.Int,
    lock_until: sql.DateTime2,
    mfa_enabled: sql.Bit,
    mfa_secret: sql.NVarChar,
    mfa_temp_secret: sql.NVarChar,
    metadata: sql.NVarChar(sql.MAX),
    profile_first_name: sql.NVarChar,
    profile_last_name: sql.NVarChar,
    profile_display_name: sql.NVarChar,
    profile_avatar_url: sql.NVarChar,
    profile_locale: sql.NVarChar,
    profile_zoneinfo: sql.NVarChar,
};

/** @implements {import('@okeav/idp-core/src/storage/interfaces.js').UserRepository} */
export class MssqlUserRepository {
    constructor(pool, { hashEmail, normalizeEmail }) {
        this.pool = pool;
        this.hashEmail = hashEmail;
        this.normalizeEmail = normalizeEmail;
    }

    async _loadFull(id) {
        const { recordset: [userRow] } = await this.pool.request()
            .input('id', sql.UniqueIdentifier, id)
            .query('SELECT * FROM dbo.idp_users WHERE id = @id');
        if (!userRow) return null;
        const [{ recordset: externalProviders }, { recordset: recoveryCodes }] = await Promise.all([
            this.pool.request().input('id', sql.UniqueIdentifier, id)
                .query('SELECT * FROM dbo.idp_user_external_providers WHERE user_id = @id'),
            this.pool.request().input('id', sql.UniqueIdentifier, id)
                .query('SELECT * FROM dbo.idp_user_recovery_codes WHERE user_id = @id ORDER BY position ASC'),
        ]);
        return assembleUser(userRow, { externalProviders, recoveryCodes });
    }

    async create(data) {
        const id = crypto.randomUUID();
        const normalizedEmail = this.normalizeEmail(data.email);
        const emailHash = this.hashEmail(data.email);
        const profile = data.profile || {};

        const transaction = new sql.Transaction(this.pool);
        await transaction.begin();
        try {
            await new sql.Request(transaction)
                .input('id', sql.UniqueIdentifier, id)
                .input('email', sql.NVarChar, normalizedEmail)
                .input('emailHash', sql.NVarChar, emailHash)
                .input('passwordHash', sql.NVarChar, data.passwordHash || null)
                .input('status', sql.NVarChar, data.status || 'PENDING_VERIFICATION')
                .input('firstName', sql.NVarChar, profile.firstName || null)
                .input('lastName', sql.NVarChar, profile.lastName || null)
                .input('displayName', sql.NVarChar, profile.displayName || null)
                .input('avatarUrl', sql.NVarChar, profile.avatarUrl || null)
                .input('locale', sql.NVarChar, profile.locale || 'en')
                .input('zoneinfo', sql.NVarChar, profile.zoneinfo || null)
                .input('metadata', sql.NVarChar(sql.MAX), JSON.stringify(data.metadata || {}))
                .query(`
                    INSERT INTO dbo.idp_users (
                        id, email, email_hash, password_hash, status,
                        profile_first_name, profile_last_name, profile_display_name, profile_avatar_url, profile_locale, profile_zoneinfo,
                        metadata
                    ) VALUES (@id, @email, @emailHash, @passwordHash, @status, @firstName, @lastName, @displayName, @avatarUrl, @locale, @zoneinfo, @metadata)
                `);

            for (const ep of data.externalProviders || []) {
                await new sql.Request(transaction)
                    .input('userId', sql.UniqueIdentifier, id)
                    .input('provider', sql.NVarChar, ep.provider)
                    .input('providerId', sql.NVarChar, ep.providerId)
                    .input('email', sql.NVarChar, ep.email || null)
                    .input('connectedAt', sql.DateTime2, ep.connectedAt || new Date())
                    .query(`
                        INSERT INTO dbo.idp_user_external_providers (user_id, provider, provider_id, email, connected_at)
                        VALUES (@userId, @provider, @providerId, @email, @connectedAt)
                    `);
            }
            await transaction.commit();
        } catch (err) {
            await transaction.rollback();
            throw err;
        }

        return this._loadFull(id);
    }

    async findById(id, opts = {}) {
        const user = await this._loadFull(id);
        return applyUserSelect(user, resolveUserSelect(opts.select));
    }

    async findByEmail(email, opts = {}) {
        const normalizedEmail = this.normalizeEmail(email);
        const emailHash = this.hashEmail(email);
        const { recordset: [userRow] } = await this.pool.request()
            .input('emailHash', sql.NVarChar, emailHash)
            .input('email', sql.NVarChar, normalizedEmail)
            .query('SELECT id FROM dbo.idp_users WHERE email_hash = @emailHash OR email = @email');
        if (!userRow) return null;
        const user = await this._loadFull(userRow.id);
        return applyUserSelect(user, resolveUserSelect(opts.select));
    }

    async findByExternalProvider(provider, providerId) {
        const { recordset: [row] } = await this.pool.request()
            .input('provider', sql.NVarChar, provider)
            .input('providerId', sql.NVarChar, providerId)
            .query('SELECT user_id FROM dbo.idp_user_external_providers WHERE provider = @provider AND provider_id = @providerId');
        if (!row) return null;
        return this._loadFull(row.user_id);
    }

    async updateById(id, patch, opts = {}) {
        const { columnSets, recoveryCodesReplace, recoveryCodeConsume } = splitUserPatch(patch);

        const transaction = new sql.Transaction(this.pool);
        await transaction.begin();
        try {
            if (columnSets.length > 0) {
                const request = new sql.Request(transaction).input('id', sql.UniqueIdentifier, id);
                const setClauses = columnSets.map((c, i) => {
                    const paramName = `p${i}`;
                    request.input(paramName, SQL_TYPE_FOR_COLUMN[c.column] || sql.NVarChar, c.value);
                    return `${c.column} = @${paramName}`;
                });
                setClauses.push('updated_at = SYSUTCDATETIME()');
                await request.query(`UPDATE dbo.idp_users SET ${setClauses.join(', ')} WHERE id = @id`);
            } else {
                // Nothing on the users table itself changed (e.g. a pure
                // recovery-codes replace), but Mongo's timestamps:true bumps
                // updatedAt on ANY findByIdAndUpdate — mirror that.
                await new sql.Request(transaction).input('id', sql.UniqueIdentifier, id)
                    .query('UPDATE dbo.idp_users SET updated_at = SYSUTCDATETIME() WHERE id = @id');
            }

            if (recoveryCodesReplace) {
                await new sql.Request(transaction).input('id', sql.UniqueIdentifier, id)
                    .query('DELETE FROM dbo.idp_user_recovery_codes WHERE user_id = @id');
                for (let position = 0; position < recoveryCodesReplace.length; position += 1) {
                    const entry = recoveryCodesReplace[position];
                    await new sql.Request(transaction)
                        .input('userId', sql.UniqueIdentifier, id)
                        .input('position', sql.SmallInt, position)
                        .input('codeHash', sql.NVarChar, entry.codeHash)
                        .input('usedAt', sql.DateTime2, entry.usedAt || null)
                        .query(`
                            INSERT INTO dbo.idp_user_recovery_codes (user_id, position, code_hash, used_at)
                            VALUES (@userId, @position, @codeHash, @usedAt)
                        `);
                }
            }

            for (const { position, usedAt } of recoveryCodeConsume) {
                await new sql.Request(transaction)
                    .input('userId', sql.UniqueIdentifier, id)
                    .input('position', sql.SmallInt, position)
                    .input('usedAt', sql.DateTime2, usedAt)
                    .query('UPDATE dbo.idp_user_recovery_codes SET used_at = @usedAt WHERE user_id = @userId AND position = @position');
            }

            await transaction.commit();
        } catch (err) {
            await transaction.rollback();
            throw err;
        }

        const user = await this._loadFull(id);
        return applyUserSelect(user, resolveUserSelect(opts.select));
    }

    /** A single UPDATE is already atomic per-row against concurrent callers — no transaction needed. */
    async incrementFailedLoginAttempts(id) {
        const { rowsAffected } = await this.pool.request()
            .input('id', sql.UniqueIdentifier, id)
            .query('UPDATE dbo.idp_users SET failed_login_attempts = failed_login_attempts + 1, updated_at = SYSUTCDATETIME() WHERE id = @id');
        if (rowsAffected[0] === 0) return null;
        return this._loadFull(id);
    }

    async linkExternalProvider(id, link) {
        await this.pool.request()
            .input('userId', sql.UniqueIdentifier, id)
            .input('provider', sql.NVarChar, link.provider)
            .input('providerId', sql.NVarChar, link.providerId)
            .input('email', sql.NVarChar, link.email || null)
            .input('connectedAt', sql.DateTime2, link.connectedAt || new Date())
            .query(`
                INSERT INTO dbo.idp_user_external_providers (user_id, provider, provider_id, email, connected_at)
                VALUES (@userId, @provider, @providerId, @email, @connectedAt)
            `);
        await this.pool.request().input('id', sql.UniqueIdentifier, id)
            .query('UPDATE dbo.idp_users SET updated_at = SYSUTCDATETIME() WHERE id = @id');
        return this._loadFull(id);
    }

    async deleteById(id) {
        await this.pool.request().input('id', sql.UniqueIdentifier, id)
            .query('DELETE FROM dbo.idp_users WHERE id = @id');
    }

    async countAll() {
        const { recordset: [{ count }] } = await this.pool.request().query('SELECT COUNT(*) AS count FROM dbo.idp_users');
        return count;
    }

    async findMany({ skip = 0, limit = 20 } = {}) {
        const { recordset } = await this.pool.request()
            .input('skip', sql.Int, skip)
            .input('limit', sql.Int, limit)
            .query('SELECT id FROM dbo.idp_users ORDER BY created_at DESC OFFSET @skip ROWS FETCH NEXT @limit ROWS ONLY');
        const users = await Promise.all(recordset.map((r) => this._loadFull(r.id)));
        // Mirrors Mongo's `.select('-passwordHash -mfaSecret')` on this one method.
        return users.map((u) => applyUserSelect(u, resolveUserSelect(null)));
    }
}
