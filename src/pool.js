import sql from 'mssql';

/**
 * @param {import('mssql').config} poolConfig
 * @returns {Promise<import('mssql').ConnectionPool>}
 */
export async function createPool(poolConfig) {
    if (!poolConfig || (!poolConfig.server && !poolConfig.connectionString)) {
        throw new Error('createMssqlStorage: config.pool (an mssql config, e.g. { server, user, password, database }) is required');
    }
    const pool = new sql.ConnectionPool(poolConfig);
    await pool.connect();
    return pool;
}
