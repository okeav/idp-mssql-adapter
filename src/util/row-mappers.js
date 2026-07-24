// Explicit, hand-written row -> object mappers, one per table — same
// rationale as the Postgres adapter: field-name quirks inherited from
// idp-core's own Mongo models (`user` vs `userId` depending on table, `code`
// storing a hash despite the name) are easier to get right explicitly than
// via a generic snake_case<->camelCase converter.
//
// SQL Server has no native JSON or array column type — `metadata`, `claims`,
// `scopes`, `redirectUris`, `allowedScopes`, `allowedGrants`, `transports`
// are stored as NVARCHAR(MAX) JSON text and need manual JSON.parse() on the
// way out (the `mssql` driver returns them as plain strings, unlike `pg`'s
// JSONB type parser which auto-parses).
function parseJson(text, fallback) {
    if (text === null || text === undefined) return fallback;
    try {
        return JSON.parse(text);
    } catch {
        return fallback;
    }
}

// SQL Server's UNIQUEIDENTIFIER type stores GUIDs as a 16-byte binary value
// — "case" only exists when converting to/from a string, and the `mssql`
// driver returns that string representation UPPERCASE. Every ID this
// package generates (crypto.randomUUID()) is lowercase, so a strict string
// comparison (e.g. `credentialDoc.user === userId` in idp-core's own
// controllers) would otherwise fail despite referring to the identical
// GUID. Every UNIQUEIDENTIFIER-typed field read back from a row goes
// through this before being handed to callers.
function lowerGuid(value) {
    return value === null || value === undefined ? value : String(value).toLowerCase();
}

export function mapServiceKeyRow(row) {
    if (!row) return null;
    return {
        id: lowerGuid(row.id),
        name: row.name,
        kid: row.kid,
        publicKey: row.public_key,
        status: row.status,
        region: row.region,
        registeredAt: row.registered_at,
        lastSeenAt: row.last_seen_at,
    };
}

export function mapCredentialRow(row) {
    if (!row) return null;
    return {
        id: lowerGuid(row.id),
        user: lowerGuid(row.user_id),
        credentialId: row.credential_id,
        publicKey: row.public_key,
        counter: Number(row.counter),
        transports: parseJson(row.transports, []),
        deviceType: row.device_type,
        backedUp: Boolean(row.backed_up),
        name: row.name,
        lastUsedAt: row.last_used_at,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}

export function mapConsentRow(row) {
    if (!row) return null;
    return {
        id: lowerGuid(row.id),
        userId: lowerGuid(row.user_id),
        clientId: row.client_id,
        scopes: parseJson(row.scopes, []),
        grantedAt: row.granted_at,
        revokedAt: row.revoked_at,
        isRevoked: Boolean(row.is_revoked),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}

const OAUTH_CLIENT_PUBLIC_COLUMNS = `
    id, name, slug, client_id, client_type, redirect_uris, allowed_scopes, allowed_grants,
    access_token_ttl, refresh_token_ttl, id_token_ttl, logo_url, website_url,
    privacy_policy_url, terms_of_service_url, support_email, status, metadata,
    created_at, updated_at
`;

export function mapOAuthClientRow(row) {
    if (!row) return null;
    return {
        id: lowerGuid(row.id),
        name: row.name,
        slug: row.slug,
        clientId: row.client_id,
        ...(row.client_secret_hash !== undefined ? { clientSecretHash: row.client_secret_hash } : {}),
        clientType: row.client_type,
        redirectUris: parseJson(row.redirect_uris, []),
        allowedScopes: parseJson(row.allowed_scopes, []),
        allowedGrants: parseJson(row.allowed_grants, []),
        accessTokenTTL: row.access_token_ttl,
        refreshTokenTTL: row.refresh_token_ttl,
        idTokenTTL: row.id_token_ttl,
        logoUrl: row.logo_url,
        websiteUrl: row.website_url,
        privacyPolicyUrl: row.privacy_policy_url,
        termsOfServiceUrl: row.terms_of_service_url,
        supportEmail: row.support_email,
        status: row.status,
        metadata: parseJson(row.metadata, {}),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}

export function mapAuthorizationCodeRow(row) {
    if (!row) return null;
    return {
        id: lowerGuid(row.id),
        code: row.code,
        clientId: row.client_id,
        userId: lowerGuid(row.user_id),
        redirectUri: row.redirect_uri,
        scopes: parseJson(row.scopes, []),
        codeChallenge: row.code_challenge,
        codeChallengeMethod: row.code_challenge_method,
        expiresAt: row.expires_at,
        used: Boolean(row.used),
        usedAt: row.used_at,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}

export function mapVerificationTokenRow(row) {
    if (!row) return null;
    return {
        id: lowerGuid(row.id),
        kind: row.kind,
        user: lowerGuid(row.user_id),
        tokenHash: row.token_hash,
        verificationCode: row.verification_code,
        expiresAt: row.expires_at,
        usedAt: row.used_at,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}

export function mapSessionRow(row) {
    if (!row) return null;
    return {
        id: lowerGuid(row.id),
        user: lowerGuid(row.user_id),
        tokenHash: row.token_hash,
        expiresAt: row.expires_at,
        kid: row.kid,
        jti: row.jti,
        revokedAt: row.revoked_at,
        deviceInfo: row.device_info,
        deviceFingerprint: row.device_fingerprint,
        ipAddress: row.ip_address,
        claims: parseJson(row.claims, {}),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}

export { OAUTH_CLIENT_PUBLIC_COLUMNS, parseJson, lowerGuid };
