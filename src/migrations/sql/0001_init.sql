-- @okeav/idp-core-mssql — initial schema.
-- Primary keys are application-generated UUIDs (crypto.randomUUID(), passed
-- in as UNIQUEIDENTIFIER by the repository layer) rather than NEWID()/
-- NEWSEQUENTIALID() defaults, matching the Postgres/DynamoDB adapters'
-- choice to keep ID generation in application code.
--
-- No native array or JSON column type in SQL Server (JSON *functions* exist,
-- but no JSON column type) — array-shaped fields (scopes, redirectUris,
-- allowedScopes, allowedGrants, transports) and free-form objects (metadata,
-- claims) are stored as NVARCHAR(MAX) JSON text, parsed/stringified by the
-- repository layer.

CREATE TABLE dbo.idp_users (
    id UNIQUEIDENTIFIER PRIMARY KEY,
    email NVARCHAR(320) NOT NULL,
    email_hash NVARCHAR(128) NULL,
    password_hash NVARCHAR(255) NULL,
    status NVARCHAR(32) NOT NULL DEFAULT 'PENDING_VERIFICATION',
    last_login_at DATETIME2 NULL,
    password_changed_at DATETIME2 NULL,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    lock_until DATETIME2 NULL,
    mfa_enabled BIT NOT NULL DEFAULT 0,
    mfa_secret NVARCHAR(255) NULL,
    mfa_temp_secret NVARCHAR(255) NULL,
    profile_first_name NVARCHAR(50) NULL,
    profile_last_name NVARCHAR(50) NULL,
    profile_display_name NVARCHAR(150) NULL,
    profile_avatar_url NVARCHAR(1000) NULL,
    profile_locale NVARCHAR(16) NOT NULL DEFAULT 'en',
    profile_zoneinfo NVARCHAR(64) NULL,
    metadata NVARCHAR(MAX) NOT NULL DEFAULT '{}',
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    updated_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);
CREATE UNIQUE INDEX idp_users_email_hash_uidx ON dbo.idp_users (email_hash) WHERE email_hash IS NOT NULL;
CREATE INDEX idp_users_status_idx ON dbo.idp_users (status);
CREATE INDEX idp_users_lock_until_idx ON dbo.idp_users (lock_until) WHERE lock_until IS NOT NULL;

-- Was Mongo's embedded `externalProviders` array — a join table here since
-- findByExternalProvider(provider, providerId) needs an indexed lookup, not
-- a wholesale array fetch.
CREATE TABLE dbo.idp_user_external_providers (
    id INT IDENTITY(1,1) PRIMARY KEY,
    user_id UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.idp_users(id) ON DELETE CASCADE,
    provider NVARCHAR(64) NOT NULL,
    provider_id NVARCHAR(255) NOT NULL,
    email NVARCHAR(320) NULL,
    connected_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT idp_user_ext_providers_uidx UNIQUE (provider, provider_id)
);
CREATE INDEX idp_user_external_providers_user_id_idx ON dbo.idp_user_external_providers (user_id);

-- Was Mongo's embedded `mfaRecoveryCodes` array — a join table with an
-- explicit `position` column since a recovery code is consumed by
-- positional array index (see mfa/controller.js in idp-core).
CREATE TABLE dbo.idp_user_recovery_codes (
    id INT IDENTITY(1,1) PRIMARY KEY,
    user_id UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.idp_users(id) ON DELETE CASCADE,
    position SMALLINT NOT NULL,
    code_hash NVARCHAR(255) NOT NULL,
    used_at DATETIME2 NULL,
    CONSTRAINT idp_user_recovery_codes_uidx UNIQUE (user_id, position)
);
CREATE INDEX idp_user_recovery_codes_user_id_idx ON dbo.idp_user_recovery_codes (user_id);

CREATE TABLE dbo.idp_sessions (
    id UNIQUEIDENTIFIER PRIMARY KEY,
    user_id UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.idp_users(id) ON DELETE CASCADE,
    token_hash NVARCHAR(255) NOT NULL,
    expires_at DATETIME2 NOT NULL,
    kid NVARCHAR(128) NOT NULL,
    jti NVARCHAR(128) NOT NULL,
    revoked_at DATETIME2 NULL,
    device_info NVARCHAR(500) NULL,
    device_fingerprint NVARCHAR(255) NULL,
    ip_address NVARCHAR(64) NULL,
    claims NVARCHAR(MAX) NOT NULL DEFAULT '{}',
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    updated_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);
CREATE INDEX idp_sessions_token_hash_revoked_idx ON dbo.idp_sessions (token_hash, revoked_at);
CREATE INDEX idp_sessions_user_revoked_expires_idx ON dbo.idp_sessions (user_id, revoked_at, expires_at);
CREATE INDEX idp_sessions_jti_idx ON dbo.idp_sessions (jti) WHERE jti IS NOT NULL;
CREATE INDEX idp_sessions_user_device_fp_idx ON dbo.idp_sessions (user_id, device_fingerprint) WHERE device_fingerprint IS NOT NULL;

-- Write-only audit trail, one row per issued access token.
CREATE TABLE dbo.idp_access_token_audit (
    id UNIQUEIDENTIFIER PRIMARY KEY,
    user_id UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.idp_users(id) ON DELETE CASCADE,
    token_hash NVARCHAR(255) NOT NULL,
    expires_at DATETIME2 NOT NULL,
    kid NVARCHAR(128) NOT NULL,
    jti NVARCHAR(128) NOT NULL,
    ip_address NVARCHAR(64) NULL,
    device_info NVARCHAR(500) NULL,
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);
CREATE INDEX idp_access_token_audit_token_hash_idx ON dbo.idp_access_token_audit (token_hash);

CREATE TABLE dbo.idp_authorization_codes (
    id UNIQUEIDENTIFIER PRIMARY KEY,
    code NVARCHAR(255) NOT NULL, -- stores the HASH despite the name, matching idp-core's own field naming
    client_id NVARCHAR(255) NOT NULL,
    user_id UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.idp_users(id) ON DELETE CASCADE,
    redirect_uri NVARCHAR(1000) NOT NULL,
    scopes NVARCHAR(MAX) NOT NULL DEFAULT '[]',
    code_challenge NVARCHAR(255) NULL,
    code_challenge_method NVARCHAR(16) NULL,
    expires_at DATETIME2 NOT NULL,
    used BIT NOT NULL DEFAULT 0,
    used_at DATETIME2 NULL,
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    updated_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT idp_auth_codes_code_uidx UNIQUE (code)
);
CREATE INDEX idp_auth_codes_code_used_idx ON dbo.idp_authorization_codes (code, used);
CREATE INDEX idp_auth_codes_client_used_expires_idx ON dbo.idp_authorization_codes (client_id, used, expires_at);

CREATE TABLE dbo.idp_consents (
    id UNIQUEIDENTIFIER PRIMARY KEY,
    user_id UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.idp_users(id) ON DELETE CASCADE,
    client_id NVARCHAR(255) NOT NULL,
    scopes NVARCHAR(MAX) NOT NULL DEFAULT '[]',
    granted_at DATETIME2 NULL,
    revoked_at DATETIME2 NULL,
    is_revoked BIT NOT NULL DEFAULT 0,
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    updated_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT idp_consents_user_client_uidx UNIQUE (user_id, client_id)
);
CREATE INDEX idp_consents_user_revoked_idx ON dbo.idp_consents (user_id, is_revoked);

CREATE TABLE dbo.idp_oauth_clients (
    id UNIQUEIDENTIFIER PRIMARY KEY,
    name NVARCHAR(255) NOT NULL,
    slug NVARCHAR(255) NOT NULL,
    client_id NVARCHAR(255) NOT NULL,
    client_secret_hash NVARCHAR(255) NOT NULL, -- app-level "hide by default", see mssql-oauth-client.repository.js
    client_type NVARCHAR(32) NOT NULL DEFAULT 'confidential',
    redirect_uris NVARCHAR(MAX) NOT NULL DEFAULT '[]',
    allowed_scopes NVARCHAR(MAX) NOT NULL DEFAULT '[]',
    allowed_grants NVARCHAR(MAX) NOT NULL DEFAULT '[]',
    access_token_ttl INT NULL,
    refresh_token_ttl INT NULL,
    id_token_ttl INT NULL,
    logo_url NVARCHAR(1000) NULL,
    website_url NVARCHAR(1000) NULL,
    privacy_policy_url NVARCHAR(1000) NULL,
    terms_of_service_url NVARCHAR(1000) NULL,
    support_email NVARCHAR(320) NULL,
    status NVARCHAR(32) NOT NULL DEFAULT 'PENDING_APPROVAL',
    metadata NVARCHAR(MAX) NOT NULL DEFAULT '{}',
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    updated_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT idp_oauth_clients_slug_uidx UNIQUE (slug),
    CONSTRAINT idp_oauth_clients_client_id_uidx UNIQUE (client_id)
);

CREATE TABLE dbo.idp_verification_tokens (
    id UNIQUEIDENTIFIER PRIMARY KEY,
    kind NVARCHAR(32) NOT NULL CHECK (kind IN ('password_reset', 'email_verification', 'magic_link')),
    user_id UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.idp_users(id) ON DELETE CASCADE,
    token_hash NVARCHAR(255) NOT NULL,
    verification_code NVARCHAR(16) NULL,
    expires_at DATETIME2 NOT NULL,
    used_at DATETIME2 NULL,
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    updated_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);
CREATE INDEX idp_verif_tokens_kind_hash_user_idx ON dbo.idp_verification_tokens (kind, token_hash, user_id);
CREATE INDEX idp_verif_tokens_kind_user_idx ON dbo.idp_verification_tokens (kind, user_id);

CREATE TABLE dbo.idp_service_keys (
    id UNIQUEIDENTIFIER PRIMARY KEY,
    name NVARCHAR(255) NOT NULL,
    kid NVARCHAR(255) NOT NULL,
    public_key NVARCHAR(MAX) NOT NULL,
    status NVARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    region NVARCHAR(64) NOT NULL DEFAULT 'global',
    registered_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    last_seen_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT idp_service_keys_kid_uidx UNIQUE (kid)
);
CREATE INDEX idp_service_keys_name_status_idx ON dbo.idp_service_keys (name, status);

CREATE TABLE dbo.idp_credentials (
    id UNIQUEIDENTIFIER PRIMARY KEY,
    user_id UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.idp_users(id) ON DELETE CASCADE,
    credential_id NVARCHAR(500) NOT NULL,
    public_key NVARCHAR(MAX) NOT NULL,
    counter BIGINT NOT NULL DEFAULT 0,
    transports NVARCHAR(MAX) NOT NULL DEFAULT '[]',
    device_type NVARCHAR(32) NOT NULL DEFAULT 'singleDevice' CHECK (device_type IN ('singleDevice', 'multiDevice')),
    backed_up BIT NOT NULL DEFAULT 0,
    name NVARCHAR(255) NULL,
    last_used_at DATETIME2 NULL,
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    updated_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT idp_credentials_credential_id_uidx UNIQUE (credential_id)
);
CREATE INDEX idp_credentials_user_id_idx ON dbo.idp_credentials (user_id);
