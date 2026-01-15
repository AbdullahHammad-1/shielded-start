-- =============================================================================
-- SHIELDED-START: PostgreSQL Row-Level Security Policies
-- =============================================================================
-- 
-- HOW TO SET TENANT/USER CONTEXT SAFELY FROM THE API
-- ---------------------------------------------------
-- 
-- CRITICAL: The tenant_id and user_id must come from validated JWT claims,
-- NEVER from request parameters or body.
-- 
-- Example (Python/SQLAlchemy):
-- 
--   def set_tenant_context(conn, tenant_id: str, user_id: str):
--       # Validate UUIDs first
--       uuid.UUID(tenant_id)  # Raises if invalid
--       uuid.UUID(user_id)
--       
--       # Use parameterized setting (prevents injection)
--       conn.execute(text("SELECT set_config('app.tenant_id', :tid, true)"), 
--                    {"tid": tenant_id})
--       conn.execute(text("SELECT set_config('app.user_id', :uid, true)"), 
--                    {"uid": user_id})
-- 
-- Example (Node.js/pg):
-- 
--   async function setTenantContext(client, tenantId, userId) {
--     // Validate UUIDs (use uuid library)
--     if (!isValidUUID(tenantId) || !isValidUUID(userId)) {
--       throw new Error('Invalid context IDs');
--     }
--     await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
--     await client.query("SELECT set_config('app.user_id', $1, true)", [userId]);
--   }
-- 
-- WITH CONNECTION POOLING (PgBouncer, etc.):
-- - Always set context at the START of each request
-- - Use transaction-local settings (set_config with is_local=true)
-- - Reset context at end of request or use SET LOCAL
-- 
-- =============================================================================

-- =============================================================================
-- SETUP: Extensions and Configuration
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- SCHEMA: Multi-Tenant Tables
-- =============================================================================

-- -----------------------------------------------------------------------------
-- TENANTS: Organization/Company accounts
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    plan VARCHAR(50) NOT NULL DEFAULT 'free',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- USERS: Individual user accounts (belong to one tenant)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);

-- Index for common queries
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- -----------------------------------------------------------------------------
-- PROJECTS: Example business resource (tenant-scoped)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
    settings JSONB DEFAULT '{}',
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_projects_tenant_id ON projects(tenant_id);
CREATE INDEX IF NOT EXISTS idx_projects_owner_id ON projects(owner_id);

-- -----------------------------------------------------------------------------
-- AUDIT_LOGS: Immutable audit trail (tenant-scoped, read-restricted)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID,
    changes JSONB,
    ip_address_hash VARCHAR(64),  -- Hashed for privacy
    user_agent_hash VARCHAR(64),  -- Hashed for privacy
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_id ON audit_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);

-- =============================================================================
-- ROW-LEVEL SECURITY: Enable and Force
-- =============================================================================
-- FORCE ensures RLS applies even to table owners (prevents bypass)

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- CRITICAL: Force RLS even for table owners
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;

-- =============================================================================
-- HELPER FUNCTIONS: Safe Context Access
-- =============================================================================

-- Get current tenant_id with validation
CREATE OR REPLACE FUNCTION current_tenant_id() 
RETURNS UUID AS $$
DECLARE
    tid TEXT;
BEGIN
    tid := current_setting('app.tenant_id', true);
    IF tid IS NULL OR tid = '' THEN
        RAISE EXCEPTION 'Tenant context not set';
    END IF;
    RETURN tid::UUID;
EXCEPTION
    WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'Invalid tenant_id format';
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Get current user_id with validation
CREATE OR REPLACE FUNCTION current_user_id() 
RETURNS UUID AS $$
DECLARE
    uid TEXT;
BEGIN
    uid := current_setting('app.user_id', true);
    IF uid IS NULL OR uid = '' THEN
        RETURN NULL;  -- Allow anonymous for some operations
    END IF;
    RETURN uid::UUID;
EXCEPTION
    WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'Invalid user_id format';
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Check if current user has a specific role
CREATE OR REPLACE FUNCTION current_user_has_role(required_role VARCHAR)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM users 
        WHERE id = current_user_id() 
        AND tenant_id = current_tenant_id()
        AND role = required_role
        AND status = 'active'
    );
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- =============================================================================
-- RLS POLICIES: Tenants Table
-- =============================================================================
-- Tenants can only see their own tenant record

-- SELECT: Only own tenant
CREATE POLICY tenant_select ON tenants
    FOR SELECT
    USING (id = current_tenant_id());

-- INSERT: Handled by admin/signup flow (not through normal app)
CREATE POLICY tenant_insert ON tenants
    FOR INSERT
    WITH CHECK (false);  -- Deny by default, handled via admin connection

-- UPDATE: Only own tenant, only specific fields
CREATE POLICY tenant_update ON tenants
    FOR UPDATE
    USING (id = current_tenant_id())
    WITH CHECK (id = current_tenant_id());

-- DELETE: Deny (handled via admin/support process)
CREATE POLICY tenant_delete ON tenants
    FOR DELETE
    USING (false);

-- =============================================================================
-- RLS POLICIES: Users Table
-- =============================================================================
-- Users can see all users in their tenant, but restricted modifications

-- SELECT: All users in same tenant
CREATE POLICY user_select ON users
    FOR SELECT
    USING (tenant_id = current_tenant_id());

-- INSERT: Only tenant admins can create users
CREATE POLICY user_insert ON users
    FOR INSERT
    WITH CHECK (
        tenant_id = current_tenant_id() 
        AND current_user_has_role('admin')
    );

-- UPDATE: Users can update themselves, admins can update anyone in tenant
CREATE POLICY user_update ON users
    FOR UPDATE
    USING (tenant_id = current_tenant_id())
    WITH CHECK (
        tenant_id = current_tenant_id()
        AND (
            id = current_user_id()  -- Self-update
            OR current_user_has_role('admin')  -- Admin update
        )
    );

-- DELETE: Only tenant admins (soft delete preferred)
CREATE POLICY user_delete ON users
    FOR DELETE
    USING (
        tenant_id = current_tenant_id()
        AND current_user_has_role('admin')
        AND id != current_user_id()  -- Can't delete yourself
    );

-- =============================================================================
-- RLS POLICIES: Projects Table
-- =============================================================================
-- Full tenant isolation with ownership considerations

-- SELECT: All projects in tenant (visibility controlled at app layer if needed)
CREATE POLICY project_select ON projects
    FOR SELECT
    USING (tenant_id = current_tenant_id());

-- INSERT: Any authenticated user in tenant can create
CREATE POLICY project_insert ON projects
    FOR INSERT
    WITH CHECK (
        tenant_id = current_tenant_id()
        AND current_user_id() IS NOT NULL
    );

-- UPDATE: Owner or admin
CREATE POLICY project_update ON projects
    FOR UPDATE
    USING (tenant_id = current_tenant_id())
    WITH CHECK (
        tenant_id = current_tenant_id()
        AND (
            owner_id = current_user_id()
            OR created_by = current_user_id()
            OR current_user_has_role('admin')
        )
    );

-- DELETE: Owner or admin only
CREATE POLICY project_delete ON projects
    FOR DELETE
    USING (
        tenant_id = current_tenant_id()
        AND (
            owner_id = current_user_id()
            OR created_by = current_user_id()
            OR current_user_has_role('admin')
        )
    );

-- =============================================================================
-- RLS POLICIES: Audit Logs Table
-- =============================================================================
-- Read-only for tenant, write via separate service account

-- SELECT: Admins only (regular users shouldn't browse audit logs)
CREATE POLICY audit_log_select ON audit_logs
    FOR SELECT
    USING (
        tenant_id = current_tenant_id()
        AND current_user_has_role('admin')
    );

-- INSERT: Allow (app service writes logs)
-- In production, use a separate service role with INSERT-only permission
CREATE POLICY audit_log_insert ON audit_logs
    FOR INSERT
    WITH CHECK (tenant_id = current_tenant_id());

-- UPDATE: Never (audit logs are immutable)
CREATE POLICY audit_log_update ON audit_logs
    FOR UPDATE
    USING (false);

-- DELETE: Never (audit logs are immutable)
CREATE POLICY audit_log_delete ON audit_logs
    FOR DELETE
    USING (false);

-- =============================================================================
-- DATABASE USERS: Least Privilege
-- =============================================================================
-- Create application-specific database users with minimal permissions

-- Application user (used by API)
-- CREATE USER app_user WITH PASSWORD 'use-secrets-manager';
-- GRANT CONNECT ON DATABASE your_db TO app_user;
-- GRANT USAGE ON SCHEMA public TO app_user;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
-- GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO app_user;

-- Read-only user (for analytics, reporting)
-- CREATE USER readonly_user WITH PASSWORD 'use-secrets-manager';
-- GRANT CONNECT ON DATABASE your_db TO readonly_user;
-- GRANT USAGE ON SCHEMA public TO readonly_user;
-- GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly_user;

-- Migration user (for schema changes only)
-- CREATE USER migration_user WITH PASSWORD 'use-secrets-manager';
-- GRANT ALL ON DATABASE your_db TO migration_user;

-- =============================================================================
-- TRIGGERS: Auto-populate tenant_id and timestamps
-- =============================================================================

-- Auto-set tenant_id on insert (defense in depth)
CREATE OR REPLACE FUNCTION set_tenant_id_on_insert()
RETURNS TRIGGER AS $$
BEGIN
    -- Always use context tenant_id, ignore any provided value
    NEW.tenant_id := current_tenant_id();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Auto-update timestamps
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply triggers
CREATE TRIGGER users_tenant_id BEFORE INSERT ON users
    FOR EACH ROW EXECUTE FUNCTION set_tenant_id_on_insert();

CREATE TRIGGER projects_tenant_id BEFORE INSERT ON projects
    FOR EACH ROW EXECUTE FUNCTION set_tenant_id_on_insert();

CREATE TRIGGER audit_logs_tenant_id BEFORE INSERT ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION set_tenant_id_on_insert();

CREATE TRIGGER users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER projects_updated_at BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER tenants_updated_at BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

-- =============================================================================
-- TESTING: Verify RLS Works
-- =============================================================================

-- Test scenario (run manually, not in migrations):
/*
-- Create test tenants
INSERT INTO tenants (id, name, slug) VALUES 
    ('11111111-1111-1111-1111-111111111111', 'Tenant A', 'tenant-a'),
    ('22222222-2222-2222-2222-222222222222', 'Tenant B', 'tenant-b');

-- Set context to Tenant A
SELECT set_config('app.tenant_id', '11111111-1111-1111-1111-111111111111', false);
SELECT set_config('app.user_id', '33333333-3333-3333-3333-333333333333', false);

-- This should ONLY return Tenant A
SELECT * FROM tenants;

-- Attempt to access Tenant B (should return 0 rows)
SELECT * FROM tenants WHERE id = '22222222-2222-2222-2222-222222222222';

-- Attempt to insert project for Tenant B (should fail or be overwritten)
INSERT INTO projects (tenant_id, name) 
VALUES ('22222222-2222-2222-2222-222222222222', 'Malicious Project');

-- Verify project was created with Tenant A's ID
SELECT tenant_id FROM projects ORDER BY created_at DESC LIMIT 1;
*/

-- =============================================================================
-- CLEANUP: Remove test data (if needed)
-- =============================================================================
/*
DELETE FROM audit_logs;
DELETE FROM projects;
DELETE FROM users;
DELETE FROM tenants WHERE slug IN ('tenant-a', 'tenant-b');
*/

