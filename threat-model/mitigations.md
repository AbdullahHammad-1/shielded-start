# Threat Model: Mitigations

## Overview

This document maps security controls to the threats identified in [threats.md](./threats.md). Each mitigation includes:
- **Owner**: Who implements and maintains this control
- **Type**: Code, Configuration, or Process
- **Implementation**: Specific guidance for this architecture

---

## Mitigation Matrix by Threat

### Authentication Threats

| Threat ID | Threat | Mitigation | Owner | Type | Status |
|-----------|--------|------------|-------|------|--------|
| AUTH-01 | Credential stuffing | Rate limiting + Account lockout + MFA | Platform | Code/Config | Required |
| AUTH-02 | Session hijacking | Short token expiry + Secure cookies + Token binding | Platform | Code | Required |
| AUTH-03 | JWT forgery | RS256 signing + Key rotation + Algorithm pinning | Platform | Config | Required |
| AUTH-04 | Token manipulation | Signature verification on every request | Gateway | Code | Required |
| AUTH-05 | Login without audit | Structured auth event logging | Platform | Code | Required |
| AUTH-06 | Credential leakage | Generic error messages | Platform | Code | Required |
| AUTH-07 | Auth endpoint flooding | WAF rules + Rate limiting | Infra | Config | Required |
| AUTH-08 | Privilege escalation via roles | Server-side role validation + Role assignment audit | App | Code | Required |

### API Threats

| Threat ID | Threat | Mitigation | Owner | Type | Status |
|-----------|--------|------------|-------|------|--------|
| API-01 | API key theft | Server-side secrets + Key rotation | Platform | Config | Required |
| API-02 | Request manipulation | Tenant_id from JWT only, never from request | App | Code | **Critical** |
| API-03 | SQL injection | Parameterized queries + ORM | App | Code | Required |
| API-04 | Action without audit | Audit logging middleware | App | Code | Required |
| API-05 | IDOR/BOLA | RLS + Ownership checks + UUIDs | App/DB | Code | **Critical** |
| API-06 | Verbose errors | Production error handler | App | Code | Required |
| API-07 | Mass assignment | Explicit field allow-lists | App | Code | Required |
| API-08 | Rate limit bypass | Tenant-based limiting + IP reputation | Gateway | Config | Recommended |
| API-09 | Broken function-level auth | Authorization middleware on all routes | App | Code | Required |

### Database Threats

| Threat ID | Threat | Mitigation | Owner | Type | Status |
|-----------|--------|------------|-------|------|--------|
| DB-01 | Connection impersonation | IAM auth + Secret rotation | Infra | Config | Required |
| DB-02 | Direct data modification | RLS + App-only DB user | DB | Config | Required |
| DB-03 | RLS bypass | Session variable validation + No BYPASSRLS | DB | Config | **Critical** |
| DB-04 | Unlogged data changes | DB audit extension (pgaudit) | DB | Config | Recommended |
| DB-05 | Tenant data leakage | RLS on all tenant tables | DB | Code | **Critical** |
| DB-06 | Backup exposure | Encrypted backups + Access logging | Infra | Config | Required |
| DB-07 | Resource exhaustion | Query timeout + Connection limits | DB | Config | Required |
| DB-08 | Privilege escalation | Least-privilege DB users | DB | Config | Required |

### Multi-Tenancy Threats

| Threat ID | Threat | Mitigation | Owner | Type | Status |
|-----------|--------|------------|-------|------|--------|
| MT-01 | Tenant impersonation | JWT signature verification | Gateway | Code | Required |
| MT-02 | Cross-tenant modification | RLS INSERT/UPDATE policies | DB | Code | **Critical** |
| MT-03 | Cross-tenant data access | RLS SELECT policies | DB | Code | **Critical** |
| MT-04 | Tenant enumeration | UUID tenant IDs + Generic errors | App | Code | Required |
| MT-05 | Noisy neighbor | Per-tenant resource quotas | App | Config | Recommended |
| MT-06 | Tenant admin escape | Separate platform admin role | App | Code | Required |

### Logging Threats

| Threat ID | Threat | Mitigation | Owner | Type | Status |
|-----------|--------|------------|-------|------|--------|
| LOG-01 | Log injection | Structured logging + Input sanitization | App | Code | Required |
| LOG-02 | Log deletion | Immutable log storage | Infra | Config | Recommended |
| LOG-03 | Incomplete logging | Audit middleware + Log coverage review | App | Code/Process | Required |
| LOG-04 | PII in logs | Field allow-list + Log review process | App | Code/Process | Required |
| LOG-05 | Log scraping | Log access controls + Access audit | Infra | Config | Required |
| LOG-06 | Log flooding | Log rate limiting + Alerts | Infra | Config | Recommended |

### Infrastructure Threats

| Threat ID | Threat | Mitigation | Owner | Type | Status |
|-----------|--------|------------|-------|------|--------|
| INF-01 | DNS hijacking | DNSSEC + DNS monitoring | Infra | Config | Recommended |
| INF-02 | Supply chain attack | Dependency scanning + Lock files | DevOps | Config | Required |
| INF-03 | CI/CD pipeline compromise | Protected branches + Signed commits | DevOps | Config | Required |
| INF-04 | Secrets in code | Secret scanning + Pre-commit hooks | DevOps | Config | **Critical** |
| INF-05 | Unencrypted traffic | TLS everywhere + Certificate management | Infra | Config | Required |
| INF-06 | DDoS attack | CDN + WAF + Auto-scaling | Infra | Config | Required |
| INF-07 | Container escape | Updated base images + Security contexts | DevOps | Config | Required |

---

## Detailed Mitigation Implementations

### CRITICAL: Tenant Isolation (MT-02, MT-03, DB-05)

**Problem**: Tenant data leaking to other tenants

**Implementation**:

```sql
-- 1. Enable RLS on every table with tenant data
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;

-- 2. Create deny-by-default policy
CREATE POLICY tenant_isolation ON projects
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- 3. Set context on every connection
SET app.tenant_id = 'validated-tenant-uuid';
```

**Owner**: Database / Backend Team
**Verification**:
```sql
-- This query should return ZERO rows
SET app.tenant_id = 'tenant-a';
SELECT * FROM projects WHERE tenant_id = 'tenant-b';
```

---

### CRITICAL: IDOR/BOLA Prevention (API-05)

**Problem**: Users accessing resources by guessing IDs

**Implementation**:

```python
# WRONG: No ownership check
@app.get("/api/documents/{document_id}")
def get_document(document_id: str):
    return db.query(Document).filter_by(id=document_id).first()

# CORRECT: RLS + Application ownership check
@app.get("/api/documents/{document_id}")
def get_document(document_id: str, current_user: User = Depends(get_current_user)):
    # RLS already filters by tenant_id
    doc = db.query(Document).filter_by(id=document_id).first()
    
    # Additional ownership check for non-admin users
    if doc and not current_user.is_admin:
        if not doc.is_accessible_by(current_user):
            raise HTTPException(404)  # Don't reveal existence
    
    return doc
```

**Owner**: Backend Team
**Verification**: Integration tests attempting cross-tenant access

---

### CRITICAL: Request Manipulation Prevention (API-02)

**Problem**: Attacker modifying tenant_id in request body

**Implementation**:

```python
# WRONG: Tenant from request body
@app.post("/api/projects")
def create_project(body: ProjectCreate):
    project = Project(
        tenant_id=body.tenant_id,  # NEVER DO THIS
        name=body.name
    )

# CORRECT: Tenant from JWT claims only
@app.post("/api/projects")
def create_project(
    body: ProjectCreate,
    current_user: User = Depends(get_current_user)
):
    project = Project(
        tenant_id=current_user.tenant_id,  # From validated JWT
        name=body.name,
        created_by=current_user.id
    )
```

**Owner**: Backend Team
**Verification**: Code review checklist, SAST rules

---

### CRITICAL: Secret Management (INF-04)

**Problem**: Secrets committed to git repository

**Implementation**:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks

# If secrets found in history:
# 1. Rotate ALL exposed secrets immediately
# 2. Use git-filter-repo to remove from history
# 3. Force-push (coordinate with team)
```

**Owner**: DevOps / Security Team
**Verification**: CI pipeline fails on secret detection

---

### Credential Stuffing Prevention (AUTH-01)

**Problem**: Automated login attempts with leaked credentials

**Implementation**:

```python
# Rate limiting configuration
RATE_LIMITS = {
    "login": {
        "per_ip": "5/minute",
        "per_user": "10/minute",
        "lockout_threshold": 5,
        "lockout_duration": 900  # 15 minutes
    }
}

# Account lockout
def check_login_attempts(email: str, ip: str):
    recent_failures = get_recent_failures(email, minutes=15)
    if recent_failures >= 5:
        raise AccountLockedError("Too many attempts. Try again later.")
    
    ip_failures = get_ip_failures(ip, minutes=5)
    if ip_failures >= 20:
        raise RateLimitError("Rate limit exceeded.")
```

**Owner**: Platform Team
**Verification**: Load testing with failure scenarios

---

### Session Hijacking Prevention (AUTH-02)

**Problem**: Stolen tokens used by attackers

**Implementation**:

```python
# Token configuration
ACCESS_TOKEN_EXPIRY = 900  # 15 minutes
REFRESH_TOKEN_EXPIRY = 604800  # 7 days

# Cookie settings for web apps
COOKIE_CONFIG = {
    "httponly": True,
    "secure": True,  # HTTPS only
    "samesite": "strict",
    "path": "/",
    "domain": ".yourapp.com"
}

# Optional: Token binding
def verify_token_binding(token: JWT, request: Request):
    if token.ip_hash and hash(request.client_ip) != token.ip_hash:
        raise TokenBindingError("Token bound to different IP")
```

**Owner**: Platform Team
**Verification**: Security testing, token handling review

---

### PII in Logs Prevention (LOG-04)

**Problem**: Sensitive data written to logs

**Implementation**:

```python
# Define what CAN be logged (allow-list approach)
LOGGABLE_FIELDS = {
    "user_id", "tenant_id", "action", "resource_type", 
    "resource_id", "timestamp", "status", "error_code"
}

# Structured logging with filtering
def create_audit_log(event: dict) -> dict:
    return {k: v for k, v in event.items() if k in LOGGABLE_FIELDS}

# NEVER log these
NEVER_LOG = {
    "password", "token", "secret", "ssn", "credit_card",
    "api_key", "private_key", "session"
}

def sanitize_for_logging(data: dict) -> dict:
    return {k: v for k, v in data.items() if k.lower() not in NEVER_LOG}
```

**Owner**: Backend Team
**Verification**: Log audit, grep for PII patterns

---

## Mitigation Verification Checklist

### Pre-Launch Security Checklist

#### Authentication & Authorization
- [ ] JWT signature verification on all protected endpoints
- [ ] Token expiry < 30 minutes for access tokens
- [ ] Refresh token rotation enabled
- [ ] Rate limiting on auth endpoints
- [ ] MFA available (required for admin)
- [ ] Role checks on all privileged operations

#### Multi-Tenancy
- [ ] RLS enabled on all tables with tenant data
- [ ] RLS FORCE enabled (no bypass for table owner)
- [ ] tenant_id comes only from JWT, never from request
- [ ] Cross-tenant access tests written and passing
- [ ] UUIDs used for all IDs (not sequential)

#### API Security
- [ ] Input validation on all endpoints
- [ ] Parameterized queries only (no string concat SQL)
- [ ] Error responses don't leak internal details
- [ ] Rate limiting per tenant and per user
- [ ] Request size limits configured
- [ ] CORS configured for specific origins only

#### Secrets & Infrastructure
- [ ] No secrets in git repository
- [ ] All secrets in Secrets Manager
- [ ] Secret rotation process documented
- [ ] TLS on all connections
- [ ] Database not publicly accessible
- [ ] Backups encrypted and access-logged

#### Logging & Monitoring
- [ ] Audit logging for all state changes
- [ ] No PII in logs (verified)
- [ ] Auth failures logged and alerted
- [ ] Log retention configured
- [ ] Incident response runbook exists

---

## Owner Responsibilities

### Platform Team
- Authentication system security
- JWT issuance and validation
- Rate limiting implementation
- Session management

### Backend Team
- Authorization logic
- Input validation
- Audit logging implementation
- IDOR prevention

### Database/DBA
- RLS policy implementation
- Database user permissions
- Query performance/safety
- Backup encryption

### DevOps/Infra
- Secret management
- CI/CD security
- Network security
- Monitoring setup

### Security Team (or designated owner)
- Threat model maintenance
- Security testing coordination
- Incident response
- Compliance documentation

---

## Mitigation Testing

### Automated Tests Required

```python
# Test: Cross-tenant access blocked
def test_cross_tenant_access_blocked():
    # Authenticate as tenant A
    token_a = get_token(tenant="tenant-a", user="user-1")
    
    # Create resource in tenant A
    project = create_project(token_a, name="Secret Project")
    
    # Authenticate as tenant B
    token_b = get_token(tenant="tenant-b", user="user-2")
    
    # Attempt to access tenant A's project
    response = client.get(f"/api/projects/{project.id}", headers=auth(token_b))
    
    assert response.status_code == 404  # Not found, not forbidden

# Test: tenant_id from request body ignored
def test_tenant_id_from_body_ignored():
    token = get_token(tenant="tenant-a")
    
    response = client.post("/api/projects", 
        headers=auth(token),
        json={
            "name": "Test",
            "tenant_id": "tenant-b"  # Malicious attempt
        }
    )
    
    created = response.json()
    assert created["tenant_id"] == "tenant-a"  # From JWT, not body

# Test: RLS cannot be bypassed
def test_rls_enforcement():
    # Direct database query (simulating compromised app)
    with db.connect() as conn:
        conn.execute("SET app.tenant_id = 'tenant-a'")
        result = conn.execute("SELECT * FROM projects WHERE tenant_id = 'tenant-b'")
        assert len(result.fetchall()) == 0
```

---

## Next Steps

1. Implement all **Critical** mitigations before launch
2. Schedule **Required** mitigations within 30 days
3. Plan **Recommended** mitigations in roadmap
4. Review threat model quarterly
5. Update mitigations after security incidents

