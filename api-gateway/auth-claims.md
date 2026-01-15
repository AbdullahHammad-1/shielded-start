# API Gateway: Auth Claims & Authorization Model

## Overview

This document defines the JWT claims model, authorization patterns, and security controls for the API layer. Proper implementation prevents IDOR/BOLA vulnerabilities and ensures tenant isolation.

---

## JWT Claims Model

### Required Claims

| Claim | Type | Description | Example |
|-------|------|-------------|---------|
| `sub` | UUID | Subject - unique user identifier | `"550e8400-e29b-41d4-a716-446655440000"` |
| `tid` | UUID | Tenant ID - organization the user belongs to | `"123e4567-e89b-12d3-a456-426614174000"` |
| `roles` | string[] | User's roles within the tenant | `["member", "project_admin"]` |
| `iat` | number | Issued at timestamp | `1704067200` |
| `exp` | number | Expiration timestamp | `1704068100` |
| `iss` | string | Issuer - your auth server | `"https://auth.yourapp.com/"` |
| `aud` | string | Audience - intended recipient | `"api.yourapp.com"` |

### Recommended Claims

| Claim | Type | Description | Purpose |
|-------|------|-------------|---------|
| `jti` | UUID | JWT ID - unique token identifier | Replay protection, revocation |
| `auth_time` | number | When user actually authenticated | Step-up auth decisions |
| `scopes` | string[] | OAuth scopes granted | Fine-grained API access |
| `email` | string | User's email (if needed) | Display only, not for auth |
| `amr` | string[] | Authentication methods used | MFA verification |

### Example JWT Payload

```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "tid": "123e4567-e89b-12d3-a456-426614174000",
  "roles": ["member"],
  "scopes": ["read:projects", "write:projects"],
  "iat": 1704067200,
  "exp": 1704068100,
  "iss": "https://auth.yourapp.com/",
  "aud": "api.yourapp.com",
  "jti": "abc123-unique-token-id",
  "auth_time": 1704060000,
  "amr": ["pwd", "mfa"]
}
```

---

## Authorization Model

### RBAC + Ownership Checks

Authorization follows a two-layer model:

1. **Role-Based Access Control (RBAC)**: Determines what *types* of operations a user can perform
2. **Ownership Checks**: Determines *which specific resources* a user can access

```
┌─────────────────────────────────────────────────────────────────┐
│                     AUTHORIZATION FLOW                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. TENANT BOUNDARY (Critical - Always First)                   │
│     ├─ Does user's tid match resource's tenant_id?              │
│     └─ If NO → 404 Not Found (don't reveal existence)           │
│                                                                 │
│  2. ROLE CHECK (What can this role do?)                         │
│     ├─ Does user's role permit this action on this type?        │
│     └─ If NO → 403 Forbidden                                    │
│                                                                 │
│  3. OWNERSHIP CHECK (For non-admin roles)                       │
│     ├─ Is user owner/member of this specific resource?          │
│     └─ If NO → 404 Not Found (don't reveal existence)           │
│                                                                 │
│  4. PROCEED WITH OPERATION                                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Role Definitions

| Role | Scope | Permissions |
|------|-------|-------------|
| `tenant_admin` | Tenant-wide | Full CRUD on all tenant resources, user management |
| `project_admin` | Per-project | Full CRUD on assigned projects only |
| `member` | Per-resource | CRUD on owned resources, read on assigned |
| `viewer` | Per-resource | Read-only on assigned resources |

### Permission Matrix

| Action | tenant_admin | project_admin | member | viewer |
|--------|--------------|---------------|--------|--------|
| List projects | All in tenant | Assigned only | Assigned only | Assigned only |
| Create project | ✅ | ❌ | ✅ (becomes owner) | ❌ |
| Read project | ✅ | If assigned | If owner/assigned | If assigned |
| Update project | ✅ | If assigned | If owner | ❌ |
| Delete project | ✅ | If assigned | If owner | ❌ |
| Manage users | ✅ | ❌ | ❌ | ❌ |
| View audit logs | ✅ | ❌ | ❌ | ❌ |

---

## BOLA/IDOR Prevention: Server-Side Enforcement Rules

### The Cardinal Rule

> **NEVER** use any identifier from the request (URL, body, headers) to determine tenant context. The tenant_id MUST come from the validated JWT claims.

### Enforcement Checklist

#### ✅ DO: Correct Patterns

```python
# CORRECT: tenant_id from JWT claims only
@app.get("/api/projects/{project_id}")
def get_project(
    project_id: str,
    current_user: User = Depends(get_current_user)  # Extracts from JWT
):
    # RLS automatically filters by current_user.tenant_id
    project = db.query(Project).filter_by(id=project_id).first()
    
    if not project:
        raise HTTPException(404)  # Don't say "not authorized", say "not found"
    
    # Additional ownership check for non-admins
    if not current_user.is_admin:
        if not project.is_accessible_by(current_user):
            raise HTTPException(404)  # Still 404, not 403
    
    return project
```

```python
# CORRECT: Creating resource with tenant from JWT
@app.post("/api/projects")
def create_project(
    body: ProjectCreate,
    current_user: User = Depends(get_current_user)
):
    project = Project(
        id=uuid.uuid4(),
        tenant_id=current_user.tenant_id,  # FROM JWT, not body
        name=body.name,
        owner_id=current_user.id,
        created_by=current_user.id
    )
    db.add(project)
    return project
```

#### ❌ DON'T: Vulnerable Patterns

```python
# WRONG: tenant_id from URL parameter
@app.get("/api/tenants/{tenant_id}/projects")
def get_projects(tenant_id: str):  # VULNERABLE TO IDOR
    return db.query(Project).filter_by(tenant_id=tenant_id).all()

# WRONG: tenant_id from request body
@app.post("/api/projects")
def create_project(body: dict):
    project = Project(
        tenant_id=body["tenant_id"],  # VULNERABLE TO IDOR
        name=body["name"]
    )
```

```python
# WRONG: 403 reveals resource exists
if project.tenant_id != current_user.tenant_id:
    raise HTTPException(403, "Access denied")  # Reveals it exists!
```

### Defense in Depth Layers

```
Layer 1: JWT Validation      → Reject invalid/expired tokens
Layer 2: Tenant Extraction   → Extract tid from validated claims
Layer 3: Application Check   → Verify ownership/assignment
Layer 4: Database RLS        → Filter queries regardless of app bugs
Layer 5: Audit Logging       → Detect anomalies after the fact
```

---

## Rate Limiting

### Configuration

| Scope | Limit | Window | Response |
|-------|-------|--------|----------|
| Per IP (unauthenticated) | 100 requests | 1 minute | 429 + Retry-After |
| Per User | 1000 requests | 1 minute | 429 + Retry-After |
| Per Tenant | 10000 requests | 1 minute | 429 + Retry-After |
| Auth endpoints | 5 requests | 1 minute | 429 + Account lockout |

### Implementation Notes

```yaml
# Example: Kong rate limiting plugin
plugins:
  - name: rate-limiting
    config:
      minute: 1000
      policy: redis
      identifier: consumer  # Uses JWT sub claim
      hide_client_headers: false
```

### Burst Handling

- Allow short bursts (2x limit) with token bucket
- Soft limit: Return 429, allow retry
- Hard limit: Block IP temporarily (repeat offenders)

---

## Replay Protection

### Mechanisms

1. **Short Token Expiry**: Access tokens expire in 15 minutes
2. **JTI Tracking**: Store `jti` claim in Redis with TTL matching token expiry
3. **Single Use (optional)**: For sensitive operations, mark token as used

### Implementation

```python
async def verify_token_not_replayed(token: JWT) -> bool:
    """Check if this specific token has been used (for sensitive ops)"""
    jti = token.claims.get("jti")
    if not jti:
        return True  # No JTI, can't track (consider requiring it)
    
    # Check if JTI exists in Redis
    key = f"used_token:{jti}"
    if await redis.exists(key):
        raise SecurityException("Token already used")
    
    # Mark as used (with expiry matching token)
    ttl = token.claims["exp"] - int(time.time())
    await redis.setex(key, ttl, "1")
    
    return True
```

---

## Session/Token Rotation

### Access Token Rotation

- **Expiry**: 15 minutes (short-lived)
- **Refresh**: Client uses refresh_token before expiry
- **No rotation**: Access tokens are stateless, just expire

### Refresh Token Rotation

```
1. Client requests token refresh
2. Server validates refresh_token
3. Server issues NEW refresh_token
4. Server invalidates OLD refresh_token
5. Client stores new tokens
```

### Implementation

```python
async def refresh_tokens(refresh_token: str) -> TokenPair:
    # Validate refresh token
    claims = verify_refresh_token(refresh_token)
    
    # Check not revoked
    if await is_token_revoked(claims["jti"]):
        raise AuthException("Token revoked")
    
    # Revoke old refresh token
    await revoke_token(claims["jti"])
    
    # Issue new pair
    user = await get_user(claims["sub"])
    return TokenPair(
        access_token=create_access_token(user, expiry=900),
        refresh_token=create_refresh_token(user, expiry=604800)
    )
```

### Logout Flow

```python
async def logout(refresh_token: str):
    claims = verify_refresh_token(refresh_token)
    
    # Revoke refresh token
    await revoke_token(claims["jti"])
    
    # Optional: Add access token to blocklist
    # (only if immediate revocation needed)
    await blocklist_access_token(claims["access_jti"], ttl=900)
```

---

## Common Startup Mistakes & How Shielded-Start Prevents Them

### Mistake 1: Trusting Client-Supplied Tenant IDs

**The Bug**:
```javascript
// Frontend sends tenant_id in request body
fetch('/api/projects', {
  body: JSON.stringify({ tenant_id: userTenantId, name: 'Project' })
});

// Backend trusts it
app.post('/api/projects', (req) => {
  db.insert({ tenant_id: req.body.tenant_id, ... });  // VULNERABLE
});
```

**How We Prevent It**:
- JWT contains `tid` claim, signed by IdP
- Backend extracts `tid` from validated JWT only
- RLS policies use `current_setting('app.tenant_id')` set from JWT
- Request body `tenant_id` is ignored or triggers alert

---

### Mistake 2: 403 vs 404 Information Leakage

**The Bug**:
```python
if project.tenant_id != user.tenant_id:
    raise HTTPException(403, "You don't have access to this project")
    # Attacker now knows the project EXISTS
```

**How We Prevent It**:
- ALL unauthorized access returns 404 (resource not found)
- RLS returns empty results for cross-tenant queries
- No distinction between "doesn't exist" and "not authorized"

---

### Mistake 3: Long-Lived Tokens Without Rotation

**The Bug**:
```python
# Token valid for 30 days, no rotation
access_token = create_token(user, expiry=30*24*60*60)
# If stolen, attacker has month-long access
```

**How We Prevent It**:
- Access tokens: 15 minutes max
- Refresh tokens: 7 days, rotated on each use
- Compromised refresh token: Single use means attacker or user gets it, not both

---

### Mistake 4: Missing Ownership Checks After Tenant Check

**The Bug**:
```python
def get_project(project_id, user):
    project = db.query(Project).filter_by(
        id=project_id, 
        tenant_id=user.tenant_id  # Good: tenant check
    ).first()
    return project  # Bad: Any user in tenant sees any project
```

**How We Prevent It**:
- Two-layer authorization: tenant boundary + ownership/assignment
- Non-admin users only see resources they own or are assigned to
- Documented in role matrix above

---

### Mistake 5: PII in Log Messages

**The Bug**:
```python
logger.info(f"User login: {user.email}, password attempt: {password}")
# PII in logs, searchable by anyone with log access
```

**How We Prevent It**:
- Explicit allow-list of loggable fields
- Never log: passwords, tokens, PII, request bodies
- Structured logging with sanitization

---

### Mistake 6: Bypassing RLS with Superuser Connections

**The Bug**:
```sql
-- App connects as postgres superuser (bypasses RLS)
psql -U postgres -d production
SELECT * FROM projects;  -- Returns ALL tenants' data
```

**How We Prevent It**:
- `FORCE ROW LEVEL SECURITY` on all tables
- App connects as `app_user` with restricted permissions
- Superuser access requires approval and is logged

---

### Mistake 7: Sequential IDs Enable Enumeration

**The Bug**:
```
GET /api/documents/1    → 404
GET /api/documents/2    → 200 (found one!)
GET /api/documents/3    → 200 (found another!)
... attacker scrapes entire database
```

**How We Prevent It**:
- UUIDs for all identifiers (non-enumerable)
- RLS means guessed IDs return 404 anyway
- Rate limiting detects enumeration attempts

---

## Implementation Checklist

### Before Launch

- [ ] JWT validation on all protected endpoints
- [ ] `tid` claim extracted from JWT, never from request
- [ ] Role checks on all privileged operations  
- [ ] Ownership checks for non-admin users
- [ ] 404 returned for unauthorized resources (not 403)
- [ ] Rate limiting configured and tested
- [ ] Token expiry ≤ 30 minutes
- [ ] Refresh token rotation enabled
- [ ] Audit logging for auth events

### Periodic Review

- [ ] Review JWT claims for unnecessary data
- [ ] Audit endpoints for missing authorization
- [ ] Test cross-tenant access (must fail)
- [ ] Review rate limit effectiveness
- [ ] Check for hardcoded credentials
- [ ] Verify token revocation works

---

## Quick Reference: Authorization Pseudocode

```python
def authorize(request, resource_type, action):
    # 1. Extract user from validated JWT (done by middleware)
    user = request.current_user
    
    # 2. For resource access, load resource with RLS
    if request.resource_id:
        resource = db.query(resource_type).filter_by(
            id=request.resource_id
            # RLS automatically adds: AND tenant_id = current_tenant_id()
        ).first()
        
        if not resource:
            raise NotFound()  # Could be: doesn't exist OR wrong tenant
        
        # 3. Ownership check (non-admins)
        if not user.is_admin(resource_type):
            if not resource.is_accessible_by(user):
                raise NotFound()  # Still 404
    
    # 4. Permission check
    if not user.has_permission(action, resource_type):
        raise Forbidden()  # This one can be 403
    
    # 5. Proceed
    return True
```

