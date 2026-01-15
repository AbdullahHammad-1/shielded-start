# Architecture Overview

## Executive Summary

This document describes the security architecture for a multi-tenant B2B SaaS application. The architecture enforces **tenant isolation at every layer** through a combination of:

1. **JWT-based authentication** with embedded tenant claims
2. **Row-Level Security (RLS)** in PostgreSQL
3. **Application-layer authorization** with ownership checks
4. **Structured audit logging** with PII controls

---

## System Context

### What We're Building

A typical B2B SaaS serving multiple organizations (tenants), where:

- Each tenant has multiple users with different roles
- Users create and manage resources (projects, documents, etc.)
- Data isolation between tenants is **non-negotiable**
- Audit trail is required for compliance

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                         INTERNET                                │
│                     (Untrusted Zone)                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      EDGE / CDN                                 │
│              (DDoS protection, WAF, TLS termination)            │
│                     Trust Level: LOW                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     API GATEWAY                                 │
│         (JWT validation, rate limiting, request routing)        │
│                    Trust Level: MEDIUM                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   APPLICATION LAYER                             │
│       (Business logic, authorization, tenant context)           │
│                    Trust Level: HIGH                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     DATA LAYER                                  │
│            (PostgreSQL with RLS, encrypted at rest)             │
│                   Trust Level: HIGHEST                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Component Architecture

### 1. Identity Provider (IdP)

**Responsibility**: User authentication, JWT issuance

**Security Controls**:
- MFA enforcement for privileged users
- Password policy (min 12 chars, complexity, breach check)
- Session management with rotation
- Tenant association stored and validated

**Implementation Options**:
| Provider | Pros | Cons |
|----------|------|------|
| Auth0 | Quick setup, good SDKs | Cost scales with MAU |
| AWS Cognito | AWS-native, cheap | Complex customization |
| Keycloak | Self-hosted, flexible | Ops overhead |
| Custom | Full control | Security risk, time cost |

**Recommended**: Auth0 or Cognito for early stage, migrate if needed.

---

### 2. API Gateway

**Responsibility**: Request validation, routing, rate limiting

**Security Controls**:
- JWT signature verification
- Token expiry validation
- Rate limiting per tenant/user
- Request size limits
- CORS enforcement

**Key Configuration**:
```yaml
# Example: Kong / AWS API Gateway pattern
jwt_validation:
  issuer: "https://auth.yourapp.com/"
  audience: "api.yourapp.com"
  algorithms: ["RS256"]
  
rate_limiting:
  per_tenant:
    requests: 1000
    window: 60s
  per_user:
    requests: 100
    window: 60s
    
request_limits:
  max_body_size: 10MB
  timeout: 30s
```

---

### 3. Application Layer

**Responsibility**: Business logic, authorization enforcement

**Security Controls**:
- Extract and validate tenant context from JWT
- Enforce RBAC based on user roles
- Ownership checks before data operations
- Input validation and sanitization
- Structured error responses (no stack traces)

**Tenant Context Flow**:
```
1. Request arrives with JWT
2. Middleware extracts tenant_id, user_id, roles from claims
3. Context object created and attached to request
4. All database operations use this context
5. Context is NEVER derived from request body/params
```

**Critical Rule**: `tenant_id` comes ONLY from the JWT, never from:
- URL parameters
- Request body
- Query strings
- Headers (other than Authorization)

---

### 4. Database Layer

**Responsibility**: Data persistence with enforced isolation

**Security Controls**:
- Row-Level Security (RLS) policies
- Tenant context set via session variables
- Encrypted at rest (AES-256)
- Encrypted in transit (TLS 1.3)
- Connection pooling with context reset

**RLS Pattern**:
```sql
-- Every query is automatically filtered
SELECT * FROM projects;
-- Becomes (via RLS):
SELECT * FROM projects WHERE tenant_id = current_setting('app.tenant_id')::uuid;
```

---

## Data Classification

| Classification | Examples | Controls |
|---------------|----------|----------|
| **Critical** | Auth tokens, API keys, passwords | Encrypted, never logged, short-lived |
| **Confidential** | User PII, billing info | Encrypted, access-logged, RLS protected |
| **Internal** | Business data, projects | RLS protected, audit logged |
| **Public** | Marketing content | CDN-cached, no auth required |

---

## Authentication Flow

### Token Lifecycle

```
1. USER LOGIN
   └─→ IdP validates credentials
   └─→ IdP issues access_token + refresh_token
   └─→ access_token contains: sub, tenant_id, roles, exp, jti

2. API REQUEST
   └─→ Gateway validates JWT signature
   └─→ Gateway checks token not expired
   └─→ Gateway passes validated claims to app
   └─→ App sets tenant context for database

3. TOKEN REFRESH
   └─→ Client uses refresh_token before access_token expires
   └─→ IdP issues new access_token (short-lived: 15 min)
   └─→ refresh_token rotated (longer-lived: 7 days)

4. LOGOUT
   └─→ Client discards tokens
   └─→ Refresh token revoked in IdP
   └─→ Access token naturally expires (or add to blocklist for immediate revocation)
```

---

## Authorization Model

### Role-Based Access Control (RBAC)

| Role | Permissions | Scope |
|------|-------------|-------|
| `tenant_admin` | Full CRUD on tenant resources | Tenant-wide |
| `project_admin` | Full CRUD on assigned projects | Project-level |
| `member` | Read + limited write on assigned resources | Resource-level |
| `viewer` | Read-only on assigned resources | Resource-level |

### Permission Checks (Pseudocode)

```python
def authorize_action(user, resource, action):
    # 1. Tenant boundary (CRITICAL - always first)
    if user.tenant_id != resource.tenant_id:
        raise ForbiddenError("Cross-tenant access denied")
    
    # 2. Role-based permission
    if not user.has_permission(action, resource.type):
        raise ForbiddenError("Insufficient permissions")
    
    # 3. Ownership/assignment check (for non-admins)
    if not user.is_tenant_admin():
        if not resource.is_accessible_by(user):
            raise ForbiddenError("Resource not assigned to user")
    
    return True
```

---

## Deployment Architecture

### Recommended Setup (Early Stage)

```
┌─────────────────────────────────────────────────────────────────┐
│                     CLOUD PROVIDER                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐       │
│  │   CloudFront│     │     ALB     │     │   RDS       │       │
│  │   (CDN)     │────▶│  (Gateway)  │────▶│ (PostgreSQL)│       │
│  └─────────────┘     └─────────────┘     └─────────────┘       │
│                             │                   │               │
│                             ▼                   │               │
│                      ┌─────────────┐            │               │
│                      │    ECS      │────────────┘               │
│                      │   (App)     │                            │
│                      └─────────────┘                            │
│                             │                                   │
│                             ▼                                   │
│                      ┌─────────────┐                            │
│                      │  Secrets    │                            │
│                      │  Manager    │                            │
│                      └─────────────┘                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Security Hardening Checklist

- [ ] VPC with private subnets for app/database
- [ ] Security groups: minimal ingress, explicit egress
- [ ] RDS: not publicly accessible, encrypted, automated backups
- [ ] Secrets Manager: rotation enabled, IAM-scoped access
- [ ] CloudTrail: enabled for audit
- [ ] GuardDuty: enabled for threat detection
- [ ] WAF: OWASP rule set on ALB

---

## Monitoring & Alerting

### Security-Relevant Metrics

| Metric | Alert Threshold | Response |
|--------|-----------------|----------|
| Failed auth attempts | >10/min per IP | Temp block, investigate |
| Cross-tenant query attempts | Any occurrence | Immediate investigation |
| RLS policy violations | Any occurrence | Immediate investigation |
| 4xx rate spike | >50% increase | Review for scanning |
| Token refresh failures | >5% of attempts | Check IdP health |

### Audit Log Requirements

Every state-changing operation must log:
- **Who**: user_id, tenant_id
- **What**: action, resource_type, resource_id
- **When**: timestamp (UTC)
- **Where**: IP, user_agent (hashed)
- **Result**: success/failure, error_code

**Never log**: passwords, tokens, PII, request/response bodies

---

## Incident Response Touchpoints

### If Breach Suspected

1. **Contain**: Revoke affected tenant's tokens
2. **Assess**: Query audit logs for affected scope
3. **Notify**: Affected tenants within SLA
4. **Remediate**: Patch vulnerability, rotate credentials
5. **Review**: Post-incident analysis, update threat model

### Key Queries for Investigation

```sql
-- All actions by a compromised user
SELECT * FROM audit_logs 
WHERE user_id = 'xxx' 
AND created_at > '2024-01-01';

-- Cross-tenant access attempts (should be empty)
SELECT * FROM audit_logs 
WHERE action = 'access_denied' 
AND error_code = 'CROSS_TENANT';
```

---

## Future Considerations

### Scale Triggers

| Trigger | Current Approach | Evolution Path |
|---------|-----------------|----------------|
| >100 tenants | Shared DB with RLS | Consider schema-per-tenant |
| >10M rows/table | Single PostgreSQL | Read replicas, partitioning |
| >1000 RPS | Single region | Multi-region, CDN caching |
| Compliance (SOC2) | Self-attestation | Formal audit, controls documentation |

### Technical Debt to Address

1. **Token revocation**: Implement blocklist for immediate invalidation
2. **Field-level encryption**: For PII beyond at-rest encryption
3. **Anomaly detection**: ML-based unusual access patterns
4. **Zero-trust internal**: Service mesh with mTLS

