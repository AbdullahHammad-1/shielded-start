# Threat Model: STRIDE Analysis

## Overview

This document analyzes threats using the **STRIDE** framework:
- **S**poofing - Pretending to be someone/something else
- **T**ampering - Modifying data or code
- **R**epudiation - Denying actions taken
- **I**nformation Disclosure - Exposing data to unauthorized parties
- **D**enial of Service - Making the system unavailable
- **E**levation of Privilege - Gaining unauthorized access levels

---

## Threat Analysis by Component

### 1. Authentication System

| ID | STRIDE | Threat | Attack Vector | Likelihood | Impact | Risk |
|----|--------|--------|---------------|------------|--------|------|
| AUTH-01 | Spoofing | Credential stuffing | Automated login attempts with leaked credentials | HIGH | HIGH | **CRITICAL** |
| AUTH-02 | Spoofing | Session hijacking | Stolen JWT from XSS, network sniffing | MEDIUM | CRITICAL | **HIGH** |
| AUTH-03 | Spoofing | JWT forgery | Weak signing key, algorithm confusion | LOW | CRITICAL | **HIGH** |
| AUTH-04 | Tampering | Token manipulation | Modify claims in unsigned/weak-signed JWT | LOW | CRITICAL | **HIGH** |
| AUTH-05 | Repudiation | Login without audit | Missing/incomplete auth logging | MEDIUM | MEDIUM | **MEDIUM** |
| AUTH-06 | Info Disclosure | Credential leakage | Error messages reveal valid usernames | MEDIUM | MEDIUM | **MEDIUM** |
| AUTH-07 | DoS | Auth endpoint flooding | Brute force causing account lockout | HIGH | MEDIUM | **MEDIUM** |
| AUTH-08 | EoP | Privilege escalation via role bugs | Manipulate role claims or bypass checks | MEDIUM | CRITICAL | **HIGH** |

### 2. API Layer

| ID | STRIDE | Threat | Attack Vector | Likelihood | Impact | Risk |
|----|--------|--------|---------------|------------|--------|------|
| API-01 | Spoofing | API key theft | Keys in client code, logs, or repos | HIGH | HIGH | **CRITICAL** |
| API-02 | Tampering | Request manipulation | Modify tenant_id in request body | HIGH | CRITICAL | **CRITICAL** |
| API-03 | Tampering | SQL injection | Unsanitized input in queries | MEDIUM | CRITICAL | **HIGH** |
| API-04 | Repudiation | Action without audit | Missing audit trail for mutations | MEDIUM | HIGH | **HIGH** |
| API-05 | Info Disclosure | **IDOR/BOLA** | Access resources by guessing IDs | HIGH | CRITICAL | **CRITICAL** |
| API-06 | Info Disclosure | Verbose errors | Stack traces in production responses | HIGH | MEDIUM | **MEDIUM** |
| API-07 | Info Disclosure | Mass assignment | Overwrite protected fields via API | MEDIUM | HIGH | **HIGH** |
| API-08 | DoS | Rate limit bypass | Distribute requests across IPs | MEDIUM | MEDIUM | **MEDIUM** |
| API-09 | EoP | Broken function-level auth | Access admin endpoints without admin role | MEDIUM | CRITICAL | **HIGH** |

### 3. Database Layer

| ID | STRIDE | Threat | Attack Vector | Likelihood | Impact | Risk |
|----|--------|--------|---------------|------------|--------|------|
| DB-01 | Spoofing | Connection impersonation | Stolen database credentials | LOW | CRITICAL | **HIGH** |
| DB-02 | Tampering | Direct data modification | SQL injection bypassing app layer | MEDIUM | CRITICAL | **HIGH** |
| DB-03 | Tampering | **RLS bypass** | SET app.tenant_id to another tenant | LOW | CRITICAL | **HIGH** |
| DB-04 | Repudiation | Unlogged data changes | Direct DB access without audit | LOW | HIGH | **MEDIUM** |
| DB-05 | Info Disclosure | **Tenant data leakage** | Query without RLS, misconfigured policy | MEDIUM | CRITICAL | **CRITICAL** |
| DB-06 | Info Disclosure | Backup exposure | Unencrypted backups, public S3 bucket | LOW | CRITICAL | **HIGH** |
| DB-07 | DoS | Resource exhaustion | Expensive queries, connection pool exhaustion | MEDIUM | HIGH | **MEDIUM** |
| DB-08 | EoP | Privilege escalation | App user has excessive DB permissions | LOW | CRITICAL | **HIGH** |

### 4. Multi-Tenancy

| ID | STRIDE | Threat | Attack Vector | Likelihood | Impact | Risk |
|----|--------|--------|---------------|------------|--------|------|
| MT-01 | Spoofing | **Tenant impersonation** | Forge tenant_id claim in JWT | LOW | CRITICAL | **HIGH** |
| MT-02 | Tampering | Cross-tenant modification | Update resource with different tenant_id | MEDIUM | CRITICAL | **CRITICAL** |
| MT-03 | Info Disclosure | **Cross-tenant data access** | IDOR allowing access to other tenant data | HIGH | CRITICAL | **CRITICAL** |
| MT-04 | Info Disclosure | Tenant enumeration | Predictable tenant IDs, error messages | MEDIUM | LOW | **LOW** |
| MT-05 | DoS | Noisy neighbor | One tenant consumes all resources | MEDIUM | HIGH | **MEDIUM** |
| MT-06 | EoP | Tenant admin escape | Tenant admin gains platform admin access | LOW | CRITICAL | **HIGH** |

### 5. Logging & Monitoring

| ID | STRIDE | Threat | Attack Vector | Likelihood | Impact | Risk |
|----|--------|--------|---------------|------------|--------|------|
| LOG-01 | Tampering | Log injection | Inject false entries via input fields | MEDIUM | MEDIUM | **MEDIUM** |
| LOG-02 | Tampering | Log deletion | Attacker covers tracks by deleting logs | LOW | HIGH | **MEDIUM** |
| LOG-03 | Repudiation | Incomplete logging | Actions not logged, can't prove what happened | MEDIUM | HIGH | **MEDIUM** |
| LOG-04 | Info Disclosure | **PII in logs** | Sensitive data written to log files | HIGH | HIGH | **HIGH** |
| LOG-05 | Info Disclosure | Log scraping | Attacker accesses centralized logs | LOW | HIGH | **MEDIUM** |
| LOG-06 | DoS | Log flooding | Generate excessive logs to fill storage | LOW | MEDIUM | **LOW** |

### 6. Infrastructure

| ID | STRIDE | Threat | Attack Vector | Likelihood | Impact | Risk |
|----|--------|--------|---------------|------------|--------|------|
| INF-01 | Spoofing | DNS hijacking | Compromise DNS to redirect traffic | LOW | CRITICAL | **HIGH** |
| INF-02 | Tampering | Supply chain attack | Malicious dependency in package manager | MEDIUM | CRITICAL | **HIGH** |
| INF-03 | Tampering | CI/CD pipeline compromise | Inject malicious code in builds | LOW | CRITICAL | **HIGH** |
| INF-04 | Info Disclosure | Secrets in code | Hardcoded credentials in repository | HIGH | CRITICAL | **CRITICAL** |
| INF-05 | Info Disclosure | Unencrypted traffic | Missing TLS on internal services | LOW | HIGH | **MEDIUM** |
| INF-06 | DoS | DDoS attack | Volumetric attack on public endpoints | MEDIUM | HIGH | **MEDIUM** |
| INF-07 | EoP | Container escape | Exploit to break out of container | LOW | CRITICAL | **HIGH** |

---

## Abuse Cases

### Abuse Case 1: Tenant Breakout Attempt

**Attacker Profile**: Malicious user of Tenant A
**Goal**: Access Tenant B's data

```
SCENARIO:
1. Attacker signs up legitimately for Tenant A
2. Obtains valid JWT with tenant_id = "tenant-a"
3. Intercepts API request and modifies tenant_id in body to "tenant-b"
4. Sends modified request to API

EXPECTED RESULT (with proper controls):
- API ignores tenant_id from request body
- Extracts tenant_id only from JWT claims
- RLS policy filters query to tenant-a data only
- Attacker sees only their own data

FAILURE MODE (without controls):
- API trusts tenant_id from request body
- Query executed for tenant-b
- Attacker accesses victim's data
```

### Abuse Case 2: Token Theft & Replay

**Attacker Profile**: External attacker with network access
**Goal**: Hijack user session

```
SCENARIO:
1. Attacker performs XSS attack on vulnerable page
2. Steals victim's access_token from localStorage
3. Replays token in their own requests
4. Attempts to use token after victim logs out

EXPECTED RESULT (with proper controls):
- Short token expiry (15 min) limits window
- Token bound to IP/User-Agent (optional)
- Logout revokes refresh_token
- Suspicious activity detected by monitoring

FAILURE MODE (without controls):
- Long-lived tokens remain valid indefinitely
- No mechanism to revoke compromised tokens
- Attacker maintains persistent access
```

### Abuse Case 3: Privilege Escalation via Role Bugs

**Attacker Profile**: Low-privilege user
**Goal**: Gain admin access

```
SCENARIO:
1. User with role="member" authenticated
2. Discovers admin endpoint: POST /api/admin/users
3. Attempts direct access to admin endpoint
4. Tries to modify own role claim in requests

EXPECTED RESULT (with proper controls):
- Endpoint checks role from JWT claims (not request)
- Authorization middleware denies non-admin users
- Attempt logged as security event
- Alert triggered on repeated failures

FAILURE MODE (without controls):
- Role checked from request parameter
- Missing authorization on admin endpoints
- Attacker creates new admin user
```

### Abuse Case 4: Insecure Direct Object Reference (IDOR)

**Attacker Profile**: Authenticated user
**Goal**: Access resources they don't own

```
SCENARIO:
1. User discovers document URL: /api/documents/doc-123
2. Notices doc-123 is a sequential or guessable ID
3. Iterates through doc-001, doc-002, ... doc-999
4. Finds documents belonging to other users/tenants

EXPECTED RESULT (with proper controls):
- UUIDs prevent enumeration
- RLS filters by tenant_id regardless of document ID
- Ownership check verifies user access
- Only empty results returned for unauthorized access

FAILURE MODE (without controls):
- Sequential/predictable IDs
- No tenant filtering
- Attacker downloads entire document database
```

### Abuse Case 5: Log Scraping / PII Leakage

**Attacker Profile**: Malicious insider or compromised service
**Goal**: Extract sensitive data from logs

```
SCENARIO:
1. Attacker gains access to log aggregation system
2. Searches logs for patterns: "email:", "password:", "ssn:"
3. Extracts PII from verbose error logs
4. Correlates with tenant data for targeted attacks

EXPECTED RESULT (with proper controls):
- PII never written to logs
- Structured logging with explicit field allow-list
- Log access requires privileged credentials
- Access to logs is itself logged and monitored

FAILURE MODE (without controls):
- Request/response bodies logged verbatim
- Exception stack traces include user data
- Logs accessible to broad team without audit
```

---

## Attack Trees

### Attack Tree: Cross-Tenant Data Access

```
GOAL: Access another tenant's data
├── OR: Exploit authentication weakness
│   ├── AND: Forge JWT
│   │   ├── Obtain signing key (leaked, weak, brute-forced)
│   │   └── Craft JWT with target tenant_id
│   ├── AND: Steal valid token
│   │   ├── XSS to extract from browser
│   │   └── Replay before expiry
│   └── AND: Session fixation
│       ├── Force victim to use attacker's session
│       └── Victim authenticates, attacker uses session
├── OR: Exploit authorization weakness
│   ├── AND: IDOR/BOLA
│   │   ├── Enumerate resource IDs
│   │   └── App fails to check ownership
│   ├── AND: Parameter tampering
│   │   ├── Modify tenant_id in request
│   │   └── App trusts client-supplied tenant_id
│   └── AND: Broken function-level auth
│       ├── Access admin endpoint
│       └── No role check on endpoint
├── OR: Exploit database weakness
│   ├── AND: SQL injection
│   │   ├── Find injectable parameter
│   │   └── Bypass RLS with crafted query
│   ├── AND: RLS misconfiguration
│   │   ├── Policy missing on table
│   │   └── Query executes without tenant filter
│   └── AND: Direct database access
│       ├── Obtain database credentials
│       └── Connect without app context
└── OR: Exploit infrastructure
    ├── AND: Backup access
    │   ├── Find unprotected backup bucket
    │   └── Download and restore database
    └── AND: Log access
        ├── Access log aggregation
        └── Extract data from verbose logs
```

---

## Risk Summary

### Critical Risks (Immediate Action Required)

| ID | Threat | Current State | Required Action |
|----|--------|---------------|-----------------|
| MT-03 | Cross-tenant data access | See mitigations | Verify RLS on ALL tables |
| API-05 | IDOR/BOLA | See mitigations | Audit all endpoints for ownership checks |
| INF-04 | Secrets in code | See mitigations | Scan git history, rotate exposed secrets |
| API-02 | Request manipulation | See mitigations | Ensure tenant_id from JWT only |

### High Risks (Address Within 30 Days)

| ID | Threat | Current State | Required Action |
|----|--------|---------------|-----------------|
| AUTH-01 | Credential stuffing | Partial | Implement rate limiting + MFA |
| AUTH-02 | Session hijacking | Partial | Short token expiry, secure cookies |
| LOG-04 | PII in logs | Unknown | Audit logging code, implement filters |
| INF-02 | Supply chain attack | Unknown | Enable dependency scanning in CI |

---

## Next Steps

With threats identified, proceed to:
1. **[mitigations.md](./mitigations.md)** - Controls for each threat
2. **[../security-decisions.md](../security-decisions.md)** - Design decisions addressing these threats

