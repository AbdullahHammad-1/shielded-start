# Threat Model: Assets Inventory

## Overview

This document identifies and classifies the assets that matter for security in a B2B multi-tenant SaaS. Assets are categorized by their value to attackers and impact if compromised.

---

## Asset Categories

### 1. Data Assets

| Asset | Description | Classification | Impact if Compromised |
|-------|-------------|----------------|----------------------|
| **Customer Business Data** | Projects, documents, configurations created by tenants | Confidential | Customer trust destroyed, regulatory fines, lawsuits |
| **User Credentials** | Passwords (hashed), MFA secrets, recovery codes | Critical | Account takeover, lateral movement |
| **API Keys & Secrets** | Database passwords, third-party API keys, encryption keys | Critical | Full system compromise, data exfiltration |
| **JWT Signing Keys** | Private keys for signing access tokens | Critical | Token forgery, complete auth bypass |
| **Tenant Configuration** | Billing info, subscription details, feature flags | Confidential | Financial fraud, service manipulation |
| **User PII** | Names, emails, phone numbers, addresses | Confidential | Privacy violations, compliance penalties |
| **Audit Logs** | Who did what, when (security-relevant events) | Internal | Cover tracks, hide breach evidence |
| **Session Tokens** | Active access_tokens and refresh_tokens | Critical | Session hijacking, impersonation |

### 2. Infrastructure Assets

| Asset | Description | Classification | Impact if Compromised |
|-------|-------------|----------------|----------------------|
| **Production Database** | PostgreSQL with all tenant data | Critical | Complete data breach |
| **Application Servers** | ECS/K8s containers running API | High | Code execution, pivot point |
| **Identity Provider** | Auth0/Cognito configuration | Critical | Auth bypass, token forgery |
| **Secrets Manager** | Vault/AWS SM containing all secrets | Critical | Full credential compromise |
| **CI/CD Pipeline** | GitHub Actions, deployment credentials | High | Supply chain attack, backdoors |
| **DNS Configuration** | Route53/Cloudflare DNS records | High | Traffic interception, phishing |
| **TLS Certificates** | Private keys for HTTPS | High | MITM attacks |
| **Backup Storage** | S3 buckets with database dumps | Critical | Historical data exposure |

### 3. Process Assets

| Asset | Description | Classification | Impact if Compromised |
|-------|-------------|----------------|----------------------|
| **Source Code** | Application codebase | High | Vulnerability discovery, IP theft |
| **Security Documentation** | Threat models, runbooks | Internal | Attacker roadmap |
| **Incident Response Procedures** | Playbooks for breach response | Internal | Delayed/ineffective response |
| **Customer Contracts** | SLAs, DPAs, security commitments | Confidential | Legal exposure |

---

## Entry Points

Entry points are locations where data or commands enter the system from external sources.

### Primary Entry Points

| Entry Point | Trust Level | Data Received | Validation Required |
|-------------|-------------|---------------|---------------------|
| **Public API (REST/GraphQL)** | Untrusted | JSON payloads, file uploads | Auth, input validation, rate limiting |
| **Authentication Endpoints** | Untrusted | Credentials, MFA codes | Brute-force protection, secure comparison |
| **Webhook Receivers** | Semi-trusted | Third-party event data | Signature verification, idempotency |
| **Admin Dashboard** | Trusted (internal) | Configuration changes | Strong auth, audit logging |
| **Database Connections** | Trusted (internal) | SQL queries | Connection auth, RLS enforcement |

### Secondary Entry Points

| Entry Point | Trust Level | Risk |
|-------------|-------------|------|
| **Email (inbound processing)** | Untrusted | Phishing, malware, header injection |
| **File Uploads** | Untrusted | Malware, XXE, path traversal |
| **OAuth Callbacks** | Semi-trusted | State manipulation, token leakage |
| **CLI Tools** | Trusted (developer) | Credential exposure, local attacks |

---

## Trust Boundaries

A trust boundary exists where data moves between components with different trust levels.

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  INTERNET (Trust: None)                                             │
│  • Anonymous users                                                  │
│  • Attackers                                                        │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  ▼ BOUNDARY: TLS + WAF + Rate Limiting                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  EDGE (Trust: Low)                                                  │
│  • CDN nodes                                                        │
│  • WAF rules applied                                                │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  ▼ BOUNDARY: JWT Validation                                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  API GATEWAY (Trust: Medium)                                        │
│  • Authenticated requests only                                      │
│  • Rate limits enforced                                             │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  ▼ BOUNDARY: Tenant Context Injection                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  APPLICATION (Trust: High)                                          │
│  • Business logic                                                   │
│  • Authorization decisions                                          │
│  • Tenant context set from JWT                                      │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  ▼ BOUNDARY: RLS Policy Enforcement                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  DATABASE (Trust: Highest)                                          │
│  • RLS filters all queries                                          │
│  • Encrypted at rest                                                │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Asset Criticality Matrix

| Asset | Confidentiality | Integrity | Availability | Overall Risk |
|-------|-----------------|-----------|--------------|--------------|
| JWT Signing Keys | CRITICAL | CRITICAL | HIGH | **CRITICAL** |
| Database Credentials | CRITICAL | CRITICAL | HIGH | **CRITICAL** |
| Customer Business Data | HIGH | HIGH | HIGH | **HIGH** |
| User Credentials (hashed) | HIGH | CRITICAL | MEDIUM | **HIGH** |
| Audit Logs | MEDIUM | CRITICAL | HIGH | **HIGH** |
| User PII | HIGH | MEDIUM | LOW | **MEDIUM** |
| Application Code | MEDIUM | HIGH | LOW | **MEDIUM** |

---

## Data Flow: Asset Touchpoints

### Authentication Flow Assets

```
User Credentials → IdP → JWT (with tenant_id) → Gateway → App → Database
                    ↓
              MFA Secrets
              Session Store
```

### Business Data Flow Assets

```
API Request → Gateway → App Context → Database Query
                ↓            ↓              ↓
           Rate Limits   Audit Log    RLS-Filtered Data
```

### Secrets Access Flow

```
App Startup → Secrets Manager → Environment Variables → Database Connection
                   ↓
              Audit Trail
              Access Logs
```

---

## Protection Requirements

### Critical Assets (Must Protect)

| Asset | Protection Requirement |
|-------|----------------------|
| JWT Signing Keys | HSM or managed KMS, never in code, rotation every 90 days |
| Database Credentials | Secrets manager, IAM-based access, rotation enabled |
| Customer Data | Encryption at rest + transit, RLS isolation, audit logging |
| Backups | Encrypted, access-logged, retention policy, tested recovery |

### High-Value Assets (Should Protect)

| Asset | Protection Requirement |
|-------|----------------------|
| Audit Logs | Immutable storage, restricted access, retention compliance |
| User PII | Minimization, encryption, access controls, deletion capability |
| Source Code | Private repos, branch protection, signed commits |

---

## Inventory Maintenance Checklist

- [ ] Review asset inventory quarterly
- [ ] Update after new feature launches
- [ ] Reassess after security incidents
- [ ] Include in onboarding for new engineers
- [ ] Map to compliance requirements (SOC2, GDPR)

---

## Next Steps

With assets identified, proceed to:
1. **[threats.md](./threats.md)** - What can go wrong with each asset
2. **[mitigations.md](./mitigations.md)** - How we protect each asset

