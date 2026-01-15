# Security Design Decisions

## Overview

This document records key security architecture decisions, including alternatives considered, reasoning, tradeoffs, and future evolution paths. Use this as a reference when reviewing the architecture or planning changes.

---

## Decision Record Format

Each decision follows this structure:
- **Decision**: What we decided
- **Context**: Why we needed to decide
- **Options Considered**: Alternatives evaluated
- **Chosen Approach**: What we selected
- **Reasoning**: Why we chose it
- **Tradeoffs / Costs**: What we gave up
- **Future Improvements**: How this might evolve

---

## Decision 1: Multi-Tenancy Isolation Strategy

### Context
B2B SaaS requires isolating customer data. Three primary approaches exist, each with different security/complexity tradeoffs.

### Options Considered

| Option | Description | Security | Complexity | Cost |
|--------|-------------|----------|------------|------|
| **A. Separate Databases** | One database per tenant | Highest | High | High (per-DB overhead) |
| **B. Shared DB, Separate Schemas** | One schema per tenant | High | Medium | Medium |
| **C. Shared DB with RLS** | Single schema, row-level filtering | High (if done right) | Low | Low |
| **D. Application-Only Filtering** | WHERE tenant_id in queries | Low (bug-prone) | Lowest | Lowest |

### Chosen Approach
**Option C: Shared Database with Row-Level Security (RLS)**

### Reasoning

1. **Security**: RLS enforces isolation at database level, protecting against application bugs
2. **Simplicity**: Single schema means simpler migrations, backups, queries
3. **Cost**: No per-tenant infrastructure overhead at early stage
4. **Performance**: PostgreSQL RLS has minimal overhead for typical query patterns
5. **Startup-appropriate**: Team can ship fast without managing complex infrastructure

### Tradeoffs / Costs

| Tradeoff | Impact | Mitigation |
|----------|--------|------------|
| No complete physical isolation | Theoretical risk if DB compromised | Defense in depth, encryption at rest |
| Noisy neighbor potential | One tenant could affect others | Per-tenant query limits, monitoring |
| Complex RLS debugging | Policy issues harder to troubleshoot | Comprehensive test suite, staging env |
| Compliance limitations | Some regulations require physical separation | Document limitations, offer upgrade path |

### Future Improvements

| Trigger | Evolution |
|---------|-----------|
| Enterprise customer requires isolation | Offer dedicated database option (premium tier) |
| >1000 tenants | Consider schema-per-tenant for large tenants |
| Performance issues | Add read replicas, consider tenant sharding |
| SOC2 Type II audit | Document RLS as compensating control |

---

## Decision 2: Authentication Approach

### Context
API authentication requires balancing security, developer experience, and operational complexity.

### Options Considered

| Option | Description | Security | UX | Ops Complexity |
|--------|-------------|----------|-----|----------------|
| **A. JWTs (stateless)** | Self-contained tokens with claims | Good | Good | Low |
| **B. Opaque Sessions** | Server-side session store | Good | Good | Medium |
| **C. API Keys** | Long-lived static credentials | Lower | Simple | Low |
| **D. mTLS** | Certificate-based auth | Highest | Complex | High |

### Chosen Approach
**Option A: JWTs with short expiry + refresh tokens**

### Reasoning

1. **Stateless**: No session store required for access token validation
2. **Claims**: Tenant ID embedded in token, available without DB lookup
3. **Standard**: Well-supported across frameworks and services
4. **Scalable**: Easy to validate across multiple services
5. **Revocation**: Refresh token rotation + short access token expiry

### Tradeoffs / Costs

| Tradeoff | Impact | Mitigation |
|----------|--------|------------|
| Token size | Larger than opaque tokens | Keep claims minimal |
| Revocation delay | Access tokens valid until expiry | 15-min expiry, blocklist for emergencies |
| Secret key management | Signing keys must be protected | KMS/HSM for signing, rotation policy |
| Clock skew sensitivity | Expiry relies on time sync | NTP on all servers, reasonable leeway |

### Future Improvements

| Trigger | Evolution |
|---------|-----------|
| Need instant revocation | Implement token blocklist with Redis |
| Microservices growth | Add service-to-service tokens |
| High-security customers | Offer hardware token / FIDO2 support |

---

## Decision 3: Logging Strategy

### Context
Logs must support debugging, auditing, and incident response while protecting privacy.

### Options Considered

| Option | Description | Security | Utility | Compliance |
|--------|-------------|----------|---------|------------|
| **A. Log everything** | Full request/response logging | Low (PII exposure) | High | Poor |
| **B. Log nothing sensitive** | Minimal structured logs | High | Lower | Good |
| **C. Tokenized logging** | Replace PII with tokens | High | High | Good |
| **D. Tiered logging** | Different levels for different data | Medium | High | Good |

### Chosen Approach
**Option B: Structured logging with explicit allow-list (PII minimization)**

### Reasoning

1. **Privacy by default**: PII never logged unless explicitly allowed
2. **Compliance**: Meets GDPR minimization principle
3. **Simplicity**: No tokenization infrastructure needed
4. **Audit support**: Sufficient context for investigations
5. **Searchability**: Structured logs enable efficient querying

### Implementation

```python
# Only these fields can be logged
LOGGABLE_FIELDS = {
    "tenant_id", "user_id", "action", "resource_type",
    "resource_id", "status", "error_code", "timestamp",
    "request_id", "duration_ms"
}

# Never log these (blocklist for defense in depth)
NEVER_LOG = {
    "password", "token", "secret", "ssn", "credit_card",
    "authorization", "cookie", "api_key"
}
```

### Tradeoffs / Costs

| Tradeoff | Impact | Mitigation |
|----------|--------|------------|
| Less debug context | Harder to reproduce issues | Add request_id correlation |
| No request body logging | Can't see what user sent | Log sanitized summary if needed |
| Separate audit system | Additional infrastructure | Use same log pipeline, different retention |

### Future Improvements

| Trigger | Evolution |
|---------|-----------|
| Compliance audit (SOC2) | Formalize log retention policy |
| Incident response needs | Add selective verbose logging (time-limited) |
| ML/Analytics use case | Implement tokenized logging for specific fields |

---

## Decision 4: Secrets Management

### Context
Application secrets (DB passwords, API keys, encryption keys) must be stored and accessed securely.

### Options Considered

| Option | Description | Security | Ops Complexity | Cost |
|--------|-------------|----------|----------------|------|
| **A. Environment variables** | Secrets in env vars | Medium | Low | Free |
| **B. Config files** | Encrypted files in repo | Low | Low | Free |
| **C. Cloud Secrets Manager** | AWS SM, GCP SM, etc. | High | Medium | Low |
| **D. HashiCorp Vault** | Self-hosted secrets manager | Highest | High | Medium |

### Chosen Approach
**Option C: Cloud Secrets Manager (AWS Secrets Manager / GCP Secret Manager)**

### Reasoning

1. **Integration**: Native integration with cloud services
2. **Rotation**: Automated rotation support
3. **Audit**: Access logging built-in
4. **Encryption**: Managed encryption with KMS
5. **Cost-effective**: Low cost for startup scale

### Implementation

```python
# Application startup
import boto3

def get_secret(secret_name: str) -> str:
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId=secret_name)
    return response['SecretString']

# Usage
DB_PASSWORD = get_secret('prod/database/password')
```

### Tradeoffs / Costs

| Tradeoff | Impact | Mitigation |
|----------|--------|------------|
| Cloud vendor dependency | Lock-in to provider | Abstract behind interface |
| Network dependency | Secret fetch requires network | Cache secrets with TTL |
| Cost at scale | Per-secret and per-request costs | Cache aggressively |

### Future Improvements

| Trigger | Evolution |
|---------|-----------|
| Multi-cloud requirement | Migrate to Vault or external-secrets operator |
| Kubernetes adoption | Use External Secrets Operator |
| Compliance requirement | Add HSM-backed keys |

---

## Decision 5: CI/CD Security

### Context
CI/CD pipelines have privileged access to production and must be secured against supply chain attacks.

### Options Considered

| Control | Implementation | Priority |
|---------|---------------|----------|
| **SAST** | Static code analysis | Required |
| **DAST** | Dynamic security testing | Recommended |
| **Dependency Scanning** | Check for vulnerable packages | Required |
| **Secret Scanning** | Detect leaked credentials | Required |
| **Container Scanning** | Check base images | Required |
| **Signed Commits** | Verify code authorship | Recommended |
| **Protected Branches** | Require reviews for main | Required |

### Chosen Approach
**Layered security with automated checks in CI pipeline**

### Implementation

```yaml
# GitHub Actions workflow
name: Security Checks

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # Secret scanning
      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2
        
      # Dependency scanning
      - name: Dependency Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: 'shielded-start'
          path: '.'
          format: 'HTML'
          
      # SAST
      - name: Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/secrets
            
      # Container scanning (if applicable)
      - name: Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'your-image:latest'
          severity: 'CRITICAL,HIGH'
```

### Tradeoffs / Costs

| Tradeoff | Impact | Mitigation |
|----------|--------|------------|
| Slower builds | +2-5 minutes per build | Run security checks in parallel |
| False positives | Developer friction | Tune rules, maintain ignore list |
| Tool maintenance | Need to update scanners | Automate tool version updates |

### Future Improvements

| Trigger | Evolution |
|---------|-----------|
| DAST requirement | Add OWASP ZAP to pipeline |
| Supply chain concerns | Implement SLSA framework |
| Compliance audit | Add SBOM generation |

---

## Decision 6: Backup & Encryption Strategy

### Context
Data must be protected at rest and recoverable in disaster scenarios.

### Options Considered

| Aspect | Options | Chosen |
|--------|---------|--------|
| **At-rest encryption** | Application-level / DB-level / Storage-level | Storage-level (RDS encryption) |
| **In-transit encryption** | TLS 1.2 / TLS 1.3 | TLS 1.3 |
| **Backup encryption** | Same key / Separate key | Same KMS key |
| **Backup frequency** | Hourly / Daily / Continuous | Daily + continuous (point-in-time) |
| **Backup retention** | 7 days / 30 days / 1 year | 30 days |

### Chosen Approach
**Storage-level encryption + automated daily backups with point-in-time recovery**

### Reasoning

1. **Simplicity**: RDS encryption handles key management
2. **Performance**: No application overhead for encryption
3. **Recovery**: Point-in-time recovery enables precise restoration
4. **Cost**: Built into RDS, no additional infrastructure
5. **Compliance**: Meets most audit requirements

### Implementation

```terraform
# RDS configuration
resource "aws_db_instance" "main" {
  identifier     = "shielded-start-prod"
  engine         = "postgres"
  engine_version = "15.4"
  
  # Encryption
  storage_encrypted = true
  kms_key_id        = aws_kms_key.database.arn
  
  # Backups
  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  
  # Point-in-time recovery
  delete_automated_backups = false
}
```

### Tradeoffs / Costs

| Tradeoff | Impact | Mitigation |
|----------|--------|------------|
| Not field-level encryption | All-or-nothing protection | Add app-level encryption for specific PII if needed |
| Same region backups | Regional disaster risk | Enable cross-region backup replication |
| 30-day retention | Limited historical recovery | Archive to S3 for longer retention |

### Future Improvements

| Trigger | Evolution |
|---------|-----------|
| Cross-region DR requirement | Enable automated cross-region replication |
| Field-level encryption need | Implement application-level encryption for PII |
| Compliance (long retention) | Archive backups to S3 Glacier |
| Ransomware concerns | Implement immutable backup storage |

---

## Decision Summary Table

| # | Decision | Chosen Approach | Key Tradeoff |
|---|----------|-----------------|--------------|
| 1 | Multi-tenancy isolation | Shared DB + RLS | No physical isolation |
| 2 | Authentication | JWT + refresh tokens | Revocation delay (15 min) |
| 3 | Logging | Structured, PII-minimized | Less debug context |
| 4 | Secrets management | Cloud Secrets Manager | Vendor dependency |
| 5 | CI/CD security | SAST + dependency scanning | Slower builds |
| 6 | Backup & encryption | Storage-level + PITR | Not field-level |

---

## Decision Review Schedule

| Review Type | Frequency | Participants |
|-------------|-----------|--------------|
| Threat model update | Quarterly | Security + Engineering leads |
| Decision review | Bi-annually | CTO + Security |
| Compliance alignment | Annually | CTO + Legal + Security |
| Post-incident review | After incidents | All relevant parties |

---

## How to Propose Changes

1. **Document the trigger**: What changed to prompt reconsideration?
2. **Analyze options**: Update the options table with new alternatives
3. **Assess impact**: What systems would change?
4. **Get review**: Security team + relevant engineering leads
5. **Document decision**: Update this file with new decision record
6. **Implement with tests**: Include security test cases

