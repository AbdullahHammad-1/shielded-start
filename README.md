# 🛡️ Shielded-Start

**A hardened security reference architecture for B2B multi-tenant SaaS startups.**

[![Security](https://img.shields.io/badge/Security-Production--Grade-green.svg)](./security-decisions.md)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](./CONTRIBUTING.md)

---

## What This Is

Shielded-Start is a **reference security architecture** designed to help early-stage B2B SaaS teams avoid the most common—and most devastating—security failures:

- **IDOR/BOLA vulnerabilities** that expose customer data across tenants
- **Tenant isolation failures** that leak data between organizations
- **Auth/session mistakes** that enable account takeover
- **Insecure logging** that exposes PII to internal tools or attackers
- **Weak segregation** that makes a single breach catastrophic

This is **not** a complete SaaS application. It's a curated set of patterns, policies, and decisions that you can adapt to your stack.

---

## Who This Is For

| Audience | Use Case |
|----------|----------|
| **CTOs / Co-founders** | Validate your security architecture before scaling |
| **Security Engineers** | Jumpstart threat modeling and RLS policy design |
| **Backend Engineers** | Implement multi-tenancy without reinventing the wheel |
| **DevOps / Platform** | Understand trust boundaries and secrets management |
| **Auditors / Compliance** | Review a well-documented security posture |

---

## Problems This Solves

### The Startup Security Gap

Most security guidance assumes enterprise resources. Startups face different constraints:

- **Small teams** → No dedicated security engineer until Series B
- **Speed pressure** → "Ship now, secure later" becomes technical debt
- **Limited budget** → Can't afford Prisma/Snyk Enterprise on Day 1
- **Changing requirements** → Architecture must evolve without rewrites

### Common Startup-Killer Failures

| Failure | Impact | How Shielded-Start Helps |
|---------|--------|--------------------------|
| IDOR/BOLA | Customer A sees Customer B's data | JWT tenant claims + RLS enforce isolation at every layer |
| Tenant data leakage | Breach affects all customers | Row-Level Security makes cross-tenant queries impossible |
| Auth bypass | Account takeover, privilege escalation | Claims model + server-side enforcement patterns |
| PII in logs | Compliance violation, breach amplification | Structured logging with explicit PII filtering |
| Secrets in code | Leaked credentials compromise everything | Secrets management decision framework |

---

## Repository Map

```
shielded-start/
├── README.md                    # You are here
├── architecture/
│   ├── overview.md              # System architecture narrative
│   └── diagrams/
│       ├── system-architecture.md   # Component + trust boundary diagram
│       └── data-flow.md             # Tenant isolation + auth flow
├── threat-model/
│   ├── assets.md                # What matters and why
│   ├── threats.md               # STRIDE-based threat analysis
│   └── mitigations.md           # Controls mapped to threats
├── database/
│   └── rls-policies.sql         # PostgreSQL RLS implementation
├── api-gateway/
│   └── auth-claims.md           # JWT claims + authorization model
└── security-decisions.md        # Key design decisions with tradeoffs
```

---

## Quickstart: How to Use This

### 1. Understand the Architecture

```bash
# Read in this order:
1. architecture/overview.md          # Big picture
2. architecture/diagrams/*.md        # Visual understanding
3. security-decisions.md             # Why we made these choices
```

### 2. Implement Database Isolation

```bash
# Copy and adapt the RLS policies
cp database/rls-policies.sql your-project/migrations/

# Key adaptations:
# - Rename tables to match your schema
# - Add policies for your custom tables
# - Test with your ORM's connection pooling
```

### 3. Implement Auth Claims Model

```bash
# Review the claims model
cat api-gateway/auth-claims.md

# Implement in your auth provider:
# - Auth0: Use Rules/Actions to add tenant_id claim
# - Cognito: Use Pre-token generation Lambda
# - Custom: Add claims in token generation
```

### 4. Run Your Own Threat Model

```bash
# Use our threat model as a template
# Adapt assets.md to your specific data
# Review threats.md against your architecture
# Assign mitigations to your team
```

### 5. Checklist Before Launch

- [ ] RLS policies tested with cross-tenant queries (must fail)
- [ ] JWT tenant_id claim verified on every API endpoint
- [ ] Audit logs capturing who/what/when without PII
- [ ] Secrets rotated and not in git history
- [ ] SAST/DAST running in CI pipeline
- [ ] Incident response runbook exists (even if basic)

---

## Key Security Principles

### 1. Defense in Depth
Never rely on a single control. Tenant isolation is enforced at:
- API Gateway (JWT validation)
- Application layer (ownership checks)
- Database layer (RLS policies)

### 2. Secure by Default
- RLS denies all access until explicitly granted
- New endpoints require explicit authorization
- Logs exclude PII unless explicitly included

### 3. Least Privilege
- Service accounts have minimal permissions
- User roles grant only necessary access
- Database connections use restricted users

### 4. Fail Secure
- Missing tenant_id → request denied (not default tenant)
- Invalid JWT → 401 (not fallback auth)
- RLS policy error → query fails (not bypassed)

---

## How to Extend

### Adding Cloud Services

When integrating AWS/GCP/Azure services:

1. **Storage (S3/GCS)**: Prefix all objects with `tenant_id/`
2. **Queues (SQS/Pub-Sub)**: Include `tenant_id` in message envelope
3. **Search (Elasticsearch)**: Add `tenant_id` to all documents, filter in queries
4. **Cache (Redis)**: Namespace keys as `tenant:{id}:resource:{id}`

### Microservices Architecture

When decomposing the monolith:

1. **Service-to-service auth**: Use mTLS or signed JWTs with service identity
2. **Tenant context propagation**: Pass `tenant_id` in headers, validate at each service
3. **Shared database**: Consider per-service schemas with cross-schema RLS
4. **Event-driven**: Include `tenant_id` in all events, validate on consume

### AI/ML Features

When adding AI capabilities:

1. **Training data**: Ensure tenant data isolation in training pipelines
2. **Model inference**: Log prompts/responses with tenant context for audit
3. **Embeddings**: Store in tenant-isolated vector namespaces
4. **Third-party APIs**: Redact PII before sending to external services

---

## Security Posture Summary

| Control | Implementation | Status |
|---------|---------------|--------|
| Multi-tenant isolation | PostgreSQL RLS + JWT claims | ✅ Documented |
| Authentication | JWT with tenant context | ✅ Documented |
| Authorization | RBAC + ownership checks | ✅ Documented |
| Audit logging | Structured, PII-filtered | ✅ Documented |
| Secrets management | Environment-based, rotatable | ✅ Documented |
| CI/CD security | SAST + dependency scanning | ✅ Documented |

---

## Disclaimer

**This is a reference architecture, not production code.**

- Patterns must be adapted to your specific stack and requirements
- Security is context-dependent; review with your team
- No warranty is provided; you are responsible for your implementation
- Consider a professional security review before handling sensitive data

---

## Contributing

We welcome contributions that improve the patterns or add new perspectives:

1. **Bug fixes**: Errors in SQL, claims model, or threat analysis
2. **Clarifications**: Better explanations of complex concepts
3. **Extensions**: Patterns for specific frameworks or cloud providers
4. **Real-world lessons**: What worked (or didn't) when you implemented these

Please open an issue before large PRs to discuss approach.

---

## License

MIT License - Use freely, attribute if you find it helpful.

---

## Acknowledgments

This architecture draws from:
- OWASP API Security Top 10
- NIST Cybersecurity Framework
- Real-world breach post-mortems
- Battle-tested patterns from production B2B SaaS

---

**Built for startups who can't afford to get security wrong.**

