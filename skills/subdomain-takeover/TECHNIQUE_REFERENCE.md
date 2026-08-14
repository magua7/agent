# SKILL: Subdomain Takeover — Detection & Exploitation Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [5. NS TAKEOVER — HIGH SEVERITY](#5-ns-takeover-high-severity)
- [6. MX TAKEOVER — EMAIL INTERCEPTION](#6-mx-takeover-email-interception)
- [7. WILDCARD DNS RISKS](#7-wildcard-dns-risks)
- [8. DETECTION & EXPLOITATION DECISION TREE](#8-detection-exploitation-decision-tree)
- [9. DEFENSE & REMEDIATION](#9-defense-remediation)
- [10. TRICK NOTES — WHAT AI MODELS MISS](#10-trick-notes-what-ai-models-miss)
<!-- zhiyugo:toc:end -->

## 5. NS TAKEOVER — HIGH SEVERITY

NS takeover is **far more dangerous** than CNAME takeover: you control **all DNS resolution** for the zone.

### How It Happens

```
target.com NS → ns1.expireddomain.com
                 ↓
attacker registers expireddomain.com
                 ↓
attacker now controls ALL DNS for target.com
(A records, MX records, TXT records — everything)
```

### Detection

```
1. Enumerate NS records: dig NS target.com +short
2. Check each NS domain: whois ns1.example.com → is the domain expired or available?
3. Also check: dig A ns1.example.com → NXDOMAIN/SERVFAIL?
4. Subdelegated zones: check NS for sub.target.com specifically
```

### Impact

- Full domain takeover (serve any content, intercept email, issue TLS certs via DNS-01)
- Issue DV certificates from any CA using DNS challenge
- Modify SPF/DKIM/DMARC → send authenticated email as target

---

## 6. MX TAKEOVER — EMAIL INTERCEPTION

When MX records point to deprovisioned mail services:

```
target.com MX → mail.deadservice.com (service discontinued)
```

If attacker can claim `mail.deadservice.com` or the mail tenant:
- Receive password reset emails
- Intercept sensitive communications
- Potentially reset accounts that use email-based auth

### Common Scenario

Expired Google Workspace / Microsoft 365 tenant → MX still points to Google/Microsoft → attacker creates new tenant and claims the domain.

---

## 7. WILDCARD DNS RISKS

If `*.target.com` has a wildcard CNAME to a claimable service:
- **Every** undefined subdomain is vulnerable
- `anything.target.com` can be taken over
- Massively increases attack surface

Detection: `dig A random1234567.target.com` — if it resolves, wildcard exists.

---

## 8. DETECTION & EXPLOITATION DECISION TREE

```
Subdomain discovered (sub.target.com)?
├── Resolve DNS records
│   ├── Has CNAME → external service?
│   │   ├── HTTP response matches known fingerprint? (Section 3)
│   │   │   ├── YES → Attempt claim on provider (Section 4)
│   │   │   │   ├── Claim successful → TAKEOVER CONFIRMED
│   │   │   │   └── Claim blocked (name reserved, region locked) → document, try variations
│   │   │   └── NO → Service active, no takeover
│   │   └── CNAME target NXDOMAIN?
│   │       ├── Target is a registrable domain? → Register it → full control
│   │       └── Target is a subdomain of active provider → check provider claim process
│   │
│   ├── Has NS records → external nameserver?
│   │   ├── NS domain expired/available? → Register → FULL ZONE TAKEOVER
│   │   └── NS domain active → no takeover
│   │
│   ├── Has MX → external mail service?
│   │   ├── Mail service deprovisioned/claimable? → Claim tenant → EMAIL INTERCEPTION
│   │   └── Active mail service → no takeover
│   │
│   └── Has A record → IP address?
│       ├── IP belongs to elastic cloud (AWS EIP, Azure, GCP)?
│       │   ├── IP unassigned? → Claim IP → serve content
│       │   └── IP assigned to another customer → no takeover
│       └── IP belongs to dedicated server → no takeover
│
└── Post-takeover impact assessment
    ├── Shared cookies with parent domain? → Session hijacking
    ├── CORS trusts *.target.com? → Cross-origin data theft
    ├── CSP whitelists *.target.com? → XSS via taken-over subdomain
    ├── OAuth redirect_uri allows sub.target.com? → Token theft
    └── Can issue TLS cert for sub.target.com? → Full MITM
```

---

## 9. DEFENSE & REMEDIATION

| Action | Priority |
|---|---|
| Remove DNS records when deprovisioning cloud resources | Critical |
| Monitor CNAME targets for NXDOMAIN responses | High |
| Use DNS monitoring tools (SecurityTrails, DNSHistory) | High |
| Claim/reserve resource names before deleting DNS records | High |
| Audit NS delegations — ensure NS domains are owned and renewed | Critical |
| Avoid wildcard CNAMEs to third-party services | Medium |
| Implement Certificate Transparency monitoring | Medium |

---

## 10. TRICK NOTES — WHAT AI MODELS MISS

1. **CNAME ≠ takeover**: A CNAME to S3 that returns 403 (bucket exists, private) is NOT vulnerable. Only `NoSuchBucket` (404) is.
2. **Region matters for S3**: Bucket names are global, but website endpoints are regional. Try matching the region from the CNAME.
3. **GitHub Pages verification**: GitHub added domain verification — org-verified domains cannot be claimed by others. Check if target uses this.
4. **Edge cases**: Some providers (e.g., Cloudfront) require specific distribution configuration, not just domain claiming.
5. **Second-order takeover**: `sub.target.com CNAME → other.target.com CNAME → dead-service.com` — the chain must be followed fully.
6. **SPF subdomain takeover**: If SPF includes `include:sub.target.com` and you take over `sub.target.com`, you can modify its SPF TXT record to authorize your mail server → send spoofed email as `target.com`.
