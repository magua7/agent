---
name: macos-security-bypass
description: >-
  macOS security bypass playbook. Use when targeting macOS endpoints and need to bypass TCC, Gatekeeper, SIP, sandbox, code signing, or entitlement-based protections during authorized red team or pentest engagements.
---

# SKILL: macOS Security Bypass — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert macOS security bypass techniques. Covers TCC bypass, Gatekeeper evasion, SIP restrictions, sandbox escape, and entitlement abuse. Pay particular attention to version-specific bypass nuances and protection interaction effects.

## 0. RELATED ROUTING

Before going deep, consider routing to:

- `macos-process-injection` when you need dylib injection, XPC exploitation, or Electron abuse after achieving initial access
- `linux-privilege-escalation` for Unix-layer privesc techniques that also apply to macOS (SUID, cron, writable paths)
- `linux-security-bypass` for shared Unix security bypass concepts

### Advanced Reference

Also inspect [TCC_BYPASS_MATRIX.md](./TCC_BYPASS_MATRIX.md) when you need:
- Per-macOS-version TCC bypass mapping
- Protection-type-specific techniques (Camera, Microphone, FDA, Automation)
- MDM/configuration profile abuse patterns

---

## 1. TCC (TRANSPARENCY, CONSENT, CONTROL) OVERVIEW

TCC is macOS's permission framework controlling access to sensitive resources (camera, microphone, contacts, full disk access, etc.).

### 1.1 TCC Database Locations

| Database | Path | Controls | Protection |
|---|---|---|---|
| User-level | `~/Library/Application Support/com.apple.TCC/TCC.db` | Per-user consent decisions | SIP-protected since Catalina |
| System-level | `/Library/Application Support/com.apple.TCC/TCC.db` | System-wide consent decisions | SIP-protected |
| MDM-managed | Via configuration profiles | Push PPPC (Privacy Preferences Policy Control) | Device management |

```sql
-- Query TCC database (requires FDA or SIP off)
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, allowed FROM access;"
```

### 1.2 TCC Bypass Categories

| Category | Mechanism | Typical Prerequisite |
|---|---|---|
| FDA app exploitation | Piggyback on apps already granted Full Disk Access | Write access to FDA app's bundle or plugin dir |
| Direct DB modification | Edit TCC.db to grant consent | SIP disabled or FDA |
| Inherited permissions | Child process inherits parent's TCC grants | Code execution in context of FDA-granted app |
| Automation abuse | Apple Events / osascript to control TCC-granted app | Automation permission (lower bar than direct TCC) |
| Mounting tricks | Mount a crafted disk image containing modified TCC.db | Local access, pre-Ventura |
| SQL injection in TCC | Malformed bundle IDs triggering SQL injection in TCC subsystem | CVE-2023-32364 and similar |

### 1.3 Known TCC Bypass Patterns

**Terminal / iTerm FDA inheritance**: Terminal.app granted FDA → any command run inherits FDA → read any file.

```bash
# If Terminal has FDA, this reads protected files directly
cat ~/Library/Mail/V*/MailData/Envelope\ Index
cat ~/Library/Messages/chat.db
```

**Finder automation**: Automate Finder (lower permission bar) to access files in protected locations.

```applescript
tell application "Finder"
  set f to POSIX file "/Users/target/Library/Mail/V9/MailData/Envelope Index"
  duplicate f to desktop
end tell
```

**System Preferences / System Settings injection**: Inject into a process that already has TCC permissions by writing to its Application Scripts folder.

**MDM profile abuse**: PPPC profiles can pre-approve TCC permissions. Rogue MDM enrollment or compromised MDM server → push PPPC payload.

---

## 2. GATEKEEPER BYPASS

Gatekeeper blocks unsigned or unnotarized apps from executing. Core enforcement depends on the `com.apple.quarantine` extended attribute.

### 2.1 Quarantine Attribute Removal

```bash
# Check quarantine attribute
xattr -l /path/to/app
# Output: com.apple.quarantine: 0083;...

# Remove quarantine (requires write access)
xattr -d com.apple.quarantine /path/to/app
# Recursive for app bundles
xattr -rd com.apple.quarantine /path/to/MyApp.app
```

### 2.2 Bypass Techniques

| Technique | How It Works | macOS Version |
|---|---|---|
| `xattr -d` removal | Remove quarantine before execution | All (requires local access) |
| App translocation bypass | Apps in certain locations skip translocation | Pre-Catalina |
| Archive tools that strip quarantine | Some unarchiver apps don't propagate quarantine | Varies by tool |
| Unsigned code in signed bundle | Notarized app bundles with unsigned nested helpers | Pre-Ventura (CVE-2022-42821) |
| Safari auto-extract + open | Downloaded ZIP auto-extracted, app opened before quarantine fully applied | Safari-specific, patched |
| ACL abuse | `com.apple.quarantine` can be blocked by ACLs set before download | Requires pre-positioning |
| Disk image (DMG) tricks | DMG mounted from network share may not carry quarantine | Network share context |
| BOM (Bill of Materials) bypass | Crafted BOM in pkg skips quarantine for extracted files | CVE-2022-22616 |

### 2.3 Gatekeeper Check Flow

```
App launched
│
├── com.apple.quarantine attribute present?
│   ├── No → execute (no Gatekeeper check)
│   └── Yes ↓
│
├── Code signature valid?
│   ├── No → block
│   └── Yes ↓
│
├── Notarized (stapled ticket or online check)?
│   ├── No → block (Catalina+)
│   └── Yes → execute
│
└── User override? (right-click → Open → confirm)
    └── Bypasses Gatekeeper once for this app
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 3. SIP (SYSTEM INTEGRITY PROTECTION)
- 4. SANDBOX ESCAPE
- 5. CODE SIGNING & ENTITLEMENTS
- 6. PERSISTENCE AFTER BYPASS
- 7. macOS SECURITY BYPASS DECISION TREE
- 8. QUICK REFERENCE: TOOL COMMANDS
