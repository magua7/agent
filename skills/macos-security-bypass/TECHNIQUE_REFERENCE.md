# SKILL: macOS Security Bypass — Expert Attack Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [3. SIP (SYSTEM INTEGRITY PROTECTION)](#3-sip-system-integrity-protection)
- [4. SANDBOX ESCAPE](#4-sandbox-escape)
- [5. CODE SIGNING & ENTITLEMENTS](#5-code-signing-entitlements)
- [6. PERSISTENCE AFTER BYPASS](#6-persistence-after-bypass)
- [7. macOS SECURITY BYPASS DECISION TREE](#7-macos-security-bypass-decision-tree)
- [8. QUICK REFERENCE: TOOL COMMANDS](#8-quick-reference-tool-commands)
<!-- zhiyugo:toc:end -->

## 3. SIP (SYSTEM INTEGRITY PROTECTION)

SIP restricts root from modifying protected system locations, loading unsigned kernel extensions, and debugging system processes.

### 3.1 SIP-Protected Locations

```
/System/
/usr/ (except /usr/local/)
/bin/
/sbin/
/var/ (selected subdirs)
/Applications/ (pre-installed Apple apps)
```

### 3.2 SIP Status & Configuration

```bash
csrutil status              # Check SIP status
csrutil disable             # Recovery Mode only
csrutil enable --without fs # Partial disable (risky)
```

### 3.3 Entitlements That Bypass SIP

| Entitlement | Effect |
|---|---|
| `com.apple.rootless.install` | Write to SIP-protected paths |
| `com.apple.rootless.install.heritable` | Child processes inherit SIP bypass |
| `com.apple.security.cs.allow-unsigned-executable-memory` | JIT/unsigned code in memory |
| `com.apple.private.security.clear-library-validation` | Load unsigned libraries |

### 3.4 Historical SIP Bypasses

| CVE | macOS | Technique |
|---|---|---|
| CVE-2021-30892 (Shrootless) | Monterey pre-12.0.1 | `system_installd` + post-install script in signed pkg |
| CVE-2022-22583 | Monterey pre-12.2 | `packagekit` + mount point manipulation |
| CVE-2022-46689 (MacDirtyCow) | Ventura pre-13.1 | Race condition on copy-on-write, overwrite SIP files |
| CVE-2023-32369 (Migraine) | Ventura pre-13.4 | Migration Assistant TCC/SIP bypass via systemmigrationd |
| CVE-2024-44243 | Sequoia pre-15.2 | StorageKit daemon exploitation |

---

## 4. SANDBOX ESCAPE

macOS sandboxing (App Sandbox, via `sandbox-exec` or entitlements) restricts app access to filesystem, network, and IPC.

### 4.1 Office Sandbox Escape Patterns

| Vector | Description |
|---|---|
| Open/Save dialog abuse | User grants file access via dialog → macro reads/writes beyond sandbox |
| `~/Library/LaunchAgents/` persistence | Some sandbox profiles allow writing LaunchAgent plists |
| Login Items manipulation | Add login item pointing to payload outside sandbox |
| Shared container exploitation | Multiple apps sharing the same App Group container |

### 4.2 IPC-Based Escape

| IPC Mechanism | Escape Vector |
|---|---|
| XPC Services | Connect to privileged XPC service with insufficient client validation |
| Mach Ports | Obtain send right to privileged task port |
| Apple Events | Automate unsandboxed app to perform actions |
| Distributed Notifications | Signal unsandboxed helper to execute payload |
| Pasteboard | Write payload to pasteboard, have unsandboxed app consume it |

### 4.3 Browser Sandbox

- Chromium: Multi-process model, renderer is sandboxed, browser process is not
- Safari: WebContent process sandboxed, parent Safari process has more privileges
- Exploit chain: renderer RCE → sandbox escape (via IPC bug to browser process) → system access

---

## 5. CODE SIGNING & ENTITLEMENTS

### 5.1 Inspecting Signatures and Entitlements

```bash
codesign -dv --verbose=4 /path/to/app       # Signature details
codesign -d --entitlements :- /path/to/app   # Dump entitlements
security cms -D -i /path/to/mobileprovision  # Provisioning profile

# Verify signature validity
codesign --verify --deep --strict /path/to/app
spctl --assess --type execute /path/to/app   # Gatekeeper assessment
```

### 5.2 Entitlement Abuse for Privilege Escalation

| Entitlement | Abuse Scenario |
|---|---|
| `com.apple.security.cs.disable-library-validation` | Load attacker dylib into entitled process |
| `com.apple.security.cs.allow-dyld-environment-variables` | DYLD_INSERT_LIBRARIES injection |
| `com.apple.security.get-task-allow` | Attach debugger, inject code |
| `com.apple.security.cs.debugger` | Debug any process |
| `com.apple.private.apfs.revert-to-snapshot` | Revert APFS snapshots, bypass modifications |

### 5.3 Hardened Runtime Bypass

Hardened Runtime prevents: DYLD env vars, debugging, unsigned memory execution. Bypasses:
- Find entitled apps that weaken Hardened Runtime (`disable-library-validation`)
- Exploit JIT-entitled apps (browsers, VMs) for unsigned code execution
- Use `get-task-allow` entitled debug builds left in production

### 5.4 Library Validation Bypass

Library validation ensures only Apple-signed or same-team-signed dylibs load.

```bash
# Find apps with library validation disabled
codesign -d --entitlements :- /Applications/*.app/Contents/MacOS/* 2>/dev/null | \
  grep -l "disable-library-validation"
```

---

## 6. PERSISTENCE AFTER BYPASS

| Method | Location | Survives Reboot | Notes |
|---|---|---|---|
| LaunchAgent | `~/Library/LaunchAgents/` | Yes | User-level, runs at login |
| LaunchDaemon | `/Library/LaunchDaemons/` | Yes | Root-level, runs at boot |
| Login Items | `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/` | Yes | Visible in System Settings |
| Cron | `crontab -e` | Yes | Often overlooked by defenders |
| Dylib hijack | Writable dylib search path | Yes | Triggered when target app launches |
| Folder Action | `~/Library/Scripts/Folder Action Scripts/` | Yes | Triggers on folder events |

---

## 7. macOS SECURITY BYPASS DECISION TREE

```
Target is macOS endpoint
│
├── Need to execute untrusted binary?
│   ├── Quarantine attribute present?
│   │   ├── Yes → xattr -d com.apple.quarantine (§2.1)
│   │   └── No → execute directly
│   └── Gatekeeper still blocks?
│       ├── Signed but not notarized → right-click → Open override
│       └── Unsigned → embed in signed bundle or use archive tricks (§2.2)
│
├── Need access to TCC-protected resources?
│   ├── FDA-granted app available?
│   │   ├── Yes → exploit FDA app context (§1.3)
│   │   └── No ↓
│   ├── Automation permission obtainable?
│   │   ├── Yes → Apple Events to TCC-granted app (§1.3)
│   │   └── No ↓
│   ├── SIP disabled?
│   │   ├── Yes → direct TCC.db modification (§1.2)
│   │   └── No → check version-specific TCC bypass (→ TCC_BYPASS_MATRIX.md)
│   └── MDM present?
│       └── Compromised MDM → push PPPC profile (§1.3)
│
├── Need to bypass SIP?
│   ├── Check macOS version → historical SIP CVE? (§3.4)
│   ├── Find entitled Apple binary → piggyback SIP-bypass entitlement (§3.3)
│   └── Recovery Mode access? → csrutil disable (§3.2)
│
├── Need sandbox escape?
│   ├── Office macro context → dialog/LaunchAgent tricks (§4.1)
│   ├── XPC service with weak validation → IPC escape (§4.2)
│   └── Browser context → renderer → sandbox escape chain (§4.3)
│
├── Need to inject into signed process?
│   ├── disable-library-validation entitlement? → dylib injection
│   ├── allow-dyld-environment-variables? → DYLD_INSERT_LIBRARIES
│   ├── get-task-allow? → debugger attach
│   └── None → check macos-process-injection SKILL.md
│
└── Need persistence?
    └── Choose method by access level (§6)
```

---

## 8. QUICK REFERENCE: TOOL COMMANDS

```bash
# Enumerate TCC permissions
tccutil reset All                              # Reset all TCC (admin)
sqlite3 TCC.db "SELECT * FROM access;"         # Read TCC DB

# Gatekeeper status
spctl --status                                 # Gatekeeper enabled?
spctl --assess -v /path/to/app                 # Check app assessment

# SIP status
csrutil status

# Find interesting entitlements across system
find /System/Applications /Applications -name "*.app" -exec sh -c \
  'codesign -d --entitlements :- "$1" 2>/dev/null | grep -q "disable-library-validation" && echo "$1"' _ {} \;

# List loaded kexts (kernel extensions)
kextstat | grep -v com.apple

# Sandbox profile inspection
sandbox-exec -p "(version 1)(allow default)" /bin/ls  # Test sandbox rules
```
