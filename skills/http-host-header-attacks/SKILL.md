---
name: http-host-header-attacks
description: >-
  HTTP Host header injection and routing abuse playbook. Use when the application
  trusts the Host header for generating URLs, routing requests, or access control
  — enabling password reset poisoning, web cache poisoning, SSRF via routing,
  and virtual host bypass.
---

# SKILL: HTTP Host Header Attacks — Injection & Routing Abuse

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Covers Host header injection for password reset poisoning, cache poisoning, SSRF via routing, and virtual host bypass. Includes bypass techniques for Host validation and framework-specific behaviors. Pay particular attention to the double-Host trick, absolute-URI override, and connection-state attacks.

## 0. RELATED ROUTING

- `web-cache-deception` when Host injection is combined with cache behavior
- `ssrf-server-side-request-forgery` when Host header routes requests to internal services
- `open-redirect` when Host injection causes redirect to attacker domain
- `waf-bypass-techniques` when Host manipulation helps bypass WAF routing
- `request-smuggling` when smuggling enables Host header manipulation past front-end validation
- `subdomain-takeover` when Host routing exposes internal vhosts resolvable via subdomain

---

## 1. ATTACK SURFACE

The Host header is used by web applications and infrastructure for:

| Usage | Exploitation |
|---|---|
| URL generation (password reset links, email links) | Inject attacker domain → user clicks link to attacker |
| Virtual host routing | Spoof Host → access internal/admin vhost |
| Cache key component | Inject different Host → poison cache for all users |
| Reverse proxy routing | Host determines backend → SSRF to internal services |
| Access control decisions | Host-based ACLs can be bypassed |
| Canonical URL / SEO redirects | Host injection → open redirect |

---

## 2. PASSWORD RESET POISONING

The most common and impactful Host header attack.

### How It Works

```
1. Attacker requests password reset for victim@target.com
2. Attacker modifies Host header in the reset request:
   POST /forgot-password HTTP/1.1
   Host: attacker.com    ← injected
   
   email=victim@target.com

3. Server generates reset link using Host header value:
   "Click here to reset: https://attacker.com/reset?token=SECRET_TOKEN"

4. Victim receives email, clicks link → token sent to attacker
5. Attacker uses token on real target.com to reset password
```

### Testing

```http
POST /forgot-password HTTP/1.1
Host: attacker-collaborator.burpcollaborator.net
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

Only supplied out-of-band callback evidence can support token leakage here. The current runtime cannot query Burp Collaborator; without a callback artifact and Evidence ID, record a capability gap rather than a finding.

### Variants

- Some apps concatenate: `Host: target.com.attacker.com` → link becomes `https://target.com.attacker.com/reset?token=xxx`
- Some apps use only the port portion: `Host: target.com:@attacker.com` → parsed as `attacker.com` in some URL parsers

---

## 3. WEB CACHE POISONING VIA HOST

```
1. Attacker sends:
   GET / HTTP/1.1
   Host: attacker.com

2. If cache keys on URL path but NOT on Host header:
   → Response cached with attacker.com in generated links/content

3. Subsequent users requesting GET / receive the poisoned response
   → Links point to attacker.com, scripts load from attacker.com
```

**Key requirement**: Cache must not include Host header in cache key, but application must use Host in response body.

Test by sending two requests with different Host values and checking if the second request returns the first's Host in the response.

---

## 4. SSRF VIA HOST ROUTING

When a reverse proxy uses Host header to route to backends:

```
GET /api/internal HTTP/1.1
Host: internal-admin-panel.local

→ Reverse proxy routes request to internal-admin-panel.local
→ Attacker accesses internal service
```

Common in:
- Nginx `proxy_pass` based on `$host`
- Apache `ProxyPass` with virtual host routing
- Kubernetes Ingress controllers
- Cloud load balancers

---

## 5. VIRTUAL HOST BYPASS

Many servers host multiple applications on the same IP via virtual hosting:

```
Target:  Host: www.target.com  → public site
Hidden:  Host: admin.target.com → admin panel (not in public DNS)
Hidden:  Host: staging.target.com → staging environment
Hidden:  Host: localhost → server status page
```

### Discovery

```
1. Brute-force Host header with common vhost names:
   ffuf -u http://TARGET_IP -H "Host: FUZZ.target.com" -w vhosts.txt

2. Try special values:
   Host: localhost
   Host: 127.0.0.1
   Host: admin
   Host: internal
   Host: intranet

3. Compare response size/content to identify different vhosts
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 6. BYPASS TECHNIQUES WHEN HOST IS VALIDATED
- 7. FRAMEWORK-SPECIFIC BEHAVIOR
- 8. CONNECTION-STATE ATTACKS
- 9. HOST HEADER ATTACK DECISION TREE
- 10. TRICK NOTES — WHAT AI MODELS MISS
