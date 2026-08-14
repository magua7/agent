# SKILL: HTTP Host Header Attacks — Injection & Routing Abuse: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [6. BYPASS TECHNIQUES WHEN HOST IS VALIDATED](#6-bypass-techniques-when-host-is-validated)
- [7. FRAMEWORK-SPECIFIC BEHAVIOR](#7-framework-specific-behavior)
- [8. CONNECTION-STATE ATTACKS](#8-connection-state-attacks)
- [9. HOST HEADER ATTACK DECISION TREE](#9-host-header-attack-decision-tree)
- [10. TRICK NOTES — WHAT AI MODELS MISS](#10-trick-notes-what-ai-models-miss)
<!-- zhiyugo:toc:end -->

## 6. BYPASS TECHNIQUES WHEN HOST IS VALIDATED

### 6.1 Override Headers

Many frameworks/proxies trust these headers over the Host header:

| Header | Frameworks That Trust It |
|---|---|
| `X-Forwarded-Host` | Symfony, Laravel, Django (when `USE_X_FORWARDED_HOST=True`), Rails (behind proxy) |
| `X-Host` | Some custom proxy configurations |
| `X-Original-URL` | IIS with URL Rewrite module |
| `X-Rewrite-URL` | IIS with URL Rewrite module |
| `Forwarded: host=attacker.com` | RFC 7239 compliant proxies |
| `X-Forwarded-Server` | Apache mod_proxy |

Test all simultaneously:

```http
GET /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Original-URL: /forgot-password
Forwarded: host=attacker.com
```

### 6.2 Absolute URL in Request Line

```http
GET http://attacker.com/path HTTP/1.1
Host: target.com
```

Per HTTP/1.1 spec (RFC 7230): if the request line contains an absolute URI, the Host header SHOULD be ignored. Some servers follow this, some don't — the mismatch between proxy and backend creates the vulnerability.

### 6.3 Double Host Header

```http
GET /path HTTP/1.1
Host: target.com
Host: attacker.com
```

Behavior varies:
- Some proxies validate first Host, app uses second
- Some servers concatenate: `target.com, attacker.com`
- RFC says: if both differ, return 400. Most servers don't.

### 6.4 Host with Port / Credentials

```http
Host: target.com:@attacker.com
Host: target.com:evil.com
Host: target.com#@attacker.com
Host: attacker.com%23@target.com
```

URL parsers may extract the "host" portion differently when credentials (`@`) or fragments (`#`) are present.

### 6.5 Trailing Dot

```http
Host: target.com.
```

DNS treats `target.com.` and `target.com` identically (trailing dot = FQDN). But Host validation may not strip the trailing dot → `target.com. ≠ target.com` in string comparison → bypass whitelist.

### 6.6 Tab / Space Injection

```http
Host: target.com\tattacker.com
Host: target.com attacker.com
```

Some parsers split on whitespace; the server may use `attacker.com` portion while validation checks `target.com` portion.

### 6.7 Wrap-Around / Enclosed Values

```http
Host: "attacker.com"
Host: <attacker.com>
```

Quoted or bracketed values may be stripped by the app but not by the validator.

---

## 7. FRAMEWORK-SPECIFIC BEHAVIOR

| Framework | Host Source | Gotcha |
|---|---|---|
| **PHP** | `$_SERVER['HTTP_HOST']` (raw header, directly injectable) | `SERVER_NAME` is safer only with `UseCanonicalName On` |
| **Django** | `HttpRequest.get_host()` checks X-Forwarded-Host first (if enabled) | `USE_X_FORWARDED_HOST=True` bypasses `ALLOWED_HOSTS` |
| **Rails** | `request.host` from Host header; trusts `X-Forwarded-Host` behind proxy | Rails 6+ `HostAuthorization` middleware mitigates |
| **Node/Express** | `req.hostname` / `req.headers.host`; with `trust proxy` uses X-Forwarded-Host | No built-in host validation |

---

## 8. CONNECTION-STATE ATTACKS

A sophisticated variant exploiting HTTP keep-alive:

```
Connection 1:
  Request 1: GET / HTTP/1.1    ← Valid Host: target.com
              Host: target.com     → Proxy validates, forwards, keeps connection open

  Request 2: GET /admin HTTP/1.1  ← Evil Host on SAME connection
              Host: evil.com       → Some proxies skip validation on subsequent requests
                                     (they validated the connection on first request)
```

This works against proxies that perform Host validation only on the first request of a keep-alive connection.

### Testing

```
1. Use Burp Repeater with "Connection: keep-alive"
2. Send normal request first
3. On same connection, send request with manipulated Host
4. Check if second request is processed differently
```

---

## 9. HOST HEADER ATTACK DECISION TREE

```
Application uses Host header in responses/behavior?
│
├── Test direct Host injection
│   ├── Change Host to attacker domain → reflected in response?
│   │   ├── YES → Check impact:
│   │   │   ├── In password reset emails? → PASSWORD RESET POISONING
│   │   │   ├── In cached responses? → WEB CACHE POISONING
│   │   │   ├── In redirects? → OPEN REDIRECT
│   │   │   └── In script/link URLs? → XSS VIA HOST
│   │   └── NO (400/403/different response) → Host is validated
│   │
│   └── Host validated? Try bypasses:
│       ├── X-Forwarded-Host header
│       ├── X-Host / X-Original-URL / Forwarded header
│       ├── Absolute URL in request line
│       ├── Double Host header
│       ├── Host: target.com:@attacker.com (URL parser confusion)
│       ├── Host: target.com. (trailing dot)
│       ├── Tab/space injection in Host value
│       └── Connection-state attack (valid first request, evil second)
│
├── Test virtual host enumeration
│   ├── Brute-force Host values against target IP
│   ├── Try: localhost, admin, staging, internal, intranet
│   └── Compare response sizes for different Host values
│
├── Test SSRF via Host routing
│   ├── Host: 127.0.0.1 → internal service?
│   ├── Host: internal-hostname.local → internal routing?
│   └── Host: 169.254.169.254 → cloud metadata?
│
└── No Host-based behavior found
    └── Check if app uses Host in server-side operations
        (email generation, webhook URLs, API callbacks)
```

---

## 10. TRICK NOTES — WHAT AI MODELS MISS

1. **Password reset poisoning doesn't require the victim to be logged in** — you request the reset, the victim just clicks the link. The token lands on your server.
2. **X-Forwarded-Host is the #1 missed bypass**: Most Host validation checks `Host` header but frameworks silently prefer `X-Forwarded-Host` when behind a proxy.
3. **Double Host header is protocol-valid but behavior-undefined**: RFC says reject with 400, but almost no server actually does this. The mismatch between proxy and app is the vulnerability.
4. **Absolute URI overrides Host per RFC**: `GET http://evil.com/path HTTP/1.1\nHost: target.com` — the spec says use the request-line URI. But not all implementations agree.
5. **Cache poisoning via Host requires the cache to exclude Host from the key**: Most CDNs include Host in the cache key. But custom Varnish/Nginx caches may not. Also test with `X-Forwarded-Host` as cache key differentiator.
6. **Connection-state attacks are rarely tested**: Automated scanners don't test keep-alive behavior. Manual testing via Burp Repeater's connection reuse is essential.
7. **DNS rebinding + Host attacks**: If you control DNS, point your domain to the target's IP → your domain resolves to their server → Host header says your domain, but request hits their server. Useful for bypassing IP-based access controls.
