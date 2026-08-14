---
name: subdomain-takeover
description: >-
  Subdomain takeover detection and exploitation playbook. Use when targets have
  dangling CNAME/NS/MX records pointing to deprovisioned cloud resources, expired
  third-party services, or unclaimed SaaS tenants that an attacker can register
  to serve content under the victim's domain.
---

# SKILL: Subdomain Takeover — Detection & Exploitation Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Covers CNAME/NS/MX takeover, per-provider fingerprint matching, claim procedures, and defensive monitoring. baseline analyses often confuse "CNAME exists" with "takeover possible" — the key is whether the *resource behind the CNAME is unclaimed and claimable*.

## 0. RELATED ROUTING

- `ssrf-server-side-request-forgery` when a subdomain takeover is used to bypass SSRF allowlists trusting `*.target.com`
- `cors-cross-origin-misconfiguration` when CORS trusts `*.target.com` — takeover → full cross-origin read
- `xss-cross-site-scripting` takeover gives you script execution under target origin (cookie theft, OAuth redirect abuse)
- `http-host-header-attacks` when Host routing leads to subdomain-scoped cache or auth issues
- `web-cache-deception` when a taken-over subdomain shares cache with the main domain

---

## 1. CORE CONCEPT

Subdomain takeover occurs when:

1. `sub.target.com` has a DNS record (CNAME, NS, A) pointing to an external service
2. The external resource is **no longer provisioned** (deleted S3 bucket, removed Heroku app, etc.)
3. The attacker can **register/claim** that exact resource name on the provider
4. The attacker now controls content served under `sub.target.com`

**Impact**: cookie theft (parent domain cookies), OAuth token interception, phishing under trusted domain, CORS bypass, CSP bypass via whitelisted subdomain.

---

## 2. DETECTION METHODOLOGY

### 2.1 CNAME Enumeration

```
1. Collect subdomains (amass, subfinder, assetfinder, crt.sh, SecurityTrails)
2. Resolve DNS for each:
   dig CNAME sub.target.com +short
3. For each CNAME → check if the CNAME target returns NXDOMAIN or a provider error
4. Match error response against fingerprint table (Section 3)
```

### 2.2 Key Signals

| Signal | Meaning |
|---|---|
| CNAME → `xxx.s3.amazonaws.com` + HTTP 404 "NoSuchBucket" | S3 bucket deleted, claimable |
| CNAME → `xxx.herokuapp.com` + "No such app" | Heroku app deleted |
| CNAME → `xxx.github.io` + 404 "There isn't a GitHub Pages site here" | GitHub Pages unclaimed |
| NXDOMAIN on the CNAME target domain itself | Target domain expired or never existed |
| CNAME → provider but HTTP 200 with default parking page | May or may not be claimable — verify |

### 2.3 Automated Tools

| Tool | Purpose |
|---|---|
| `subjack` | Automated CNAME takeover checking |
| `nuclei -t takeovers/` | Nuclei takeover detection templates |
| `can-i-take-over-xyz` (GitHub) | Reference for which services are vulnerable |
| `dnsreaper` | Multi-provider takeover scanner |
| `subzy` | Fast subdomain takeover verification |

---

## 3. SERVICE PROVIDER FINGERPRINT TABLE

| Provider | CNAME Pattern | Fingerprint (HTTP Response) | Claimable? |
|---|---|---|---|
| **AWS S3** | `*.s3.amazonaws.com` / `*.s3-website-*.amazonaws.com` | `NoSuchBucket` (404) | Yes — create bucket with matching name |
| **GitHub Pages** | `*.github.io` | `There isn't a GitHub Pages site here` (404) | Yes — create repo + enable Pages |
| **Heroku** | `*.herokuapp.com` / `*.herokudns.com` | `No such app` | Yes — create app with matching name |
| **Azure** | `*.azurewebsites.net` / `*.cloudapp.azure.com` / `*.trafficmanager.net` | Various default pages, NXDOMAIN | Yes — register matching resource |
| **Shopify** | `*.myshopify.com` | `Sorry, this shop is currently unavailable` | Yes — create shop, add custom domain |
| **Fastly** | CNAME to Fastly edge | `Fastly error: unknown domain` | Yes — add domain to Fastly service |
| **Pantheon** | `*.pantheonsite.io` | `404 Site Not Found` with Pantheon branding | Yes |
| **Tumblr** | `*.tumblr.com` (custom domain CNAME) | `There's nothing here` / `Whatever you were looking for doesn't exist` | Yes |
| **WordPress.com** | CNAME to `*.wordpress.com` | `Do you want to register` | Yes — claim domain in WP.com |
| **Zendesk** | `*.zendesk.com` | `Help Center Closed` / Zendesk branding on error | Yes — create matching subdomain |
| **Unbounce** | `*.unbouncepages.com` | `The requested URL was not found` | Yes |
| **Ghost** | `*.ghost.io` | `404 Not Found` Ghost error | Yes |
| **Surge.sh** | `*.surge.sh` | `project not found` | Yes |
| **Fly.io** | CNAME to `*.fly.dev` | Fly.io default 404 | Yes |

---

## 4. TAKEOVER PROCEDURE — COMMON PROVIDERS

### 4.1 AWS S3

```
1. Confirm: curl -s http://sub.target.com → "NoSuchBucket"
2. Extract bucket name from CNAME (e.g., sub.target.com.s3.amazonaws.com → bucket = "sub.target.com")
3. aws s3 mb s3://sub.target.com --region <region>
4. Upload index.html proving control
5. Enable static website hosting
```

### 4.2 GitHub Pages

```
1. Confirm: curl -s https://sub.target.com → "There isn't a GitHub Pages site here"
2. Create GitHub repo (any name)
3. Add CNAME file containing "sub.target.com"
4. Enable GitHub Pages in repo settings
5. Wait for DNS propagation (GitHub verifies CNAME match)
```

### 4.3 Heroku

```
1. Confirm: curl -s http://sub.target.com → "No such app"
2. heroku create <app-name-from-cname>
3. heroku domains:add sub.target.com
4. Deploy proof-of-concept page
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 5. NS TAKEOVER — HIGH SEVERITY
- 6. MX TAKEOVER — EMAIL INTERCEPTION
- 7. WILDCARD DNS RISKS
- 8. DETECTION & EXPLOITATION DECISION TREE
- 9. DEFENSE & REMEDIATION
- 10. TRICK NOTES — WHAT AI MODELS MISS
