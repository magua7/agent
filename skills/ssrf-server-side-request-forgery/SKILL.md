---
name: ssrf-server-side-request-forgery
description: >-
  SSRF playbook. Use when the server fetches URLs, resolves hostnames, imports remote content, or can be driven toward internal networks, cloud metadata, or secondary protocols.
---

# SKILL: Server-Side Request Forgery (SSRF) — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert SSRF techniques. Covers URL filter bypass, cloud metadata endpoints, protocol exploitation, blind SSRF detection, and chaining to RCE. baseline analyses know basic 169.254.169.254 — this file covers what they miss. For real-world CVE chains, DNS Rebinding deep dives, K8s SSRF, and SSRF → Redis → RCE full exploitation, inspect the companion [SCENARIOS.md](./SCENARIOS.md).

## 0. QUICK START

### Extended Scenarios

Also inspect [SCENARIOS.md](./SCENARIOS.md) when you need:
- WebLogic SSRF (CVE-2014-4210) — `uddiexplorer/SearchPublicRegistries.jsp` + `operator` parameter + `%0D%0A` CRLF to inject Redis commands
- SSRF → internal Redis → write crontab reverse shell complete payload chain
- DNS Rebinding deep dive — TTL=0 trick, initial-legit→second-internal resolution, `rbndr.us` service
- Kubernetes SSRF (CVE-2020-8555) and bypass (CVE-2020-8562) via DNS rebinding
- SSRF through PDF/screenshot generators — `<iframe>` and `<img>` in HTML-to-PDF
- Gopher protocol full TCP injection — Redis, MySQL, FastCGI payloads via Gopherus
- URL parser confusion for filter bypass — `#@`, `\@`, `%00@`, IPv6-mapped IPv4

### Advanced Reference

Also inspect [URL_PARSER_TRICKS.md](./URL_PARSER_TRICKS.md) when you need:
- URL parser differential table: Python urllib vs requests vs Java URL vs PHP parse_url vs Node url.parse vs Go net/url
- Full cloud metadata endpoint catalog (AWS IMDSv1/v2, GCP, Azure, DigitalOcean, Alibaba Cloud, Oracle Cloud, Kubernetes, Hetzner, OpenStack)
- gopher:// payload recipes for Redis, MySQL, SMTP, FastCGI, Memcached (with encoding rules)
- DNS Rebinding detailed attack flow with TTL manipulation and TOCTOU analysis
- PDF/wkhtmltopdf/WeasyPrint/Chrome headless/PhantomJS SSRF patterns and exfiltration techniques

If you just found a parameter that fetches a URL, perform first-pass confirmation here directly.

### First-pass payloads

```text
http://127.0.0.1/
http://localhost/
http://169.254.169.254/latest/meta-data/
http://[::1]/
http://127.1/
```

### Host validation bypass families

| Validation Type | Try |
|---|---|
| blocks `localhost` string | `127.0.0.1`, `127.1`, `[::1]` |
| blocks direct IP only | internal DNS name, decimal/octal/hex IP forms |
| allowlist by prefix | username part, subdomain confusion, redirect chain |
| follows redirects | benign external URL redirecting to internal target |
| parses once, fetches twice | mixed encoding or DNS rebinding style targets |

### Protocol routing

| Goal | Protocol / Target |
|---|---|
| cloud credentials | metadata HTTP endpoints |
| internal HTTP admin | `http://127.0.0.1:port/` |
| Redis / raw TCP style abuse | `gopher://` |
| local file read candidate | `file://` |
| dictionary / banner tests | `dict://` |

---

## 1. FINDING SSRF SURFACE

Look for **any parameter containing DNS names, IP addresses, or URLs**:

```
loc=           url=        path=         endpoint=
imageUrl=      dest=       redirect=     uri=
callback=      load=       file=         resource=
link=          src=        data=         ref=
```

**Less obvious SSRF vectors**:
- PDF/screenshot generation (URL to capture)
- Webhook configuration fields
- Import/export via URL (CSV import, RSS/Atom feeds)
- OAuth redirect URI (sometimes triggers server-side fetch)
- `X-Forwarded-Host` / `X-Real-IP` headers in proxy chains
- XML `DOCTYPE` with external entity (`file://`, `http://`)
- GraphQL `@link` directive (federation)
- Content-Type: `text/html` pages parsed for `<link>` preload headers

---

## 2. CONFIRMATION EVIDENCE MODEL

- Preserve the exact authorized input, a stable baseline response, and the response to one changed variable as separate Evidence records.
- Treat an out-of-band callback as evidence only when a supplied callback artifact correlates to the request by token and time. The runtime has no Collaborator or interact.sh client.
- Timing claims require repeated measurements, controls, and error bounds; one slow response is not proof of an open internal port.
- Never infer permission to contact localhost, private ranges, or cloud metadata. Every destination must already be explicit in `TaskSpec` scope and accepted by execution policy.
- If callback collection, state-changing requests, or an in-scope destination is unavailable, return a capability or scope gap and keep the result as a hypothesis.

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 3. CLOUD METADATA ENDPOINTS — MUST-TRY
- 4. IP ADDRESS FILTER BYPASS TECHNIQUES
- 5. URL SCHEME ATTACKS
- 6. BLIND SSRF DETECTION
- 7. INTERNAL SERVICE EXPLOITATION
- 8. SSRF + FILTER BYPASS DECISION TREE
- 9. THE SSRF-FILTER MINDSET
