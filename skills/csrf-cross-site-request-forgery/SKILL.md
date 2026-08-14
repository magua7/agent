---
name: csrf-cross-site-request-forgery
description: >-
  CSRF testing playbook. Use when reviewing state-changing web flows, anti-CSRF defenses, SameSite behavior, JSON CSRF, login CSRF, and OAuth state handling.
---

# SKILL: CSRF — Cross-Site Request Forgery — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert CSRF techniques. Covers modern bypass vectors (SameSite gaps, custom header flaws, tokenless bypass patterns), JSON CSRF, multipart CSRF, chaining with XSS. baseline analyses often present only basic CSRF without covering SameSite edge cases and common broken token implementations.

## 0. RELATED ROUTING

Related catalog routes:
- `cors-cross-origin-misconfiguration` when JSON endpoints become readable cross-origin
- `oauth-oidc-misconfiguration` when login, account linking, or callback binding relies on OAuth state

---

## 1. CORE CONCEPT

CSRF exploits a victim's active session to perform state-changing requests **from the attacker's origin**.

**Required conditions**:
1. Victim is authenticated (active session cookie)
2. Server identifies session via cookie only (no secondary check)
3. Attacker can predict/construct the valid request
4. Cookie is sent cross-origin (SameSite=None or legacy behavior)

---

## 2. FINDING CSRF TARGETS

**High-value state-changing endpoints**:
```
- Password change         ← account takeover
- Email change            ← account takeover
- Add admin / change role ← privilege escalation
- Bank/payment transfer   ← financial impact
- OAuth app authorization ← hijack oauth flow
- Account deletion
- Two-factor auth disable  
- SSH key / API key addition
- Webhook configuration
- Profile/contact info update
```

---

## 3. TOKEN BYPASS TECHNIQUES

### No Token Present
Simplest case — form simply lacks CSRF token. Check if POST /change-email has any token. If not → trivially exploitable.

### Token Not Validated (most common finding!)
Token exists in request but is never verified server-side:
```
Remove the _csrf_token parameter entirely → does request still succeed?
→ YES → trivial bypass
```

### Token tied to session but not to user

This hypothesis requires supplied captures from two explicitly authorized accounts, including each session/token binding and a cross-session negative control. ZhiyuGo cannot operate browser sessions or issue the state-changing request; without those Evidence IDs, record a capability gap.

### Token in Cookie Only
When server sets CSRF token as cookie and expects it back in a header/form:
```
Set-Cookie: csrf=ATTACKER_CONTROLLED
→ If cookie can be set by subdomain (cookie tossing): set cookie to known value
→ Submit form with known token in header + known token in cookie = bypass
```

### Static or Predictable Token
```
→ Same token across all users/sessions
→ Token = base64(username) or md5(session_id) → reversible
→ Token = timestamp → predictable
```

### Double Submit Cookie Pattern (broken if subdomain trusted)
```
If attacker can write cookies for .target.com from subdomain XSS or cookie tossing:
→ Set csrf_cookie=CONTROLLED on .target.com
→ Submit request with X-CSRF-Token: CONTROLLED
→ Server checks header == cookie → match → bypass
```

---

## 4. SAMESITE BYPASS SCENARIOS

**SameSite=Lax** (modern browser default): cookies sent for top-level GET navigation, NOT for cross-site iframe/form POST.

**Bypass SameSite=Lax via GET method**:
```html
<!-- If server accepts GET for state-changing endpoint: -->
<img src="https://target.com/account/delete?confirm=yes">
<script>document.location = 'https://target.com/transfer?to=attacker&amount=1000';</script>
```

**Bypass via subdomain XSS (SameSite Lax/Strict)**:
```javascript
// XSS on sub.target.com → same-site origin → SameSite cookies sent!
// Use XSS as staging point for CSRF
window.location = 'https://target.com/account/modify?evil=true';
```

**SameSite=None** (legacy or explicit): cookies sent everywhere → classic CSRF applies.

**Cookie issued recently? Lax exemption:**
Chrome has a 2-minute exception where Lax cookies ARE sent on cross-site POSTs if the cookie was just set (for OAuth flows). Race window: set cookie, immediately trigger CSRF within 2 minutes.

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 5. CSRF PROOF OF CONCEPT TEMPLATES
- 6. JSON CSRF
- 7. MULTIPART CSRF
- 8. CSRF + XSS COMBINATION (CSRF Token Bypass)
- 9. OAUTH CSRF (STATE PARAMETER MISSING)
- 10. CSRF TESTING CHECKLIST
- 11. JSON CSRF TECHNIQUES
- 12. MULTIPART CSRF & CLIENT-SIDE PATH TRAVERSAL
- … plus 5 additional sections
