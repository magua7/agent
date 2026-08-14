---
name: deserialization-insecure
description: >-
  Insecure deserialization playbook. Use when Java, PHP, or Python applications deserialize untrusted data via ObjectInputStream, unserialize, pickle, or similar mechanisms that may lead to RCE, file access, or privilege escalation.
---

# SKILL: Insecure Deserialization — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert deserialization techniques across Java, PHP, and Python. Covers gadget chain selection, traffic fingerprinting, tool usage (ysoserial, PHPGGC), Shiro/WebLogic/Commons Collections specifics, Phar deserialization, and Python pickle abuse. Pay particular attention to the distinction between finding the sink and finding a usable gadget chain.

## 0. RELATED ROUTING

- `jndi-injection` when deserialization leads to JNDI lookup (e.g., post-JDK 8u191 bypass via LDAP → deserialization)
- `unauthorized-access-common-services` when the deserialization endpoint is an exposed management service (RMI Registry, T3, AJP)

### Advanced Reference

Also inspect [JAVA_GADGET_CHAINS.md](./JAVA_GADGET_CHAINS.md) when you need:
- Java gadget chain version compatibility matrix (CommonsCollections 1–7, CommonsBeanutils, Spring, JDK-only, Groovy, Hibernate, ROME, C3P0, etc.)
- SnakeYAML gadget (ScriptEngineManager/URLClassLoader) with exploit JAR structure
- Hessian/Kryo/Avro/XStream deserialization patterns and traffic fingerprints
- .NET ViewState deserialization (machineKey requirement, ViewState forgery with ysoserial.net, Blacklist3r)
- Ruby YAML.load vs YAML.safe_load exploitation with version-specific chains
- Detection fingerprints: magic bytes table by format (Java `AC ED`, .NET `AAEAAD`, Python pickle `80 0N`, PHP `O:`, Ruby `04 08`)

---

## 1. TRAFFIC FINGERPRINTING — IS IT DESERIALIZATION?

### Java Serialized Objects

| Indicator | Where to Look |
|---|---|
| Hex `ac ed 00 05` | Raw binary in request/response body, cookies, POST params |
| Base64 `rO0AB` | Cookies (`rememberMe`), hidden form fields, JWT claims |
| `Content-Type: application/x-java-serialized-object` | HTTP headers |
| T3/IIOP protocol traffic | WebLogic ports (7001, 7002) |

### PHP Serialized Objects

| Indicator | Where to Look |
|---|---|
| `O:NUMBER:"ClassName"` pattern | POST body, cookies, session files |
| `a:NUMBER:{` (array) | Same locations |
| `phar://` URI usage | File operations accepting user-controlled paths |

### Python Pickle

| Indicator | Where to Look |
|---|---|
| Hex `80 03` or `80 04` (protocol 3/4) | Binary data in requests, message queues |
| Base64-encoded binary blob | API params, cookies, Redis values |
| `pickle.loads` / `pickle.load` in source | Code review / whitebox |

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 2. JAVA — GADGET CHAINS AND TOOLS
- 3. PHP — unserialize AND PHAR
- 4. PYTHON — PICKLE
- 5. DETECTION METHODOLOGY
- 6. DEFENSE AWARENESS
- 7. QUICK REFERENCE — KEY PAYLOADS
- 8. RUBY DESERIALIZATION
- 9. .NET DESERIALIZATION
- … plus 7 additional sections
