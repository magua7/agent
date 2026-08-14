---
name: ssti-server-side-template-injection
description: >-
  SSTI playbook. Use when template expressions, server-side rendering, preview features, or templating engines may evaluate attacker-controlled content.
---

# SKILL: Server-Side Template Injection (SSTI) — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert SSTI techniques. Covers polyglot detection probes, engine fingerprinting, Jinja2/FreeMarker/Twig/ERB RCE chains, client-side Angular SSTI, and bypass techniques. Pay particular attention to sandbox escape MRO chains and non-Jinja2 engines. For PHP CMS template eval, Jira SSTI, Confluence OGNL, and Spring Cloud Gateway SpEL, inspect the companion [SCENARIOS.md](./SCENARIOS.md).

## 0. RELATED ROUTING

Before deeper analysis, consider these catalog routes:
- First use the polyglot probe sequence at the top of this file for low-noise fingerprinting
- `expression-language-injection` when `${7*7}` or `%{7*7}` resolves in Java (SpEL/OGNL) — different attack surface from template engines

### Extended Scenarios

Also inspect [SCENARIOS.md](./SCENARIOS.md) when you need:
- Maccms 8.x PHP template `eval` — `{if-A:phpinfo()}{endif-A}` in `vod-search`, base64 bypass for webshell write
- Jira CVE-2019-11581 — "Contact Administrators" form → Velocity template injection → command output in admin email
- Spring Cloud Gateway SpEL (CVE-2022-22947) — actuator route injection with `StreamUtils.copyToByteArray` for output capture
- Struts2 OGNL S2-045 (CVE-2017-5638) — Content-Type header OGNL injection with `_memberAccess` / `OgnlUtil` blacklist clear
- Confluence OGNL CVE-2021-26084 — `createpage-entervariables.action` with `\u0027` unicode bypass
- SSTI vs EL injection disambiguation guide
- Additional template engines: ASP.NET Razor, Elixir EEx, PHP Smarty/Latte/Blade, JS Pug/Handlebars/Nunjucks/EJS/Lodash + universal detection + blind SSTI + Flask PIN calculation

**SCENARIOS.md reference (§7–§11):** For expanded payloads and engine-specific notes on Razor, EEx/LEEx/HEEx, PHP stacks, JavaScript template engines, the universal polyglot probe, mathematical fingerprinting, blind SSTI (boolean / time / OOB), and Flask debug PIN prerequisites, see [SCENARIOS.md](./SCENARIOS.md). This skill keeps a short checklist in §13–§15.

### Engine Payloads Reference

For extended engine-specific fingerprinting, payload matrices (Jinja2, Twig, Freemarker, Velocity, Pebble, Mako, Slim, Handlebars, Thymeleaf, Smarty, ERB, Jade/Pug), and blind SSTI detection techniques (timing-based, DNS-based), see [ENGINE_PAYLOADS.md](./ENGINE_PAYLOADS.md).

### Universal detection & blind SSTI (pointer)

Use the polyglot payload and math probes in §1 and §13 first; when you need fuller blind-test patterns and per-engine examples (including non-Python stacks), follow [SCENARIOS.md](./SCENARIOS.md) §11 and cross-check §14 here for technique names (boolean, time, OOB, error-based).

---

## 1. DETECTION — POLYGLOT PROBE SEQUENCE

First test: distinguish SSTI from XSS. Send these probes and check if **math is evaluated** server-side:

```
{{7*7}}        → IF returns 49 (not {{7*7}}) → Jinja2 or Twig
${7*7}         → IF returns 49 → FreeMarker, Velocity, or Java EL
#{7*7}         → Ruby (ERB interpolation in strings)
<#assign x=7*7>${x}  → FreeMarker
@{7*7}         → Thymeleaf
*{7*7}         → Thymeleaf SpEL (*{...})
```

**Jinja2 vs Twig disambiguation**:
```
{{7*'7'}}
→ 7777777  = Jinja2 (Python string multiplication)
→ 49       = Twig (PHP numeric)
```

**Safe detection probe** (no math, just boolean):
```
{{''.__class__}}   → class 'str' = Python/Jinja2
```

---

## 2. ENGINE-TO-LANGUAGE MAPPING

| Template Engine | Language | Framework |
|---|---|---|
| Jinja2 | Python | Flask, FastAPI |
| Django Templates | Python | Django |
| Mako | Python | Pyramid |
| Twig | PHP | Symfony, Laravel |
| Smarty | PHP | Various |
| FreeMarker | Java | Spring MVC |
| Velocity | Java | Various Java |
| Pebble | Java | Various Java |
| Thymeleaf | Java | Spring Boot |
| ERB | Ruby | Rails |
| Slim / Haml | Ruby | Rails |
| Jade / Pug | Node.js | Express |
| Handlebars | Node.js | Express |
| Tornado | Python | Tornado |

Identifying language from errors → then narrow to template engine.

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 3. JINJA2 (PYTHON FLASK) — RCE CHAINS
- 4. JINJA2 SANDBOX BYPASS TECHNIQUES
- 5. FREEMARKER (JAVA) — RCE
- 6. TWIG (PHP) — RCE
- 7. VELOCITY (JAVA) — RCE
- 8. ERB (RUBY RAILS) — RCE
- 9. THYMELEAF (JAVA SPRING) — RCE
- 10. CLIENT-SIDE TEMPLATE INJECTION (AngularJS)
- … plus 5 additional sections
