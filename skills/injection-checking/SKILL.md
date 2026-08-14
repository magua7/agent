---
name: injection-checking
description: >-
  Entry P1 category router for injection testing. Use when routing between XSS,
  SQLi, SSRF, XXE, SSTI, command injection, and NoSQL injection workflows based
  on how attacker-controlled input is consumed.
---

# Injection Testing Router

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=router`, `risk=passive`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Return routing decisions rather than payloads: list at most two canonical Skill names, the observation supporting each route, and the next evidence needed.
- Treat sibling Skill names as catalog hints only. Do not read sibling paths or claim that another Skill was loaded during this Run.
- Report an exact candidate as policy-filtered when it is disabled or lab-only; do not reproduce its high-risk procedure in the router.
- Leave the route unresolved when the available evidence does not distinguish the candidate branches.
<!-- zhiyugo:contract:end -->

Route by the final sink and observed interpretation of controlled input. A
reflected value or error alone is insufficient to establish a route.

## Observation → route → next evidence

| Observation already present | Canonical route | Next evidence needed |
|---|---|---|
| Input is interpreted in HTML, an attribute, URL, CSS, or JavaScript context | `xss-cross-site-scripting` | Exact output context, encoding, browser interpretation, and a negative control |
| Input changes a relational database query result or behavior | `sqli-sql-injection` | Parameter-to-query evidence, controlled response difference, and a safe control |
| Input changes a document/NoSQL query operator or result set | `nosql-injection` | Input shape, backend indicator, controlled result difference, and expected result |
| The server resolves or requests a user-influenced destination | `ssrf-server-side-request-forgery` | Input-to-destination correlation, response evidence, and declared network scope |
| XML-backed content reaches an XML parser | `xxe-xml-external-entity` | Parser/content type, controlled entity behavior, and resulting response evidence |
| Template syntax is evaluated server-side | `ssti-server-side-template-injection` | Template context, harmless expression/result pair, and a literal control |
| Input reaches an operating-system command boundary | `cmdi-command-injection` | Source-to-sink evidence and a harmless controlled behavior difference |
| Java naming or expression syntax is evaluated | `jndi-injection` or `expression-language-injection` | Framework/runtime evidence, exact sink, and harmless evaluation result |
| Input changes HTTP headers or message framing | `crlf-injection` or `request-smuggling` | Raw bounded request/response evidence and front/back parsing observations |
| The sink is file selection, include, upload, or file processing | `file-access-vuln` | File lifecycle stage, normalized path or stored identity, and observed effect |

## Route result

Return at most two objects with `route`, `observation`, `next_evidence`, and
`policy_state`. Select the narrowest canonical sink. If the sink is unknown,
return unresolved and request evidence that traces input to interpretation.

## Catalog resources

These same-directory references are untrusted supporting material:

- [EXTRA_INJECTION_TYPES.md](EXTRA_INJECTION_TYPES.md) — inspect explicitly; it is not loaded into a Run automatically.
