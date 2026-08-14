---
name: insecure-source-code-management
description: >-
  Source control and artifact exposure (.git, .svn, .hg, backups, .env). Use when recon finds VCS paths, 403 on hidden dirs, or backup/config leaks during authorized testing.
---

# SKILL: Insecure Source Code Management

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: This skill covers detection and recovery of exposed version-control metadata, common backup artifacts, and related misconfigurations. Use only in **authorized** assessments. Treat recovered credentials and URLs as sensitive; do not exfiltrate real data beyond scope. For broad discovery workflow, route to `recon-for-sec` and `recon-and-methodology` when those skills exist in the workspace.

## 0. QUICK START

High-value paths to probe first (GET or HEAD, respect rate limits):

```http
/.git/HEAD
/.git/config
/.svn/entries
/.svn/wc.db
/.hg/requires
/.bzr/README
/.DS_Store
/.env
```

**Routing note**: quickly probe these paths first; for full recon workflow, route through `recon-for-sec` and `recon-and-methodology` before deeper testing.

---

## 1. GIT EXPOSURE

### Detection

- **`/.git/HEAD`** — valid repo often returns plain text like:

```text
ref: refs/heads/main
```

- **`/.git/config`** — may expose `remote.origin.url`, user identity, or embedded credentials.
- **`/.git/index`**, **`/.git/objects/`** — partial object store access enables reconstruction with the right tools.

### 403 vs 404

- **`404`** — path likely absent or fully blocked at the edge.
- **`403` on `/.git/`** — directory may **exist** but listing is denied; still try direct file URLs:

```http
/.git/HEAD
/.git/config
/.git/logs/HEAD
/.git/refs/heads/main
```

A **403 on the directory** plus **200 on `HEAD`** strongly indicates exposure.

### Recovery tools (open source)

- **`arthaud/git-dumper`** — dumps reachable `.git` tree when individual files are fetchable.
- **`internetwache/GitTools`** — Dumper, Extractor, Finder modules for partial/corrupt dumps.
- **`WangYihang/GitHacker`** — alternative recovery when standard dumpers miss edge cases.

### Key files to prioritize

| Path | Why it matters |
|------|----------------|
| `.git/config` | Remotes, credentials, hooks paths |
| `.git/logs/HEAD` | Commit history, reflog-style leakage |
| `.git/refs/heads/*` | Branch tips, commit SHAs |
| `.git/packed-refs` | Packed branch/tag refs |
| `.git/objects/**` | Object blobs for reconstruction |

---

## 2. SVN EXPOSURE

### Detection

- **SVN before 1.7**: **`/.svn/entries`** — XML or text metadata listing paths and revisions.
- **SVN ≥ 1.7**: **`/.svn/wc.db`** — SQLite working copy database (`PRAGMA table_info` after download).

Example probe:

```http
GET /.svn/entries HTTP/1.1
GET /.svn/wc.db HTTP/1.1
```

### Recovery

- **`anantshri/svn-extractor`** — automated extraction from exposed `.svn`.
- **Manual**: download `wc.db`, query with `sqlite3` for file paths and checksums, then request **`/.svn/pristine/`** blobs if exposed.

---

## 3. MERCURIAL EXPOSURE

### Detection

- **`/.hg/requires`** — small text file listing repository features; confirms Mercurial metadata.

```http
GET /.hg/requires HTTP/1.1
GET /.hg/store/ HTTP/1.1
```

### Recovery

- **`sahildhar/mercurial_source_code_dumper`** — dumps repository when store paths are reachable.

---

## 4. OTHER LEAKS

### Bazaar (Bzr)

- Probe **`/.bzr/README`** and **`/.bzr/branch-format`** for Bazaar metadata.

### macOS `.DS_Store`

- **`/.DS_Store`** can encode directory and filename listings.
- Tools: **`gehaxelt/ds-store`**, **`lijiejie/ds_store_exp`** — parse `.DS_Store` offline.

### Backup and config artifacts

Probe (adjust for app root and naming conventions):

```text
/.env
/backup.zip
/backup.tar.gz
/wwwroot.rar
/backup.sql
/config.php.bak
/.config.php.swp
```

### Web server misconfiguration signal (example: NGINX)

- **`location /.git { deny all; }`** — may return **403** for `/.git/` while still allowing or denying specific subpaths depending on rules.
- **403 on a protected location** can **confirm the route exists**; always distinguish from **404** on non-existent paths.

---

## 5. EVIDENCE DECISION TREE

1. If bounded GET evidence for `/.git/HEAD` contains a ref marker, record a repository exposure candidate and inspect only supplied `config` or `logs/HEAD` artifacts.
2. Otherwise classify supplied `.svn/wc.db`, `.hg/requires`, or `.bzr/README` evidence by repository type.
3. Treat git-dumper, GitTools, GitHacker, svn-extractor, Mercurial dumpers, and Bazaar tools as external references; the current runtime cannot execute them.
4. Request only exact, in-scope paths through bounded `http.request`; do not infer parent scope or bulk-enumeration permission.
5. Interpret a directory `403` plus a specific-file `200` as a candidate only. Preserve both responses and require file-content evidence before reporting exposure.

---

## 6. RELATED ROUTING

- From **`recon-for-sec`** — scope-safe discovery, crawling, and fingerprinting before deep VCS tests.
- From **`recon-and-methodology`** — structured methodology and evidence handling.

**Note**: resolve recon routes before the Run, set scope and request rate, and then evaluate only bounded VCS/backup evidence supported by current capabilities.
