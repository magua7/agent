---
name: upload-insecure-files
description: >-
  Insecure file upload playbook. Use when testing upload validation, storage paths, processing pipelines, preview behavior, overwrite risks, and upload-to-RCE chains.
---

# SKILL: Upload Insecure Files — Validation Bypass, Storage Abuse, and Processing Chains

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert file upload attack playbook. Use when the target accepts files, imports, avatars, media, documents, or archives and you need the full workflow: validation bypass, storage path abuse, post-upload access, parser exploitation, multi-tenant overwrite, and chaining into XSS, XXE, CMDi, traversal, or business logic impact. For web server parsing vulnerabilities, PUT method exploitation, and specific CVEs (WebLogic, Flink, Tomcat), inspect the companion [SCENARIOS.md](./SCENARIOS.md).

## 0. RELATED ROUTING

### Extended Scenarios

Also inspect [SCENARIOS.md](./SCENARIOS.md) when you need:
- IIS parsing vulnerabilities — `x.asp/` directory parsing, `;` semicolon truncation (`shell.asp;.jpg`)
- Nginx parsing misconfiguration — `avatar.jpg/.php` with `cgi.fix_pathinfo=1`
- Apache parsing — multiple extensions, `AddHandler`, CVE-2017-15715 `\n` (0x0A) bypass
- PUT method exploitation — IIS WebDAV PUT+COPY, Tomcat CVE-2017-12615 `readonly` + `.jsp/` bypass
- WebLogic CVE-2018-2894 arbitrary file upload via Web Service Test Page
- Apache Flink CVE-2020-17518 file upload with path traversal
- Upload + parsing vulnerability chain — EXIF PHP code + Nginx `/.php` path info
- Full extension bypass reference table (PHP/ASP/JSP alternatives, case variations, null bytes)

Use this file as the deep upload workflow reference. Related catalog routes:
- `path-traversal-lfi` when filename, extraction path, or include path becomes file-system control
- `xss-cross-site-scripting` when uploads are rendered in browser contexts
- `xxe-xml-external-entity` when SVG, OOXML, or XML imports are accepted
- `cmdi-command-injection` when a processor, converter, or media pipeline executes system tools
- `business-logic-vulnerabilities` when quotas, overwrite rules, approvals, or storage paths create logic bugs

---

## 1. CORE MODEL

Every upload feature should be tested as four separate trust boundaries:

1. **Accept**: what validation happens before the file is stored?
2. **Store**: where is the file written and under what name and permissions?
3. **Process**: what background tools, converters, scanners, parsers, or extractors touch it?
4. **Serve**: how is it later downloaded, rendered, transformed, or shared?

Many targets validate only one stage. The bug usually appears in a different stage than the one where the file was uploaded.

---

## 2. RECON QUESTIONS FIRST

Before payload selection, answer these:

- Which extensions are allowed, denied, or normalized?
- Does the backend trust extension, MIME type, magic bytes, or all three?
- Is the file renamed, transcoded, unzipped, scanned, or re-hosted?
- Is retrieval direct, proxied, signed, or served from a CDN?
- Can one user predict or overwrite another user's file path?
- Do filenames, metadata, or previews reflect back into HTML, logs, admin consoles, or PDFs?

---

## 3. VALIDATION BYPASS MATRIX

| Validation Style | What to Test |
|---|---|
| extension blacklist | double extension, case toggles, trailing dot, alternate separators |
| content-type only | mismatched multipart `Content-Type`, browser vs proxy rewrite |
| magic-byte only | polyglot files or valid header plus dangerous tail content |
| server-side rename | whether dangerous content survives rename and later rendering |
| image-only policy | SVG, malformed image plus metadata, parser differential |
| archive or import only | zip contents, nested path names, XML members, decompression behavior |

Representative bypass families:

```text
shell.php.jpg
avatar.jpg.php
file.asp;.jpg
file.php%00.jpg
file.svg
archive.zip
```

This small sample set already covers the main use cases of the former standalone upload payload helper, so no extra entry is needed for first-pass selection.

Do not stop at upload success. Successful upload without dangerous retrieval or processing is not enough.

---

## 4. STORAGE AND RETRIEVAL ABUSE

### Predictable or controllable paths

Look for patterns like:

```text
/uploads/USER_ID/avatar.png
/files/org-slug/report.pdf
/cdn/tmp/<uuid>/<filename>
```

Test for:

- cross-tenant read by guessing IDs, slugs, or UUID patterns
- overwrite by reusing another user's filename
- path normalization bugs in filename or archive members
- private file exposed through direct object URL despite UI-level access control

### Filename-based injection surfaces

A safe file can still be dangerous if the **filename** is reflected into:

- gallery HTML
- admin moderation panels
- PDF/CSV export jobs
- logs, audit views, or email notifications

If filename is reflected, treat it like stored input, not like passive metadata.

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 5. PROCESSING-CHAIN ATTACKS
- 6. HIGH-VALUE EXPLOITATION PATHS
- 7. AUTHORIZATION AND BUSINESS LOGIC CHECKS
- 8. TEST SEQUENCE
- 9. CHAINING MAP
- 10. OPERATOR CHECKLIST
- 11. UPLOAD SUCCESS RATE MODEL & ADVANCED METHODOLOGY
- 12. POLYGLOT FILE TECHNIQUES
- … plus 4 additional sections
