---
name: dependency-confusion
description: >-
  Supply-chain testing via package-manager dependency confusion: when internal package names resolve to attacker-controlled public registries, leading to malicious install and script execution. Use for npm/pip/gem/Maven/Composer/Docker manifest review and authorized red-team supply-chain exercises.
---

# SKILL: Dependency Confusion — Supply Chain Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert dependency-confusion methodology. Covers how private package names leak, how public registries can win version resolution, ecosystem-specific pitfalls (npm scopes, pip extra indexes, Maven repo order), recon commands, non-destructive PoC patterns (callbacks, not data exfil), and defensive controls. Pair with supply-chain recon workflows when manifests or CI caches are in scope. **Only use on systems and programs you are authorized to test.**

## 0. QUICK START

**What to look for first**

- **Manifests** listing package names that look **internal** (short unscoped names, org-specific tokens, product codenames) without a **hard-private registry lock**.
- Evidence the **same name** might exist—or be **squattable**—on a **public** registry with a **higher semver** than the private feed publishes.
- **Lockfiles** missing, stale, or not enforced in CI so `install`/`build` can drift toward public metadata.

**Fast mental model**: *If the resolver can see both private and public indexes, and version ranges allow it, the “newest” matching version may be the attacker’s.*

Routing note: if the task comes from supply-chain, repository exposure, or CI-build recon, first use `recon-for-sec` to list internal package names and possible public-registry collisions.

---

## 1. CORE CONCEPT

1. **Private packages**: An organization ships libraries only on an internal registry (or under conventions that imply “ours”), e.g. a scoped name like `@org-scope/internal-utils` or an **unscoped** name such as `acme-billing-sdk`.
2. **Attacker squats the name**: The same package name is published on a **public** registry (npmjs, PyPI, RubyGems, etc.).
3. **Resolver preference**: Many setups resolve **highest matching version** across **all configured indexes** (or merge metadata), so a public `9.9.9` can beat a private `1.2.3` if ranges allow.
4. **Execution**: Package managers run **lifecycle scripts** (npm `preinstall`/`postinstall`, setuptools entry points, etc.) → **attacker code runs** on developer laptops, CI, or production image builds.

This is a **supply-chain** class issue: impact is often **broad** (many consumers) and **silent** until build or runtime hooks fire.

---

## 2. AFFECTED ECOSYSTEMS

| Ecosystem | Typical manifest | Confusion angle |
|-----------|------------------|-----------------|
| **npm** | `package.json` | **Scoped** packages (`@scope/pkg`) are **safer** when the scope is **owned** on the registry; **unscoped** private-style names are **high risk**. Multiple registries / `.npmrc` `registry` vs per-scope `@scope:registry=` misconfiguration increases risk. |
| **pip** | `requirements.txt`, `pyproject.toml`, `setup.py` | `pip install -i` / **`--extra-index-url`** merges indexes; a public index can serve a **higher version** for the same distribution name. |
| **RubyGems** | `Gemfile` | **`source`** order and additional sources; ambiguous gem names reachable from rubygems.org. |
| **Maven** | `pom.xml` | **Repository** declaration **order** and **mirror** settings; a public repo publishing the same `groupId:artifactId` under a higher version can win if policy allows. |
| **Composer** | `composer.json` | **Packagist** is default; private packages without **`repositories`**/`canonical` discipline may collide with public names. |
| **Docker** | `FROM`, image tags | **Typosquatting** on container registries (e.g. public hub) for images with names similar to internal base images. |

---

## 3. RECONNAISSANCE

**Where internal names leak**

- Committed **`package.json`**, **`requirements.txt`**, **`Gemfile`**, **`pom.xml`**, **`composer.json`** in repos or forks.
- **JavaScript source maps**, bundled assets, or **error stack traces** referencing package paths.
- **`.npmrc`**, **`.pypirc`**, **CI logs** showing install URLs or mirror endpoints.
- **Issue trackers**, **gist snippets**, and **dependency graphs** from SBOM exports.

**Check public squatting / claimability (read-only)**

```bash
# npm — metadata for a name (unscoped)
npm view some-internal-package-name version

# npm — scoped (requires scope to exist / be readable)
npm view @some-scope/internal-lib versions --json

# PyPI — dry-run style version probe (adjust name; fails if not found)
python3 -m pip install --dry-run 'some-internal-package-name==99.99.99'

# RubyGems — query remote
gem search '^some-internal-package-name$' --remote

# Maven Central — search coordinates (example pattern)
# curl "https://search.maven.org/solrsearch/select?q=g:com.example+AND+a:internal-lib&rows=1&wt=json"
```

Routing note: after package-name enumeration, consider PoC only in authorized environments; public registry lookups themselves are usually passive recon.

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 4. EXPLOITATION
- 5. TOOLS
- 6. DEFENSE
- 7. DECISION TREE
- Related routing
