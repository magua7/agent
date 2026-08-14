---
name: mobile-ssl-pinning-bypass
description: >-
  Mobile SSL pinning bypass playbook. Use when intercepting HTTPS traffic from mobile applications that implement certificate pinning, public key pinning, or SPKI hash pinning on Android and iOS, including React Native, Flutter, and Xamarin frameworks.
---

# SKILL: Mobile SSL Pinning Bypass — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert SSL pinning bypass techniques for mobile platforms. Covers Android and iOS bypass methods (Frida, Objection, Xposed, SSL Kill Switch), framework-specific bypasses (Flutter, React Native, Xamarin), and troubleshooting non-standard pinning implementations. Pay particular attention to framework-specific hook points and multi-layer pinning configurations.

## 0. RELATED ROUTING

Before going deep, consider routing to:

- `android-pentesting-tricks` for broader Android testing beyond SSL bypass
- `ios-pentesting-tricks` for broader iOS testing beyond SSL bypass
- `api-sec` once traffic is intercepted for API-level testing

---

## 1. SSL PINNING TYPES

| Pinning Type | What Is Pinned | Resilience | Common In |
|---|---|---|---|
| Certificate pinning | Exact leaf certificate (DER/PEM) | Low (breaks on cert rotation) | Legacy apps |
| Public key pinning | Subject Public Key Info | Medium (survives cert renewal if key unchanged) | Modern apps |
| SPKI hash pinning | SHA-256 of SPKI | Medium (same as public key) | OkHttp, AFNetworking |
| CA pinning | Intermediate or root CA cert | High (any cert from that CA works) | Enterprise apps |
| Multi-pin (backup pins) | Primary + backup pins | High (fallback pins) | HPKP-aware apps |

### How Pinning Works

```
TLS Handshake
│
├── Server presents certificate chain
│
├── Standard validation (system trust store)
│   └── Passes? continue : connection fails
│
└── Pin validation (app-level check)
    ├── Extract server cert/pubkey/SPKI hash
    ├── Compare against embedded pins
    └── Match found? → allow : → reject connection
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 2. ANDROID BYPASS METHODS
- 3. iOS BYPASS METHODS
- 4. FRAMEWORK-SPECIFIC BYPASSES
- 5. CERTIFICATE TRANSPARENCY & HPKP
- 6. TROUBLESHOOTING
- 7. SSL PINNING BYPASS DECISION TREE
- 8. PROXY SETUP QUICK REFERENCE
