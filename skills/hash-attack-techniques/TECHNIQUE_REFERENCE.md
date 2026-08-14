# SKILL: Hash Attack Techniques — Expert Cryptanalysis Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [2. MD5 COLLISION ATTACKS](#2-md5-collision-attacks)
- [3. SHA-1 COLLISION](#3-sha-1-collision)
- [4. BIRTHDAY ATTACK](#4-birthday-attack)
- [5. HMAC TIMING ATTACK](#5-hmac-timing-attack)
- [6. MEET-IN-THE-MIDDLE (HASH)](#6-meet-in-the-middle-hash)
- [7. HASH PROOF-OF-WORK](#7-hash-proof-of-work)
- [8. RAINBOW TABLES & SALTING](#8-rainbow-tables-salting)
- [9. DECISION TREE](#9-decision-tree)
- [10. TOOLS](#10-tools)
<!-- zhiyugo:toc:end -->

## 2. MD5 COLLISION ATTACKS

### 2.1 Identical-Prefix Collision (fastcoll)

Two messages with same prefix but different content, producing identical MD5.

```bash
# Generate collision pair
fastcoll -p prefix_file -o collision1.bin collision2.bin

# Result: MD5(collision1.bin) == MD5(collision2.bin)
# Files differ in exactly 128 bytes (two MD5 blocks)
```

### 2.2 Chosen-Prefix Collision (hashclash)

Two messages with different chosen prefixes, appended with computed suffixes to collide.

```bash
# hashclash (Marc Stevens)
./hashclash prefix1.bin prefix2.bin

# Result: MD5(prefix1 || suffix1) == MD5(prefix2 || suffix2)
```

### 2.3 UniColl (Single-Block Near-Collision)

Produces two messages differing in a single byte within one MD5 block, with same hash.

```
Application: forge two PDF/PE files with same MD5
  - File 1: benign content
  - File 2: malicious content
  - Same MD5 hash
```

### 2.4 Collision Applications

| Application | Technique | Impact |
|---|---|---|
| Certificate forgery | Chosen-prefix | Rogue CA certificate (proven in 2008) |
| Binary substitution | Identical-prefix + conditional | Two executables, same MD5, different behavior |
| PDF collision | UniColl | Two PDFs showing different content |
| Git commit collision | Chosen-prefix (SHAttered for SHA1) | Two commits with same hash |
| CTF: bypass MD5 check | fastcoll | Two different inputs accepted as same |

### 2.5 CTF MD5 Collision Tricks

```php
// PHP: md5($_GET['a']) == md5($_GET['b']) && $_GET['a'] != $_GET['b']

// Method 1: Array trick (not real collision)
?a[]=1&b[]=2  // md5(array) returns NULL, NULL == NULL

// Method 2: Real collision (fastcoll output, URL-encoded binary)
?a=<collision1_urlencoded>&b=<collision2_urlencoded>

// Method 3: 0e magic hashes (loose comparison ==)
// md5("240610708") = "0e462097431906509019562988736854"
// md5("QNKCDZO")   = "0e830400451993494058024219903391"
// PHP: "0e..." == "0e..." is TRUE (both evaluate to 0 as floats)
```

---

## 3. SHA-1 COLLISION

### 3.1 SHAttered Attack (2017)

First practical SHA-1 collision: two PDF files with same SHA-1.

- Complexity: ~2^63 SHA-1 computations
- Cost: ~$110K on GPU clusters (2017 prices)
- Tool: shattered.io provides the collision PDFs

### 3.2 SHA-1 Chosen-Prefix Collision (2020)

- Complexity: ~2^63.4 computations
- Practical for attacking PGP/GnuPG key servers
- Demonstrates SHA-1 is broken for collision resistance

### 3.3 Impact

```
SHA-1 should NOT be used for:
  ✗ Digital signatures
  ✗ Certificate fingerprints
  ✗ Git commit integrity (migration to SHA-256 in progress)
  ✗ Deduplication based on hash

SHA-1 is still OK for:
  ✓ HMAC-SHA1 (collision resistance not required)
  ✓ HKDF-SHA1 (PRF security suffices)
  ✓ Non-adversarial checksums
```

---

## 4. BIRTHDAY ATTACK

### 4.1 Generic Birthday Bound

```
For n-bit hash: expected collisions after ~2^(n/2) hashes

Hash     Bits    Birthday bound
MD5      128     2^64
SHA-1    160     2^80
SHA-256  256     2^128

CTF application: if hash is truncated to k bits,
collision in ~2^(k/2) attempts
```

### 4.2 Birthday Attack Implementation

```python
import hashlib
import os

def birthday_attack(hash_func, output_bits, max_attempts=2**28):
    """Find collision for truncated hash."""
    mask = (1 << output_bits) - 1
    seen = {}

    for _ in range(max_attempts):
        msg = os.urandom(16)
        h = int(hash_func(msg).hexdigest(), 16) & mask

        if h in seen and seen[h] != msg:
            return seen[h], msg  # collision!
        seen[h] = msg

    return None

# Example: find collision for first 32 bits of SHA-256
result = birthday_attack(hashlib.sha256, 32)
```

---

## 5. HMAC TIMING ATTACK

### 5.1 Vulnerable Comparison

```python
# VULNERABLE: early-exit string comparison
def verify_hmac(received, expected):
    return received == expected  # Python == compares left to right

# The comparison may short-circuit on first differing byte,
# leaking timing information
```

### 5.2 Attack Strategy

```python
import requests
import time

def hmac_timing_attack(url, data, hmac_len=32):
    """Byte-by-byte HMAC recovery via timing."""
    known = ""

    for pos in range(hmac_len * 2):  # hex chars
        best_char = ""
        best_time = 0

        for c in "0123456789abcdef":
            candidate = known + c + "0" * (hmac_len * 2 - len(known) - 1)
            times = []

            for _ in range(50):  # multiple samples for accuracy
                start = time.perf_counter_ns()
                requests.get(url, params={**data, "mac": candidate})
                elapsed = time.perf_counter_ns() - start
                times.append(elapsed)

            avg_time = sorted(times)[len(times)//2]  # median
            if avg_time > best_time:
                best_time = avg_time
                best_char = c

        known += best_char
        print(f"Position {pos}: {known}")

    return known
```

### 5.3 Constant-Time Comparison (Defense)

```python
import hmac

# SECURE: constant-time comparison
def verify_hmac_secure(received, expected):
    return hmac.compare_digest(received, expected)
```

---

## 6. MEET-IN-THE-MIDDLE (HASH)

### 6.1 Concept

Split hash computation into two halves, precompute one, match against the other.

```
Hash computation: H = f(g(x₁), h(x₂))

Precompute: table[g(x₁)] = x₁  for all x₁ in space₁
Search:     for each x₂ in space₂:
              if h(x₂) in table:
                found! (x₁, x₂)

Time:  O(2^(n/2)) instead of O(2^n)
Space: O(2^(n/2))
```

---

## 7. HASH PROOF-OF-WORK

### 7.1 Common CTF PoW Formats

```python
# Format 1: Find x such that SHA256(prefix + x) starts with N zero bits
import hashlib

def solve_pow_prefix(prefix, zero_bits):
    target = '0' * (zero_bits // 4)
    i = 0
    while True:
        candidate = prefix + str(i)
        h = hashlib.sha256(candidate.encode()).hexdigest()
        if h.startswith(target):
            return str(i)
        i += 1

# Format 2: Find x such that SHA256(x) ends with specific suffix
def solve_pow_suffix(suffix_hex, hash_func=hashlib.sha256):
    i = 0
    while True:
        h = hash_func(str(i).encode()).hexdigest()
        if h.endswith(suffix_hex):
            return str(i)
        i += 1
```

### 7.2 GPU-Accelerated PoW

```bash
# hashcat for SHA256 PoW
hashcat -a 3 -m 1400 --hex-charset \
  "0000000000000000000000000000000000000000000000000000000000000000:prefix" \
  "?a?a?a?a?a?a?a?a"
```

---

## 8. RAINBOW TABLES & SALTING

### 8.1 Rainbow Table Attack

```
Precomputed chain: password → hash → reduce → password₂ → hash₂ → ...
Lookup: given hash h, check if h appears in any chain
Time-memory tradeoff: less space than full table, more time than direct lookup
```

### 8.2 Salt Defeats Rainbow Tables

```
Without salt: H(password) — same password always produces same hash
With salt:    H(salt || password) — different salt per user

Rainbow tables are password-specific, not (salt+password)-specific
Each unique salt requires a separate table → infeasible
```

### 8.3 Modern Password Hashing

| Algorithm | Salt | Iterations | Memory-Hard | Recommended |
|---|---|---|---|---|
| MD5 | No | 1 | No | Never |
| SHA-256 | No | 1 | No | Never for passwords |
| bcrypt | Yes | Configurable | No | Yes |
| scrypt | Yes | Configurable | Yes | Yes |
| Argon2 | Yes | Configurable | Yes | Best choice |
| PBKDF2 | Yes | Configurable | No | Acceptable |

---

## 9. DECISION TREE

```
Hash-related challenge — what's the scenario?
│
├─ Have H(secret || message), need to extend?
│  ├─ Hash is MD5/SHA1/SHA256/SHA512?
│  │  └─ Yes → Length extension attack
│  │     └─ Need: MAC value, original message, secret length
│  │        └─ Tool: HashPump or hash_extender
│  │
│  └─ Hash is SHA3/HMAC/BLAKE2?
│     └─ Length extension doesn't work
│        └─ Look for other vulnerabilities
│
├─ Need two inputs with same hash?
│  ├─ MD5?
│  │  ├─ Same prefix → fastcoll (seconds)
│  │  ├─ Different prefixes → hashclash (hours)
│  │  └─ CTF PHP loose comparison → 0e magic hashes
│  │
│  ├─ SHA-1?
│  │  └─ SHAttered (expensive, use precomputed if possible)
│  │
│  └─ SHA-256+?
│     └─ No practical collision attack
│        └─ Look for logic flaws instead
│
├─ Need to forge HMAC?
│  ├─ Timing side channel available?
│  │  └─ Byte-by-byte timing attack
│  │
│  ├─ Key is short/weak?
│  │  └─ Brute force key with hashcat
│  │
│  └─ No weakness?
│     └─ HMAC is secure — look elsewhere
│
├─ Hash is truncated (short output)?
│  └─ Birthday attack — collision in 2^(bits/2)
│
├─ Proof of work?
│  └─ Brute force with parallel computation
│     ├─ Python multiprocessing for < 28 bits
│     ├─ hashcat/GPU for > 28 bits
│     └─ Optimize: pre-increment string, avoid re-encoding
│
└─ Password hash cracking?
   ├─ No salt → rainbow tables (pre-computed)
   ├─ Known salt → hashcat / John the Ripper
   └─ Memory-hard (Argon2/scrypt) → limited by memory, slow brute force
```

---

## 10. TOOLS

| Tool | Purpose | Usage |
|---|---|---|
| **HashPump** | Length extension attack | `hashpump -s MAC -d data -k secret_len -a extension` |
| **hash_extender** | Length extension (multiple algorithms) | `hash_extender --data D --secret L --append E --sig MAC` |
| **fastcoll** | MD5 identical-prefix collision | `fastcoll -p prefix -o out1 out2` |
| **hashclash** | MD5 chosen-prefix collision | `hashclash prefix1 prefix2` |
| **hashcat** | Password/hash cracking (GPU) | `hashcat -m MODE -a ATTACK hash wordlist` |
| **John the Ripper** | Password cracking (CPU/GPU) | `john --wordlist=rockyou.txt hashes.txt` |
| **CyberChef** | Quick hash computation and encoding | Web-based |
