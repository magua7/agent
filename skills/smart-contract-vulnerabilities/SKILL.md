---
name: smart-contract-vulnerabilities
description: >-
  Smart contract vulnerability playbook. Use when auditing Solidity/EVM contracts for reentrancy, integer overflow, access control, delegatecall, flash loan, signature replay, and MEV-related attack patterns.
---

# SKILL: Smart Contract Vulnerabilities — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert smart contract audit techniques. Covers reentrancy (single, cross-function, cross-contract, read-only), integer overflow, access control, delegatecall, randomness manipulation, flash loans, signature replay, front-running/MEV, and CREATE2 exploitation. Pay particular attention to subtle cross-contract reentrancy and storage layout collisions in proxy patterns.

## 0. RELATED ROUTING

- `defi-attack-patterns` when the vulnerability is part of a DeFi protocol exploit (flash loans, oracle manipulation, governance attacks)
- `deserialization-insecure` when the target is off-chain infrastructure deserializing blockchain data

### Advanced Reference

Also inspect [SOLIDITY_VULN_PATTERNS.md](./SOLIDITY_VULN_PATTERNS.md) when you need:
- Side-by-side vulnerable vs fixed code patterns for each vulnerability class
- Gas optimization traps that introduce vulnerabilities
- Proxy pattern storage collision examples with slot calculations

---

## 1. REENTRANCY

The most iconic smart contract vulnerability. External calls transfer execution control; if state is not updated before the call, the callee can re-enter.

### 1.1 Classic Reentrancy (Single-Function)

```
Victim.withdraw()
  ├── checks balance[msg.sender] > 0          ✓
  ├── msg.sender.call{value: balance}("")     ← external call
  │   └── Attacker.receive()
  │       └── Victim.withdraw()               ← re-enters before state update
  │           ├── checks balance[msg.sender]   ← still > 0!
  │           └── sends ETH again
  └── balance[msg.sender] = 0                 ← too late
```

### 1.2 Cross-Function Reentrancy

Two functions share state; attacker re-enters a different function during callback:

| Step | Execution | State |
|---|---|---|
| 1 | Call `withdraw()` → external call | balance still positive |
| 2 | Attacker fallback calls `transfer(attacker2)` | balance used before reset |
| 3 | `transfer` reads stale balance → moves funds | attacker2 receives tokens |
| 4 | Original `withdraw` completes, zeroes balance | damage done |

### 1.3 Cross-Contract Reentrancy

Contract A calls Contract B, which calls back into Contract A (or Contract C that reads A's stale state). Especially dangerous in DeFi protocols where multiple contracts share state.

### 1.4 Read-Only Reentrancy

The re-entered function is a `view` function used by a third-party contract for price calculation. No state modification in the victim, but the stale intermediate state misleads the reader.

**Real-world**: Curve pool `get_virtual_price()` read during `remove_liquidity()` callback → inflated price → profit on dependent lending protocol.

### Mitigations

| Pattern | Protection Level |
|---|---|
| Checks-Effects-Interactions (CEI) | Core defense; update state before external call |
| `ReentrancyGuard` (OpenZeppelin) | Mutex lock; prevents same-tx re-entry |
| Pull payment pattern | Eliminate external calls in state-changing functions |
| CEI + guard on all public functions | Defense-in-depth against cross-function |

---

## 2. INTEGER OVERFLOW / UNDERFLOW

### Pre-Solidity 0.8

Arithmetic silently wraps: `uint8(255) + 1 == 0`, `uint8(0) - 1 == 255`.

| Attack | Example |
|---|---|
| Balance underflow | `balances[attacker] -= amount` when amount > balance → huge balance |
| Supply overflow | `totalSupply + mintAmount` wraps → bypass cap checks |
| Timelock bypass | `lockTime[msg.sender] + extend` wraps to past → early unlock |

### Post-Solidity 0.8

Default checked arithmetic reverts on overflow. But `unchecked{}` blocks reintroduce risk:

```solidity
unchecked {
    // "gas optimization" — but if i can be influenced by user input, overflow returns
    for (uint i = start; i < end; i++) { ... }
}
```

### SafeMath Bypass Scenarios

- Casting: `uint256` → `uint128` truncation before SafeMath check
- Assembly blocks: `mstore` / `add` bypass Solidity-level checks
- Intermediate multiplication overflow before division: `(a * b) / c` where `a * b` overflows

---

## 3. ACCESS CONTROL

### tx.origin vs msg.sender

| Property | `msg.sender` | `tx.origin` |
|---|---|---|
| Value | Immediate caller | EOA that initiated the tx |
| Safe for auth | Yes | **No** — phishing contract can inherit tx.origin |

Attack: trick owner into calling attacker contract → attacker contract calls victim with owner's `tx.origin`.

### Common Patterns

| Issue | Impact |
|---|---|
| Missing `onlyOwner` on critical functions | Anyone can call admin functions |
| Unprotected `selfdestruct` | Anyone can destroy the contract, force-send ETH |
| Unprotected `delegatecall` | Attacker executes arbitrary code in victim's context |
| Default visibility (pre-0.6.0) | Functions default to `public` |
| Missing zero-address checks | Ownership transferred to `address(0)` |

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 4. RANDOMNESS MANIPULATION
- 5. DELEGATECALL VULNERABILITIES
- 6. FRONT-RUNNING / MEV
- 7. SIGNATURE REPLAY
- 8. SELF-DESTRUCT & FORCE-SEND ETH
- 9. CREATE2 & DETERMINISTIC ADDRESS EXPLOITATION
- 10. FLASH LOAN ATTACK PATTERNS
- 11. SHORT ADDRESS ATTACK
- … plus 2 additional sections
