---
name: defi-attack-patterns
description: >-
  DeFi attack pattern playbook. Use when analyzing flash loan attacks, price oracle manipulation, MEV sandwich attacks, governance exploits, bridge vulnerabilities, and token standard edge cases in decentralized finance protocols.
---

# SKILL: DeFi Attack Patterns — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert DeFi exploitation techniques. Covers flash loan mechanics, oracle manipulation (spot vs TWAP), MEV extraction (sandwich, JIT, liquidation), precision loss attacks, governance exploits, bridge vulnerabilities, and token standard pitfalls. Pay particular attention to the single-transaction atomicity constraint of flash loans and the distinction between spot price and TWAP manipulation.

## 0. RELATED ROUTING

- `smart-contract-vulnerabilities` for underlying Solidity vulnerability patterns (reentrancy, integer overflow, delegatecall)
- `deserialization-insecure` when targeting off-chain bridge relayer or indexer infrastructure

---

## 1. FLASH LOAN ATTACKS

### 1.1 Mechanism

Flash loans provide uncollateralized borrowing within a single transaction. The entire borrow → use → repay cycle must complete atomically; if repayment fails, the transaction reverts as if nothing happened.

| Provider | Max Amount | Fee |
|---|---|---|
| Aave V3 | Pool liquidity per asset | 0.05% (can be 0 for approved borrowers) |
| dYdX | Pool liquidity | 0 (uses internal balance manipulation) |
| Uniswap V3 | Pool liquidity per pair | 0.3% (swap fee tier) |
| Balancer | Pool liquidity | Protocol-configurable |

### 1.2 Price Oracle Manipulation

```
1. Flash borrow 100,000 WETH
2. Swap 100,000 WETH → TOKEN on AMM_A
   → TOKEN spot price on AMM_A skyrockets
3. On Lending_Protocol (reads AMM_A spot price as oracle):
   → Deposit small TOKEN collateral (valued at inflated price)
   → Borrow large amount of WETH against it
4. Swap TOKEN back → WETH on AMM_A (restore price)
5. Repay flash loan (100,000 WETH + fee)
6. Keep borrowed WETH from Lending_Protocol minus collateral cost
```

**Key insight**: protocols using AMM spot reserves (`getReserves()`) as price oracles are vulnerable. Must use TWAP or external oracle (Chainlink).

### 1.3 Liquidity Pool Drain via Reentrancy

Flash borrow → deposit into pool → trigger reentrancy during callback → withdraw more than deposited → repay loan.

Exploits the combination of flash loan capital with reentrancy in pool accounting logic.

### 1.4 Governance Flash Borrow

```
1. Flash borrow governance tokens
2. Create/vote on malicious proposal (if no snapshot or timelock)
3. Proposal passes instantly
4. Execute proposal (drain treasury, change admin, etc.)
5. Return governance tokens
```

Defense: snapshot-based voting (Compound Governor Bravo), timelocks, minimum proposal period.

---

## 2. PRICE ORACLE MANIPULATION

### 2.1 Spot Price vs TWAP

| Oracle Type | Manipulation Cost | Time Window |
|---|---|---|
| Spot price (`getReserves()`) | Single large swap (flash loanable) | Same transaction |
| TWAP (Time-Weighted Average) | Sustained multi-block manipulation | Multiple blocks (expensive) |
| Chainlink aggregator | Compromise ≥ majority of oracle nodes | Practically infeasible |

### 2.2 AMM Manipulation Flow

```
Normal state: Pool has 1000 ETH + 1,000,000 USDC → price = 1000 USDC/ETH

Attack:
├── Swap 9000 ETH into pool
│   Pool now: 10000 ETH + 100,000 USDC (constant product)
│   Spot price: 10 USDC/ETH (crashed 100x)
├── Dependent contract reads this price
│   → Liquidates positions at wrong price
│   → Or allows cheap borrowing against ETH collateral
├── Swap back: buy ETH with USDC
│   Price restores to ~1000 USDC/ETH
└── Net profit = value extracted from dependent contract - swap slippage - fees
```

### 2.3 Chainlink Oracle Staleness

```solidity
(, int price, , uint updatedAt, ) = priceFeed.latestRoundData();
// Missing checks:
// 1. price > 0
// 2. updatedAt != 0
// 3. block.timestamp - updatedAt < HEARTBEAT
// 4. answeredInRound >= roundId
```

If oracle is stale (network congestion, L2 sequencer down), price can be hours old → arbitrage against stale price.

**L2 Sequencer Risk**: If Arbitrum/Optimism sequencer is down, Chainlink prices freeze. When it comes back, prices jump → mass liquidations at wrong prices.

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 3. MEV (MAXIMAL EXTRACTABLE VALUE)
- 4. PRECISION LOSS EXPLOITATION
- 5. GOVERNANCE ATTACKS
- 6. BRIDGE EXPLOITS
- 7. TOKEN STANDARD EDGE CASES
- 8. NOTABLE DEFI EXPLOITS REFERENCE
- 9. DECISION TREE
