---
name: business-logic-vulnerabilities
description: >-
  Business logic vulnerability playbook. Use when reasoning about workflows, race conditions, price manipulation, coupon abuse, state machines, and multi-step authorization gaps.
---

# SKILL: Business Logic Vulnerabilities — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Business logic flaws are scanner-invisible and high-reward on bug bounty. This skill covers race conditions, price manipulation, workflow bypass, coupon/referral abuse, negative values, and state machine attacks. These require human reasoning, not automation. For specific exploitation techniques (payment precision/overflow, captcha bypass, password reset flaws, user enumeration), inspect the companion [SCENARIOS.md](./SCENARIOS.md).

### Extended Scenarios

Also inspect [SCENARIOS.md](./SCENARIOS.md) when you need:
- Payment precision & integer overflow attacks — 32-bit overflow to negative, decimal rounding exploitation, negative shipping fees
- Payment parameter tampering checklist — price, discount, currency, gateway, return_url fields
- Condition race practical patterns — parallel coupon application, gift card double-spend with Burp group send
- Captcha bypass techniques — drop verification request, remove parameter, clear cookies to reset counter, OCR with tesseract
- Arbitrary password reset — predictable tokens (`md5(username)`), session replacement attack, registration overwrite
- User information enumeration — login error message difference, masked data reconstruction across endpoints, base64 uid cookie manipulation
- Frontend restriction bypass — array parameters for multiple coupons (`couponid[0]`/`couponid[1]`), remove `disabled`/`readonly` attributes
- Application-layer DoS patterns — regex backtracking, WebSocket abuse

---

## 1. PRICE AND VALUE MANIPULATION

### Negative Quantity / Price
Many applications validate "amount > 0" but not for currency:
```
Add to cart with quantity: -1
Update quantity to: -100
{
  "quantity": -5,
  "price": -99.99     ← may be accepted
}
```
**Impact**: Receive credit to account, items for free, bank transfers in reverse.

### Integer Overflow
```
quantity: 2147483648   ← INT_MAX + 1 overflows to negative in 32-bit
price: 9999999999999   ← exceeds float precision → rounds to 0
```

### Rounding Manipulation
```
Item price: $0.001
Order 1000 items → each rounds down → total = $0.00
```

### Currency Exchange Rate Lag
```
1. Deposit using currency A at rate X
2. Rate changes
3. Withdraw using currency A at new rate → profit from rate difference
```

### Free Upgrade via Promo Stacking
Test combining discount codes, referral credits, welcome bonuses:
```
Apply promo: FREE50  → 50% off
Apply promo: REFER10 → additional 10%
Apply loyalty points → additional discount
Total: -$5 (free + credit)
```

---

## 2. RACE CONDITIONS

**Concept**: Two operations run simultaneously before the first completes its check-update cycle.

### Double-spend / double-redeem evidence model

A credible race-condition candidate requires a single-request baseline, synchronized request timestamps from an authorized external harness, every response, state before and after the batch, and a sequential negative control. A duplicate success is only a finding when the cited state evidence proves the invariant was violated.

The current Tool Registry cannot issue synchronized state-changing requests. Burp concurrency features and custom harnesses are external analyst references; report a capability gap instead of claiming this test ran.

### Account Registration Race
```
Register with same email simultaneously → two accounts created → data isolation broken
Password reset token race → reuse same token twice
Email verification race → verify multiple email addresses
```

### Limit Bypass via Race
```
"Claim once" discounts, freebies, "first order" bonus:
→ Send 10 parallel POST /claim requests
→ Race window: all pass the "already claimed?" check before any write
```

---

## 3. WORKFLOW / STEP SKIP BYPASS

### Payment Flow Bypass
```
Normal flow:
  1. Add to cart
  2. Enter shipping info
  3. Enter payment (card/wallet)
  4. Click confirm → payment charged
  5. Order confirmed

Attack: Skip to step 5 directly
POST /api/orders/confirm {"cart_id": "1234", "payment_status": "paid"}
→ Does server trust client-sent payment_status?
```

### Multi-Step Verification Skip
```
Password reset flow:
  1. Enter email
  2. Receive token
  3. Enter token
  4. Set new password (requires valid token from step 3)

Attack: Try going to step 4 without completing step 3:
POST /reset/password {"email": "victim@x.com", "token": "invalid", "new_pass": "hacked"}
→ Does server check that token was properly validated?

Or: Try token from old/expired flow → still accepted?
```

### 2FA Bypass
```
Normal flow:
  1. Enter username + password → success
  2. Enter 2FA code → logged in

Attack: After step 1 success, go directly to /dashboard
→ Is session created before 2FA completes?
→ Does /dashboard require 2FA-complete check or just "authenticated" flag?
```

### Shipping Without Payment
```
  1. Add item to cart
  2. Enter shipping address
  3. Select payment method (credit card)
  4. Apply promo code (100% discount or gift card)  
  5. Final amount: $0
  6. Order placed

Attack: Apply 100% discount code → no actual payment processed → item ships
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 4. COUPON AND REFERRAL ABUSE
- 5. ACCOUNT / PRIVILEGE LOGIC FLAWS
- 6. API BUSINESS LOGIC FLAWS
- 7. SUBSCRIPTION / TIER CONFUSION
- 8. FILE UPLOAD BUSINESS LOGIC
- 9. TESTING APPROACH
- 10. HIGH-IMPACT CHECKLISTS
