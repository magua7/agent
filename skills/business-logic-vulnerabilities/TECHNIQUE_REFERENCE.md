# SKILL: Business Logic Vulnerabilities — Expert Attack Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [4. COUPON AND REFERRAL ABUSE](#4-coupon-and-referral-abuse)
- [5. ACCOUNT / PRIVILEGE LOGIC FLAWS](#5-account-privilege-logic-flaws)
- [6. API BUSINESS LOGIC FLAWS](#6-api-business-logic-flaws)
- [7. SUBSCRIPTION / TIER CONFUSION](#7-subscription-tier-confusion)
- [8. FILE UPLOAD BUSINESS LOGIC](#8-file-upload-business-logic)
- [9. TESTING APPROACH](#9-testing-approach)
- [10. HIGH-IMPACT CHECKLISTS](#10-high-impact-checklists)
<!-- zhiyugo:toc:end -->

## 4. COUPON AND REFERRAL ABUSE

### Coupon Stacking
```
Test: Can you apply multiple coupon codes?
Test: Does "SAVE20" + promo stack to >100%?
Test: Apply coupon, remove item, keep discount applied, add different item
```

### Referral Loop
```
1. Create Account_A
2. Register Account_B with Account_A's referral code → both get credit
3. Create Account_C with Account_B's referral code
4. Ad infinitum with throwaway emails
→ Infinite credit generation
```

### Coupon = Fixed Dollar Amount on Variable-Price Item
```
Coupon: -$5 off any order
Buy item worth $3, use -$5 coupon → net -$2 (credit balance)
```

---

## 5. ACCOUNT / PRIVILEGE LOGIC FLAWS

### Email Verification Bypass
```
1. Register with email A (legitimate, verified)
2. Change email to B (attacker's email, unverified)
3. Use account as verified — does server enforce re-verification?

Or: Change email to victim's email → no verification → account claim
```

### Password Reset Token Binding
```
1. Request password reset for your account → get token
2. Change your email address (account settings)
3. Reuse old password reset token → does it still work for old email?

Or: Request reset for victim@target.com
    Token sent to victim but check: does URL reveal predictable token pattern?
```

### OAuth Account Linking Abuse
```
1. Have victim's email (but not their password)
2. Register with victim's email → get account with same email
3. Link OAuth (Google/GitHub) to your account
4. Victim logs in with Google → server finds email match → merges with YOUR account
```

---

## 6. API BUSINESS LOGIC FLAWS

### Object State Manipulation
```
order.status = "pending"
→ PUT /api/orders/1234 {"status": "refunded"}   ← self-trigger refund
→ PUT /api/orders/1234 {"status": "shipped"}    ← mark as shipped without shipping
```

### Transaction Reuse
```
1. Initiate payment → get transaction_id
2. Complete purchase
3. Reuse same transaction_id for second purchase:
   POST /api/checkout {"transaction_id": "USED_TX", "cart": "new_cart"}
```

### Limit Count Manipulation
```
Daily transfer limit = $1000
→ Transfer $999, cancel, transfer $999 (limit not updated on cancel)
→ Parallel transfers (race condition on limit check)
→ Different payment types not sharing limit counter
```

---

## 7. SUBSCRIPTION / TIER CONFUSION

```
Free tier: cannot access feature X
Paid tier: can access feature X

Attack: 
- Sign up for paid trial → enable feature X → downgrade to free
  → Does feature X get disabled on downgrade? 
  → Can you continue using feature X?

Or:
- Inspect premium endpoint list from JS bundle
- Directly call premium endpoints with free account token
→ Server checks subscription for UI but not API?
```

---

## 8. FILE UPLOAD BUSINESS LOGIC

For the full upload attack workflow beyond pure logic flaws, route to:
- `upload-insecure-files`

```
Upload size limit: 10MB
→ Upload 10MB → compress client-side → server decompresses → bomb?
(Zip bomb: 1KB zip → 1GB file = denial of service)

Upload type restriction:
→ Upload .csv for "data import" → inject formulas: =SYSTEM("calc")
  (CSV injection in Excel macro context)
→ Upload avatar → server converts → attack converter (ImageMagick, FFmpeg CVEs)

Storage path prediction:
→ /uploads/USER_ID/filename
→ Can you overwrite other user's file by knowing their ID + filename?
```

---

## 9. TESTING APPROACH

```
For each business process:
1. Map the INTENDED flow (happy path)
2. Ask: "What if I skip step N?"
3. Ask: "What if I send negative/zero/MAX values?"
4. Ask: "What if I repeat this step twice?" (idempotency)
5. Ask: "What happens if I do A then B instead of B then A?"
6. Ask: "What if two users do this simultaneously?"
7. Ask: "Can I modify the 'trusted' status fields?"
8. Think from financial/resource impact angle → highest bounty
```

---

## 10. HIGH-IMPACT CHECKLISTS

### E-commerce / Payment
```
□ Negative quantity in cart
□ Apply multiple conflicting coupons
□ Race condition: double-spend gift card
□ Skip payment step directly to order confirmation  
□ Refund without return (trigger refund on delivered item via state change)
□ Currency rounding exploitation
```

### Authentication / Account
```
□ 2FA bypass by direct URL access after password step
□ Password reset token reuse after email change
□ Email verification bypass (change email after verification)
□ OAuth account takeover via email match
□ Register with existing unverified email
```

### Subscriptions / Limits
```
□ Access premium features after downgrade
□ Exceed rate/usage limits via parallel requests
□ Referral loop for infinite credits
□ Free trial ≠ time-limited (no enforcement after trial)
□ Direct API call to premium endpoint without subscription check
```
