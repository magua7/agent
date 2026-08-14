# SKILL: HTTP Parameter Pollution (HPP): detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [5. DECISION TREE](#5-decision-tree)
<!-- zhiyugo:toc:end -->

## 5. DECISION TREE

```text
                    +-------------------------+
                    | Duplicate param name    |
                    | same request            |
                    +------------+------------+
                                 |
              +------------------+------------------+
              |                                     |
       +------v------+                       +------v------+
       | Single app  |                       | WAF / CDN / |
       | layer only  |                       | proxy chain |
       +------+------+                       +------+------+
              |                                     |
    +---------v---------+                 +---------v---------+
    | Read framework    |                 | Map each hop:     |
    | docs + test       |                 | first/last/join/  |
    | a=1&a=2 vs swap   |                 | array             |
    +---------+---------+                 +---------+---------+
              |                                     |
              +------------------+------------------+
                                 |
                          +------v------+
                          | Pick attack |
                          | template    |
                          +------+------+
                                 |
         +-----------+-----------+-----------+-----------+
         |           |           |           |           |
    +----v----+ +----v----+ +----v----+ +----v----+ +----v----+
    | WAF vs  | | SSRF    | | CSRF    | | Logic   | | JSON    |
    | app     | | split   | | token   | | numeric | | dup key |
    | value   | | URL     | | confuse | | fields  | | parsers |
    +---------+ +---------+ +---------+ +---------+ +---------+
```

---

**Safety & scope**: HPP testing can change server state (payments, account settings). Run only where **explicitly authorized**, with scoped accounts, and document parser behavior before high-impact requests.
