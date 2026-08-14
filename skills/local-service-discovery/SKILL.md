---
name: local-service-discovery
description: >-
  Discover bounded TCP services on an explicitly authorized localhost target.
  Use for local service inventory when exact hosts and ports are already in scope.
---

# Local service discovery

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Restrict activity to the exact TaskSpec scope. Use only bounded registry actions accepted by execution policy; this project Skill does not permit exploitation.
- Preserve baseline and test ToolResults as Evidence, including errors and negative observations, before drawing a conclusion.
- Treat command examples as reference syntax, not as shell access. Stop when a required capability or explicit target is absent.
- Complete only after every success criterion is assessed from cited evidence.
<!-- zhiyugo:contract:end -->

1. Confirm the exact host/IP and port set are present in the task scope and
   inputs. An objective mentioning a host is not authorization by itself.
2. Request the `network.scan` capability with a bounded list of TCP ports.
3. Preserve the complete tool result as evidence and record which scanner
   engine produced it.
4. Create an informational finding only when the structured result identifies
   at least one open port. Do not invent service versions or vulnerabilities.
5. Treat an empty open-port list as a valid negative result when the action
   succeeded. Treat unavailable/timeout/policy errors as failures, not as a
   clean scan.
6. Completion requires a successful action, intact evidence, and explicit
   coverage of the plan criterion.
