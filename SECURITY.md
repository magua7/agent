# Security Policy

## Authorized use only

This project is an orchestration kernel for systems you own or are explicitly
authorized to assess. Operators are responsible for written authorization,
scope, timing, data handling, and applicable law. The runtime's scope checks
are defense in depth; they are not proof of consent.

The MVP intentionally omits arbitrary shell/Python execution and exploit
automation. Local tools enforce explicit network/file scope, bounded inputs,
timeouts, and auditable results.

## Reporting a vulnerability

Do not include live credentials, private target data, or weaponized public
exploits in an issue. Use the repository owner's private security-reporting
channel when one is configured. Until then, disclose only a minimal reproducible
description to the maintainer.
