# capture.pcap

<p align="center">
  <img src="https://img.shields.io/badge/Category-Network%20Forensics-blueviolet?style=for-the-badge&logo=wireshark" alt="Category">
  <img src="https://img.shields.io/badge/Difficulty-Easy-brightgreen?style=for-the-badge" alt="Difficulty">
  <img src="https://img.shields.io/badge/Points-250-blue?style=for-the-badge" alt="Points">
  <img src="https://img.shields.io/badge/Tools-Wireshark%20|%20tshark%20|%20xxd-lightgrey?style=for-the-badge&logo=linux" alt="Tools">
</p>

---

## Executive Summary

`capture.pcap` is a network forensics challenge analyzing a packet capture file recording anomalous traffic originating from internal host `192.168.1.42`. While standard HTTP and chat packet inspection yields no plaintext flags, inspection of DNS traffic reveals a classic **DNS exfiltration tunnel**. The infected client generates a sequential series of DNS `A` record queries to subdomains of `redphoenix.com`. Each subdomain is composed of a 2-character hexadecimal string representing a single ASCII character. Reconstructing the sequence of queries and decoding the hex stream uncovers the flag: `RPCTF{wiresh4rk_3la_9ed_l7al}`.

---

## Fundamental Concepts for Beginners

### 1. What is DNS Exfiltration (DNS Tunneling)?
In enterprise computer networks, strict firewalls block almost all outbound TCP/UDP traffic to unauthorized external IP addresses. However, nearly every network permits outbound **DNS traffic** (UDP port 53) to recursive resolvers like Google DNS (`8.8.8.8`) or Cloudflare (`1.1.1.1`) so that workstations can resolve web addresses.

Attackers abuse this open channel to exfiltrate stolen data:
1. The infected endpoint encodes stolen data into subdomains: `<chunk>.<attacker-domain>.com`.
2. The internal DNS resolver forwards this query to the authoritative nameserver controlled by the attacker.
3. The attacker records the queried subdomains and reassembles the payload!

```
 +------------------+                      +--------------------+                      +-------------------------+
 | Infected Host    |                      | Recursive Resolver |                      | Attacker Nameserver     |
 | (192.168.1.42)   |                      | (8.8.8.8:53)       |                      | (ns1.redphoenix.com)    |
 +------------------+                      +--------------------+                      +-------------------------+
          |                                          |                                              |
          |  DNS Query: 52.redphoenix.com ('R')      |                                              |
          |----------------------------------------->|                                              |
          |                                          |  Forward Query: 52.redphoenix.com            |
          |                                          |--------------------------------------------->|
          |                                          |                                              | [Logs: '52']
          |  DNS Query: 50.redphoenix.com ('P')      |                                              |
          |----------------------------------------->|                                              |
          |                                          |  Forward Query: 50.redphoenix.com            |
          |                                          |--------------------------------------------->|
          |                                          |                                              | [Logs: '50']
          v                                          v                                              v
```

---

## Step 1: Initial PCAP Triage & Protocol Inspection

We begin by verifying the file format and searching for cleartext strings:

```bash
$ file capture.pcap
capture.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 262144)

$ strings capture.pcap | grep -iE "RPCTF|flag"
# (No results returned)
```

The flag is not transmitted as plain text in HTTP, FTP, or unencrypted chat payloads.

---

## Step 2: Protocol Breakdown & DNS Anomaly Detection

We examine protocol distribution and summary packets using `tshark`:

```bash
$ tshark -r capture.pcap -q -z io,phs
===================================================================
Protocol Hierarchy Statistics
Filter: 
eth                                      frames:224 bytes:18204
  ip                                     frames:224 bytes:18204
    udp                                  frames:224 bytes:18204
      dns                                frames:224 bytes:18204
===================================================================
```

The entire capture consists strictly of **DNS traffic** over UDP!

Listing the queried domain names:

```bash
$ tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | head -n 15
office.com
login.microsoftonline.com
icloud.com
github.com
61.redphoenix.com
5f.redphoenix.com
39.redphoenix.com
65.redphoenix.com
64.redphoenix.com
5f.redphoenix.com
6c.redphoenix.com
37.redphoenix.com
61.redphoenix.com
6c.redphoenix.com
7d.redphoenix.com
```

### Anomaly Analysis:
1. Queries to legitimate domains (`office.com`, `github.com`) act as background noise.
2. An anomalous burst of queries targets `*.redphoenix.com`.
3. Every subdomain before `.redphoenix.com` consists of exactly **two hexadecimal characters** (`0-9`, `a-f`).

Let's check the first few hex queries in the ASCII table:
- `52` $\rightarrow$ ASCII `R`
- `50` $\rightarrow$ ASCII `P`
- `43` $\rightarrow$ ASCII `C`
- `54` $\rightarrow$ ASCII `T`
- `46` $\rightarrow$ ASCII `F`
- `7b` $\rightarrow$ ASCII `{`
- ...
- `7d` $\rightarrow$ ASCII `}`

The attacker transmitted the flag character-by-character as 2-digit hex subdomains!

---

## Step 3: Extraction & Decoding

We construct a `tshark` command to:
1. Filter for client requests (`dns.flags.response == 0`).
2. Match queries containing `redphoenix`.
3. Extract only the `dns.qry.name` field.
4. Cut the first subdomain label before `.`.
5. Remove newlines and decode hex with `xxd`:

```bash
$ tshark -r capture.pcap \
    -Y 'dns.flags.response == 0 && dns.qry.name contains "redphoenix"' \
    -T fields -e dns.qry.name \
    | cut -d'.' -f1 \
    | tr -d '\n' \
    | xxd -r -p
```

### Decoded Output:
```text
RPCTF{wiresh4rk_3la_9ed_l7al}
```

---

## Output & Flag Capture

**Captured Flag:**
```
RPCTF{wiresh4rk_3la_9ed_l7al}
```
*(Cultural Note: "wireshark 3la 9ed l7al" is Moroccan Darija meaning "humble Wireshark" or "making do with simple tools".)*

---

## Threat Hunting & SOC Detection Rules

Security Operations Centers (SOCs) defend against DNS tunneling with the following detection mechanisms:

### 1. Suricata / Snort Rule:
```suricata
alert dns $HOME_NET any -> any 53 (
    msg:"ET HUNT Suspicious High-Frequency 2-Char Hex Subdomains (Exfiltration)";
    dns.query; pcre:"/^[0-9a-f]{2}\.[a-z0-9\-\.]+\.[a-z]{2,}$/i";
    threshold: type threshold, track by_src, count 10, seconds 20;
    classtype:bad-unknown; sid:1000942; rev:1;
)
```

### 2. Behavioral Indicators:
- **High Query Volume to Rare Domains:** Hundreds of unique lookups to a newly registered second-level domain (SLD).
- **High Shannon Entropy:** Domain names exhibiting randomness or hex/base64 distribution characteristics.
- **NXDomain Spikes:** High failure rates from typo-squatted tunneling domains.
