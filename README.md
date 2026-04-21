# WiFiAid

A real-time Wi-Fi health monitor for macOS (with stub support for iOS) built with Swift and SwiftUI.

## Overview

WiFiAid continuously probes your local network using ICMP echo requests and surfaces latency, packet loss, jitter, and throughput metrics for your gateway and nearby LAN hosts. It presents everything in a compact, auto-refreshing dashboard alongside a 0–100 health score so you can tell at a glance how your Wi-Fi connection is behaving.

## Features

| Feature | Detail |
|---|---|
| **Gateway probing** | Sends ICMP echo requests at 30 Hz to your default gateway |
| **LAN host discovery** | Pings all 253 addresses in your /24 subnet on startup and every 60 s, then adopts responding hosts from the ARP table (up to 6 extra peers) |
| **Rolling statistics** | Maintains 1 s and 10 s rolling windows per host: p50, p95, p99 latency, packet loss %, jitter (standard deviation), and last RTT |
| **Health score (0–100)** | Weighted combination of loss (40 %), RTT (30 %), jitter (20 %), and RSSI (10 %) computed over the 10 s window |
| **Throughput** | Real-time RX / TX in kbps read directly from the network interface counters |
| **Wi-Fi details** *(macOS)* | SSID, BSSID, and RSSI via CoreWLAN |
| **Hostname resolution** | Async reverse-DNS lookups for every discovered host |
| **MAC addresses** | Read from the kernel ARP table and displayed per peer |

## Requirements

* **macOS 13 Ventura or later** (primary target)
* Xcode 15 or later
* The `com.apple.developer.networking.wifi-info` entitlement (already included in `WiFiAid.entitlements`)

## Getting Started

```bash
# 1. Clone the repository
git clone https://github.com/leok7v/WiFiAid.git
cd WiFiAid

# 2. Open the Xcode project
open WiFiAid.xcodeproj
```

Select your development team in Signing & Capabilities (or fill in Developer.xcconfig with your DEVELOPMENT_TEAM identifier).
Build and run the WiFiAid scheme on your Mac.
Note: ICMP sockets require the app to run with the appropriate network entitlements. On macOS the sandbox allows unprivileged ICMP (SOCK_DGRAM / IPPROTO_ICMP) without root, but you must have a valid code-signing identity.

## Architecture
Everything lives in a single Swift file, TheApp.swift, organised into distinct layers:

```
TheApp.swift
├── Network helpers (pure functions, nonisolated)
│   ├── IPv4          – lightweight IPv4 value type
│   ├── discoverDefaultRoute()  – sysctl(PF_ROUTE) gateway discovery
│   ├── dumpArpTable()          – sysctl ARP table dump
│   ├── ifaceAddrs / ifaceStats – getifaddrs wrappers
│   ├── subnet24()              – /24 address enumeration
│   ├── buildICMPEcho / icmpChecksum – ICMP packet construction
│   └── lookupHostname()        – getnameinfo reverse DNS
│
├── ICMPProber   – non-blocking ICMP send/receive engine (DispatchQueue)
├── NameResolver – concurrent reverse-DNS resolver
├── RollingStats – lock-protected sliding-window percentile calculator
├── ProbeStore   – manages per-host 1 s and 10 s RollingStats instances
│
├── WiFiHealth   – @MainActor ObservableObject; orchestrates all of the above
│                  and publishes data to the UI at 10 Hz
│
└── ContentView  – SwiftUI dashboard (score card, info card, peer table)
```

## UI at a Glance

```
WiFiAid
Probing at 30 Hz

87 /100                          -62 dBm
                                 HomeNetwork
                                 aa:bb:cc:dd:ee:ff

iface en0   self 192.168.1.42
gw 192.168.1.1   5 hosts
floor 3.20 ms   rx 1204 / tx 88 kbps

Peer            p50     excess    p95    loss
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛜 Gateway      3.2 ms  —        4.8 ms  0.0%
   192.168.1.1
   aa:bb:cc:00:11:22
Host            4.1 ms  0.9 ms   6.2 ms  0.0%
   192.168.1.10
```

Score colours: green ≥ 80 · yellow ≥ 50 · red < 50
Excess colours: grey < 1 ms · primary < 5 ms · orange < 20 ms · red ≥ 20 ms

Score Formula

```
score = 0.40 × lossScore
      + 0.30 × rttScore
      + 0.20 × jitterScore
      + 0.10 × rssiScore        (macOS only; 70 when unavailable)

lossScore   = clamp(100 × (5  − loss%)   / 5 )
rttScore    = clamp(100 × (50 − p50 ms)  / 48)
jitterScore = clamp(100 × (20 − jitter)  / 19)
rssiScore   = clamp(100 × (RSSI + 90)    / 40)   [dBm; −90 → 0, −50 → 100]
```

## AI experiments (to suggest what to do)

Free AI: "LLM from URL" — https://818233.xyz/ used

https://www.reddit.com/r/LLMDevs/comments/1mm0j73/i_built_a_free_ai_service_to_get_chat_completions/
https://www.scamadviser.com/check-website/818233.xyz
https://www.reddit.com/user/yvonuk/

https://github.com/ruanyf/weekly/issues/7738
https://github.com/ruanyf/weekly/issues/7517

also works as Web Proxy e.g. https://web.818233.xyz/wikipedia.org
https://x.com/mcwangcn/status/1954984384907579886

Other Free AI services from: https://free.waxianzhi.com/

Completely free / No login required:

LM Arena — https://lmarena.ai/
Free AI Image Generator — https://freeaiimage.net/zh/
Free AI for Everyone — https://free.stockai.trade/
LLM from URL — https://818233.xyz/
Face Swap Video — https://faceswapvideo.io/
Dreamify AI Painting Charity Station — https://dreamify.slmnb.cn/zh
Stable Diffusion Online — https://stablediffusionweb.com/
Scribble Diffusion — https://scribblediffusion.com/
TinyWow — https://tinywow.com/
Tldraw — https://www.tldraw.com/

Completely free / Registration or login required (for reference):

Nano Banana / Gemini 2.5 Flash Image — https://gemini.google.com/
Google AI Studio — https://aistudio.google.com/
AnyRouter Charity Website — https://anyrouter.top/
Codeium — https://codeium.com/
Hugging Face — https://huggingface.co/
CapCut — https://www.capcut.com/
Civitai — https://civitai.com/


curl -N -X POST https://free.stockai.trade/api/chat \
  -H 'Content-Type: application/json' \
  -d '{"model":"openrouter/free","webSearch":false,"targetLanguage":"en","id":"test1","messages":[{"id":"u1","role":"user","parts":[{"type":"text","text":"Say hello in 3 words"}]}]}'
