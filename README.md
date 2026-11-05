<div align="center">

# ApkSentry

**On-device static analysis for Android packages: APK, APKS and XAPK.**

[![Build](https://github.com/Med-Nouaoury/apksentry/actions/workflows/build.yml/badge.svg)](https://github.com/Med-Nouaoury/apksentry/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Android 8.0+](https://img.shields.io/badge/Android-8.0%2B-3ddc84.svg)

[العربية](README.ar.md) · [Download](../../releases) · [Benchmark](#measured-accuracy) · [Limitations](#limitations)

</div>

---

ApkSentry inspects an Android package **before** you install it and explains, in plain language, what the app is capable of and whether it shows signs of malware or tampering. It is built for people who install apps from outside Google Play.

- **Fully on-device.** No file is ever uploaded. Optional hash lookups send only SHA-256 hashes, using your own API keys.
- **No third-party parsers.** ZIP/ZIP64, binary XML, Dalvik bytecode, ELF and APK signatures are all parsed by the project's own engine.
- **Measured, not claimed.** Detection and false-positive rates come from a reproducible benchmark on real malware (see below).

## Contents

- [How it works](#how-it-works)
- [Measured accuracy](#measured-accuracy)
- [Per-app firewall](#per-app-firewall)
- [Installation](#installation)
- [Command-line usage](#command-line-usage)
- [Limitations](#limitations)
- [Building from source](#building-from-source)
- [Roadmap](#roadmap)
- [License and credits](#license-and-credits)

## How it works

Each scan produces two independent scores and a plain-language summary:

| Score | Question it answers |
|---|---|
| **Risk score** (0–100) | Does the code behave like malware? |
| **Modification score** (0–100) | Was the app modified or re-signed by someone other than its developer? |

| Risk score | Verdict |
|---|---|
| 0–9 | Low: no warning signs found (never a guarantee) |
| 10–34 | Low to medium: minor observations |
| 35–59 | Medium: review the findings before installing |
| 60–100 | High: do not install |

The engine combines the following layers.

### Code and behavior

| Layer | Description |
|---|---|
| **Dalvik emulator (unpacker)** | Packed malware carries its real code encrypted and decrypts it at runtime. ApkSentry executes the app's start-up code inside a purpose-built Dalvik interpreter, captures the decrypted code as it is loaded, and analyzes it like the rest of the app. It supports multiple packing layers. The sandbox exposes no real files, network, processes or class loaders, and enforces step, memory, time and depth budgets. |
| **Behavior rules** | 20+ rules covering common Android malware families: banking trojans, overlay attacks, SMS/OTP theft, keyloggers, clippers, ransomware, droppers, backdoors and malicious VPNs. Capabilities are distinguished from behaviors, so a permission alone is not treated as malicious. |
| **Taint analysis** | Inter-procedural, flow-sensitive tracking of personal data (device IDs, location, contacts, SMS, clipboard, accounts, notifications, on-screen text) through registers, fields and calls to network or SMS sinks. |
| **Bytecode analysis** | Full DEX instruction decoding with control-flow graphs, call graph, encrypted strings and string-decryption routines. |
| **ARM64 emulator (native code)** | Native code cannot do anything harmful without going through one of two doors: JNI (Android APIs, requested by name) or libc/system calls. ApkSentry runs the app's own native libraries in a from-scratch ARM64 interpreter where both doors are fakes it controls: every request is recorded (sending SMS, reading files, resolving a server, running a command), nothing reaches the device, and code or strings decrypted in memory are captured. The two emulators are linked, so Java → native → Java chains run end to end. The interpreter is verified instruction by instruction against Unicorn (60,000 random instructions, zero differences). |
| **Native libraries** | JNI exports and imports, direct system calls (`svc` on ARM/ARM64, `syscall` on x86_64), high-entropy packed sections, anti-analysis strings. |

### Identity and integrity

| Layer | Description |
|---|---|
| **Signature verification** | Cryptographic verification of APK Signature Scheme v2/v3 (signature and chunked content digests). Any byte changed after signing is detected. |
| **Official signer** | Compares the signer with the copy installed from Google Play, a user trust list, and the public AOSP test key. |
| **Impersonation** | Resolves the visible app name from `resources.arsc` in every locale and compares it with ~40 popular apps, catching typos, Cyrillic look-alikes, leetspeak and one-character package typosquats. A famous name on a foreign package combined with SMS or accessibility permissions is flagged as the banking-trojan pattern. |
| **Reputation (F-Droid)** | A weekly-updated list of every F-Droid signing certificate. An exact signer match identifies a reproducible, reviewed build. |
| **Modification tools** | MT Manager, NP Manager, Lucky Patcher, Xposed; commercial protectors (Jiagu, Bangcle, Legu, DexProtector…); unknown packers. |
| **Evasion tricks** | Fake ZIP compression methods, fake encryption flags, permission flooding, invisible characters in names. |

### Threat intelligence (optional)

| Layer | Description |
|---|---|
| **Hash lookups** | MalwareBazaar and VirusTotal lookups for the package and every file inside it, using your own free API keys. |
| **Similarity (TLSH)** | Fuzzy hashing that matches lightly modified variants of known malware, offline, against a database of recent Android samples. The Kotlin implementation is byte-identical to the reference `py-tlsh`. |

### Security audit of the app itself

Reported separately from the risk score: trust-all `TrustManager`, permissive `HostnameVerifier`, WebView SSL-error bypass, ECB/DES/RC4, hard-coded keys, exported providers, cleartext traffic, and leaked secrets (AWS, Stripe, GitHub, Slack and JWT tokens, plus Telegram bots and Discord webhooks used for exfiltration).

## Measured accuracy

The engine is evaluated with [`bench/benchmark.py`](bench/benchmark.py) on real Android malware from [MalwareBazaar](https://bazaar.abuse.ch/) and clean apps from [F-Droid](https://f-droid.org/). The benchmark runs on disposable GitHub Actions runners, and samples are deleted after scanning.

**Latest run: v3.9.0, November 2026.** 246 malware samples across 25 families (Hydra, Cerberus, Alien, SpyNote, Coper, IRATA, droppers and others), and 389 clean apps.

| Risk threshold | Malware detected | Clean apps flagged |
|---|---:|---:|
| ≥ 10 | 95.9% | 23.9% |
| **≥ 35** | **92.3%** | **6.9%** |
| ≥ 60 | 85.4% | 3.1% |

How to read these numbers:

- The benchmark runs the **engine alone**. Hash lookups, the TLSH database and the F-Droid reputation layer are disabled, because the samples come from those same sources and would inflate the results.
- Most clean apps that are flagged are legitimate **dual-use tools** (remote control, device finders, app lockers). In the app, the F-Droid reputation layer recognizes their official builds.
- The clean set follows the latest F-Droid releases, so it changes slightly between runs. False-positive rates move by about one point from that alone.
- The malware set reflects what MalwareBazaar receives, which is mostly known banking families. Detection of novel or targeted malware will be lower.

Reproduce it locally (requires a MalwareBazaar key):

```bash
export MB_API_KEY=...
python3 bench/benchmark.py --cli apksentry-cli.jar --malware 300 --fdroid 200
```

To run it without handling malware on your own machine instead, add a repository secret named `MB_API_KEY`, then start **Actions → Benchmark → Run workflow**.

## Per-app firewall

Static analysis cannot see what encrypted or native code does at runtime, so ApkSentry includes a local VPN-based firewall. No traffic leaves the device through any external server.

- **Block an app's internet access** directly from its scan result. The block is persistent: it remains active after ApkSentry is closed and is restored automatically after a reboot or an update.
- **Watch an app live:** every domain it requests is listed and classified as known, ads/tracking, unfamiliar or suspicious, and can be blocked with one tap.
- Blocked connection attempts are counted per app, including direct connections to IP addresses.

Android allows only one active VPN at a time. Enabling **Always-on VPN** for ApkSentry in system settings provides the strongest guarantee after a reboot.

## Installation

Download `ApkSentry.apk` from [Releases](../../releases). Every release is built by GitHub Actions directly from this repository, and checksums are published in `SHA256SUMS.txt`.

Requirements: Android 8.0 (API 26) or later. The user interface is currently in Arabic.

## Command-line usage

The same engine ships as a desktop tool (`apksentry-cli.jar`, Java 17+):

```bash
java -jar apksentry-cli.jar app.apks --out report.txt
java -jar apksentry-cli.jar app.apk --mb <MALWAREBAZAAR_KEY> --vt <VIRUSTOTAL_KEY>
java -jar apksentry-cli.jar app.apk --trusted trusted.txt   # one "package SHA-256" pair per line
java -jar apksentry-cli.jar app.apk --tlsh-db malware_tlsh.csv
```

| Option | Description |
|---|---|
| `--out FILE` | Write the report to a file |
| `--mb KEY`, `--vt KEY` | Hash lookups on MalwareBazaar and VirusTotal |
| `--trusted FILE` | Trusted package/signer pairs |
| `--tlsh-db FILE` | Offline similarity database |
| `--no-flow` | Skip taint analysis (faster) |
| `--no-reputation` | Disable the F-Droid reputation layer |

## Limitations

- **No scanner guarantees safety.** A low score means no warning signs were found, not that the app is safe.
- **Native emulation has limits.** Game engines (Unity, Unreal, Flutter…) and libraries over 12 MB are not executed, rare instructions stop the emulation rather than being guessed, and code that detects emulators can behave differently. When the real code stays hidden, ApkSentry says so explicitly, and when almost all of the code is hidden this way, the app is not reported as low risk.
- **Code downloaded later from a server cannot be seen** by any scanner. The per-app firewall is the answer to that case.
- **Taint analysis is approximate.** Some reflection, native and inheritance paths are not resolved.
- **Behavior rules can match legitimate tools** that genuinely need sensitive permissions. Every finding is shown with its reason, so you can judge it yourself.
- **v1 (JAR) signatures are read but not cryptographically verified.** Android verifies them at install time.

## Building from source

```bash
./gradlew :core:test :app:assembleDebug
```

| Module | Contents |
|---|---|
| `core/` | Scanning engine in plain Kotlin, with no Android or third-party dependencies |
| `app/` | Android app (Jetpack Compose) |
| `bench/` | Accuracy benchmark |
| `tools/` | Generator for the F-Droid signer list |

Releases are published by pushing a tag:

```bash
git tag v3.7.2 && git push origin v3.7.2
```

To sign releases with a stable key, add the repository secrets `KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS` and `KEY_PASSWORD`. Without them, each build is signed with a different debug key and cannot be installed over the previous version.

## Roadmap

- [x] Runtime network monitoring
- [x] Persistent per-app firewall
- [x] Multi-layer unpacking
- [x] Native (ARM64) emulation
- [ ] Scan apps already installed on the phone
- [ ] English user interface
- [ ] Rules updatable without a new release
- [ ] v1 signature verification

## License and credits

Released under the [MIT License](LICENSE).

- Font: IBM Plex Sans Arabic ([SIL OFL 1.1](licenses/IBM-Plex-Sans-Arabic-OFL.txt))
- Icons: Material Icons (Apache 2.0)
- TLSH: algorithm and tables ported from the Trend Micro reference implementation (Apache 2.0 / BSD)
- Threat intelligence: [MalwareBazaar](https://bazaar.abuse.ch/) by abuse.ch, and [VirusTotal](https://www.virustotal.com/). Their data is queried with the user's own keys and is not redistributed.
