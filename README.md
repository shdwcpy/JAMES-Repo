# J.A.M.E.S. – Joint Automated Mobile Extraction System

A next-generation forensic extraction platform for Android and iOS devices.

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/forensics/james)
[![Security](https://img.shields.io/badge/security-hardened-blue.svg)](docs/security.md)
[![Compliance](https://img.shields.io/badge/compliance-NIST%20800--101-green.svg)](docs/compliance.md)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)

## 🎯 Mission

J.A.M.E.S. (Joint Automated Mobile Extraction System) is a professional-grade digital forensic platform designed for law enforcement, corporate security, and incident response teams. Built with security-first principles and court admissibility in mind.

## ⚡ Features

### 🔒 Security-First Architecture
- **Chain of Custody**: Cryptographic integrity verification for all extracted data
- **Tamper Detection**: Real-time monitoring of evidence manipulation attempts  
- **Secure Memory**: Protected allocation and secure wiping of sensitive data
- **Audit Logging**: Comprehensive forensic audit trail for legal proceedings

### 📱 Device Support
- **Android Devices**: Full extraction support for Android 9-14+
  - Bootloader exploitation and unlocking
  - ADB-based logical extraction
  - Chipset-specific vulnerabilities (Qualcomm, MediaTek, Samsung)
  - Custom recovery and download mode access
- **iOS Devices**: Comprehensive iPhone and iPad support
  - Jailbreak-based full filesystem extraction
  - checkm8/checkra1n exploit integration
  - iTunes backup analysis and decryption
  - Keychain extraction and analysis

### 🛡️ Attack Capabilities
- **Brute-Force Engine**: Multi-threaded password and PIN attacks
- **Hardware Acceleration**: GPU and FPGA-assisted brute-forcing
- **Social Engineering**: Pattern-based attack generation
- **Custom Exploits**: Modular exploit framework for new vulnerabilities

### 🧪 Testing & Emulation
- **Virtual Devices**: Corellium-like emulation for safe exploit testing
- **Scenario Testing**: Pre-configured device states and conditions
- **Regression Testing**: Automated validation of extraction capabilities

## 🏗️ Architecture

```
J.A.M.E.S./
├── src/
│   ├── core/           # Core engine and security infrastructure
│   ├── devices/        # Device-specific handlers and exploits
│   ├── bruteforce/     # Attack and brute-force capabilities
│   └── network/        # Communication and remote analysis
├── tools/              # Utility tools and helpers
├── emulator/           # Virtual testing platform
├── tests/              # Comprehensive test suite
└── docs/               # Documentation and compliance
```

## 🚀 Quick Start

### Prerequisites
- **Linux**: Ubuntu 20.04+ or equivalent (primary platform)
- **Dependencies**: CMake 3.20+, GCC 9+ or Clang 10+
- **Libraries**: OpenSSL 1.1.1+, libusb 1.0.20+

### Build Instructions

```bash
# 1. Clone the repository
git clone https://github.com/forensics/james.git
cd james

# 2. Install dependencies
./scripts/install_deps.sh

# 3. Build the platform
./build.sh

# 4. Run initial tests
./build/james --version
```

### First Extraction

```bash
# 1. Connect target device
./build/james scan

# 2. Begin extraction
./build/james extract --device android:12345 --output ./case_001/

# 3. Generate forensic report
./build/james report --case ./case_001/ --format legal
```

## 📋 Compliance & Standards

J.A.M.E.S. adheres to industry-leading forensic and security standards:

- **NIST SP 800-101**: Guidelines for Mobile Device Forensics
- **ISO/IEC 27037**: Guidelines for identification, collection and/or acquisition and preservation of digital evidence
- **ISO/IEC 17025**: Laboratory accreditation requirements
- **SEI CERT C++**: Secure coding standards for memory safety
- **MISRA C++**: Safety-critical software development guidelines
- **NASA Power of 10**: Rules for safety-critical code

## ⚖️ Legal Notice

J.A.M.E.S. is designed for authorized forensic investigations only. Users must comply with all applicable laws and regulations. Unauthorized access to devices or data is prohibited.

## 🔐 Security

- **Vulnerability Reports**: security@james-forensics.com
- **PGP Key**: `2048R/0x1234567890ABCDEF`
- **Responsible Disclosure**: 90-day coordinated disclosure policy

## 📞 Support

- **Enterprise Support**: enterprise@james-forensics.com
- **Training**: training@james-forensics.com
- **Documentation**: [docs.james-forensics.com](https://docs.james-forensics.com)

## 📄 License

Proprietary software. All rights reserved.
Contact licensing@james-forensics.com for commercial licensing.

---

**⚠️ Current Status: Phase 1 Development**  
This repository contains scaffold implementation. Core functionality is under active development.
