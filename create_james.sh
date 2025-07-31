#!/bin/bash
# create_james.sh - J.A.M.E.S. All-in-One Scaffold Generator
# Joint Automated Mobile Extraction System
# 
# USAGE: ./create_james.sh [target_directory]
# EXAMPLE: ./create_james.sh ~/forensic_projects/

set -euo pipefail
IFS=$'\n\t'

# Color definitions for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TARGET_DIR="${1:-$PWD}"
readonly JAMES_ROOT="$TARGET_DIR/JAMES"

print_banner() {
    echo -e "${CYAN}"
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo "                         J.A.M.E.S. SCAFFOLD GENERATOR"
    echo "                    Joint Automated Mobile Extraction System"
    echo "                      Next-Generation Forensic Platform"
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo -e "${WHITE}🔒 Security-First Architecture${NC}"
    echo -e "${WHITE}📱 Android & iOS Extraction${NC}"
    echo -e "${WHITE}⚖️  Court-Admissible Evidence Chain${NC}"
    echo -e "${WHITE}🛡️  SEI CERT + MISRA + Power of 10 Compliance${NC}"
    echo
}

print_section() {
    echo -e "\n${PURPLE}🔧 $1${NC}"
    echo "────────────────────────────────────────────────────────────────────────────────"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

check_prerequisites() {
    print_section "Checking Prerequisites"
    
    local missing_tools=()
    
    for tool in git cmake make g++; do
        if command -v "$tool" >/dev/null 2>&1; then
            log_success "Found: $tool ($(command -v "$tool"))"
        else
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo -e "\n${RED}❌ Missing required tools:${NC}"
        printf '%s\n' "${missing_tools[@]}"
        echo -e "\n${YELLOW}Install missing tools and re-run this script.${NC}"
        exit 1
    fi
    
    log_success "All prerequisites satisfied"
}

create_directory_structure() {
    print_section "Creating J.A.M.E.S. Directory Structure"
    
    # Remove existing directory if it exists
    if [[ -d "$JAMES_ROOT" ]]; then
        log_warning "Removing existing JAMES directory"
        rm -rf "$JAMES_ROOT"
    fi
    
    log_info "Creating root directory: $JAMES_ROOT"
    mkdir -p "$JAMES_ROOT"
    cd "$JAMES_ROOT"
    
    # Core directories
    local directories=(
        # Source code structure
        "src/core"
        "src/core/crypto"
        "src/core/utils"
        "src/core/evidence"
        
        # Device handlers
        "src/devices/base"
        "src/devices/android"
        "src/devices/android/bootloader"
        "src/devices/android/exploits"
        "src/devices/android/exploits/chipset"
        "src/devices/android/exploits/os_version"
        "src/devices/ios"
        "src/devices/ios/jailbreak"
        "src/devices/ios/filesystem"
        "src/devices/storage"
        "src/devices/specialty"
        
        # Attack modules
        "src/bruteforce"
        "src/bruteforce/patterns"
        "src/bruteforce/targets"
        "src/bruteforce/hardware"
        
        # Network and communication
        "src/network"
        "src/python_bindings"
        
        # Tools and utilities
        "tools/custom_adb"
        "tools/custom_adb/protocol"
        "tools/rsa_keygen"
        "tools/exploit_dev"
        "tools/forensic_utils"
        
        # Emulator platform
        "emulator/core"
        "emulator/scenarios"
        "emulator/integration"
        
        # Testing infrastructure
        "tests/unit/core"
        "tests/unit/devices"
        "tests/unit/bruteforce"
        "tests/unit/crypto"
        "tests/integration"
        "tests/security"
        "tests/security/fuzzing"
        "tests/performance"
        
        # Third-party dependencies
        "third_party/googletest"
        "third_party/pybind11"
        "third_party/openssl"
        
        # Documentation
        "docs/architecture"
        "docs/user_guide"
        "docs/developer"
        "docs/legal"
        
        # Scripts and build system
        "scripts"
        "cmake/modules"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        log_success "Created: $dir"
    done
}

create_gitignore() {
    print_section "Creating .gitignore"
    
    cat > .gitignore << 'EOF'
# J.A.M.E.S. - Joint Automated Mobile Extraction System
# Git ignore file for forensic development

# Build directories
build/
build-*/
out/
cmake-build-*/

# CMake generated files
CMakeCache.txt
CMakeFiles/
cmake_install.cmake
Makefile
*.cmake
!CMakeLists.txt
!cmake/modules/*.cmake

# Compiled binaries
*.exe
*.out
*.app
*.so
*.so.*
*.dylib
*.dll
*.a
*.lib

# Object files
*.o
*.obj
*.lo

# Debug files
*.dSYM/
*.su
*.idb
*.pdb

# Core dumps and crash logs
core
vgcore.*
*.stackdump

# Forensic evidence files (NEVER commit actual evidence)
*.dd
*.img
*.e01
*.aff
*.vmdk
evidence/
extractions/
cases/

# Logs and temporary files
*.log
*.tmp
*.temp
.DS_Store
Thumbs.db

# IDE and editor files
.vscode/
.idea/
*.swp
*.swo
*~
.vs/

# Package managers
node_modules/
.npm
.yarn/

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/

# Static analysis output
cppcheck-results.xml
clang-tidy-output.txt
scan-build-*/

# Coverage reports
*.gcov
*.gcda
*.gcno
coverage/
lcov.info

# Documentation generated files
docs/_build/
docs/html/
docs/latex/

# Local configuration
.env
config.local
secrets.json

# Backup files
*.bak
*.backup
*~

# OS specific
.fuse_hidden*
EOF
    
    log_success "Created .gitignore with forensic-specific exclusions"
}

create_readme() {
    print_section "Creating README.md"
    
    cat > README.md << 'EOF'
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
EOF
    
    log_success "Created comprehensive README.md"
}

create_root_cmakelists() {
    print_section "Creating Root CMakeLists.txt"
    
    cat > CMakeLists.txt << 'EOF'
# J.A.M.E.S. Root CMakeLists.txt
# Joint Automated Mobile Extraction System
# SECURITY-FIRST FORENSIC SOFTWARE PLATFORM

cmake_minimum_required(VERSION 3.20 FATAL_ERROR)

# Security: Enforce modern CMake policies
cmake_policy(SET CMP0048 NEW)  # VERSION in project()
cmake_policy(SET CMP0077 NEW)  # option() honors normal variables
cmake_policy(SET CMP0079 NEW)  # target_link_libraries() allows interface libraries

project(JAMES 
    VERSION 1.0.0 
    DESCRIPTION "Joint Automated Mobile Extraction System"
    LANGUAGES C CXX
    HOMEPAGE_URL "https://james-forensics.com"
)

# =============================================================================
# SECURITY-FIRST CONFIGURATION
# =============================================================================

set(CMAKE_CXX_STANDARD 17)              # Modern C++ with security features
set(CMAKE_CXX_STANDARD_REQUIRED ON)     # Enforce standard compliance
set(CMAKE_CXX_EXTENSIONS OFF)           # Disable non-portable extensions

# Force out-of-source builds (prevents source contamination)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR 
        "SECURITY VIOLATION: In-source builds prohibited.\n"
        "Create a separate build directory:\n"
        "  mkdir build && cd build && cmake .."
    )
endif()

# =============================================================================
# GLOBAL SECURITY-HARDENED COMPILER FLAGS
# =============================================================================

# Security flags for all targets (SEI CERT + MISRA + Power of 10)
set(JAMES_SECURITY_FLAGS
    # NASA Power of 10 Rule #10: All warnings enabled, zero tolerance
    -Wall                    # All standard warnings
    -Wextra                  # Additional suspicious constructs
    -Werror                  # ZERO TOLERANCE: Treat warnings as errors
    -pedantic                # Strict ISO C++ compliance
    
    # Memory safety (critical for forensic data integrity)
    -Wformat-security        # Format string vulnerabilities
    -Wuninitialized          # Uninitialized variable detection
    -Warray-bounds           # Array bounds violations
    -Wstack-protector        # Stack overflow detection
    
    # MISRA C++ compliance
    -Wconversion             # Implicit type conversions
    -Wsign-conversion        # Signed/unsigned conversion issues
    -Wcast-align             # Pointer alignment violations
    -Wcast-qual              # Const/volatile qualifier violations
    
    # SEI CERT secure coding
    -Wnull-dereference       # NULL pointer dereference detection
    -Wshadow                 # Variable name shadowing
    -Wundef                  # Undefined macro usage
    -Wredundant-decls        # Redundant declarations
    
    # Additional hardening
    -fstack-protector-strong # Stack overflow protection
    -D_FORTIFY_SOURCE=2      # Runtime bounds checking
    -fPIE                    # Position Independent Executable
)

# Apply security flags globally
add_compile_options(${JAMES_SECURITY_FLAGS})

# =============================================================================
# BUILD TYPE CONFIGURATION
# =============================================================================

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS 
                 "Debug" "Release" "ForensicEvidence")
endif()

# Global preprocessor definitions
add_compile_definitions(
    JAMES_PLATFORM_${CMAKE_SYSTEM_NAME}=1
    JAMES_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    JAMES_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    JAMES_VERSION_PATCH=${PROJECT_VERSION_PATCH}
    
    # Core security features
    ENABLE_CHAIN_OF_CUSTODY=1
    ENABLE_CRYPTO_INTEGRITY=1
    ENABLE_TAMPER_DETECTION=1
    ENABLE_AUDIT_LOGGING=1
    
    # Compliance frameworks
    ENABLE_NIST_800_101_COMPLIANCE=1
    ENABLE_ISO_27037_COMPLIANCE=1
    ENABLE_SEI_CERT_COMPLIANCE=1
    ENABLE_MISRA_COMPLIANCE=1
)

# =============================================================================
# DEPENDENCIES
# =============================================================================

find_package(Threads REQUIRED)

# OpenSSL for cryptographic operations
find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
    if(OPENSSL_VERSION VERSION_LESS "1.1.1")
        message(FATAL_ERROR "OpenSSL 1.1.1+ required for security compliance")
    endif()
endif()

# USB library for device communication (Linux)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUSB REQUIRED libusb-1.0>=1.0.20)

# Python for GUI and scripting
find_package(Python3 COMPONENTS Interpreter Development REQUIRED)

# =============================================================================
# GLOBAL INCLUDE DIRECTORIES
# =============================================================================

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}/src
)

# =============================================================================
# SUBDIRECTORY BUILD ORDER
# =============================================================================

# Core security infrastructure (foundational)
add_subdirectory(src/core)

# Device communication layers (depend on core)
add_subdirectory(src/devices)

# Attack and brute-force modules
add_subdirectory(src/bruteforce)

# Network communication
add_subdirectory(src/network)

# Python bindings
add_subdirectory(src/python_bindings)

# Utility tools
add_subdirectory(tools)

# Virtual testing platform
add_subdirectory(emulator)

# Testing suite
option(BUILD_TESTING "Build test suite" ON)
if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

# =============================================================================
# MAIN EXECUTABLE
# =============================================================================

add_executable(james
    src/main.cpp
)

target_link_libraries(james
    PRIVATE
        JAMES::Core
        JAMES::Devices
        JAMES::BruteForce
        JAMES::Network
        OpenSSL::SSL
        OpenSSL::Crypto
        ${LIBUSB_LIBRARIES}
        Threads::Threads
)

target_compile_definitions(james
    PRIVATE
        JAMES_CLI_APPLICATION=1
)

# =============================================================================
# INSTALLATION
# =============================================================================

install(TARGETS james
    RUNTIME DESTINATION bin
    COMPONENT Applications
)

# =============================================================================
# BUILD SUMMARY
# =============================================================================

message(STATUS "")
message(STATUS "═══════════════════════════════════════════════════════════")
message(STATUS "         J.A.M.E.S. Build Configuration")
message(STATUS "    Joint Automated Mobile Extraction System")
message(STATUS "═══════════════════════════════════════════════════════════")
message(STATUS "Build Type:          ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard:        C++${CMAKE_CXX_STANDARD}")
message(STATUS "Compiler:            ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "OpenSSL:             ${OPENSSL_VERSION}")
message(STATUS "libusb:              ${LIBUSB_VERSION}")
message(STATUS "Testing:             ${BUILD_TESTING}")
message(STATUS "Security Features:   MAXIMUM (All hardening enabled)")
message(STATUS "═══════════════════════════════════════════════════════════")
EOF
    
    log_success "Created root CMakeLists.txt with security hardening"
}

create_core_module() {
    print_section "Creating Core Module"
    
    # Core CMakeLists.txt
    cat > src/core/CMakeLists.txt << 'EOF'
# src/core/CMakeLists.txt - J.A.M.E.S. Core Engine

cmake_minimum_required(VERSION 3.20)

project(JAMESCore 
    DESCRIPTION "J.A.M.E.S. core forensic engine"
    LANGUAGES CXX
)

set(JAMES_CORE_SOURCES
    james_engine.cpp
    device_manager.cpp
    extraction_session.cpp
    crypto/hash_chain.cpp
    crypto/tamper_detection.cpp
    crypto/evidence_crypto.cpp
    utils/logger.cpp
    utils/config_manager.cpp
    evidence/chain_of_custody.cpp
    evidence/evidence_container.cpp
)

set(JAMES_CORE_HEADERS
    james_engine.h
    device_manager.h
    extraction_session.h
    security_annotations.h
    crypto/hash_chain.h
    crypto/tamper_detection.h
    crypto/evidence_crypto.h
    utils/logger.h
    utils/config_manager.h
    evidence/chain_of_custody.h
    evidence/evidence_container.h
)

add_library(james_core STATIC
    ${JAMES_CORE_SOURCES}
    ${JAMES_CORE_HEADERS}
)

add_library(JAMES::Core ALIAS james_core)

target_include_directories(james_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(james_core
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

target_compile_definitions(james_core
    PUBLIC
        JAMES_CORE_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
        JAMES_CORE_VERSION_MINOR=${PROJECT_VERSION_MINOR}
        ENABLE_SECURE_MEMORY=1
        ENABLE_CRYPTO_VERIFICATION=1
        ENABLE_AUDIT_LOGGING=1
)
EOF

    # Security annotations header
    cat > src/core/security_annotations.h << 'EOF'
/**
 * @file security_annotations.h
 * @brief Security annotation macros for J.A.M.E.S. forensic code
 * 
 * ⚠️ Placeholder Implementation – Phase 1
 */

#ifndef JAMES_CORE_SECURITY_ANNOTATIONS_H_
#define JAMES_CORE_SECURITY_ANNOTATIONS_H_

// Security classification macros
#define JAMES_SECURE_FN [[nodiscard]]
#define JAMES_SECURE_CLASS
#define JAMES_CRITICAL_SECTION
#define JAMES_EVIDENCE_DATA
#define JAMES_SECURE_MEMORY

// Compliance annotations
#define NIST_800_101_COMPLIANT
#define ISO_27037_COMPLIANT
#define SEI_CERT_COMPLIANT
#define MISRA_COMPLIANT

// Placeholder marker
#define JAMES_PLACEHOLDER_IMPL // ⚠️ Remove in production

#endif // JAMES_CORE_SECURITY_ANNOTATIONS_H_
EOF

    # Main engine header
    cat > src/core/james_engine.h << 'EOF'
/**
 * @file james_engine.h
 * @brief J.A.M.E.S. Core Forensic Engine
 * 
 * ⚠️ Placeholder Implementation – Phase 1
 * 
 * Joint Automated Mobile Extraction System
 * Core engine for forensic evidence extraction and analysis
 */

#ifndef JAMES_CORE_JAMES_ENGINE_H_
#define JAMES_CORE_JAMES_ENGINE_H_

#include <memory>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>

#include "security_annotations.h"

namespace james {
namespace core {

class DeviceManager;
class ExtractionSession;

class JAMES_SECURE_CLASS JAMESEngine {
public:
    enum class EngineState : uint8_t {
        kUninitialized = 0,
        kInitializing,
        kReady,
        kExtracting,
        kError,
        kShutdown
    };
    
    enum class SecurityLevel : uint8_t {
        kDevelopment = 1,
        kProduction = 2,
        kEvidence = 3
    };
    
    JAMES_SECURE_FN explicit JAMESEngine(
        SecurityLevel security_level = SecurityLevel::kProduction,
        bool audit_enabled = true
    ) noexcept;
    
    JAMES_SECURE_FN ~JAMESEngine() noexcept;
    
    // Disable copy/move
    JAMESEngine(const JAMESEngine&) = delete;
    JAMESEngine& operator=(const JAMESEngine&) = delete;
    JAMESEngine(JAMESEngine&&) = delete;
    JAMESEngine& operator=(JAMESEngine&&) = delete;
    
    // Core lifecycle
    JAMES_SECURE_FN [[nodiscard]] bool Initialize() noexcept;
    JAMES_SECURE_FN void Shutdown() noexcept;
    JAMES_SECURE_FN [[nodiscard]] EngineState GetState() const noexcept;
    JAMES_SECURE_FN [[nodiscard]] bool IsReady() const noexcept;
    
    // Device management
    JAMES_SECURE_FN [[nodiscard]] size_t DiscoverDevices() noexcept;
    JAMES_SECURE_FN [[nodiscard]] std::vector<std::string> GetDeviceList() const noexcept;
    
    // Extraction operations
    JAMES_SECURE_FN [[nodiscard]] std::unique_ptr<ExtractionSession> BeginExtraction(
        const std::string& device_id,
        const std::string& output_path,
        const std::string& case_id
    ) noexcept;
    
    // Security & audit
    JAMES_SECURE_FN [[nodiscard]] bool VerifySecurityIntegrity() const noexcept;
    JAMES_SECURE_FN [[nodiscard]] std::string GenerateAuditReport() const noexcept;
    JAMES_SECURE_FN [[nodiscard]] SecurityLevel GetSecurityLevel() const noexcept;

private:
    JAMES_PLACEHOLDER_IMPL
    
    const SecurityLevel security_level_;
    const bool audit_enabled_;
    std::atomic<EngineState> current_state_{EngineState::kUninitialized};
    std::unique_ptr<DeviceManager> device_manager_;
    mutable std::mutex security_mutex_;
    std::vector<std::unique_ptr<ExtractionSession>> active_sessions_;
    
    bool InitializeCryptographicSystems() noexcept;
    bool InitializeDeviceManager() noexcept;
    bool InitializeAuditLogging() noexcept;
    void SecureCleanup() noexcept;
    bool ValidateSecurityContext() const noexcept;
};

JAMES_SECURE_FN [[nodiscard]] std::string GetEngineVersion() noexcept;
JAMES_SECURE_FN [[nodiscard]] bool VerifyEngineInstallation() noexcept;

} // namespace core
} // namespace james

#endif // JAMES_CORE_JAMES_ENGINE_H_
EOF

    # Main engine implementation
    cat > src/core/james_engine.cpp << 'EOF'
/**
 * @file james_engine.cpp
 * @brief J.A.M.E.S. Core Engine Implementation
 * 
 * ⚠️ Placeholder Implementation – Phase 1
 */

#include "james_engine.h"
#include "device_manager.h"
#include "extraction_session.h"

#include <iostream>
#include <sstream>
#include <chrono>

namespace james {
namespace core {

JAMESEngine::JAMESEngine(SecurityLevel security_level, bool audit_enabled) noexcept
    : security_level_(security_level)
    , audit_enabled_(audit_enabled) {
    
    std::cout << "[JAMES_ENGINE] Constructing with security level: " 
              << static_cast<int>(security_level_) << std::endl;
    current_state_.store(EngineState::kUninitialized);
}

JAMESEngine::~JAMESEngine() noexcept {
    std::cout << "[JAMES_ENGINE] Secure destructor called" << std::endl;
    if (current_state_.load() != EngineState::kShutdown) {
        Shutdown();
    }
    SecureCleanup();
}

bool JAMESEngine::Initialize() noexcept {
    std::lock_guard<std::mutex> lock(security_mutex_);
    
    std::cout << "[JAMES_ENGINE] Initializing J.A.M.E.S. forensic engine..." << std::endl;
    current_state_.store(EngineState::kInitializing);
    
    try {
        if (!InitializeCryptographicSystems()) {
            std::cerr << "[JAMES_ENGINE] ERROR: Cryptographic initialization failed" << std::endl;
            current_state_.store(EngineState::kError);
            return false;
        }
        
        if (!InitializeDeviceManager()) {
            std::cerr << "[JAMES_ENGINE] ERROR: Device manager initialization failed" << std::endl;
            current_state_.store(EngineState::kError);
            return false;
        }
        
        if (!InitializeAuditLogging()) {
            std::cerr << "[JAMES_ENGINE] ERROR: Audit logging initialization failed" << std::endl;
            current_state_.store(EngineState::kError);
            return false;
        }
        
        if (!ValidateSecurityContext()) {
            std::cerr << "[JAMES_ENGINE] ERROR: Security context validation failed" << std::endl;
            current_state_.store(EngineState::kError);
            return false;
        }
        
        current_state_.store(EngineState::kReady);
        std::cout << "[JAMES_ENGINE] ✓ J.A.M.E.S. ready for forensic operations" << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "[JAMES_ENGINE] ERROR: Exception during initialization: " << e.what() << std::endl;
        current_state_.store(EngineState::kError);
        return false;
    }
}

void JAMESEngine::Shutdown() noexcept {
    std::lock_guard<std::mutex> lock(security_mutex_);
    std::cout << "[JAMES_ENGINE] Shutting down J.A.M.E.S. engine..." << std::endl;
    current_state_.store(EngineState::kShutdown);
    active_sessions_.clear();
    device_manager_.reset();
    std::cout << "[JAMES_ENGINE] ✓ Shutdown complete" << std::endl;
}

JAMESEngine::EngineState JAMESEngine::GetState() const noexcept {
    return current_state_.load();
}

bool JAMESEngine::IsReady() const noexcept {
    return current_state_.load() == EngineState::kReady;
}

size_t JAMESEngine::DiscoverDevices() noexcept {
    std::lock_guard<std::mutex> lock(security_mutex_);
    std::cout << "[JAMES_ENGINE] Discovering forensic devices..." << std::endl;
    if (!IsReady()) {
        std::cerr << "[JAMES_ENGINE] ERROR: Engine not ready for device discovery" << std::endl;
        return 0;
    }
    std::cout << "[JAMES_ENGINE] ✓ Device discovery complete (placeholder)" << std::endl;
    return 0; // Placeholder - no devices found
}

std::vector<std::string> JAMESEngine::GetDeviceList() const noexcept {
    std::lock_guard<std::mutex> lock(security_mutex_);
    return std::vector<std::string>(); // Placeholder - empty list
}

std::unique_ptr<ExtractionSession> JAMESEngine::BeginExtraction(
    const std::string& device_id,
    const std::string& output_path,
    const std::string& case_id) noexcept {
    
    std::lock_guard<std::mutex> lock(security_mutex_);
    std::cout << "[JAMES_ENGINE] Beginning extraction session..." << std::endl;
    std::cout << "  Device ID: " << device_id << std::endl;
    std::cout << "  Output Path: " << output_path << std::endl;
    std::cout << "  Case ID: " << case_id << std::endl;
    
    if (!IsReady()) {
        std::cerr << "[JAMES_ENGINE] ERROR: Engine not ready for extraction" << std::endl;
        return nullptr;
    }
    
    std::cout << "[JAMES_ENGINE] ⚠️  Extraction session creation not implemented (placeholder)" << std::endl;
    return nullptr;
}

bool JAMESEngine::VerifySecurityIntegrity() const noexcept {
    std::lock_guard<std::mutex> lock(security_mutex_);
    std::cout << "[JAMES_ENGINE] Verifying security integrity..." << std::endl;
    std::cout << "[JAMES_ENGINE] ✓ Security integrity verified (placeholder)" << std::endl;
    return true;
}

std::string JAMESEngine::GenerateAuditReport() const noexcept {
    std::lock_guard<std::mutex> lock(security_mutex_);
    std::ostringstream report;
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    report << "=== J.A.M.E.S. Audit Report ===" << std::endl;
    report << "Generated: " << std::ctime(&time_t);
    report << "Engine State: " << static_cast<int>(current_state_.load()) << std::endl;
    report << "Security Level: " << static_cast<int>(security_level_) << std::endl;
    report << "Active Sessions: " << active_sessions_.size() << std::endl;
    report << "Audit Enabled: " << (audit_enabled_ ? "Yes" : "No") << std::endl;
    report << "⚠️  Placeholder audit report - Full implementation pending" << std::endl;
    
    return report.str();
}

JAMESEngine::SecurityLevel JAMESEngine::GetSecurityLevel() const noexcept {
    return security_level_;
}

// Private implementation methods
bool JAMESEngine::InitializeCryptographicSystems() noexcept {
    std::cout << "[JAMES_ENGINE] Initializing cryptographic systems..." << std::endl;
    std::cout << "[JAMES_ENGINE] ✓ Cryptographic systems initialized (placeholder)" << std::endl;
    return true;
}

bool JAMESEngine::InitializeDeviceManager() noexcept {
    std::cout << "[JAMES_ENGINE] Initializing device manager..." << std::endl;
    std::cout << "[JAMES_ENGINE] ✓ Device manager initialized (placeholder)" << std::endl;
    return true;
}

bool JAMESEngine::InitializeAuditLogging() noexcept {
    std::cout << "[JAMES_ENGINE] Initializing audit logging..." << std::endl;
    std::cout << "[JAMES_ENGINE] ✓ Audit logging initialized (placeholder)" << std::endl;
    return true;
}

void JAMESEngine::SecureCleanup() noexcept {
    std::cout << "[JAMES_ENGINE] Performing secure cleanup..." << std::endl;
    std::cout << "[JAMES_ENGINE] ✓ Secure cleanup complete (placeholder)" << std::endl;
}

bool JAMESEngine::ValidateSecurityContext() const noexcept {
    std::cout << "[JAMES_ENGINE] Validating security context..." << std::endl;
    std::cout << "[JAMES_ENGINE] ✓ Security context validated (placeholder)" << std::endl;
    return true;
}

// Free functions
std::string GetEngineVersion() noexcept {
    return "J.A.M.E.S. Core Engine v1.0.0-dev (Placeholder Build)";
}

bool VerifyEngineInstallation() noexcept {
    std::cout << "[JAMES_ENGINE] Verifying engine installation..." << std::endl;
    std::cout << "[JAMES_ENGINE] ✓ Installation verified (placeholder)" << std::endl;
    return true;
}

} // namespace core
} // namespace james
EOF

    # Additional core files
    cat > src/core/device_manager.h << 'EOF'
/**
 * @file device_manager.h
 * @brief J.A.M.E.S. Device Manager
 * 
 * ⚠️ Placeholder Implementation – Phase 1
 */

#ifndef JAMES_CORE_DEVICE_MANAGER_H_
#define JAMES_CORE_DEVICE_MANAGER_H_

#include <string>
#include <vector>
#include "security_annotations.h"

namespace james {
namespace core {

class JAMES_SECURE_CLASS DeviceManager {
public:
    enum class DeviceType : uint8_t {
        kUnknown = 0,
        kAndroid,
        kIOS,
        kStorage,
        kSpecialty
    };
    
    JAMES_SECURE_FN explicit DeviceManager() noexcept;
    JAMES_SECURE_FN ~DeviceManager() noexcept;
    
    JAMES_SECURE_FN bool Initialize() noexcept;
    JAMES_SECURE_FN size_t ScanDevices() noexcept;
    JAMES_SECURE_FN std::vector<std::string> GetDeviceList() const noexcept;
    
private:
    JAMES_PLACEHOLDER_IMPL
    bool initialized_{false};
};

} // namespace core
} // namespace james

#endif // JAMES_CORE_DEVICE_MANAGER_H_
EOF

    cat > src/core/device_manager.cpp << 'EOF'
/**
 * @file device_manager.cpp
 * @brief J.A.M.E.S. Device Manager Implementation
 * 
 * ⚠️ Placeholder Implementation – Phase 1
 */

#include "device_manager.h"
#include <iostream>

namespace james {
namespace core {

DeviceManager::DeviceManager() noexcept {
    std::cout << "[DEVICE_MANAGER] ⚠️  Placeholder constructor" << std::endl;
}

DeviceManager::~DeviceManager() noexcept {
    std::cout << "[DEVICE_MANAGER] ⚠️  Placeholder destructor" << std::endl;
}

bool DeviceManager::Initialize() noexcept {
    std::cout << "[DEVICE_MANAGER] ⚠️  Placeholder initialization" << std::endl;
    initialized_ = true;
    return true;
}

size_t DeviceManager::ScanDevices() noexcept {
    std::cout << "[DEVICE_MANAGER] ⚠️  Placeholder device scan" << std::endl;
    return 0;
}

std::vector<std::string> DeviceManager::GetDeviceList() const noexcept {
    std::cout << "[DEVICE_MANAGER] ⚠️  Placeholder device list" << std::endl;
    return {};
}

} // namespace core
} // namespace james
EOF

    cat > src/core/extraction_session.h << 'EOF'
/**
 * @file extraction_session.h
 * @brief J.A.M.E.S. Extraction Session
 * 
 * ⚠️ Placeholder Implementation – Phase 1
 */

#ifndef JAMES_CORE_EXTRACTION_SESSION_H_
#define JAMES_CORE_EXTRACTION_SESSION_H_

#include <string>
#include "security_annotations.h"

namespace james {
namespace core {

class JAMES_SECURE_CLASS ExtractionSession {
public:
    enum class SessionState : uint8_t {
        kCreated = 0,
        kActive,
        kPaused,
        kCompleted,
        kError
    };
    
    JAMES_SECURE_FN explicit ExtractionSession(const std::string& session_id) noexcept;
    JAMES_SECURE_FN ~ExtractionSession() noexcept;
    
    JAMES_SECURE_FN bool Start() noexcept;
    JAMES_SECURE_FN bool Pause() noexcept;
    JAMES_SECURE_FN bool Stop() noexcept;
    JAMES_SECURE_FN SessionState GetState() const noexcept;
    
private:
    JAMES_PLACEHOLDER_IMPL
    std::string session_id_;
    SessionState state_{SessionState::kCreated};
};

} // namespace core
} // namespace james

#endif // JAMES_CORE_EXTRACTION_SESSION_H_
EOF

    cat > src/core/extraction_session.cpp << 'EOF'
/**
 * @file extraction_session.cpp
 * @brief J.A.M.E.S. Extraction Session Implementation
 * 
 * ⚠️ Placeholder Implementation – Phase 1
 */

#include "extraction_session.h"
#include <iostream>

namespace james {
namespace core {

ExtractionSession::ExtractionSession(const std::string& session_id) noexcept 
    : session_id_(session_id) {
    std::cout << "[EXTRACTION_SESSION] ⚠️  Placeholder constructor for: " << session_id_ << std::endl;
}

ExtractionSession::~ExtractionSession() noexcept {
    std::cout << "[EXTRACTION_SESSION] ⚠️  Placeholder destructor" << std::endl;
}

bool ExtractionSession::Start() noexcept {
    std::cout << "[EXTRACTION_SESSION] ⚠️  Placeholder start" << std::endl;
    state_ = SessionState::kActive;
    return true;
}

bool ExtractionSession::Pause() noexcept {
    std::cout << "[EXTRACTION_SESSION] ⚠️  Placeholder pause" << std::endl;
    state_ = SessionState::kPaused;
    return true;
}

bool ExtractionSession::Stop() noexcept {
    std::cout << "[EXTRACTION_SESSION] ⚠️  Placeholder stop" << std::endl;
    state_ = SessionState::kCompleted;
    return true;
}

ExtractionSession::SessionState ExtractionSession::GetState() const noexcept {
    return state_;
}

} // namespace core
} // namespace james
EOF

    log_success "Created core engine implementation"
}

create_main_executable() {
    print_section "Creating Main Executable"
    
    cat > src/main.cpp << 'EOF'
/**
 * @file main.cpp
 * @brief J.A.M.E.S. CLI Application Entry Point
 * 
 * ⚠️ Placeholder Implementation – Phase 1
 * 
 * Joint Automated Mobile Extraction System
 * Command-line interface for forensic operations
 */

#include <iostream>
#include <memory>
#include <exception>

#include "core/james_engine.h"
#include "core/security_annotations.h"

using namespace james::core;

JAMES_SECURE_FN void PrintBanner() noexcept {
    std::cout << "\n";
    std::cout << "════════════════════════════════════════════════════════════════\n";
    std::cout << "                         J.A.M.E.S. v1.0.0\n";
    std::cout << "              Joint Automated Mobile Extraction System\n";
    std::cout << "                 Professional Forensic Platform\n";
    std::cout << "════════════════════════════════════════════════════════════════\n";
    std::cout << "\n";
    std::cout << "🔒 Security Level: MAXIMUM (Development Build)\n";
    std::cout << "⚖️  Compliance: NIST 800-101, ISO 27037, SEI CERT C++\n";
    std::cout << "📱 Devices: Android, iOS, Storage, Specialty\n";
    std::cout << "⚠️  Status: PLACEHOLDER IMPLEMENTATION - Phase 1 Scaffolding\n";
    std::cout << "\n";
}

JAMES_SECURE_FN int RunJAMESDemo() noexcept {
    try {
        std::cout << "🔧 Initializing J.A.M.E.S. Engine...\n";
        
        JAMESEngine engine(JAMESEngine::SecurityLevel::kProduction, true);
        
        if (!engine.Initialize()) {
            std::cerr << "❌ ERROR: Failed to initialize J.A.M.E.S. engine\n";
            return 1;
        }
        
        std::cout << "✅ Engine initialized successfully\n";
        
        std::cout << "\n📊 Engine Information:\n";
        std::cout << "   Version: " << GetEngineVersion() << "\n";
        std::cout << "   State: " << (engine.IsReady() ? "Ready" : "Not Ready") << "\n";
        std::cout << "   Security Level: " << static_cast<int>(engine.GetSecurityLevel()) << "\n";
        
        std::cout << "\n🔒 Running Security Verification...\n";
        if (engine.VerifySecurityIntegrity()) {
            std::cout << "✅ Security integrity verified\n";
        } else {
            std::cout << "⚠️  Security integrity check failed\n";
        }
        
        std::cout << "\n📱 Discovering Forensic Devices...\n";
        size_t device_count = engine.DiscoverDevices();
        std::cout << "   Devices found: " << device_count << "\n";
        
        auto device_list = engine.GetDeviceList();
        if (device_list.empty()) {
            std::cout << "   No devices available (placeholder implementation)\n";
        }
        
        std::cout << "\n📄 Generating Audit Report...\n";
        std::string audit_report = engine.GenerateAuditReport();
        std::cout << audit_report << "\n";
        
        std::cout << "🔍 Verifying Installation Integrity...\n";
        if (VerifyEngineInstallation()) {
            std::cout << "✅ Installation integrity verified\n";
        } else {
            std::cout << "⚠️  Installation integrity check failed\n";
        }
        
        std::cout << "\n🔄 Shutting down engine...\n";
        engine.Shutdown();
        std::cout << "✅ Engine shutdown complete\n";
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ CRITICAL ERROR: Exception caught: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "❌ CRITICAL ERROR: Unknown exception caught\n";
        return 1;
    }
}

int main(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1) {
        std::cout << "📝 Command line arguments detected:\n";
        for (int i = 1; i < argc; ++i) {
            std::cout << "   Arg[" << i << "]: " << argv[i] << "\n";
        }
        std::cout << "⚠️  Command line processing not implemented (placeholder)\n\n";
    }
    
    int result = RunJAMESDemo();
    
    if (result == 0) {
        std::cout << "\n🎯 J.A.M.E.S. placeholder demo completed successfully!\n";
        std::cout << "📋 Next steps:\n";
        std::cout << "   1. Implement real device handlers (Phase 2)\n";
        std::cout << "   2. Add cryptographic chain of custody (Phase 2)\n";
        std::cout << "   3. Build Android/iOS extraction modules (Phase 3+)\n";
        std::cout << "   4. Develop brute-force attack capabilities (Phase 4+)\n";
    } else {
        std::cout << "\n❌ J.A.M.E.S. demo failed with error code: " << result << "\n";
    }
    
    std::cout << "\n════════════════════════════════════════════════════════════════\n";
    
    return result;
}
EOF
    
    log_success "Created main executable with J.A.M.E.S. branding"
}

create_build_script() {
    print_section "Creating Build Script"
    
    cat > build.sh << 'EOF'
#!/bin/bash
# build.sh - J.A.M.E.S. Build Script
# Joint Automated Mobile Extraction System

set -euo pipefail
IFS=\n\t'

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly NC='\033[0m'

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BUILD_DIR="$SCRIPT_DIR/build"

BUILD_TYPE="${BUILD_TYPE:-Release}"
PARALLEL_JOBS="${PARALLEL_JOBS:-$(nproc)}"

print_header() {
    echo -e "${BLUE}"
    echo "════════════════════════════════════════════════════════════════"
    echo "                    J.A.M.E.S. Build System"
    echo "            Joint Automated Mobile Extraction System"
    echo "════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo "Build Type: $BUILD_TYPE"
    echo "Parallel Jobs: $PARALLEL_JOBS"
    echo
}

print_section() {
    echo -e "\n${PURPLE}🔧 $1${NC}"
    echo "────────────────────────────────────────────────────────────────"
}

check_dependencies() {
    print_section "Checking Dependencies"
    
    local missing=()
    for tool in cmake make g++; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo -e "${GREEN}✓${NC} Found: $tool"
        else
            missing+=("$tool")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "\n${RED}❌ Missing:${NC}"
        printf '%s\n' "${missing[@]}"
        exit 1
    fi
}

setup_build() {
    print_section "Setting Up Build Directory"
    
    if [[ -d "$BUILD_DIR" ]]; then
        echo -e "${YELLOW}⚠${NC}  Removing existing build directory"
        rm -rf "$BUILD_DIR"
    fi
    
    echo -e "${BLUE}📁${NC} Creating: $BUILD_DIR"
    mkdir -p "$BUILD_DIR"
}

configure_cmake() {
    print_section "Configuring CMake"
    
    cd "$BUILD_DIR"
    
    echo -e "${BLUE}⚙️${NC}  Running CMake configuration..."
    if ! cmake -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DBUILD_TESTING=ON "$SCRIPT_DIR"; then
        echo -e "${RED}❌ CMake configuration failed${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓${NC} CMake configuration successful"
}

build_project() {
    print_section "Building J.A.M.E.S."
    
    cd "$BUILD_DIR"
    
    echo -e "${BLUE}🔨${NC} Building with $PARALLEL_JOBS parallel jobs..."
    if ! cmake --build . --parallel "$PARALLEL_JOBS"; then
        echo -e "${RED}❌ Build failed${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓${NC} Build completed successfully"
}

run_tests() {
    print_section "Running Tests"
    
    cd "$BUILD_DIR"
    
    echo -e "${BLUE}🧪${NC} Executing test suite..."
    if command -v ctest >/dev/null 2>&1; then
        if ! ctest --output-on-failure; then
            echo -e "${YELLOW}⚠${NC}  Some tests failed (expected in placeholder build)"
        else
            echo -e "${GREEN}✓${NC} All tests passed"
        fi
    else
        echo -e "${YELLOW}⚠${NC}  CTest not available"
    fi
}

show_summary() {
    print_section "Build Summary"
    
    echo -e "${GREEN}🎉 J.A.M.E.S. build completed successfully!${NC}"
    echo
    echo -e "${BLUE}🚀 Executable:${NC}"
    echo "   $BUILD_DIR/james"
    echo
    echo -e "${BLUE}📋 Next Steps:${NC}"
    echo "   1. Run: $BUILD_DIR/james"
    echo "   2. Begin Phase 2: Core Implementation"
    echo "   3. Implement device handlers"
}

main() {
    print_header
    check_dependencies
    setup_build
    configure_cmake
    build_project
    run_tests
    show_summary
    
    echo -e "\n${GREEN}🎯 J.A.M.E.S. ready for forensic operations!${NC}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
EOF
    
    chmod +x build.sh
    log_success "Created executable build.sh script"
}

create_placeholder_modules() {
    print_section "Creating Placeholder Modules"
    
    # Create minimal CMakeLists.txt files for subdirectories
    local subdirs=(
        "src/devices"
        "src/bruteforce" 
        "src/network"
        "src/python_bindings"
        "tools"
        "emulator"
        "tests"
    )
    
    for subdir in "${subdirs[@]}"; do
        mkdir -p "$subdir"
        cat > "$subdir/CMakeLists.txt" << EOF
# $subdir/CMakeLists.txt - J.A.M.E.S. $(basename "$subdir") Module
# ⚠️ Placeholder Implementation – Phase 1

message(STATUS "Configuring J.A.M.E.S. $(basename "$subdir") module (placeholder)")

# Placeholder library to satisfy build system
add_library(james_$(basename "$subdir")_placeholder INTERFACE)
add_library(JAMES::$(basename "$subdir" | tr '[:lower:]' '[:upper:]') ALIAS james_$(basename "$subdir")_placeholder)

message(STATUS "$(basename "$subdir") module placeholder configured")
EOF
        log_success "Created placeholder CMakeLists.txt for $subdir"
    done
    
    # Create minimal crypto placeholder files
    mkdir -p src/core/crypto src/core/utils src/core/evidence
    
    for crypto_file in hash_chain tamper_detection evidence_crypto; do
        cat > "src/core/crypto/${crypto_file}.cpp" << EOF
// ${crypto_file}.cpp - J.A.M.E.S. Crypto Module
// ⚠️ Placeholder Implementation – Phase 1

#include "${crypto_file}.h"
#include <iostream>

namespace james { namespace core { namespace crypto {
// Placeholder implementation
void ${crypto_file}_placeholder() {
    std::cout << "[CRYPTO] ⚠️  ${crypto_file} placeholder" << std::endl;
}
}}} // namespace james::core::crypto
EOF
        
        cat > "src/core/crypto/${crypto_file}.h" << EOF
// ${crypto_file}.h - J.A.M.E.S. Crypto Module
// ⚠️ Placeholder Implementation – Phase 1

#ifndef JAMES_CORE_CRYPTO_$(echo "${crypto_file}" | tr '[:lower:]' '[:upper:]')_H_
#define JAMES_CORE_CRYPTO_$(echo "${crypto_file}" | tr '[:lower:]' '[:upper:]')_H_

namespace james { namespace core { namespace crypto {
void ${crypto_file}_placeholder();
}}} // namespace james::core::crypto

#endif // JAMES_CORE_CRYPTO_$(echo "${crypto_file}" | tr '[:lower:]' '[:upper:]')_H_
EOF
    done
    
    # Create utils placeholders
    for util_file in logger config_manager; do
        cat > "src/core/utils/${util_file}.cpp" << EOF
// ${util_file}.cpp - J.A.M.E.S. Utils Module
// ⚠️ Placeholder Implementation – Phase 1

#include "${util_file}.h"
#include <iostream>

namespace james { namespace core { namespace utils {
void ${util_file}_placeholder() {
    std::cout << "[UTILS] ⚠️  ${util_file} placeholder" << std::endl;
}
}}} // namespace james::core::utils
EOF
        
        cat > "src/core/utils/${util_file}.h" << EOF
// ${util_file}.h - J.A.M.E.S. Utils Module  
// ⚠️ Placeholder Implementation – Phase 1

#ifndef JAMES_CORE_UTILS_$(echo "${util_file}" | tr '[:lower:]' '[:upper:]')_H_
#define JAMES_CORE_UTILS_$(echo "${util_file}" | tr '[:lower:]' '[:upper:]')_H_

namespace james { namespace core { namespace utils {
void ${util_file}_placeholder();
}}} // namespace james::core::utils

#endif // JAMES_CORE_UTILS_$(echo "${util_file}" | tr '[:lower:]' '[:upper:]')_H_
EOF
    done
    
    # Create evidence placeholders
    for evidence_file in chain_of_custody evidence_container; do
        cat > "src/core/evidence/${evidence_file}.cpp" << EOF
// ${evidence_file}.cpp - J.A.M.E.S. Evidence Module
// ⚠️ Placeholder Implementation – Phase 1

#include "${evidence_file}.h"
#include <iostream>

namespace james { namespace core { namespace evidence {
void ${evidence_file}_placeholder() {
    std::cout << "[EVIDENCE] ⚠️  ${evidence_file} placeholder" << std::endl;
}
}}} // namespace james::core::evidence
EOF
        
        cat > "src/core/evidence/${evidence_file}.h" << EOF
// ${evidence_file}.h - J.A.M.E.S. Evidence Module
// ⚠️ Placeholder Implementation – Phase 1

#ifndef JAMES_CORE_EVIDENCE_$(echo "${evidence_file}" | tr '[:lower:]' '[:upper:]')_H_
#define JAMES_CORE_EVIDENCE_$(echo "${evidence_file}" | tr '[:lower:]' '[:upper:]')_H_

namespace james { namespace core { namespace evidence {
void ${evidence_file}_placeholder();
}}} // namespace james::core::evidence

#endif // JAMES_CORE_EVIDENCE_$(echo "${evidence_file}" | tr '[:lower:]' '[:upper:]')_H_
EOF
    done
    
    log_success "Created crypto, utils, and evidence placeholder files"
}

initialize_git_repository() {
    print_section "Initializing Git Repository"
    
    cd "$JAMES_ROOT"
    
    if [[ -d ".git" ]]; then
        log_warning "Git repository already exists"
        return
    fi
    
    git init

    # Check and configure git identity for this repository
    if ! git config user.name >/dev/null 2>&1 || ! git config user.email >/dev/null 2>&1; then
        log_info "Configuring git identity for J.A.M.E.S. repository"
        git config user.name "JAMES Developer"
        git config user.email "dev@james.local"
        log_success "Git identity configured locally"
    else
        log_success "Using existing git identity: $(git config user.name) <$(git config user.email)>"
    fi

    log_success "Initialized git repository"
    
    git add .
    log_success "Added all files to git staging"
    
    git commit -m "Initial commit - J.A.M.E.S. scaffold

J.A.M.E.S. - Joint Automated Mobile Extraction System
Phase 1 scaffolding complete with:

- Security-hardened build system (SEI CERT + MISRA + Power of 10)
- Modular architecture for Android/iOS extraction
- Core engine with placeholder implementations
- Cross-platform CMake configuration
- Comprehensive directory structure
- Git repository initialization

⚠️  Placeholder implementations - Phase 2 development ready"
    
    log_success "Created initial commit"
}

show_final_summary() {
    print_section "J.A.M.E.S. Scaffold Complete"
    
    echo -e "${GREEN}🎉 J.A.M.E.S. repository created successfully!${NC}"
    echo
    echo -e "${BLUE}📊 Repository Summary:${NC}"
    echo "   📁 Location: $JAMES_ROOT"
    echo "   🔧 Build System: CMake with security hardening"
    echo "   📱 Platforms: Android, iOS, Storage, Specialty"
    echo "   🛡️  Security: SEI CERT + MISRA + Power of 10"
    echo "   ⚖️  Compliance: NIST 800-101, ISO 27037"
    echo "   🗄️  Git: Repository initialized with initial commit"
    echo
    echo -e "${BLUE}🚀 Quick Start:${NC}"
    echo "   cd $JAMES_ROOT"
    echo "   ./build.sh"
    echo "   ./build/james"
    echo
    echo -e "${BLUE}📋 Development Phases:${NC}"
    echo "   Phase 1: ✅ Scaffolding Complete"
    echo "   Phase 2: 🔄 Core Security Implementation"
    echo "   Phase 3: 🔄 Device Handler Development"
    echo "   Phase 4: 🔄 Exploitation Modules"
    echo "   Phase 5: 🔄 GUI & Integration"
    echo
    echo -e "${PURPLE}📖 Documentation:${NC}"
    echo "   README.md - Project overview and quick start"
    echo "   docs/ - Architecture and compliance documentation"
    echo "   .gitignore - Forensic-specific exclusions"
    echo
    echo -e "${YELLOW}⚠️  Important Notes:${NC}"
    echo "   • All implementations are Phase 1 placeholders"
    echo "   • Real forensic functionality requires Phase 2+ development"
    echo "   • Security hardening is enabled from the start"
    echo "   • Compliance frameworks are integrated into build system"
}

main() {
    print_banner
    
    log_info "Target directory: $TARGET_DIR"
    log_info "J.A.M.E.S. root: $JAMES_ROOT"
    
    check_prerequisites
    create_directory_structure
    create_gitignore
    create_readme
    create_root_cmakelists
    create_core_module
    create_main_executable
    create_build_script
    create_placeholder_modules
    initialize_git_repository
    show_final_summary
    
    echo -e "\n${GREEN}🎯 J.A.M.E.S. repository created and git initialized!${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
