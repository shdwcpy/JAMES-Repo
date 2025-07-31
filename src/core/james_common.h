// =============================================================================
// 📁 FILE: src/core/james_common.h - UPDATED WITH MISSING INCLUDES
// 🏷 REASONING: Add missing standard library includes for compilation
// 🏷 REASONING: Add missing standard library includes
// =============================================================================

#pragma once

// Standard library includes - SEI-CERT compliant
#include <cstdint>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <atomic>
#include <chrono>
#include <functional>
#include <algorithm>
#include <exception>
#include <sstream>
#include <iostream>
#include <fstream>
#include <iomanip>      // For std::setfill, std::setw, std::put_time
#include <thread>       // For std::this_thread::get_id
#include <cctype>       // For ::tolower in utils functions
#include <ctime>
#include <exception>
#include <mutex>

// Platform detection
#if defined(__linux__)
    #define JAMES_PLATFORM_LINUX 1
    #include <unistd.h>
    #include <sys/types.h>
#elif defined(_WIN32) || defined(_WIN64)
    #define JAMES_PLATFORM_WINDOWS 1
    #include <windows.h>
#elif defined(__APPLE__)
    #define JAMES_PLATFORM_MACOS 1
    #include <unistd.h>
    #include <sys/types.h>
#else
    #define JAMES_PLATFORM_UNKNOWN 1  
#endif
#include <iomanip>

// Compiler detection and attributes
#if defined(__GNUC__) || defined(__clang__)
    #define JAMES_LIKELY(x)   __builtin_expect(!!(x), 1)
    #define JAMES_UNLIKELY(x) __builtin_expect(!!(x), 0)
    #define JAMES_FORCE_INLINE __attribute__((always_inline)) inline
    #define JAMES_NO_INLINE __attribute__((noinline))
    #define JAMES_DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
    #define JAMES_LIKELY(x)   (x)
    #define JAMES_UNLIKELY(x) (x)
    #define JAMES_FORCE_INLINE __forceinline  
    #define JAMES_NO_INLINE __declspec(noinline)
    #define JAMES_DEPRECATED __declspec(deprecated)
#else
    #define JAMES_LIKELY(x)   (x)
    #define JAMES_UNLIKELY(x) (x)
    #define JAMES_FORCE_INLINE inline
    #define JAMES_NO_INLINE
    #define JAMES_DEPRECATED
#endif

// Version information
#define JAMES_PLATFORM_STRING "UNIX MACOS WINDOWS"
#define JAMES_VERSION_MAJOR 1
#define JAMES_VERSION_MINOR 0
#define JAMES_VERSION_PATCH 0
#define JAMES_VERSION_STRING "1.0.0"

// Security annotations - TEACHING: These provide security context for code review
#define JAMES_SECURITY_CRITICAL    [[deprecated("Security-critical code - requires review")]]
#define JAMES_EVIDENCE_HANDLING    [[deprecated("Handles forensic evidence - chain of custody required")]]
#define JAMES_CRYPTO_OPERATION     [[deprecated("Cryptographic operation - security audit required")]]
#define JAMES_EXTERNAL_INTERFACE   [[deprecated("External interface - input validation required")]]

// Memory security macros
#define JAMES_SECURE_ZERO(ptr, size) \
    do { \
        volatile uint8_t* _p = reinterpret_cast<volatile uint8_t*>(ptr); \
        for (size_t _i = 0; _i < (size); ++_i) { \
            _p[_i] = 0; \
        } \
    } while(0)

// MISRA compliance - safe arithmetic operations
#define JAMES_SAFE_ADD(a, b, max_val) \
    (((a) > (max_val) - (b)) ? (max_val) : ((a) + (b)))

#define JAMES_SAFE_MUL(a, b, max_val) \
    (((a) != 0 && (b) > (max_val) / (a)) ? (max_val) : ((a) * (b)))

// Debugging and logging macros
#ifdef NDEBUG
    #define JAMES_DEBUG(x) do {} while(0)
    #define JAMES_ASSERT(condition) do {} while(0)
#else
    #define JAMES_DEBUG(x) do { std::cerr << "[DEBUG] " << x << std::endl; } while(0)
    #define JAMES_ASSERT(condition) \
        do { \
            if (!(condition)) { \
                std::cerr << "[ASSERT] " << #condition << " failed at " \
                         << __FILE__ << ":" << __LINE__ << std::endl; \
                std::abort(); \
            } \
        } while(0)
#endif

// Forensic logging levels - matches industry standards
enum class LogLevel : uint8_t {
    TRACE = 0,    // Detailed execution flow
    DEBUG = 1,    // Development information  
    INFO = 2,     // General information
    WARN = 3,     // Warning conditions
    ERROR = 4,    // Error conditions
    FATAL = 5,    // Fatal errors
    AUDIT = 6     // Forensic audit events
};

// Common result codes for forensic operations
enum class JAMESResultCode : uint16_t {
    SUCCESS = 0,
    
    // General errors (1000-1999)
    UNKNOWN_ERROR = 1000,
    INVALID_PARAMETER = 1001,
    NULL_POINTER = 1002,
    OUT_OF_MEMORY = 1003,
    TIMEOUT = 1004,
    CANCELLED = 1005,
    
    // Device errors (2000-2999)
    DEVICE_NOT_FOUND = 2000,
    DEVICE_NOT_CONNECTED = 2001,
    DEVICE_COMMUNICATION_ERROR = 2002,
    DEVICE_LOCKED = 2003,
    DEVICE_ROOTED_REQUIRED = 2004,
    
    // Security errors (3000-3999)
    SECURITY_VIOLATION = 3000,
    TAMPER_DETECTED = 3001,
    CRYPTO_ERROR = 3002,
    AUTHENTICATION_FAILED = 3003,
    PERMISSION_DENIED = 3004,
    
    // Evidence errors (4000-4999)
    EVIDENCE_CORRUPTED = 4000,
    HASH_MISMATCH = 4001,
    CHAIN_OF_CUSTODY_BROKEN = 4002,
    EVIDENCE_SEALED = 4003,
    
    // Extraction errors (5000-5999)
    EXTRACTION_FAILED = 5000,
    EXTRACTION_INCOMPLETE = 5001,
    EXTRACTION_CORRUPTED = 5002,
    UNSUPPORTED_METHOD = 5003
};

// Forward declarations
namespace james {
    template<typename T> class JAMESResult;
    namespace core {
        class JAMESEngine;
        class DeviceManager;
        class AuditLogger;
        class SecurityManager;
        class EvidenceManager;
        struct DeviceInfo;
    }
}

// Utility functions
namespace james::utils {
    
    // TEACHING: Safe string operations for forensic tools
    // Prevents buffer overflows that could corrupt evidence
    inline std::string SafeSubstring(const std::string& str, size_t pos, size_t len = std::string::npos) noexcept {
        try {
            if (pos >= str.length()) return "";
            return str.substr(pos, len);
        } catch (...) {
            return "";
        }
    }
    
    // Secure string comparison - constant time to prevent timing attacks
    inline bool SecureStringCompare(const std::string& a, const std::string& b) noexcept {
        if (a.length() != b.length()) return false;
        
        volatile uint8_t result = 0;
        for (size_t i = 0; i < a.length(); ++i) {
            result |= static_cast<uint8_t>(a[i] ^ b[i]);
        }
        return result == 0;
    }
    
    // Generate timestamp string for forensic logging
    inline std::string GetTimestamp() noexcept {
        try {
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) % 1000;
            
            std::ostringstream oss;
            oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
            oss << "." << std::setfill('0') << std::setw(3) << ms.count() << "Z";
            return oss.str();
        } catch (...) {
            return "TIMESTAMP_ERROR";
        }
    }
    
    // Validate hexadecimal string (for hashes, device IDs, etc.)
    inline bool IsValidHex(const std::string& str) noexcept {
        if (str.empty()) return false;
        
        for (char c : str) {
            if (!((c >= '0' && c <= '9') || 
                  (c >= 'A' && c <= 'F') || 
                  (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }
    
    // Convert bytes to human-readable size
    inline std::string FormatBytes(uint64_t bytes) noexcept {
        const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
        const int unitCount = sizeof(units) / sizeof(units[0]);
        
        double size = static_cast<double>(bytes);
        int unitIndex = 0;
        
        while (size >= 1024.0 && unitIndex < unitCount - 1) {
            size /= 1024.0;
            unitIndex++;
        }
        
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2) << size << " " << units[unitIndex];
        return oss.str();
    }
}