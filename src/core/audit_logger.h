// =============================================================================
// 📁 FILE: src/core/audit_logger.h - SECURITY-HARDENED HEADER
// 🏷 REASONING: Forensic audit trail with maximum security compliance
// 🔒 STANDARDS: SEI-CERT C++, MISRA C++:2023, NASA Power of 10, NIST SP 800-53
// =============================================================================

#pragma once

#include "james_common.h"
#include "james_result.h"
#include <string>
#include <chrono>
#include <memory>
#include <cstdint>
#include <vector>
#include <array>

namespace james::core {

    // SECURITY: Fixed-size enums prevent buffer overflow attacks
    // MISRA C++:2023 Rule 7-2-1: Enumerations shall have explicitly specified underlying type
    enum class AuditLevel : uint8_t {
        DEBUG = 0,    // Development/troubleshooting only
        INFO = 1,     // General information  
        WARNING = 2,  // Potential issues
        ERROR = 3,    // Error conditions
        CRITICAL = 4, // Security events, evidence handling
        MAX_LEVEL = 4 // SECURITY: Boundary check value
    };

    // FORENSIC REQUIREMENT: Comprehensive event classification
    // SECURITY: Use specific ranges to prevent enum injection attacks
    enum class AuditEvent : uint16_t {
        // Engine lifecycle (1000-1999)
        ENGINE_STARTUP = 1000,
        ENGINE_READY = 1001,
        ENGINE_SHUTDOWN = 1002,
        ENGINE_SHUTDOWN_COMPLETE = 1003,
        ENGINE_ERROR = 1004,
        
        // Device operations (2000-2999)
        DEVICE_DISCOVERY_START = 2000,
        DEVICE_DISCOVERY_COMPLETE = 2001,
        DEVICE_CONNECTED = 2002,
        DEVICE_DISCONNECTED = 2003,
        DEVICE_INFO_RETRIEVED = 2004,
        DEVICE_ERROR = 2005,
        
        // Extraction operations (3000-3999)
        EXTRACTION_START = 3000,
        EXTRACTION_PROGRESS = 3001,
        EXTRACTION_COMPLETE = 3002,
        EXTRACTION_ABORT = 3003,
        EXTRACTION_ERROR = 3004,
        
        // Evidence integrity (4000-4999)
        EVIDENCE_HASH_CREATED = 4000,
        EVIDENCE_HASH_VERIFIED = 4001,
        EVIDENCE_HASH_MISMATCH = 4002,
        EVIDENCE_SEALED = 4003,
        EVIDENCE_UNSEALED = 4004,
        
        // Security events (9000-9999)
        SECURITY_VIOLATION = 9000,
        TAMPER_DETECTED = 9001,
        UNAUTHORIZED_ACCESS = 9002,
        CRYPTO_ERROR = 9003,
        
        // SECURITY: Boundary values for validation
        MIN_VALID_EVENT = 1000,
        MAX_VALID_EVENT = 9999
    };

    // SECURITY: Constrained string lengths prevent buffer overflows
    // NASA Power of 10 Rule 1: Restrict dynamic memory allocation
    struct AuditLogLimits {
        static constexpr size_t MAX_MESSAGE_LENGTH = 1024U;
        static constexpr size_t MAX_DEVICE_ID_LENGTH = 64U;
        static constexpr size_t MAX_INSTANCE_ID_LENGTH = 128U;
        static constexpr size_t MAX_FILE_PATH_LENGTH = 512U;
        static constexpr size_t MAX_LOG_ENTRIES_IN_MEMORY = 10000U;
        static constexpr size_t MAX_CONCURRENT_WRITERS = 1U; // Single writer pattern
    };

    // SECURITY: Audit entry structure with integrity protection
    struct AuditEntry {
        std::chrono::system_clock::time_point timestamp;
        AuditEvent event;
        AuditLevel level;
        std::array<char, AuditLogLimits::MAX_MESSAGE_LENGTH> message;
        std::array<char, AuditLogLimits::MAX_DEVICE_ID_LENGTH> deviceId;
        uint64_t sequenceNumber;
        uint32_t checksum; // SECURITY: Integrity protection
        
        // SECURITY: Initialize all fields to prevent information leakage
        AuditEntry() noexcept 
            : timestamp(std::chrono::system_clock::now())
            , event(AuditEvent::ENGINE_ERROR)
            , level(AuditLevel::ERROR)
            , message{}
            , deviceId{}
            , sequenceNumber(0U)
            , checksum(0U) {
            // SECURITY: Zero-initialize arrays to prevent data leakage
            message.fill('\0');
            deviceId.fill('\0');
        }
    };

    class AuditLogger {
    public:
        // MISRA C++:2023 Rule 12-1-1: Constructors shall be explicit unless intended for conversion
        explicit AuditLogger() noexcept;
        
        // SECURITY: Virtual destructor for secure cleanup
        virtual ~AuditLogger() noexcept;

        // Copy/move operations explicitly deleted for security
        // SECURITY: Prevent accidental copying of security-sensitive objects
        AuditLogger(const AuditLogger&) = delete;
        AuditLogger& operator=(const AuditLogger&) = delete;
        AuditLogger(AuditLogger&&) = delete;
        AuditLogger& operator=(AuditLogger&&) = delete;
        
        // Initialization with input validation
        [[nodiscard]] james::JAMESResult<bool> Initialize(const std::string& instanceId) noexcept;
        void Shutdown() noexcept;
        
        // SECURITY: Const-qualified getters prevent accidental modification
        [[nodiscard]] bool IsInitialized() const noexcept;
        [[nodiscard]] uint64_t GetSequenceNumber() const noexcept;
        [[nodiscard]] std::string GetInstanceId() const noexcept;
        
        // Core logging functions with input validation
        void LogEvent(AuditEvent event, const std::string& message, AuditLevel level) noexcept;
        void LogEvent(AuditEvent event, const std::string& message, AuditLevel level, 
                     const std::string& deviceId) noexcept;
        
        // Evidence-specific logging with enhanced security
        void LogEvidenceEvent(const std::string& evidenceId, const std::string& action, 
                             const std::string& hash) noexcept;
        
        // Security logging with tamper detection
        void LogSecurityEvent(const std::string& event, const std::string& details) noexcept;
        
        // Query functions with bounds checking
        [[nodiscard]] james::JAMESResult<std::vector<std::string>> GetAuditTrail() const noexcept;
        [[nodiscard]] james::JAMESResult<std::vector<std::string>> GetAuditTrail(
            std::chrono::system_clock::time_point startTime,
            std::chrono::system_clock::time_point endTime) const noexcept;
        
        // Secure export with integrity verification
        [[nodiscard]] james::JAMESResult<bool> ExportAuditLog(const std::string& filePath) const noexcept;
        [[nodiscard]] james::JAMESResult<bool> VerifyLogIntegrity() const noexcept;
        
        // SECURITY: Secure log rotation to prevent disk exhaustion attacks
        [[nodiscard]] james::JAMESResult<bool> RotateLog() noexcept;
        [[nodiscard]] james::JAMESResult<uint64_t> GetLogSize() const noexcept;

    private:
        struct AuditLoggerImpl;
        std::unique_ptr<AuditLoggerImpl> pImpl;
        
        // SECURITY: Private validation methods
        [[nodiscard]] static bool ValidateEvent(AuditEvent event) noexcept;
        [[nodiscard]] static bool ValidateLevel(AuditLevel level) noexcept;
        [[nodiscard]] static bool ValidateString(const std::string& str, size_t maxLength) noexcept;
        [[nodiscard]] static uint32_t CalculateChecksum(const AuditEntry& entry) noexcept;
        
        // SECURITY: Secure internal logging method
        void InternalLogEvent(const AuditEntry& entry) noexcept;
    };

} // namespace james::core