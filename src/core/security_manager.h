// -----------------------------------------------------------------------------
// 📁 FILE: src/core/security_manager.h  
// 🏷 REASONING: Central security authority - prevents tampering and ensures integrity
// -----------------------------------------------------------------------------

#pragma once

#include "james_common.h" 
#include "james_result.h"
#include <string>
#include <memory>
#include <cstdint>

namespace james::core {

// SECURITY: Cryptographic key management
enum class KeyType : uint8_t {
    EVIDENCE_SIGNING = 1,
    EVIDENCE_ENCRYPTION = 2,
    AUDIT_INTEGRITY = 3,
    SESSION_AUTH = 4
};

class SecurityManager {
public:
    SecurityManager() noexcept;
    ~SecurityManager() noexcept;
    
    // Initialization with instance binding
    [[nodiscard]] james::JAMESResult<bool> Initialize(const std::string& instanceId) noexcept;
    void Shutdown() noexcept;
    
    // Tamper detection
    [[nodiscard]] bool IsTampered() const noexcept;
    void MarkTampered(const std::string& reason) noexcept;
    
    // Cryptographic operations
    [[nodiscard]] james::JAMESResult<std::string> ComputeHash(
        const void* data, size_t length) const noexcept;
    [[nodiscard]] james::JAMESResult<std::string> ComputeFileHash(
        const std::string& filePath) const noexcept;
    
    // Digital signatures for evidence integrity
    [[nodiscard]] james::JAMESResult<std::string> SignData(
        const void* data, size_t length, KeyType keyType) const noexcept;
    [[nodiscard]] james::JAMESResult<bool> VerifySignature(
        const void* data, size_t length, const std::string& signature, KeyType keyType) const noexcept;
    
    // Secure key generation and management
    [[nodiscard]] james::JAMESResult<std::string> GenerateSessionKey() const noexcept;
    [[nodiscard]] james::JAMESResult<bool> ValidateSystemIntegrity() const noexcept;

private:
    struct SecurityManagerImpl;
    std::unique_ptr<SecurityManagerImpl> pImpl;
};

} // namespace james::core