// =============================================================================
// 📁 FILE: src/core/security_manager.cpp - SECURITY MANAGER IMPLEMENTATION  
// 🏷 REASONING: Cryptographic operations and integrity checking
// 🏷 REASONING: Fix OpenSSL includes and add missing headers
// =============================================================================

#include "security_manager.h"
#include "james_common.h"
#include <fstream>
#include <iomanip>

// OpenSSL includes with proper error handling
#ifdef OPENSSL_VERSION_MAJOR
    // OpenSSL 3.0+
    #include <openssl/evp.h>
    #include <openssl/rand.h>
    #include <openssl/core_names.h>
#else
    // OpenSSL 1.1.x
    #include <openssl/sha.h>
    #include <openssl/evp.h>
    #include <openssl/rand.h>
#endif

// Add backward compatibility macro for older OpenSSL
#ifndef EVP_sha256
    #define EVP_sha256 EVP_sha256
#endif

namespace james::core {

    struct SecurityManager::SecurityManagerImpl {
        std::string instanceId;
        std::atomic<bool> tamperDetected{false};
        std::string tamperReason;
        std::mutex tamperMutex;
        bool isInitialized{false};
        
        // Convert binary data to hex string
        std::string BinaryToHex(const unsigned char* data, size_t length) const noexcept {
            std::ostringstream oss;
            for (size_t i = 0; i < length; ++i) {
                oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
            }
            return oss.str();
        }
    };

    SecurityManager::SecurityManager() noexcept
        : pImpl(std::make_unique<SecurityManagerImpl>()) {
    }

    SecurityManager::~SecurityManager() noexcept {
        Shutdown();
    }

    james::JAMESResult<bool> SecurityManager::Initialize(const std::string& instanceId) noexcept {
        try {
            if (pImpl->isInitialized) {
                return james::JAMESResult<bool>::Failure("Security manager already initialized");
            }
            
            pImpl->instanceId = instanceId;
            
            // Initialize OpenSSL
            OpenSSL_add_all_algorithms();
            
            // Seed random number generator
            if (RAND_poll() != 1) {
                return james::JAMESResult<bool>::Failure("Failed to seed random number generator");
            }
            
            pImpl->isInitialized = true;
            
            return james::JAMESResult<bool>::Success(true);
            
        } catch (const std::exception& e) {
            return james::JAMESResult<bool>::Failure(
                std::string("Security manager initialization failed: ") + e.what());
        }
    }

    void SecurityManager::Shutdown() noexcept {
        try {
            if (pImpl->isInitialized) {
                EVP_cleanup();
                pImpl->isInitialized = false;
            }
        } catch (...) {
            // Never throw from shutdown
        }
    }

    bool SecurityManager::IsTampered() const noexcept {
        return pImpl->tamperDetected.load(std::memory_order_acquire);
    }

    void SecurityManager::MarkTampered(const std::string& reason) noexcept {
        std::lock_guard<std::mutex> lock(pImpl->tamperMutex);
        pImpl->tamperDetected.store(true, std::memory_order_release);
        pImpl->tamperReason = reason;
    }

    james::JAMESResult<std::string> SecurityManager::ComputeHash(
        const void* data, size_t length) const noexcept {
        try {
            if (!pImpl->isInitialized) {
                return james::JAMESResult<std::string>::Failure("Security manager not initialized");
            }
            
            if (data == nullptr || length == 0) {
                return james::JAMESResult<std::string>::Failure("Invalid input data");
            }
            
            // Use EVP interface for OpenSSL 3.0 compatibility
            EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
            if (!mdctx) {
                return james::JAMESResult<std::string>::Failure("Failed to create hash context");
            }
            
            // Initialize hash context
            if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
                EVP_MD_CTX_free(mdctx);
                return james::JAMESResult<std::string>::Failure("Failed to initialize SHA256");
            }
            
            // Update hash with data
            if (EVP_DigestUpdate(mdctx, data, length) != 1) {
                EVP_MD_CTX_free(mdctx);
                return james::JAMESResult<std::string>::Failure("Failed to update SHA256");
            }
            
            // Finalize hash
            unsigned char hash[EVP_MAX_MD_SIZE];
            unsigned int hash_len = 0;
            
            if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
                EVP_MD_CTX_free(mdctx);
                return james::JAMESResult<std::string>::Failure("Failed to finalize SHA256");
            }
            
            EVP_MD_CTX_free(mdctx);
            
            // Convert to hex string
            std::string hexHash = pImpl->BinaryToHex(hash, hash_len);
            
            // Secure clear the hash from stack
            JAMES_SECURE_ZERO(hash, sizeof(hash));
            
            return james::JAMESResult<std::string>::Success(hexHash);
            
        } catch (const std::exception& e) {
            return james::JAMESResult<std::string>::Failure(
                std::string("Hash computation failed: ") + e.what());
        }
    }

    // REPLACE the ComputeFileHash method with this version:
    james::JAMESResult<std::string> SecurityManager::ComputeFileHash(
        const std::string& filePath) const noexcept {
        try {
            std::ifstream file(filePath, std::ios::binary);
            if (!file.is_open()) {
                return james::JAMESResult<std::string>::Failure("Failed to open file: " + filePath);
            }
            
            // Use EVP interface for OpenSSL 3.0 compatibility
            EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
            if (!mdctx) {
                return james::JAMESResult<std::string>::Failure("Failed to create hash context");
            }
            
            if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
                EVP_MD_CTX_free(mdctx);
                return james::JAMESResult<std::string>::Failure("Failed to initialize SHA256");
            }
            
            // Read file in chunks and update hash
            char buffer[4096];
            while (file.good()) {
                file.read(buffer, sizeof(buffer));
                if (static_cast<size_t>(file.gcount()) > 0) {
                    if (EVP_DigestUpdate(mdctx, buffer, static_cast<size_t>(file.gcount())) != 1) {
                        EVP_MD_CTX_free(mdctx);
                        return james::JAMESResult<std::string>::Failure("Failed to update SHA256");
                    }
                }
            }
            
            // Finalize hash
            unsigned char hash[EVP_MAX_MD_SIZE];
            unsigned int hash_len = 0;
            
            if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
                EVP_MD_CTX_free(mdctx);
                return james::JAMESResult<std::string>::Failure("Failed to finalize SHA256");
            }
            
            EVP_MD_CTX_free(mdctx);
            
            // Convert to hex string
            std::string hexHash = pImpl->BinaryToHex(hash, hash_len);
            
            // Secure clear the hash and buffer
            JAMES_SECURE_ZERO(hash, sizeof(hash));
            JAMES_SECURE_ZERO(buffer, sizeof(buffer));
            
            return james::JAMESResult<std::string>::Success(hexHash);
            
        } catch (const std::exception& e) {
            return james::JAMESResult<std::string>::Failure(
                std::string("File hash computation failed: ") + e.what());
        }
    }

    james::JAMESResult<std::string> SecurityManager::SignData(
        const void* /*data*/, size_t /*length*/, KeyType /*keyType*/) const noexcept {
        // TODO: Implement digital signatures
        return james::JAMESResult<std::string>::Failure("Digital signatures not yet implemented");
    }

    james::JAMESResult<bool> SecurityManager::VerifySignature(
        const void* /*data*/, size_t /*length*/, const std::string& /*signature*/, KeyType /*keyType*/) const noexcept {
        // TODO: Implement signature verification
        return james::JAMESResult<bool>::Failure("Signature verification not yet implemented");
    }

    james::JAMESResult<std::string> SecurityManager::GenerateSessionKey() const noexcept {
        try {
            unsigned char key[32]; // 256-bit key
            if (RAND_bytes(key, sizeof(key)) != 1) {
                return james::JAMESResult<std::string>::Failure("Failed to generate random key");
            }
            
            std::string hexKey = pImpl->BinaryToHex(key, sizeof(key));
            
            // Secure clear the key from memory
            JAMES_SECURE_ZERO(key, sizeof(key));
            
            return james::JAMESResult<std::string>::Success(hexKey);
            
        } catch (const std::exception& e) {
            return james::JAMESResult<std::string>::Failure(
                std::string("Session key generation failed: ") + e.what());
        }
    }

    james::JAMESResult<bool> SecurityManager::ValidateSystemIntegrity() const noexcept {
        // TODO: Implement system integrity validation
        return james::JAMESResult<bool>::Success(true);
    }

} // namespace james::core