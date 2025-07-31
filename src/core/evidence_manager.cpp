// =============================================================================
// 📁 FILE: src/core/evidence_manager.cpp - EVIDENCE MANAGER IMPLEMENTATION
// 🏷 REASONING: Chain of custody and evidence integrity management
// =============================================================================

#include "evidence_manager.h"
#include "james_common.h"
#include <filesystem>
#include <fstream>
#include <thread>

namespace james::core {

    struct EvidenceManager::EvidenceManagerImpl {
        AuditLogger* auditLogger;
        SecurityManager* securityManager;
        
        std::unordered_map<std::string, EvidenceMetadata> evidenceDatabase;
        std::mutex evidenceMutex;
        std::string evidenceStorePath;
        bool isInitialized{false};
        
        EvidenceManagerImpl(AuditLogger* audit, SecurityManager* security)
            : auditLogger(audit), securityManager(security) {}
        
        std::string GenerateEvidenceId() const noexcept {
            auto now = std::chrono::system_clock::now();
            auto epoch = now.time_since_epoch();
            auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
            
            std::ostringstream oss;
            oss << "EVD_" << std::hex << millis << "_" << std::this_thread::get_id();
            return oss.str();
        }
    };

    EvidenceManager::EvidenceManager(AuditLogger* auditLogger, SecurityManager* securityManager) noexcept
        : pImpl(std::make_unique<EvidenceManagerImpl>(auditLogger, securityManager))
        , m_auditLogger(auditLogger)
        , m_securityManager(securityManager) {
    }

    EvidenceManager::~EvidenceManager() noexcept {
        Shutdown();
    }

    james::JAMESResult<bool> EvidenceManager::Initialize() noexcept {
        try {
            if (pImpl->isInitialized) {
                return james::JAMESResult<bool>::Failure("Evidence manager already initialized");
            }
            
            // Create evidence storage directory
            pImpl->evidenceStorePath = "evidence";
            std::filesystem::create_directories(pImpl->evidenceStorePath);
            
            pImpl->isInitialized = true;
            
            m_auditLogger->LogEvent(AuditEvent::ENGINE_READY, 
                "Evidence manager initialized", AuditLevel::INFO);
            
            return james::JAMESResult<bool>::Success(true);
            
        } catch (const std::exception& e) {
            return james::JAMESResult<bool>::Failure(
                std::string("Evidence manager initialization failed: ") + e.what());
        }
    }

    void EvidenceManager::Shutdown() noexcept {
        try {
            if (pImpl->isInitialized) {
                std::lock_guard<std::mutex> lock(pImpl->evidenceMutex);
                
                // TODO: Serialize evidence database
                pImpl->evidenceDatabase.clear();
                pImpl->isInitialized = false;
                
                m_auditLogger->LogEvent(AuditEvent::ENGINE_SHUTDOWN_COMPLETE,
                    "Evidence manager shutdown", AuditLevel::INFO);
            }
        } catch (...) {
            // Never throw from shutdown
        }
    }

    james::JAMESResult<std::string> EvidenceManager::CreateEvidenceContainer(
        const std::string& deviceId, const std::string& examiner, 
        const std::string& caseNumber) noexcept {
        try {
            std::lock_guard<std::mutex> lock(pImpl->evidenceMutex);
            
            if (!pImpl->isInitialized) {
                return james::JAMESResult<std::string>::Failure("Evidence manager not initialized");
            }
            
            std::string evidenceId = pImpl->GenerateEvidenceId();
            
            EvidenceMetadata metadata;
            metadata.evidenceId = evidenceId;
            metadata.sourceDeviceId = deviceId;
            metadata.acquisitionTime = std::chrono::system_clock::now();
            metadata.examinerName = examiner;
            metadata.caseNumber = caseNumber;
            metadata.isSealed = false;
            metadata.evidenceSize = 0;
            
            // Create evidence directory
            std::filesystem::path evidencePath = 
                std::filesystem::path(pImpl->evidenceStorePath) / evidenceId;
            std::filesystem::create_directories(evidencePath);
            metadata.evidencePath = evidencePath.string();
            
            // Add initial chain of custody entry
            std::ostringstream custodyEntry;
            custodyEntry << james::utils::GetTimestamp() << " - Created by " << examiner 
                        << " for case " << caseNumber;
            metadata.chainOfCustody.push_back(custodyEntry.str());
            
            pImpl->evidenceDatabase[evidenceId] = metadata;
            
            m_auditLogger->LogEvidenceEvent(evidenceId, "CREATED", "PENDING");
            
            return james::JAMESResult<std::string>::Success(evidenceId);
            
        } catch (const std::exception& e) {
            return james::JAMESResult<std::string>::Failure(
                std::string("Failed to create evidence container: ") + e.what());
        }
    }

    james::JAMESResult<bool> EvidenceManager::SealEvidence(const std::string& /*evidenceId*/) noexcept {
        // TODO: Implement evidence sealing with cryptographic protection
        return james::JAMESResult<bool>::Failure("Evidence sealing not yet implemented");
    }

    james::JAMESResult<bool> EvidenceManager::VerifyEvidenceIntegrity(const std::string& /*evidenceId*/) noexcept {
        // TODO: Implement evidence integrity verification
        return james::JAMESResult<bool>::Failure("Evidence verification not yet implemented");
    }

    james::JAMESResult<std::string> EvidenceManager::ComputeEvidenceHash(const std::string& evidencePath) noexcept {
        return m_securityManager->ComputeFileHash(evidencePath);
    }

    james::JAMESResult<bool> EvidenceManager::AddCustodyEntry(
        const std::string& evidenceId, const std::string& custodian, 
        const std::string& action) noexcept {
        try {
            std::lock_guard<std::mutex> lock(pImpl->evidenceMutex);
            
            auto it = pImpl->evidenceDatabase.find(evidenceId);
            if (it == pImpl->evidenceDatabase.end()) {
                return james::JAMESResult<bool>::Failure("Evidence not found: " + evidenceId);
            }
            
            std::ostringstream custodyEntry;
            custodyEntry << james::utils::GetTimestamp() << " - " << action 
                        << " by " << custodian;
            
            it->second.chainOfCustody.push_back(custodyEntry.str());
            
            m_auditLogger->LogEvidenceEvent(evidenceId, "CUSTODY_UPDATE", custodian);
            
            return james::JAMESResult<bool>::Success(true);
            
        } catch (const std::exception& e) {
            return james::JAMESResult<bool>::Failure(
                std::string("Failed to add custody entry: ") + e.what());
        }
    }

    james::JAMESResult<EvidenceMetadata> EvidenceManager::GetEvidenceMetadata(
        const std::string& evidenceId) const noexcept {
        try {
            std::lock_guard<std::mutex> lock(pImpl->evidenceMutex);
            
            auto it = pImpl->evidenceDatabase.find(evidenceId);
            if (it == pImpl->evidenceDatabase.end()) {
                return james::JAMESResult<EvidenceMetadata>::Failure("Evidence not found: " + evidenceId);
            }
            
            return james::JAMESResult<EvidenceMetadata>::Success(it->second);
            
        } catch (const std::exception& e) {
            return james::JAMESResult<EvidenceMetadata>::Failure(
                std::string("Failed to get evidence metadata: ") + e.what());
        }
    }

    james::JAMESResult<std::vector<std::string>> EvidenceManager::ListEvidence() const noexcept {
        try {
            std::lock_guard<std::mutex> lock(pImpl->evidenceMutex);
            
            std::vector<std::string> evidenceList;
            evidenceList.reserve(pImpl->evidenceDatabase.size());
            
            for (const auto& [evidenceId, metadata] : pImpl->evidenceDatabase) {
                evidenceList.push_back(evidenceId);
            }
            
            return james::JAMESResult<std::vector<std::string>>::Success(std::move(evidenceList));
            
        } catch (const std::exception& e) {
            return james::JAMESResult<std::vector<std::string>>::Failure(
                std::string("Failed to list evidence: ") + e.what());
        }
    }

} // namespace james::core