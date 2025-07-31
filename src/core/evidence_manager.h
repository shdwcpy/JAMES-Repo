// -----------------------------------------------------------------------------
// 📁 FILE: src/core/evidence_manager.h
// 🏷 REASONING: Chain of custody and evidence integrity - core forensic requirement  
// -----------------------------------------------------------------------------

#pragma once

#include "james_common.h"
#include "james_result.h"
#include "audit_logger.h"
#include "security_manager.h"
#include <string>
#include <memory>
#include <chrono>
#include <vector>

namespace james::core {

// FORENSIC: Evidence metadata for chain of custody
struct EvidenceMetadata {
    std::string evidenceId;
    std::string sourceDeviceId;
    std::string extractionMethod;
    std::chrono::system_clock::time_point acquisitionTime;
    std::string examinerName;
    std::string caseNumber;
    std::string originalHash;
    std::string currentHash;
    std::vector<std::string> chainOfCustody;
    bool isSealed;
    size_t evidenceSize;
    std::string evidencePath;
};

class EvidenceManager {
public:
    EvidenceManager(AuditLogger* auditLogger, SecurityManager* securityManager) noexcept;
    ~EvidenceManager() noexcept;
    
    // Initialization
    [[nodiscard]] james::JAMESResult<bool> Initialize() noexcept;
    void Shutdown() noexcept;
    
    // Evidence creation and sealing
    [[nodiscard]] james::JAMESResult<std::string> CreateEvidenceContainer(
        const std::string& deviceId, const std::string& examiner, 
        const std::string& caseNumber) noexcept;
    
    [[nodiscard]] james::JAMESResult<bool> SealEvidence(
        const std::string& evidenceId) noexcept;
    
    // Evidence integrity
    [[nodiscard]] james::JAMESResult<bool> VerifyEvidenceIntegrity(
        const std::string& evidenceId) noexcept;
    
    [[nodiscard]] james::JAMESResult<std::string> ComputeEvidenceHash(
        const std::string& evidencePath) noexcept;
    
    // Chain of custody
    [[nodiscard]] james::JAMESResult<bool> AddCustodyEntry(
        const std::string& evidenceId, const std::string& custodian, 
        const std::string& action) noexcept;
    
    // Evidence metadata
    [[nodiscard]] james::JAMESResult<EvidenceMetadata> GetEvidenceMetadata(
        const std::string& evidenceId) const noexcept;
    
    [[nodiscard]] james::JAMESResult<std::vector<std::string>> ListEvidence() const noexcept;

private:
    struct EvidenceManagerImpl;
    std::unique_ptr<EvidenceManagerImpl> pImpl;
    AuditLogger* m_auditLogger;
    SecurityManager* m_securityManager;
};

} // namespace james::core