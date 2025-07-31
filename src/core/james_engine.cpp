// =============================================================================
// 📁 FILE: src/core/james_engine.cpp - COMPLETE IMPLEMENTATION WITH MISSING METHODS
// =============================================================================

#include "james_engine.h"
#include "device_manager.h"
#include "extraction_session.h"
#include "audit_logger.h"
#include "security_manager.h"
#include "evidence_manager.h"
#include <chrono>
#include <thread>
#include <sstream>

namespace james::core {

    // SECURITY-CRITICAL: Engine implementation with tamper detection
    struct JAMESEngine::JAMESEngineImpl {
        std::unique_ptr<DeviceManager> deviceManager;
        std::unique_ptr<AuditLogger> auditLogger;
        std::unique_ptr<SecurityManager> securityManager;
        std::unique_ptr<EvidenceManager> evidenceManager;
        
        // Security state tracking
        std::atomic<uint64_t> operationCounter{0};
        std::atomic<bool> tamperDetected{false};
        std::string engineInstanceId;
        std::chrono::steady_clock::time_point initTime;
        
        // TEACHING: Constructor initializes in dependency order
        JAMESEngineImpl() {
            // Generate unique instance ID for this session
            auto now = std::chrono::system_clock::now();
            auto epoch = now.time_since_epoch();
            auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
            
            std::ostringstream oss;
            oss << "JAMES_" << std::hex << millis << "_" << std::this_thread::get_id();
            engineInstanceId = oss.str();
            
            initTime = std::chrono::steady_clock::now();
        }
    };

    JAMESEngine::JAMESEngine() noexcept 
        : pImpl(std::make_unique<JAMESEngineImpl>()) {
        // SECURITY: Initialize with defensive state
        m_state.store(EngineState::UNINITIALIZED, std::memory_order_release);
    }

    JAMESEngine::~JAMESEngine() noexcept {
        // SECURITY-CRITICAL: Ensure clean shutdown on destruction
        if (m_state.load(std::memory_order_acquire) != EngineState::UNINITIALIZED) {
            Shutdown();
        }
    }

    // TEACHING: Why we validate state transitions
    // In forensics, improper state handling could compromise evidence integrity
    james::JAMESResult<bool> JAMESEngine::Initialize() noexcept {
        std::cout << "Inside Engine Initialize" << std::endl;
        std::lock_guard<std::mutex> lock(m_stateMutex);
        
        try {
            // SECURITY: Verify we're in correct state for initialization
            std::cout << "Inside Engine - check initialization state" << std::endl;
            if (m_state.load(std::memory_order_acquire) != EngineState::UNINITIALIZED) {
                return james::JAMESResult<bool>::Failure(
                    "Engine already initialized or in invalid state"
                );
            }
            
            m_state.store(EngineState::INITIALIZING, std::memory_order_release);
            
            // PHASE 1: Initialize Security Manager (must be first)
            pImpl->securityManager = std::make_unique<SecurityManager>();
            auto secResult = pImpl->securityManager->Initialize(pImpl->engineInstanceId);
            std::cout << "Inside Engine - initialize security manager " << std::endl;
            if (!secResult.IsSuccess()) {
                m_state.store(EngineState::ERROR, std::memory_order_release);
                return james::JAMESResult<bool>::Failure(
                    "Security manager initialization failed: " + secResult.GetErrorMessage()
                );
            }
            
            // PHASE 2: Initialize Audit Logger
            pImpl->auditLogger = std::make_unique<AuditLogger>();
            auto auditResult = pImpl->auditLogger->Initialize(pImpl->engineInstanceId);
            if (!auditResult.IsSuccess()) {
                m_state.store(EngineState::ERROR, std::memory_order_release);
                return james::JAMESResult<bool>::Failure(
                    "Audit logger initialization failed: " + auditResult.GetErrorMessage()
                );
            }
            
            // Log the engine start - FORENSIC REQUIREMENT
            pImpl->auditLogger->LogEvent(AuditEvent::ENGINE_STARTUP, 
                "J.A.M.E.S. Engine v1.0.0 initialized", 
                AuditLevel::CRITICAL);
            
            // PHASE 3: Initialize Evidence Manager
            pImpl->evidenceManager = std::make_unique<EvidenceManager>(
                pImpl->auditLogger.get(), 
                pImpl->securityManager.get()
            );
            auto evidenceResult = pImpl->evidenceManager->Initialize();
            if (!evidenceResult.IsSuccess()) {
                m_state.store(EngineState::ERROR, std::memory_order_release);
                return james::JAMESResult<bool>::Failure(
                    "Evidence manager initialization failed: " + evidenceResult.GetErrorMessage()
                );
            }

            // PHASE 4: Initialize Device Manager (last, depends on others)
            pImpl->deviceManager = std::make_unique<DeviceManager>(
                pImpl->auditLogger.get(),
                pImpl->securityManager.get()
            );
            auto deviceResult = pImpl->deviceManager->Initialize();
            if (!deviceResult.IsSuccess()) {
                m_state.store(EngineState::ERROR, std::memory_order_release);
                return james::JAMESResult<bool>::Failure(
                    "Device manager initialization failed: " + deviceResult.GetErrorMessage()
                );
            }

            // SUCCESS: All components initialized
            m_state.store(EngineState::READY, std::memory_order_release);
            pImpl->auditLogger->LogEvent(AuditEvent::ENGINE_READY, 
                "All engine components initialized successfully", 
                AuditLevel::INFO);
            
            return james::JAMESResult<bool>::Success(true);
            
        } catch (const std::exception& e) {
            m_state.store(EngineState::ERROR, std::memory_order_release);
            return james::JAMESResult<bool>::Failure(
                std::string("Engine initialization exception: ") + e.what()
            );
        }
    }

    // TEACHING: Clean shutdown is critical in forensics
    // Improper shutdown could corrupt evidence or leave security vulnerabilities
    void JAMESEngine::Shutdown() noexcept {
        std::lock_guard<std::mutex> lock(m_stateMutex);
        
        try {
            auto currentState = m_state.load(std::memory_order_acquire);
            if (currentState == EngineState::UNINITIALIZED || 
                currentState == EngineState::SHUTTING_DOWN) {
                return; // Already shut down or shutting down
            }
            
            m_state.store(EngineState::SHUTTING_DOWN, std::memory_order_release);
            
            // Log shutdown initiation
            if (pImpl->auditLogger) {
                pImpl->auditLogger->LogEvent(AuditEvent::ENGINE_SHUTDOWN, 
                    "Engine shutdown initiated", 
                    AuditLevel::CRITICAL);
            }
            
            // Shutdown in reverse dependency order
            if (pImpl->deviceManager) {
                pImpl->deviceManager->Shutdown();
                pImpl->deviceManager.reset();
            }
            
            if (pImpl->evidenceManager) {
                pImpl->evidenceManager->Shutdown();
                pImpl->evidenceManager.reset();
            }
            
            // Audit logger shuts down last to capture all events
            if (pImpl->auditLogger) {
                pImpl->auditLogger->LogEvent(AuditEvent::ENGINE_SHUTDOWN_COMPLETE, 
                    "Engine shutdown completed successfully", 
                    AuditLevel::CRITICAL);
                pImpl->auditLogger->Shutdown();
                pImpl->auditLogger.reset();
            }
            
            if (pImpl->securityManager) {
                pImpl->securityManager->Shutdown();
                pImpl->securityManager.reset();
            }
            
            m_state.store(EngineState::UNINITIALIZED, std::memory_order_release);
            
        } catch (...) {
            // SECURITY: Never throw from shutdown
            m_state.store(EngineState::ERROR, std::memory_order_release);
        }
    }

    EngineState JAMESEngine::GetState() const noexcept {
        return m_state.load(std::memory_order_acquire);
    }

    bool JAMESEngine::IsReady() const noexcept {
        return GetState() == EngineState::READY;
    }

    DeviceManager& JAMESEngine::GetDeviceManager() noexcept {
        // SECURITY: Return valid reference or abort
        if (!pImpl->deviceManager) {
            std::terminate(); // Better than returning invalid reference
        }
        return *pImpl->deviceManager;
    }

    const DeviceManager& JAMESEngine::GetDeviceManager() const noexcept {
        if (!pImpl->deviceManager) {
            std::terminate();
        }
        return *pImpl->deviceManager;
    }

    // ADDED: High-level device discovery method
    james::JAMESResult<std::vector<DeviceInfo>> JAMESEngine::DiscoverDevices() noexcept {
        try {
            // Check engine state
            if (!IsReady()) {
                return james::JAMESResult<std::vector<DeviceInfo>>::Failure(
                    "Engine not ready for device discovery"
                );
            }
            
            // Increment operation counter
            pImpl->operationCounter.fetch_add(1, std::memory_order_acq_rel);
            
            // Delegate to device manager
            auto result = pImpl->deviceManager->DiscoverDevices();
            
            // Log the operation
            if (pImpl->auditLogger) {
                if (result.IsSuccess()) {
                    auto devices = result.GetValue();
                    pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_DISCOVERY_COMPLETE,
                        "Device discovery completed, found " + std::to_string(devices.size()) + " devices",
                        AuditLevel::INFO);
                } else {
                    pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_ERROR,
                        "Device discovery failed: " + result.GetErrorMessage(),
                        AuditLevel::ERROR);
                }
            }
            
            return result;
            
        } catch (const std::exception& e) {
            return james::JAMESResult<std::vector<DeviceInfo>>::Failure(
                "Device discovery exception: " + std::string(e.what())
            );
        }
    }

    // ADDED: High-level evidence container creation method
    james::JAMESResult<std::string> JAMESEngine::CreateEvidenceContainer(
        const std::string& deviceId, 
        const std::string& examiner, 
        const std::string& caseNumber) noexcept {
        try {
            // Check engine state
            if (!IsReady()) {
                return james::JAMESResult<std::string>::Failure(
                    "Engine not ready for evidence creation"
                );
            }
            
            // Increment operation counter
            pImpl->operationCounter.fetch_add(1, std::memory_order_acq_rel);
            
            // Delegate to evidence manager
            auto result = pImpl->evidenceManager->CreateEvidenceContainer(deviceId, examiner, caseNumber);
            
            // Log the operation
            if (pImpl->auditLogger) {
                if (result.IsSuccess()) {
                    pImpl->auditLogger->LogEvent(AuditEvent::EVIDENCE_HASH_CREATED,
                        "Evidence container created for device " + deviceId + 
                        ", case " + caseNumber + ", examiner " + examiner,
                        AuditLevel::CRITICAL);
                } else {
                    pImpl->auditLogger->LogEvent(AuditEvent::EVIDENCE_HASH_MISMATCH,
                        "Evidence container creation failed: " + result.GetErrorMessage(),
                        AuditLevel::ERROR);
                }
            }
            
            return result;
            
        } catch (const std::exception& e) {
            return james::JAMESResult<std::string>::Failure(
                "Evidence container creation exception: " + std::string(e.what())
            );
        }
    }

    // SECURITY-CRITICAL: Tamper detection
    bool JAMESEngine::DetectTamper() const noexcept {
        if (!pImpl->securityManager) {
            return true; // Assume tampered if security manager unavailable
        }
        
        return pImpl->securityManager->IsTampered() || 
            pImpl->tamperDetected.load(std::memory_order_acquire);
    }

    // Increment operation counter for audit trail
    uint64_t JAMESEngine::GetOperationCount() const noexcept {
        return pImpl->operationCounter.load(std::memory_order_acquire);
    }

    std::string JAMESEngine::GetEngineInstanceId() const noexcept {
        return pImpl->engineInstanceId;
    }

} // namespace james::core