// =============================================================================
// 📁 FILE: src/core/james_engine.h - COMPLETE HEADER WITH MISSING METHODS
// =============================================================================

#pragma once

#include "james_common.h"
#include "james_result.h"
#include "device_info.h"
#include <memory>
#include <atomic>
#include <mutex>
#include <cstdint>
#include <vector>
#include <string>

namespace james::core {

    // Forward declarations
    class DeviceManager;
    class AuditLogger;
    class SecurityManager;
    class EvidenceManager;

    enum class EngineState : uint8_t {
        UNINITIALIZED = 0,
        INITIALIZING = 1,
        READY = 2,
        PROCESSING = 3,
        ERROR = 4,
        SHUTTING_DOWN = 5
    };

    class JAMESEngine {
    public:
        JAMESEngine() noexcept;
        ~JAMESEngine() noexcept;

        [[nodiscard]] james::JAMESResult<bool> Initialize() noexcept;
        void Shutdown() noexcept;

        [[nodiscard]] EngineState GetState() const noexcept;
        [[nodiscard]] bool IsReady() const noexcept;

        // Component access methods
        [[nodiscard]] DeviceManager& GetDeviceManager() noexcept;
        [[nodiscard]] const DeviceManager& GetDeviceManager() const noexcept;

        // ADDED: High-level API methods that main.cpp expects
        [[nodiscard]] james::JAMESResult<std::vector<DeviceInfo>> DiscoverDevices() noexcept;
        [[nodiscard]] james::JAMESResult<std::string> CreateEvidenceContainer(
            const std::string& deviceId, 
            const std::string& examiner, 
            const std::string& caseNumber) noexcept;

        // Security and monitoring
        [[nodiscard]] bool DetectTamper() const noexcept;
        [[nodiscard]] uint64_t GetOperationCount() const noexcept;
        [[nodiscard]] std::string GetEngineInstanceId() const noexcept;

    private:
        struct JAMESEngineImpl;
        std::unique_ptr<JAMESEngineImpl> pImpl;
        
        std::atomic<EngineState> m_state{EngineState::UNINITIALIZED};
        mutable std::mutex m_stateMutex;
    };

} // namespace james::core