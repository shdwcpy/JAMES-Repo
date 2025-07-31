// =============================================================================
// 📁 FILE: src/core/android_handler.h - COMPLETE HEADER
// =============================================================================

#pragma once

#include "james_common.h"
#include "james_result.h"
#include "device_info.h"
#include <string>
#include <memory>
#include <vector>
#include <cstdint>

namespace james::core {

    class AuditLogger;
    class SecurityManager;

    enum class AndroidExtractionMethod : uint8_t {
        LOGICAL = 1,
        PHYSICAL = 2,
        FILE_SYSTEM = 3,
        ADB_BACKUP = 4,
        FASTBOOT = 5,
        CUSTOM_RECOVERY = 6
    };

    class AndroidHandler {
    public:
        AndroidHandler(AuditLogger* auditLogger, SecurityManager* securityManager) noexcept;
        ~AndroidHandler() noexcept;

        [[nodiscard]] james::JAMESResult<bool> Initialize() noexcept;
        void Shutdown() noexcept;

        [[nodiscard]] james::JAMESResult<std::vector<DeviceInfo>> DiscoverDevices() noexcept;
        [[nodiscard]] james::JAMESResult<bool> ConnectToDevice(const std::string& deviceId) noexcept;
        [[nodiscard]] james::JAMESResult<bool> DisconnectDevice(const std::string& deviceId) noexcept;

        [[nodiscard]] james::JAMESResult<DeviceInfo> GetDeviceInfo(const std::string& deviceId) noexcept;
        [[nodiscard]] james::JAMESResult<std::vector<AndroidExtractionMethod>> 
            GetSupportedMethods(const std::string& deviceId) noexcept;

        [[nodiscard]] james::JAMESResult<bool> EnableADBDebugging(const std::string& deviceId) noexcept;
        [[nodiscard]] james::JAMESResult<bool> CheckRootStatus(const std::string& deviceId) noexcept;
        [[nodiscard]] james::JAMESResult<std::string> ExecuteADBCommand(
            const std::string& deviceId, const std::string& command) noexcept;

        [[nodiscard]] james::JAMESResult<bool> PrepareForExtraction(
            const std::string& deviceId, AndroidExtractionMethod method) noexcept;

    private:
        struct AndroidHandlerImpl;
        std::unique_ptr<AndroidHandlerImpl> pImpl;
    };

} // namespace james::core