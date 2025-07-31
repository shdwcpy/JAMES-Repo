#pragma once

#include "james_common.h"
#include "james_result.h"
#include "device_info.h"
#include <string>
#include <cstdint>
#include <vector>
#include <cstdint>
#include <memory>
#include <cstdint>

namespace james::core {

    class AuditLogger;
    class SecurityManager;

    class DeviceManager {
    public:
        DeviceManager(AuditLogger* auditLogger, SecurityManager* securityManager) noexcept;
        ~DeviceManager() noexcept;

        [[nodiscard]] james::JAMESResult<bool> Initialize() noexcept;
        void Shutdown() noexcept;

        [[nodiscard]] james::JAMESResult<std::vector<DeviceInfo>> DiscoverDevices() noexcept;
        [[nodiscard]] james::JAMESResult<bool> ConnectToDevice(const std::string& deviceId) noexcept;
        [[nodiscard]] james::JAMESResult<bool> DisconnectDevice(const std::string& deviceId) noexcept;
        
        [[nodiscard]] james::JAMESResult<DeviceInfo> GetDeviceInfo(const std::string& deviceId) const noexcept;
        [[nodiscard]] bool IsDeviceConnected(const std::string& deviceId) const noexcept;
        [[nodiscard]] std::vector<std::string> GetConnectedDevices() const noexcept;

    private:
        struct DeviceManagerImpl;
        std::unique_ptr<DeviceManagerImpl> pImpl;
    };

} // namespace james::core
