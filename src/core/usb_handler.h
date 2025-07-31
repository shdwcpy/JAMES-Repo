// =============================================================================
// 📁 FILE: src/core/usb_handler.h - COMPLETE HEADER
// =============================================================================

#pragma once

#include "james_common.h"
#include "james_result.h" 
#include "device_info.h"
#include "audit_logger.h"
#include "security_manager.h"
#include <string>
#include <memory>
#include <vector>

namespace james::core {

    class USBHandler {
    public:
        USBHandler(AuditLogger* auditLogger, SecurityManager* securityManager) noexcept;
        ~USBHandler() noexcept;
        
        // Handler lifecycle
        [[nodiscard]] james::JAMESResult<bool> Initialize() noexcept;
        void Shutdown() noexcept;
        
        // Device discovery and connection
        [[nodiscard]] james::JAMESResult<std::vector<DeviceInfo>> DiscoverDevices() noexcept;
        [[nodiscard]] james::JAMESResult<bool> ConnectToDevice(const std::string& deviceId) noexcept;
        [[nodiscard]] james::JAMESResult<bool> DisconnectDevice(const std::string& deviceId) noexcept;
        
        // Device information
        [[nodiscard]] james::JAMESResult<DeviceInfo> GetDeviceInfo(const std::string& deviceId) noexcept;

    private:
        struct USBHandlerImpl;
        std::unique_ptr<USBHandlerImpl> pImpl;
    };
} // namespace james::core
