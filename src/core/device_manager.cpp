// =============================================================================
// 📁 FILE: src/core/device_manager.cpp - FINAL PATCHED VERSION
// 🏷 REASONING: Complete device management implementation with all handlers
// =============================================================================

#include "device_manager.h"
#include "device_info.h"
#include "android_handler.h"
#include "ios_handler.h"
#include "usb_handler.h"
#include <algorithm>
#include <thread>
#include <sstream>

namespace james::core {

// SECURITY-CRITICAL: Device manager implementation
struct DeviceManager::DeviceManagerImpl {
    AuditLogger* auditLogger;
    SecurityManager* securityManager;
    
    // Device handlers - TEACHING: Strategy pattern for different device types
    std::unique_ptr<AndroidHandler> androidHandler;
    std::unique_ptr<iOSHandler> iosHandler;
    std::unique_ptr<USBHandler> usbHandler;
    
    // Connected devices tracking
    std::unordered_map<std::string, DeviceInfo> connectedDevices;
    std::mutex devicesMutex;
    
    // Discovery state
    std::atomic<bool> discoveryInProgress{false};
    std::atomic<uint32_t> discoveryCounter{0};
    
    DeviceManagerImpl(AuditLogger* audit, SecurityManager* security) 
        : auditLogger(audit), securityManager(security) {}
};

DeviceManager::DeviceManager(AuditLogger* auditLogger, SecurityManager* securityManager) noexcept
    : pImpl(std::make_unique<DeviceManagerImpl>(auditLogger, securityManager)) {
}

DeviceManager::~DeviceManager() noexcept {
    Shutdown();
}

// TEACHING: Why we initialize handlers in specific order
// Android first (most common), then iOS, then generic USB
james::JAMESResult<bool> DeviceManager::Initialize() noexcept {
    try {
        pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_DISCOVERY_START, 
            "Initializing device manager", AuditLevel::INFO);
        
        // Initialize Android handler first (most common forensic target)
        pImpl->androidHandler = std::make_unique<AndroidHandler>(
            pImpl->auditLogger, pImpl->securityManager);
        auto androidResult = pImpl->androidHandler->Initialize();
        if (!androidResult.IsSuccess()) {
            pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_ERROR, 
                "Android handler initialization failed: " + androidResult.GetErrorMessage(), 
                AuditLevel::ERROR);
            // Continue - other handlers might work
        }
        
        // Initialize iOS handler
        pImpl->iosHandler = std::make_unique<iOSHandler>(
            pImpl->auditLogger, pImpl->securityManager);
        auto iosResult = pImpl->iosHandler->Initialize();
        if (!iosResult.IsSuccess()) {
            pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_ERROR, 
                "iOS handler initialization failed: " + iosResult.GetErrorMessage(), 
                AuditLevel::ERROR);
        }
        
        // Initialize USB handler (for generic storage devices, SIM cards, etc.)
        pImpl->usbHandler = std::make_unique<USBHandler>(
            pImpl->auditLogger, pImpl->securityManager);
        auto usbResult = pImpl->usbHandler->Initialize();
        if (!usbResult.IsSuccess()) {
            pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_ERROR, 
                "USB handler initialization failed: " + usbResult.GetErrorMessage(), 
                AuditLevel::ERROR);
        }
        
        pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_DISCOVERY_COMPLETE, 
            "Device manager initialized successfully", AuditLevel::INFO);
        
        return james::JAMESResult<bool>::Success(true);
        
    } catch (const std::exception& e) {
        pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_ERROR, 
            std::string("Device manager initialization exception: ") + e.what(), 
            AuditLevel::ERROR);
        return james::JAMESResult<bool>::Failure(
            std::string("Device manager initialization failed: ") + e.what());
    }
}

void DeviceManager::Shutdown() noexcept {
    try {
        // Disconnect all devices first
        {
            std::lock_guard<std::mutex> lock(pImpl->devicesMutex);
            for (const auto& [deviceId, deviceInfo] : pImpl->connectedDevices) {
                pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_DISCONNECTED, 
                    "Device disconnected during shutdown: " + deviceId, 
                    AuditLevel::INFO, deviceId);
            }
            pImpl->connectedDevices.clear();
        }
        
        // Shutdown handlers in reverse order
        if (pImpl->usbHandler) {
            pImpl->usbHandler->Shutdown();
            pImpl->usbHandler.reset();
        }
        
        if (pImpl->iosHandler) {
            pImpl->iosHandler->Shutdown();
            pImpl->iosHandler.reset();
        }
        
        if (pImpl->androidHandler) {
            pImpl->androidHandler->Shutdown();
            pImpl->androidHandler.reset();
        }
        
    } catch (...) {
        // Never throw from shutdown
    }
}

// TEACHING: Device discovery is the cornerstone of forensic tools
// We need to detect ALL possible evidence sources reliably
james::JAMESResult<std::vector<DeviceInfo>> DeviceManager::DiscoverDevices() noexcept {
    try {
        // SECURITY: Prevent concurrent discovery operations
        bool expected = false;
        if (!pImpl->discoveryInProgress.compare_exchange_strong(expected, true)) {
            return james::JAMESResult<std::vector<DeviceInfo>>::Failure(
                "Device discovery already in progress");
        }
        
        // Increment discovery counter for audit trail
        auto discoveryId = pImpl->discoveryCounter.fetch_add(1, std::memory_order_acq_rel);
        
        std::ostringstream logMsg;
        logMsg << "Starting device discovery session #" << discoveryId;
        pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_DISCOVERY_START, 
            logMsg.str(), AuditLevel::INFO);
        
        std::vector<DeviceInfo> discoveredDevices;
        
        // PHASE 1: Android device discovery
        if (pImpl->androidHandler) {
            auto androidDevices = pImpl->androidHandler->DiscoverDevices();
            if (androidDevices.IsSuccess()) {
                const auto& devices = androidDevices.GetValue();
                discoveredDevices.insert(discoveredDevices.end(), 
                    devices.begin(), devices.end());
                
                std::ostringstream androidLog;
                androidLog << "Discovered " << devices.size() << " Android device(s)";
                pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_DISCOVERY_COMPLETE, 
                    androidLog.str(), AuditLevel::INFO);
            }
        }
        
        // PHASE 2: iOS device discovery  
        if (pImpl->iosHandler) {
            auto iosDevices = pImpl->iosHandler->DiscoverDevices();
            if (iosDevices.IsSuccess()) {
                const auto& devices = iosDevices.GetValue();
                discoveredDevices.insert(discoveredDevices.end(), 
                    devices.begin(), devices.end());
                
                std::ostringstream iosLog;
                iosLog << "Discovered " << devices.size() << " iOS device(s)";
                pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_DISCOVERY_COMPLETE, 
                    iosLog.str(), AuditLevel::INFO);
            }
        }
        
        // PHASE 3: Generic USB device discovery (storage, SIM readers, etc.)
        if (pImpl->usbHandler) {
            auto usbDevices = pImpl->usbHandler->DiscoverDevices();
            if (usbDevices.IsSuccess()) {
                const auto& devices = usbDevices.GetValue();
                discoveredDevices.insert(discoveredDevices.end(), 
                    devices.begin(), devices.end());
                
                std::ostringstream usbLog;
                usbLog << "Discovered " << devices.size() << " USB storage device(s)";
                pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_DISCOVERY_COMPLETE, 
                    usbLog.str(), AuditLevel::INFO);
            }
        }
        
        // Sort devices by type and name for consistent presentation
        std::sort(discoveredDevices.begin(), discoveredDevices.end(), 
            [](const DeviceInfo& a, const DeviceInfo& b) {
                if (a.deviceType != b.deviceType) {
                    return static_cast<int>(a.deviceType) < static_cast<int>(b.deviceType);
                }
                return a.friendlyName < b.friendlyName;
            });
        
        std::ostringstream finalLog;
        finalLog << "Discovery session #" << discoveryId << " completed. "
                 << "Total devices found: " << discoveredDevices.size();
        pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_DISCOVERY_COMPLETE, 
            finalLog.str(), AuditLevel::INFO);
        
        pImpl->discoveryInProgress.store(false, std::memory_order_release);
        
        return james::JAMESResult<std::vector<DeviceInfo>>::Success(std::move(discoveredDevices));
        
    } catch (const std::exception& e) {
        pImpl->discoveryInProgress.store(false, std::memory_order_release);
        pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_ERROR, 
            std::string("Device discovery exception: ") + e.what(), 
            AuditLevel::ERROR);
        return james::JAMESResult<std::vector<DeviceInfo>>::Failure(
            std::string("Device discovery failed: ") + e.what());
    }
}

// TEACHING: Connection establishment is security-critical
// We need to authenticate devices and establish secure channels
james::JAMESResult<bool> DeviceManager::ConnectToDevice(const std::string& deviceId) noexcept {
    try {
        std::lock_guard<std::mutex> lock(pImpl->devicesMutex);
        
        // Check if already connected
        if (pImpl->connectedDevices.find(deviceId) != pImpl->connectedDevices.end()) {
            return james::JAMESResult<bool>::Failure("Device already connected: " + deviceId);
        }
        
        pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_CONNECTED, 
            "Attempting to connect to device: " + deviceId, 
            AuditLevel::INFO, deviceId);
        
        // Determine device type and route to appropriate handler
        DeviceInfo deviceInfo;
        bool connectionSuccess = false;
        
        // Try Android handler first
        if (pImpl->androidHandler) {
            auto androidConnection = pImpl->androidHandler->ConnectToDevice(deviceId);
            if (androidConnection.IsSuccess()) {
                auto deviceInfoResult = pImpl->androidHandler->GetDeviceInfo(deviceId);
                if (deviceInfoResult.IsSuccess()) {
                    deviceInfo = deviceInfoResult.GetValue();
                    connectionSuccess = true;
                }
            }
        }
        
        // Try iOS handler if Android failed
        if (!connectionSuccess && pImpl->iosHandler) {
            auto iosConnection = pImpl->iosHandler->ConnectToDevice(deviceId);
            if (iosConnection.IsSuccess()) {
                auto deviceInfoResult = pImpl->iosHandler->GetDeviceInfo(deviceId);
                if (deviceInfoResult.IsSuccess()) {
                    deviceInfo = deviceInfoResult.GetValue();
                    connectionSuccess = true;
                }
            }
        }
        
        // Try USB handler if others failed
        if (!connectionSuccess && pImpl->usbHandler) {
            auto usbConnection = pImpl->usbHandler->ConnectToDevice(deviceId);
            if (usbConnection.IsSuccess()) {
                auto deviceInfoResult = pImpl->usbHandler->GetDeviceInfo(deviceId);
                if (deviceInfoResult.IsSuccess()) {
                    deviceInfo = deviceInfoResult.GetValue();
                    connectionSuccess = true;
                }
            }
        }
        
        if (connectionSuccess) {
            // Store device info
            pImpl->connectedDevices[deviceId] = deviceInfo;
            
            pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_CONNECTED, 
                "Successfully connected to device: " + deviceInfo.friendlyName, 
                AuditLevel::INFO, deviceId);
            
            return james::JAMESResult<bool>::Success(true);
        } else {
            pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_ERROR, 
                "Failed to connect to device: " + deviceId, 
                AuditLevel::ERROR, deviceId);
            
            return james::JAMESResult<bool>::Failure("Unable to connect to device: " + deviceId);
        }
        
    } catch (const std::exception& e) {
        pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_ERROR, 
            std::string("Device connection exception: ") + e.what(), 
            AuditLevel::ERROR, deviceId);
        return james::JAMESResult<bool>::Failure(
            std::string("Device connection failed: ") + e.what());
    }
}

james::JAMESResult<bool> DeviceManager::DisconnectDevice(const std::string& deviceId) noexcept {
    try {
        std::lock_guard<std::mutex> lock(pImpl->devicesMutex);
        
        auto deviceIt = pImpl->connectedDevices.find(deviceId);
        if (deviceIt == pImpl->connectedDevices.end()) {
            return james::JAMESResult<bool>::Failure("Device not connected: " + deviceId);
        }
        
        const DeviceInfo& deviceInfo = deviceIt->second;
        
        // Disconnect from appropriate handler based on device type
        bool disconnectionSuccess = false;
        
        switch (deviceInfo.deviceType) {
            case DeviceType::ANDROID:
                if (pImpl->androidHandler) {
                    auto result = pImpl->androidHandler->DisconnectDevice(deviceId);
                    disconnectionSuccess = result.IsSuccess();
                }
                break;
                
            case DeviceType::IOS:
                if (pImpl->iosHandler) {
                    auto result = pImpl->iosHandler->DisconnectDevice(deviceId);
                    disconnectionSuccess = result.IsSuccess();
                }
                break;
                
            default:
                if (pImpl->usbHandler) {
                    auto result = pImpl->usbHandler->DisconnectDevice(deviceId);
                    disconnectionSuccess = result.IsSuccess();
                }
                break;
        }
        
        if (disconnectionSuccess) {
            pImpl->connectedDevices.erase(deviceIt);
            
            pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_DISCONNECTED, 
                "Successfully disconnected device: " + deviceInfo.friendlyName, 
                AuditLevel::INFO, deviceId);
            
            return james::JAMESResult<bool>::Success(true);
        } else {
            pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_ERROR, 
                "Failed to disconnect device: " + deviceId, 
                AuditLevel::ERROR, deviceId);
            
            return james::JAMESResult<bool>::Failure("Failed to disconnect device: " + deviceId);
        }
        
    } catch (const std::exception& e) {
        pImpl->auditLogger->LogEvent(AuditEvent::DEVICE_ERROR, 
            std::string("Device disconnection exception: ") + e.what(), 
            AuditLevel::ERROR, deviceId);
        return james::JAMESResult<bool>::Failure(
            std::string("Device disconnection failed: ") + e.what());
    }
}

james::JAMESResult<DeviceInfo> DeviceManager::GetDeviceInfo(const std::string& deviceId) const noexcept {
    try {
        std::lock_guard<std::mutex> lock(pImpl->devicesMutex);
        
        auto deviceIt = pImpl->connectedDevices.find(deviceId);
        if (deviceIt == pImpl->connectedDevices.end()) {
            return james::JAMESResult<DeviceInfo>::Failure("Device not connected: " + deviceId);
        }
        
        return james::JAMESResult<DeviceInfo>::Success(deviceIt->second);
        
    } catch (const std::exception& e) {
        return james::JAMESResult<DeviceInfo>::Failure(
            std::string("Failed to get device info: ") + e.what());
    }
}

bool DeviceManager::IsDeviceConnected(const std::string& deviceId) const noexcept {
    try {
        std::lock_guard<std::mutex> lock(pImpl->devicesMutex);
        return pImpl->connectedDevices.find(deviceId) != pImpl->connectedDevices.end();
    } catch (...) {
        return false;
    }
}

std::vector<std::string> DeviceManager::GetConnectedDevices() const noexcept {
    try {
        std::lock_guard<std::mutex> lock(pImpl->devicesMutex);
        
        std::vector<std::string> deviceIds;
        deviceIds.reserve(pImpl->connectedDevices.size());
        
        for (const auto& [deviceId, deviceInfo] : pImpl->connectedDevices) {
            deviceIds.push_back(deviceId);
        }
        
        return deviceIds;
        
    } catch (...) {
        return {};
    }
}

} // namespace james::core
