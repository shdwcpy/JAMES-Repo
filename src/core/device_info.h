// =============================================================================
// 📁 FILE: src/core/device_info.h - FINAL PATCHED VERSION
// 🏷 REASONING: Complete device metadata structure with forensic requirements
// =============================================================================

#pragma once

#include "james_common.h"
#include <string>
#include <chrono>
#include <vector>
#include <cstdint>

namespace james::core {

// Enhanced device type enumeration for comprehensive forensic coverage
enum class DeviceType : uint8_t {
    UNKNOWN = 0,
    
    // Mobile devices
    ANDROID = 1,
    IOS = 2,
    WINDOWS_MOBILE = 3,
    BLACKBERRY = 4,
    
    // Storage devices
    USB_STORAGE = 10,
    SD_CARD = 11,
    MICRO_SD = 12,
    CF_CARD = 13,
    
    // SIM and cellular
    SIM_CARD = 20,
    ESIM = 21,
    
    // IoT and specialized devices
    DRONE = 30,
    GPS_DEVICE = 31,
    CAMERA = 32,
    SMARTWATCH = 33,
    VEHICLE_INFOTAINMENT = 34,
    
    // Custom/Unknown
    CUSTOM = 255
};

// Device security state for forensic assessment
enum class SecurityState : uint8_t {
    UNKNOWN = 0,
    UNLOCKED = 1,           // Device is unlocked and accessible
    LOCKED = 2,             // Device is locked with PIN/password/pattern
    ENCRYPTED = 3,          // Device has encryption enabled
    ROOTED_JAILBROKEN = 4,  // Device has been rooted/jailbroken
    DEVELOPER_MODE = 5,     // Developer options enabled
    ADB_ENABLED = 6,        // ADB debugging enabled
    BOOTLOADER_UNLOCKED = 7,// Bootloader is unlocked
    FASTBOOT_MODE = 8,      // Device in fastboot/download mode
    RECOVERY_MODE = 9,      // Device in recovery mode
    DFU_MODE = 10          // Device in DFU (Device Firmware Update) mode
};

// Connection interface types
enum class ConnectionInterface : uint8_t {
    UNKNOWN = 0,
    USB = 1,
    WIFI = 2,
    BLUETOOTH = 3,
    LIGHTNING = 4,      // iOS Lightning connector
    USB_C = 5,
    MICRO_USB = 6,
    PROPRIETARY = 7     // Custom connector
};

// Comprehensive device information structure for forensic operations
struct DeviceInfo {
    // === BASIC IDENTIFICATION ===
    std::string deviceId;           // Unique device identifier (serial, UDID, etc.)
    std::string serialNumber;       // Hardware serial number
    std::string imei;              // IMEI (for cellular devices)
    std::string imsi;              // IMSI (SIM card identifier)
    DeviceType deviceType;          // Type of device
    std::string friendlyName;       // Human-readable name
    std::string manufacturer;       // Device manufacturer (Apple, Samsung, etc.)
    std::string model;              // Device model (iPhone 13, Galaxy S21, etc.)
    std::string marketingName;      // Marketing name if different from model
    
    // === SOFTWARE INFORMATION ===
    std::string osVersion;          // Operating system version
    std::string osName;             // OS name (iOS, Android, etc.)
    std::string buildNumber;        // OS build number
    std::string kernelVersion;      // Kernel version (if available)
    std::string bootloaderVersion;  // Bootloader version
    std::string basebandVersion;    // Baseband/modem firmware version
    std::vector<std::string> securityPatches; // Installed security patches
    
    // === HARDWARE SPECIFICATIONS ===
    std::string cpuArchitecture;    // CPU architecture (arm64, armv7, x86_64, etc.)
    std::string chipset;            // Chipset name (A15 Bionic, Snapdragon 888, etc.)
    uint64_t totalStorage;          // Total storage capacity in bytes
    uint64_t availableStorage;      // Available storage in bytes
    uint64_t totalRam;              // Total RAM in bytes
    uint64_t availableRam;          // Available RAM in bytes
    std::string displayResolution;  // Screen resolution (1920x1080, etc.)
    
    // === SECURITY ASSESSMENT ===
    SecurityState securityState;    // Current security state
    bool isEncrypted;              // Full disk encryption status
    bool isRooted;                 // Root/jailbreak status
    bool isDebuggingEnabled;       // Debug mode status
    bool hasSecureBootEnabled;     // Secure boot status
    bool hasTEEEnabled;            // Trusted Execution Environment
    bool isMDMManaged;             // Mobile Device Management status
    std::string encryptionType;     // Type of encryption (AES-256, etc.)
    std::string lockscreenType;     // Lockscreen type (PIN, password, biometric)
    
    // === NETWORK INFORMATION ===
    std::string wifiMacAddress;     // WiFi MAC address
    std::string bluetoothAddress;   // Bluetooth MAC address
    std::string ipAddress;          // Current IP address
    std::string carrierName;        // Mobile carrier name
    std::string networkType;        // Network type (4G, 5G, WiFi)
    
    // === INSTALLED APPLICATIONS ===
    std::vector<std::string> installedApps;     // List of installed applications
    std::vector<std::string> systemApps;       // System applications
    std::vector<std::string> hiddenApps;       // Hidden/disabled applications
    uint32_t totalAppCount;                     // Total number of apps
    
    // === FORENSIC METADATA ===
    std::chrono::system_clock::time_point discoveryTime;     // When device was discovered
    std::chrono::system_clock::time_point lastSeen;          // Last successful communication
    std::chrono::system_clock::time_point lastBootTime;      // Last boot time (if available)
    ConnectionInterface connectionInterface;                  // How device is connected
    std::string connectionInterfaceDetails;                   // Additional connection info
    bool isSupported;                                        // Whether extraction is supported
    std::vector<std::string> supportedMethods;              // Available extraction methods
    std::string forensicNotes;                              // Additional forensic notes
    
    // === ACQUISITION INFORMATION ===
    std::string acquisitionHash;    // Hash of device state at discovery
    std::string examinerName;       // Name of examiner
    std::string caseNumber;         // Associated case number
    std::string evidenceNumber;     // Evidence tag number
    std::string acquisitionTool;    // Tool used for acquisition
    std::string acquisitionVersion; // Tool version
    
    // === BATTERY AND POWER ===
    int batteryLevel;              // Current battery percentage (0-100, -1 if unknown)
    bool isCharging;               // Whether device is currently charging
    std::string powerState;        // Power state details
    
    // Default constructor with secure defaults
    DeviceInfo() 
        : deviceType(DeviceType::UNKNOWN)
        , totalStorage(0)
        , availableStorage(0)
        , totalRam(0)
        , availableRam(0)
        , securityState(SecurityState::UNKNOWN)
        , isEncrypted(false)
        , isRooted(false)
        , isDebuggingEnabled(false)
        , hasSecureBootEnabled(false)
        , hasTEEEnabled(false)
        , isMDMManaged(false)
        , totalAppCount(0)
        , discoveryTime(std::chrono::system_clock::now())
        , lastSeen(std::chrono::system_clock::now())
        , connectionInterface(ConnectionInterface::UNKNOWN)
        , isSupported(false)
        , batteryLevel(-1)
        , isCharging(false) {}
    
    // === UTILITY FUNCTIONS ===
    
    [[nodiscard]] std::string GetTypeString() const noexcept {
        switch (deviceType) {
            case DeviceType::ANDROID: return "Android";
            case DeviceType::IOS: return "iOS";
            case DeviceType::WINDOWS_MOBILE: return "Windows Mobile";
            case DeviceType::BLACKBERRY: return "BlackBerry";
            case DeviceType::USB_STORAGE: return "USB Storage";
            case DeviceType::SD_CARD: return "SD Card";
            case DeviceType::MICRO_SD: return "MicroSD Card";
            case DeviceType::CF_CARD: return "CompactFlash Card";
            case DeviceType::SIM_CARD: return "SIM Card";
            case DeviceType::ESIM: return "eSIM";
            case DeviceType::DRONE: return "Drone";
            case DeviceType::GPS_DEVICE: return "GPS Device";
            case DeviceType::CAMERA: return "Digital Camera";
            case DeviceType::SMARTWATCH: return "Smartwatch";
            case DeviceType::VEHICLE_INFOTAINMENT: return "Vehicle Infotainment";
            case DeviceType::CUSTOM: return "Custom Device";
            default: return "Unknown";
        }
    }
    
    [[nodiscard]] std::string GetSecurityString() const noexcept {
        switch (securityState) {
            case SecurityState::UNLOCKED: return "Unlocked";
            case SecurityState::LOCKED: return "Locked";
            case SecurityState::ENCRYPTED: return "Encrypted";
            case SecurityState::ROOTED_JAILBROKEN: return "Rooted/Jailbroken";
            case SecurityState::DEVELOPER_MODE: return "Developer Mode";
            case SecurityState::ADB_ENABLED: return "ADB Enabled";
            case SecurityState::BOOTLOADER_UNLOCKED: return "Bootloader Unlocked";
            case SecurityState::FASTBOOT_MODE: return "Fastboot Mode";
            case SecurityState::RECOVERY_MODE: return "Recovery Mode";
            case SecurityState::DFU_MODE: return "DFU Mode";
            default: return "Unknown";
        }
    }
    
    [[nodiscard]] std::string GetConnectionString() const noexcept {
        switch (connectionInterface) {
            case ConnectionInterface::USB: return "USB";
            case ConnectionInterface::WIFI: return "WiFi";
            case ConnectionInterface::BLUETOOTH: return "Bluetooth";
            case ConnectionInterface::LIGHTNING: return "Lightning";
            case ConnectionInterface::USB_C: return "USB-C";
            case ConnectionInterface::MICRO_USB: return "Micro USB";
            case ConnectionInterface::PROPRIETARY: return "Proprietary";
            default: return "Unknown";
        }
    }
    
    // TEACHING: Forensic feasibility assessment
    // This determines if we can extract data from the device based on its current state
    [[nodiscard]] bool IsExtractionFeasible() const noexcept {
        // Basic requirements: device must be supported and have extraction methods
        if (!isSupported || supportedMethods.empty()) {
            return false;
        }
        
        // Check security state - some states allow extraction
        switch (securityState) {
            case SecurityState::UNLOCKED:
            case SecurityState::ADB_ENABLED:
            case SecurityState::ROOTED_JAILBROKEN:
            case SecurityState::DEVELOPER_MODE:
            case SecurityState::FASTBOOT_MODE:
            case SecurityState::RECOVERY_MODE:
            case SecurityState::DFU_MODE:
                return true;
                
            case SecurityState::BOOTLOADER_UNLOCKED:
                // Bootloader unlocked allows some extraction methods
                return true;
                
            case SecurityState::LOCKED:
            case SecurityState::ENCRYPTED:
                // May still be possible with specialized techniques
                // Check if we have bypass methods available
                for (const auto& method : supportedMethods) {
                    if (method.find("Physical") != std::string::npos ||
                        method.find("Chip-off") != std::string::npos ||
                        method.find("JTAG") != std::string::npos) {
                        return true;
                    }
                }
                return false;
                
            default:
                return false;
        }
    }
    
    // Calculate forensic priority score (higher = more urgent/valuable)
    [[nodiscard]] int GetForensicPriority() const noexcept {
        int priority = 0;
        
        // Device type priority
        switch (deviceType) {
            case DeviceType::ANDROID:
            case DeviceType::IOS:
                priority += 100; // Mobile devices are highest priority
                break;
            case DeviceType::USB_STORAGE:
            case DeviceType::SD_CARD:
                priority += 80; // Storage devices are high priority
                break;
            case DeviceType::DRONE:
            case DeviceType::GPS_DEVICE:
                priority += 60; // IoT devices medium-high priority
                break;
            default:
                priority += 40; // Other devices medium priority
                break;
        }
        
        // Security state adjustments
        if (securityState == SecurityState::UNLOCKED) priority += 50;
        if (securityState == SecurityState::ADB_ENABLED) priority += 40;
        if (isRooted) priority += 30;
        if (securityState == SecurityState::ENCRYPTED) priority -= 20;
        
        // Battery level consideration (for mobile devices)
        if (deviceType == DeviceType::ANDROID || deviceType == DeviceType::IOS) {
            if (batteryLevel > 0) {
                if (batteryLevel < 10) priority -= 30; // Very low battery - urgent
                else if (batteryLevel < 25) priority -= 10; // Low battery
                else if (batteryLevel > 80) priority += 10; // Good battery level
            }
        }
        
        // Connection stability
        if (connectionInterface == ConnectionInterface::USB || 
            connectionInterface == ConnectionInterface::USB_C) {
            priority += 20; // Stable connection
        }
        
        return std::max(0, priority); // Ensure non-negative
    }
    
    // Get human-readable device summary for forensic reports
    [[nodiscard]] std::string GetDeviceSummary() const noexcept {
        std::ostringstream summary;
        
        summary << GetTypeString();
        if (!manufacturer.empty()) {
            summary << " (" << manufacturer;
            if (!model.empty()) {
                summary << " " << model;
            }
            summary << ")";
        }
        
        if (!osVersion.empty()) {
            summary << " - " << osName << " " << osVersion;
        }
        
        summary << " [" << GetSecurityString() << "]";
        
        if (batteryLevel >= 0) {
            summary << " Battery: " << batteryLevel << "%";
        }
        
        return summary.str();
    }
    
    // Check if device has specific capability
    [[nodiscard]] bool HasCapability(const std::string& capability) const noexcept {
        // Convert to lowercase for case-insensitive comparison
        std::string lowerCap = capability;
        std::transform(lowerCap.begin(), lowerCap.end(), lowerCap.begin(), ::tolower);
        
        for (const auto& method : supportedMethods) {
            std::string lowerMethod = method;
            std::transform(lowerMethod.begin(), lowerMethod.end(), lowerMethod.begin(), ::tolower);
            if (lowerMethod.find(lowerCap) != std::string::npos) {
                return true;
            }
        }
        
        return false;
    }
    
    // Get storage utilization percentage
    [[nodiscard]] double GetStorageUtilization() const noexcept {
        if (totalStorage == 0) return 0.0;
        
        uint64_t usedStorage = totalStorage - availableStorage;
        return (static_cast<double>(usedStorage) / static_cast<double>(totalStorage)) * 100.0;
    }
    
    // Check if device is in a forensically advantageous state
    [[nodiscard]] bool IsForensicallyAdvantaged() const noexcept {
        return isRooted || 
               securityState == SecurityState::UNLOCKED ||
               securityState == SecurityState::ADB_ENABLED ||
               securityState == SecurityState::DEVELOPER_MODE ||
               securityState == SecurityState::BOOTLOADER_UNLOCKED ||
               securityState == SecurityState::FASTBOOT_MODE ||
               securityState == SecurityState::RECOVERY_MODE ||
               securityState == SecurityState::DFU_MODE;
    }
    
    // Get time since last communication
    [[nodiscard]] std::chrono::seconds GetTimeSinceLastSeen() const noexcept {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::seconds>(now - lastSeen);
    }
    
    // Update last seen timestamp
    void UpdateLastSeen() noexcept {
        lastSeen = std::chrono::system_clock::now();
    }
    
    // Validate device information integrity
    [[nodiscard]] bool IsValid() const noexcept {
        // Basic validation checks
        if (deviceId.empty()) return false;
        if (deviceType == DeviceType::UNKNOWN) return false;
        if (friendlyName.empty()) return false;
        
        // Logical consistency checks
        if (totalStorage > 0 && availableStorage > totalStorage) return false;
        if (totalRam > 0 && availableRam > totalRam) return false;
        if (batteryLevel > 100) return false;
        
        return true;
    }
    
    // Get forensic evidence identifier
    [[nodiscard]] std::string GetEvidenceIdentifier() const noexcept {
        std::ostringstream identifier;
        
        if (!caseNumber.empty()) {
            identifier << caseNumber << "_";
        }
        
        if (!evidenceNumber.empty()) {
            identifier << evidenceNumber << "_";
        }
        
        identifier << GetTypeString() << "_";
        
        if (!serialNumber.empty()) {
            identifier << serialNumber;
        } else {
            identifier << deviceId;
        }
        
        return identifier.str();
    }
};

} // namespace james::core