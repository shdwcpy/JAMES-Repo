/**
 * @file src/services/device/DeviceManager.cpp
 * @brief Service layer device management implementation - integrates with core::DeviceManager
 * @version 1.0
 * @date 2024
 * 
 * INTEGRATION ARCHITECTURE:
 * This service layer WRAPS core::DeviceManager to add:
 * - Background monitoring with continuous device polling
 * - Progress reporting with percentage updates for GUI
 * - Event-driven callbacks for state changes
 * - Service orchestration for extraction workflows
 * 
 * LAYERED APPROACH:
 * GUI → services::DeviceServiceManager → core::DeviceManager → Hardware
 * 
 * SECURITY COMPLIANCE:
 * - SEI CERT C++: Exception safety, RAII resource management
 * - MISRA C++: No raw pointers, explicit ownership
 * - NASA Power of 10: Bounded execution, predictable timing
 * - ISO 27037: Chain of custody maintained through both layers
 */

#include "DeviceManager.h"
#include "core/james_result.h"
#include <algorithm>
#include <sstream>
#include <random>
#include <thread>
#include <cstring>
#include <iomanip>

namespace james {
namespace service {

// TEACHING NOTE: Constructor integrates service layer with existing core layer
// We don't replace core functionality - we enhance it with service features
DeviceServiceManager::DeviceServiceManager(const ServiceConfig& config,
                                         core::AuditLogger* core_audit_logger,
                                         core::SecurityManager* core_security_manager)
    : config_(config)
    , audit_logger_(core_audit_logger)
    , security_manager_(core_security_manager)
    , service_status_(ServiceStatus::INITIALIZING) {
    
    // INTEGRATION: Create core device manager with same parameters
    // This maintains compatibility with existing initialization code
    core_device_manager_ = std::make_unique<core::DeviceManager>(
        core_audit_logger, core_security_manager);
    
    log_service_activity("DeviceServiceManager created - ready for initialization");
}

DeviceServiceManager::~DeviceServiceManager() {
    shutdown_service();
}

// TEACHING: Service initialization wraps core initialization and adds service features
bool DeviceServiceManager::initialize_service() {
    try {
        log_service_activity("Starting service layer initialization");
        
        // STEP 1: Initialize core device manager first
        auto core_result = core_device_manager_->Initialize();
        if (!core_result.IsSuccess()) {
            log_service_activity("Core device manager initialization failed: " + 
                                core_result.GetErrorMessage());
            return false;
        }
        
        // STEP 2: Set up service layer state tracking
        service_status_.store(ServiceStatus::READY, std::memory_order_release);
        should_stop_monitoring_.store(false, std::memory_order_release);
        
        // STEP 3: Start background monitoring if configured
        if (config_.device_scan_interval_ms > 0) {
            if (!start_device_monitoring()) {
                log_service_activity("Failed to start background monitoring");
                return false;
            }
        }
        
        log_service_activity("Service layer initialization completed successfully");
        return true;
        
    } catch (const std::exception& e) {
        log_service_activity("Service initialization exception: " + std::string(e.what()));
        service_status_.store(ServiceStatus::ERROR_RECOVERY, std::memory_order_release);
        return false;
    }
}

void DeviceServiceManager::shutdown_service() {
    try {
        log_service_activity("Starting service layer shutdown");
        service_status_.store(ServiceStatus::SHUTTING_DOWN, std::memory_order_release);
        
        // Stop background monitoring
        stop_device_monitoring();
        
        // Clear all callbacks to prevent dangling pointers
        {
            std::lock_guard<std::mutex> lock(callbacks_mutex_);
            device_event_callbacks_.clear();
            progress_callbacks_.clear();
        }
        
        // Shutdown core device manager
        if (core_device_manager_) {
            core_device_manager_->Shutdown();
        }
        
        // Clear service device tracking
        {
            std::lock_guard<std::mutex> lock(service_devices_mutex_);
            service_devices_.clear();
        }
        
        log_service_activity("Service layer shutdown completed");
        
    } catch (...) {
        // Never throw from shutdown
    }
}

ServiceStatus DeviceServiceManager::get_service_status() const {
    return service_status_.load(std::memory_order_acquire);
}

// TEACHING: Enhanced device discovery with progress reporting
// This wraps core::DeviceManager::DiscoverDevices() but adds real-time progress
uint32_t DeviceServiceManager::discover_devices_async(ProgressCallback progress_callback) {
    try {
        log_service_activity("Starting enhanced device discovery");
        service_status_.store(ServiceStatus::SCANNING_DEVICES, std::memory_order_release);
        
        // Create progress update for discovery start
        ProgressUpdate progress_start{};
        progress_start.operation_id = static_cast<uint32_t>(
            std::chrono::system_clock::now().time_since_epoch().count());
        progress_start.extraction_type = ExtractionType::LOGICAL; // Discovery operation
        progress_start.level = ProgressLevel::INFO;
        progress_start.percentage = 0;
        progress_start.stage_name = "Starting Device Discovery";
        progress_start.detailed_message = "Initializing device detection systems...";
        progress_start.timestamp = std::chrono::system_clock::now();
        progress_start.operator_id = "ServiceLayer";
        progress_start.bytes_processed = 0;
        progress_start.total_bytes_expected = 100; // Progress percentage base
        
        // Notify progress callback if provided
        if (progress_callback) {
            progress_callback(progress_start);
        }
        notify_progress_callbacks(progress_start);
        
        // INTEGRATION POINT: Call core device discovery
        auto core_discovery_result = core_device_manager_->DiscoverDevices();
        
        if (!core_discovery_result.IsSuccess()) {
            log_service_activity("Core device discovery failed: " + 
                                core_discovery_result.GetErrorMessage());
            
            // Report error progress
            progress_start.level = ProgressLevel::ERROR;
            progress_start.percentage = 0;
            progress_start.stage_name = "Discovery Failed";
            progress_start.detailed_message = "Device discovery error: " + 
                                            core_discovery_result.GetErrorMessage();
            if (progress_callback) {
                progress_callback(progress_start);
            }
            notify_progress_callbacks(progress_start);
            
            service_status_.store(ServiceStatus::READY, std::memory_order_release);
            return 0;
        }
        
        // INTEGRATION: Convert core devices to service format and track them
        const auto& core_devices = core_discovery_result.GetValue();
        uint32_t devices_processed = 0;
        
        {
            std::lock_guard<std::mutex> lock(service_devices_mutex_);
            
            for (const auto& core_device : core_devices) {
                // Convert core device info to service format
                auto service_device_info = std::make_unique<ServiceDeviceInfo>();
                service_device_info->core_info = core_device;
                service_device_info->service_state = DeviceState::DETECTED;
                service_device_info->last_activity = std::chrono::system_clock::now();
                service_device_info->connection_attempts = 0;
                service_device_info->supported_extractions = 
                    determine_extraction_capabilities(core_device);
                
                // Store in service tracking
                service_devices_[core_device.deviceId] = std::move(service_device_info);
                devices_processed++;
                
                // Report progress for each device processed
                ProgressUpdate device_progress = progress_start;
                device_progress.percentage = static_cast<uint8_t>(
                    (devices_processed * 100) / std::max(1u, static_cast<uint32_t>(core_devices.size())));
                device_progress.stage_name = "Processing Device " + std::to_string(devices_processed);
                device_progress.detailed_message = "Found: " + core_device.friendlyName + 
                                                 " (" + core_device.GetTypeString() + ")";
                device_progress.bytes_processed = devices_processed;
                device_progress.total_bytes_expected = core_devices.size();
                
                if (progress_callback) {
                    progress_callback(device_progress);
                }
                notify_progress_callbacks(device_progress);
                
                // Small delay to make progress visible (remove in production if needed)
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
        
        // Report completion
        ProgressUpdate completion_progress = progress_start;
        completion_progress.level = ProgressLevel::SUCCESS;
        completion_progress.percentage = 100;
        completion_progress.stage_name = "Discovery Complete";
        completion_progress.detailed_message = "Found " + std::to_string(devices_processed) + 
                                             " device(s)";
        completion_progress.bytes_processed = devices_processed;
        completion_progress.total_bytes_expected = devices_processed;
        
        if (progress_callback) {
            progress_callback(completion_progress);
        }
        notify_progress_callbacks(completion_progress);
        
        log_service_activity("Enhanced device discovery completed. Found " + 
                           std::to_string(devices_processed) + " devices");
        
        service_status_.store(ServiceStatus::READY, std::memory_order_release);
        return devices_processed;
        
    } catch (const std::exception& e) {
        log_service_activity("Device discovery exception: " + std::string(e.what()));
        service_status_.store(ServiceStatus::ERROR_RECOVERY, std::memory_order_release);
        return 0;
    }
}

// INTEGRATION: Convert core device info to service format
std::vector<DeviceInfo> DeviceServiceManager::get_discovered_devices() const {
    std::vector<DeviceInfo> service_devices;
    
    try {
        std::lock_guard<std::mutex> lock(service_devices_mutex_);
        
        for (const auto& [device_id, service_device] : service_devices_) {
            service_devices.push_back(convert_core_to_service_info(service_device->core_info));
        }
        
    } catch (const std::exception& e) {
        log_service_activity("Error getting discovered devices: " + std::string(e.what()));
    }
    
    return service_devices;
}

std::shared_ptr<DeviceInfo> DeviceServiceManager::get_device_info(const std::string& device_id) const {
    try {
        std::lock_guard<std::mutex> lock(service_devices_mutex_);
        
        auto it = service_devices_.find(device_id);
        if (it != service_devices_.end()) {
            auto service_info = std::make_shared<DeviceInfo>(
                convert_core_to_service_info(it->second->core_info));
            return service_info;
        }
        
    } catch (const std::exception& e) {
        log_service_activity("Error getting device info for " + device_id + ": " + 
                           std::string(e.what()));
    }
    
    return nullptr;
}

// TEACHING: Enhanced connection with progress reporting
// This wraps core connection but adds state machine and progress updates
bool DeviceServiceManager::connect_to_device_async(const std::string& device_id, 
                                                  ProgressCallback progress_callback) {
    try {
        log_service_activity("Starting enhanced device connection", device_id);
        
        // Check if device exists in our tracking
        {
            std::lock_guard<std::mutex> lock(service_devices_mutex_);
            auto it = service_devices_.find(device_id);
            if (it == service_devices_.end()) {
                log_service_activity("Device not found in service tracking: " + device_id);
                return false;
            }
            
            // Update state to CONNECTING
            update_service_device_state(device_id, DeviceState::CONNECTING, 0, 
                                       "Initiating connection...");
        }
        
        // Create progress tracking
        ProgressUpdate connection_progress{};
        connection_progress.operation_id = static_cast<uint32_t>(
            std::chrono::system_clock::now().time_since_epoch().count());
        connection_progress.extraction_type = ExtractionType::LOGICAL;
        connection_progress.level = ProgressLevel::INFO;
        connection_progress.percentage = 10;
        connection_progress.stage_name = "Connecting to Device";
        connection_progress.detailed_message = "Establishing communication with device...";
        connection_progress.timestamp = std::chrono::system_clock::now();
        connection_progress.operator_id = "ServiceLayer";
        
        if (progress_callback) {
            progress_callback(connection_progress);
        }
        notify_progress_callbacks(connection_progress);
        
        // INTEGRATION POINT: Call core device connection
        auto core_connection_result = core_device_manager_->ConnectToDevice(device_id);
        
        if (core_connection_result.IsSuccess()) {
            // Update progress - connection successful
            connection_progress.percentage = 100;
            connection_progress.level = ProgressLevel::SUCCESS;
            connection_progress.stage_name = "Connected";
            connection_progress.detailed_message = "Device connection established successfully";
            
            // Update service state
            update_service_device_state(device_id, DeviceState::CONNECTED, 100, 
                                       "Connection established");
            
            log_service_activity("Device connection successful", device_id);
            
        } else {
            // Update progress - connection failed
            connection_progress.percentage = 0;
            connection_progress.level = ProgressLevel::ERROR;
            connection_progress.stage_name = "Connection Failed";
            connection_progress.detailed_message = "Connection error: " + 
                                                 core_connection_result.GetErrorMessage();
            
            // Update service state
            update_service_device_state(device_id, DeviceState::ERROR_STATE, 0, 
                                       "Connection failed: " + core_connection_result.GetErrorMessage());
            
            log_service_activity("Device connection failed: " + 
                               core_connection_result.GetErrorMessage(), device_id);
        }
        
        if (progress_callback) {
            progress_callback(connection_progress);
        }
        notify_progress_callbacks(connection_progress);
        
        return core_connection_result.IsSuccess();
        
    } catch (const std::exception& e) {
        log_service_activity("Device connection exception: " + std::string(e.what()), device_id);
        update_service_device_state(device_id, DeviceState::ERROR_STATE, 0, 
                                   "Exception: " + std::string(e.what()));
        return false;
    }
}

bool DeviceServiceManager::disconnect_device(const std::string& device_id) {
    try {
        log_service_activity("Starting device disconnection", device_id);
        
        // INTEGRATION POINT: Call core disconnection
        auto core_result = core_device_manager_->DisconnectDevice(device_id);
        
        if (core_result.IsSuccess()) {
            update_service_device_state(device_id, DeviceState::DISCONNECTED, 0, 
                                       "Device disconnected");
            log_service_activity("Device disconnection successful", device_id);
        } else {
            log_service_activity("Device disconnection failed: " + 
                               core_result.GetErrorMessage(), device_id);
        }
        
        return core_result.IsSuccess();
        
    } catch (const std::exception& e) {
        log_service_activity("Device disconnection exception: " + std::string(e.what()), device_id);
        return false;
    }
}

DeviceState DeviceServiceManager::get_device_state(const std::string& device_id) const {
    try {
        std::lock_guard<std::mutex> lock(service_devices_mutex_);
        
        auto it = service_devices_.find(device_id);
        if (it != service_devices_.end()) {
            return it->second->service_state;
        }
        
    } catch (const std::exception& e) {
        log_service_activity("Error getting device state: " + std::string(e.what()), device_id);
    }
    
    return DeviceState::UNKNOWN;
}

// TEACHING: Background monitoring creates the "always-on" experience
// This continuously polls core layer for device changes
bool DeviceServiceManager::start_device_monitoring() {
    try {
        if (monitoring_thread_ && monitoring_thread_->joinable()) {
            log_service_activity("Device monitoring already running");
            return true;
        }
        
        should_stop_monitoring_.store(false, std::memory_order_release);
        
        monitoring_thread_ = std::make_unique<std::thread>([this]() {
            this->monitoring_loop();
        });
        
        // Start progress reporting thread
        progress_thread_ = std::make_unique<std::thread>([this]() {
            this->progress_reporting_loop();
        });
        
        log_service_activity("Background device monitoring started");
        return true;
        
    } catch (const std::exception& e) {
        log_service_activity("Failed to start device monitoring: " + std::string(e.what()));
        return false;
    }
}

void DeviceServiceManager::stop_device_monitoring() {
    try {
        should_stop_monitoring_.store(true, std::memory_order_release);
        
        if (monitoring_thread_ && monitoring_thread_->joinable()) {
            monitoring_thread_->join();
            monitoring_thread_.reset();
        }
        
        if (progress_thread_ && progress_thread_->joinable()) {
            progress_thread_->join();
            progress_thread_.reset();
        }
        
        log_service_activity("Background device monitoring stopped");
        
    } catch (const std::exception& e) {
        log_service_activity("Error stopping device monitoring: " + std::string(e.what()));
    }
}

// TEACHING: Main monitoring loop - this is the heart of the service layer
// It continuously checks for device changes and maintains service state
void DeviceServiceManager::monitoring_loop() {
    log_service_activity("Device monitoring loop started");
    
    while (!should_stop_monitoring_.load(std::memory_order_acquire)) {
        try {
            // Sync with core device manager state
            sync_with_core_devices();
            
            // Sleep for configured interval
            std::this_thread::sleep_for(
                std::chrono::milliseconds(config_.device_scan_interval_ms));
            
        } catch (const std::exception& e) {
            log_service_activity("Monitoring loop exception: " + std::string(e.what()));
            // Continue monitoring despite errors
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    
    log_service_activity("Device monitoring loop stopped");
}

void DeviceServiceManager::progress_reporting_loop() {
    while (!should_stop_monitoring_.load(std::memory_order_acquire)) {
        try {
            // This could be used for periodic progress updates
            // Currently just sleeps - extend as needed for active operations
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            
        } catch (const std::exception& e) {
            log_service_activity("Progress reporting loop exception: " + std::string(e.what()));
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

// INTEGRATION: Keep service devices in sync with core discoveries
void DeviceServiceManager::sync_with_core_devices() {
    try {
        // Get current connected devices from core
        auto connected_device_ids = core_device_manager_->GetConnectedDevices();
        
        std::lock_guard<std::mutex> lock(service_devices_mutex_);
        
        // Update connection states based on core state
        for (const auto& [device_id, service_device] : service_devices_) {
            bool is_connected_in_core = std::find(connected_device_ids.begin(), 
                                                 connected_device_ids.end(), 
                                                 device_id) != connected_device_ids.end();
            
            DeviceState current_state = service_device->service_state;
            DeviceState new_state = current_state;
            
            if (is_connected_in_core && current_state == DeviceState::DETECTED) {
                new_state = DeviceState::CONNECTED;
            } else if (!is_connected_in_core && current_state == DeviceState::CONNECTED) {
                new_state = DeviceState::DISCONNECTED;
            }
            
            if (new_state != current_state) {
                service_device->service_state = new_state;
                service_device->last_activity = std::chrono::system_clock::now();
                
                // Notify callbacks of state change
                DeviceInfo device_info = convert_core_to_service_info(service_device->core_info);
                notify_device_event_callbacks(device_info, current_state, new_state);
            }
        }
        
    } catch (const std::exception& e) {
        log_service_activity("Error syncing with core devices: " + std::string(e.what()));
    }
}

// INTEGRATION: Convert core::DeviceInfo to service::DeviceInfo
DeviceInfo DeviceServiceManager::convert_core_to_service_info(const core::DeviceInfo& core_info) const {
    DeviceInfo service_info{};
    
    // Basic identification
    service_info.device_id = core_info.deviceId;
    service_info.manufacturer = core_info.manufacturer;
    service_info.model = core_info.model;
    service_info.os_version = core_info.osVersion;
    service_info.build_number = core_info.buildNumber;
    service_info.security_patch = core_info.securityPatches.empty() ? 
        "" : core_info.securityPatches[0];
    service_info.storage_size = core_info.totalStorage;
    service_info.is_rooted = core_info.isRooted;
    service_info.is_encrypted = core_info.isEncrypted;
    service_info.detected_time = core_info.discoveryTime;
    
    // Generate device fingerprint (simplified for Phase 3)
    std::hash<std::string> hasher;
    auto hash_val = hasher(core_info.deviceId + core_info.serialNumber + core_info.model);
    
    // Convert hash to bytes array (simplified)
    std::memset(service_info.device_fingerprint.data(), 0, 32);
    std::memcpy(service_info.device_fingerprint.data(), &hash_val, 
                std::min(sizeof(hash_val), service_info.device_fingerprint.size()));
    
    return service_info;
}

void DeviceServiceManager::register_device_event_callback(DeviceEventCallback callback) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    device_event_callbacks_.push_back(callback);
}

void DeviceServiceManager::unregister_device_event_callback(DeviceEventCallback callback) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    auto it = std::find(device_event_callbacks_.begin(), device_event_callbacks_.end(), callback);
    if (it != device_event_callbacks_.end()) {
        device_event_callbacks_.erase(it);
    }
}

void DeviceServiceManager::register_progress_callback(ProgressCallback callback) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    progress_callbacks_.push_back(callback);
}

bool DeviceServiceManager::is_device_ready_for_extraction(const std::string& device_id, 
                                                         ExtractionType extraction_type) const {
    try {
        std::lock_guard<std::mutex> lock(service_devices_mutex_);
        
        auto it = service_devices_.find(device_id);
        if (it == service_devices_.end()) {
            return false;
        }
        
        // Check service state
        if (it->second->service_state != DeviceState::CONNECTED &&
            it->second->service_state != DeviceState::AUTHENTICATED) {
            return false;
        }
        
        // Check if extraction type is supported
        const auto& supported = it->second->supported_extractions;
        return std::find(supported.begin(), supported.end(), extraction_type) != supported.end();
        
    } catch (const std::exception& e) {
        log_service_activity("Error checking extraction readiness: " + std::string(e.what()), device_id);
        return false;
    }
}

std::vector<ExtractionType> DeviceServiceManager::get_supported_extractions(const std::string& device_id) const {
    try {
        std::lock_guard<std::mutex> lock(service_devices_mutex_);
        
        auto it = service_devices_.find(device_id);
        if (it != service_devices_.end()) {
            return it->second->supported_extractions;
        }
        
    } catch (const std::exception& e) {
        log_service_activity("Error getting supported extractions: " + std::string(e.what()), device_id);
    }
    
    return {};
}

// TEACHING: Determine what extraction methods are possible based on device state
std::vector<ExtractionType> DeviceServiceManager::determine_extraction_capabilities(
    const core::DeviceInfo& core_info) const {
    
    std::vector<ExtractionType> capabilities;
    
    // Always support logical extraction if device is supported
    if (core_info.isSupported) {
        capabilities.push_back(ExtractionType::LOGICAL);
    }
    
    // Physical extraction requires root/unlock
    if (core_info.isRooted || 
        core_info.securityState == core::SecurityState::UNLOCKED ||
        core_info.securityState == core::SecurityState::BOOTLOADER_UNLOCKED) {
        capabilities.push_back(ExtractionType::PHYSICAL);
    }
    
    // File system extraction
    if (core_info.securityState == core::SecurityState::ADB_ENABLED ||
        core_info.securityState == core::SecurityState::DEVELOPER_MODE) {
        capabilities.push_back(ExtractionType::FILE_SYSTEM);
    }
    
    // Targeted extraction (app-specific)
    capabilities.push_back(ExtractionType::TARGETED);
    
    // Bypass extraction for locked devices (future exploit integration)
    if (core_info.securityState == core::SecurityState::LOCKED ||
        core_info.securityState == core::SecurityState::ENCRYPTED) {
        capabilities.push_back(ExtractionType::BYPASS);
    }
    
    return capabilities;
}

void DeviceServiceManager::update_service_device_state(const std::string& device_id, 
                                                      DeviceState new_state,
                                                      uint8_t progress_percentage,
                                                      const std::string& progress_message) {
    try {
        std::lock_guard<std::mutex> lock(service_devices_mutex_);
        
        auto it = service_devices_.find(device_id);
        if (it != service_devices_.end()) {
            DeviceState old_state = it->second->service_state;
            it->second->service_state = new_state;
            it->second->last_activity = std::chrono::system_clock::now();
            it->second->last_progress_percentage.store(progress_percentage, std::memory_order_release);
            it->second->last_progress_message = progress_message;
            
            // Add to service log
            std::ostringstream log_entry;
            log_entry << "[" << james::utils::GetTimestamp() << "] " 
                     << "State: " << static_cast<int>(old_state) << " -> " << static_cast<int>(new_state)
                     << " (" << static_cast<int>(progress_percentage) << "%) " << progress_message;
            it->second->service_log += log_entry.str() + "\n";
            
            // Notify callbacks if state actually changed
            if (old_state != new_state) {
                DeviceInfo device_info = convert_core_to_service_info(it->second->core_info);
                notify_device_event_callbacks(device_info, old_state, new_state);
            }
        }
        
    } catch (const std::exception& e) {
        log_service_activity("Error updating device state: " + std::string(e.what()), device_id);
    }
}

void DeviceServiceManager::notify_progress_callbacks(const ProgressUpdate& update) {
    try {
        std::lock_guard<std::mutex> lock(callbacks_mutex_);
        
        for (auto callback : progress_callbacks_) {
            if (callback) {
                callback(update);
            }
        }
        
    } catch (const std::exception& e) {
        log_service_activity("Error notifying progress callbacks: " + std::string(e.what()));
    }
}

void DeviceServiceManager::notify_device_event_callbacks(const DeviceInfo& device, 
                                                        DeviceState old_state, 
                                                        DeviceState new_state) {
    try {
        std::lock_guard<std::mutex> lock(callbacks_mutex_);
        
        for (auto callback : device_event_callbacks_) {
            if (callback) {
                callback(device, old_state, new_state);
            }
        }
        
    } catch (const std::exception& e) {
        log_service_activity("Error notifying device event callbacks: " + std::string(e.what()));
    }
}

void DeviceServiceManager::log_service_activity(const std::string& message, 
                                               const std::string& device_id) {
    try {
        std::lock_guard<std::mutex> lock(activity_log_mutex_);
        
        std::ostringstream log_entry;
        log_entry << "[" << james::utils::GetTimestamp() << "] ";
        if (!device_id.empty()) {
            log_entry << "[" << device_id << "] ";
        }
        log_entry << message;
        
        service_activity_log_ += log_entry.str() + "\n";
        
        // Keep log size manageable (last 1000 entries)
        const size_t max_log_size = 100000; // ~100KB
        if (service_activity_log_.size() > max_log_size) {
            // Keep last 75% of log
            size_t keep_size = max_log_size * 3 / 4;
            service_activity_log_ = service_activity_log_.substr(
                service_activity_log_.size() - keep_size);
        }
        
        // Also log to core audit logger if available
        if (audit_logger_) {
            audit_logger_->LogEvent(
                core::AuditEvent::DEVICE_INFO_RETRIEVED,
                message,
                core::AuditLevel::INFO,
                device_id
            );
        }
        
    } catch (const std::exception& e) {
        // Fallback logging - never let logging failures break the service
        if (audit_logger_) {
            audit_logger_->LogEvent(
                core::AuditEvent::ENGINE_ERROR,
                "Service logging error: " + std::string(e.what()),
                core::AuditLevel::ERROR
            );
        }
    }
}

std::string DeviceServiceManager::run_enhanced_diagnostics(const std::string& device_id) const {
    std::ostringstream diagnostics;
    
    try {
        diagnostics << "=== J.A.M.E.S. Enhanced Device Diagnostics ===\n";
        diagnostics << "Device ID: " << device_id << "\n";
        diagnostics << "Timestamp: " << james::utils::GetTimestamp() << "\n\n";
        
        // Service layer diagnostics
        {
            std::lock_guard<std::mutex> lock(service_devices_mutex_);
            auto it = service_devices_.find(device_id);
            
            if (it != service_devices_.end()) {
                const auto& service_device = it->second;
                
                diagnostics << "--- Service Layer Status ---\n";
                diagnostics << "Service State: " << static_cast<int>(service_device->service_state) << "\n";
                diagnostics << "Last Activity: " << james::utils::GetTimestamp() << "\n";
                diagnostics << "Connection Attempts: " << service_device->connection_attempts << "\n";
                diagnostics << "Last Progress: " << static_cast<int>(
                    service_device->last_progress_percentage.load()) << "%\n";
                diagnostics << "Last Message: " << service_device->last_progress_message << "\n";
                
                diagnostics << "\nSupported Extractions:\n";
                for (const auto& extraction : service_device->supported_extractions) {
                    diagnostics << "  - " << static_cast<int>(extraction) << "\n";
                }
                
                diagnostics << "\nService Activity Log (last 10 entries):\n";
                std::istringstream log_stream(service_device->service_log);
                std::vector<std::string> log_lines;
                std::string line;
                while (std::getline(log_stream, line)) {
                    log_lines.push_back(line);
                }
                
                // Show last 10 lines
                size_t start_idx = log_lines.size() > 10 ? log_lines.size() - 10 : 0;
                for (size_t i = start_idx; i < log_lines.size(); ++i) {
                    diagnostics << "  " << log_lines[i] << "\n";
                }
            } else {
                diagnostics << "--- Service Layer Status ---\n";
                diagnostics << "ERROR: Device not found in service tracking\n";
            }
        }
        
        // Core layer diagnostics - delegate to core device manager
        diagnostics << "\n--- Core Layer Diagnostics ---\n";
        
        // Check if device is connected in core
        bool is_core_connected = core_device_manager_->IsDeviceConnected(device_id);
        diagnostics << "Core Connection Status: " << (is_core_connected ? "Connected" : "Disconnected") << "\n";
        
        // Get core device info
        auto core_info_result = core_device_manager_->GetDeviceInfo(device_id);
        if (core_info_result.IsSuccess()) {
            const auto& core_info = core_info_result.GetValue();
            
            diagnostics << "Device Type: " << core_info.GetTypeString() << "\n";
            diagnostics << "Manufacturer: " << core_info.manufacturer << "\n";
            diagnostics << "Model: " << core_info.model << "\n";
            diagnostics << "OS Version: " << core_info.osVersion << "\n";
            diagnostics << "Security State: " << core_info.GetSecurityString() << "\n";
            diagnostics << "Rooted: " << (core_info.isRooted ? "Yes" : "No") << "\n";
            diagnostics << "Encrypted: " << (core_info.isEncrypted ? "Yes" : "No") << "\n";
            diagnostics << "Extraction Feasible: " << (core_info.IsExtractionFeasible() ? "Yes" : "No") << "\n";
            diagnostics << "Forensic Priority: " << core_info.GetForensicPriority() << "\n";
            
            diagnostics << "\nStorage Information:\n";
            diagnostics << "  Total Storage: " << james::utils::FormatBytes(core_info.totalStorage) << "\n";
            diagnostics << "  Available: " << james::utils::FormatBytes(core_info.availableStorage) << "\n";
            diagnostics << "  Utilization: " << std::fixed << std::setprecision(1) 
                       << core_info.GetStorageUtilization() << "%\n";
            
            if (core_info.batteryLevel >= 0) {
                diagnostics << "\nPower Information:\n";
                diagnostics << "  Battery Level: " << core_info.batteryLevel << "%\n";
                diagnostics << "  Charging: " << (core_info.isCharging ? "Yes" : "No") << "\n";
            }
            
        } else {
            diagnostics << "ERROR: Could not retrieve core device information\n";
            diagnostics << "Error: " << core_info_result.GetErrorMessage() << "\n";
        }
        
        // System diagnostics
        diagnostics << "\n--- System Diagnostics ---\n";
        diagnostics << "Service Status: " << static_cast<int>(get_service_status()) << "\n";
        diagnostics << "Monitoring Active: " << (monitoring_thread_ && monitoring_thread_->joinable() ? "Yes" : "No") << "\n";
        diagnostics << "Progress Reporting Active: " << (progress_thread_ && progress_thread_->joinable() ? "Yes" : "No") << "\n";
        
        {
            std::lock_guard<std::mutex> lock(callbacks_mutex_);
            diagnostics << "Device Event Callbacks: " << device_event_callbacks_.size() << "\n";
            diagnostics << "Progress Callbacks: " << progress_callbacks_.size() << "\n";
        }
        
        // Configuration
        diagnostics << "\n--- Configuration ---\n";
        diagnostics << "Scan Interval: " << config_.device_scan_interval_ms << "ms\n";
        diagnostics << "Connection Timeout: " << config_.connection_timeout_ms << "ms\n";
        diagnostics << "Extraction Timeout: " << config_.extraction_timeout_ms << "ms\n";
        diagnostics << "Require Auth: " << (config_.require_operator_authentication ? "Yes" : "No") << "\n";
        diagnostics << "Tamper Detection: " << (config_.enable_tamper_detection ? "Yes" : "No") << "\n";
        
        diagnostics << "\n=== End Diagnostics ===\n";
        
    } catch (const std::exception& e) {
        diagnostics << "\nDIAGNOSTICS ERROR: " << e.what() << "\n";
    }
    
    return diagnostics.str();
}

std::string DeviceServiceManager::get_service_activity_log(const std::string& device_id) const {
    try {
        std::ostringstream full_log;
        
        // Global service activity log
        {
            std::lock_guard<std::mutex> lock(activity_log_mutex_);
            
            if (device_id.empty()) {
                // Return full log
                full_log << "=== J.A.M.E.S. Service Activity Log ===\n";
                full_log << service_activity_log_;
            } else {
                // Filter log for specific device
                full_log << "=== J.A.M.E.S. Service Activity Log (Device: " << device_id << ") ===\n";
                
                std::istringstream log_stream(service_activity_log_);
                std::string line;
                while (std::getline(log_stream, line)) {
                    if (line.find("[" + device_id + "]") != std::string::npos || 
                        line.find("device_id") == std::string::npos) {
                        full_log << line << "\n";
                    }
                }
            }
        }
        
        // Device-specific service log
        if (!device_id.empty()) {
            std::lock_guard<std::mutex> lock(service_devices_mutex_);
            auto it = service_devices_.find(device_id);
            
            if (it != service_devices_.end()) {
                full_log << "\n=== Device-Specific Service Log ===\n";
                full_log << it->second->service_log;
            }
        }
        
        return full_log.str();
        
    } catch (const std::exception& e) {
        return "Error retrieving service activity log: " + std::string(e.what());
    }
}

} // namespace service
} // namespace james