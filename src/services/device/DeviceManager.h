/**
 * @file DeviceManager.h
 * @brief Device detection, connection management, and state tracking
 * @version 1.0
 * @date 2024
 * 
 * ARCHITECTURE PURPOSE:
 * This class is the "Device Service" equivalent to Cellebrite's device handling.
 * It continuously monitors for mobile devices, manages their connection state,
 * and provides the foundation for extraction operations.
 * 
 * SECURITY COMPLIANCE:
 * - SEI CERT C++: RAII for resource management, exception safety
 * - MISRA C++: No raw pointers, explicit ownership
 * - NASA Power of 10: Bounded loops, predictable execution
 * - ISO 27037: Complete audit trail of device interactions
 */

#ifndef JAMES_DEVICE_MANAGER_H
#define JAMES_DEVICE_MANAGER_H

#include "ServiceTypes.h"
#include <memory>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <atomic>
#include <vector>
#include <functional>

namespace james {
namespace service {

/**
 * @class DeviceManager
 * @brief Central device detection and management service
 * 
 * TEACHING NOTE: This class implements the Observer pattern for device events
 * and manages the complete lifecycle of device connections. In real forensic
 * tools, this would interface with USB drivers, ADB, and iTunes/3uTools.
 * 
 * The state machine here is critical - it determines when exploitation
 * techniques can be applied and tracks device readiness for extraction.
 */
class DeviceManager {
public:
    /**
     * @brief Constructor initializes the device management system
     * @param config Service configuration parameters
     * 
     * SECURITY NOTE: Constructor validates all configuration parameters
     * to prevent service misconfiguration that could compromise extraction
     */
    explicit DeviceManager(const ServiceConfig& config);
    
    /**
     * @brief Destructor ensures clean shutdown
     * 
     * MISRA C++: Destructor must be virtual for proper cleanup
     * in inheritance hierarchies (future extensibility)
     */
    virtual ~DeviceManager();

    // === CORE SERVICE INTERFACE ===
    
    /**
     * @brief Start the device monitoring service
     * @return true if service started successfully
     * 
     * TEACHING NOTE: This starts the background thread that continuously
     * scans for devices. Similar to how Cellebrite's service runs in background.
     */
    bool start_service();
    
    /**
     * @brief Stop the device monitoring service
     * 
     * NASA Power of 10: All services must have deterministic shutdown
     */
    void stop_service();
    
    /**
     * @brief Get current service status
     * @return Current operational status of the device manager
     */
    ServiceStatus get_service_status() const;

    // === DEVICE DISCOVERY AND MANAGEMENT ===
    
    /**
     * @brief Force an immediate device scan
     * @return Number of devices currently connected
     * 
     * This is called when user clicks "Refresh Devices" in GUI
     */
    uint32_t scan_for_devices();
    
    /**
     * @brief Get all currently detected devices
     * @return Vector of device information structures
     * 
     * GUI calls this to populate the device list
     */
    std::vector<DeviceInfo> get_connected_devices() const;
    
    /**
     * @brief Get specific device information
     * @param device_id Unique device identifier
     * @return Device info if found, nullptr otherwise
     */
    std::shared_ptr<DeviceInfo> get_device_info(const std::string& device_id) const;
    
    /**
     * @brief Get current state of a specific device
     * @param device_id Device to query
     * @return Current state in the device state machine
     */
    DeviceState get_device_state(const std::string& device_id) const;

    // === DEVICE CONNECTION MANAGEMENT ===
    
    /**
     * @brief Initiate connection to a specific device
     * @param device_id Target device identifier
     * @return true if connection attempt started successfully
     * 
     * TEACHING NOTE: This begins the handshake process. In real implementation,
     * this would involve ADB connection, iTunes detection, or custom protocols.
     * The connection process is asynchronous - callbacks report progress.
     */
    bool connect_to_device(const std::string& device_id);
    
    /**
     * @brief Disconnect from a specific device
     * @param device_id Device to disconnect from
     * @return true if disconnection initiated successfully
     */
    bool disconnect_from_device(const std::string& device_id);
    
    /**
     * @brief Attempt device authentication (unlock/root)
     * @param device_id Target device
     * @param auth_method Authentication method to attempt
     * @return true if authentication attempt started
     * 
     * EXPLOIT INTEGRATION POINT: This is where advanced unlock techniques
     * would be injected in a real forensic tool
     */
    bool authenticate_device(const std::string& device_id, const std::string& auth_method);

    // === EVENT CALLBACK REGISTRATION ===
    
    /**
     * @brief Register callback for device state changes
     * @param callback Function to call when device state changes
     * 
     * ARCHITECTURE NOTE: This implements the Observer pattern, allowing
     * GUI and other components to react to device events without tight coupling
     */
    void register_device_event_callback(DeviceEventCallback callback);
    
    /**
     * @brief Unregister device event callback
     * @param callback Previously registered callback to remove
     */
    void unregister_device_event_callback(DeviceEventCallback callback);

    // === DEVICE CAPABILITY DETECTION ===
    
    /**
     * @brief Check if device supports specific extraction types
     * @param device_id Device to check
     * @param extraction_type Type of extraction to verify
     * @return true if device supports this extraction method
     * 
     * TEACHING NOTE: Different devices support different extraction methods.
     * This helps the GUI show only available options to the user.
     */
    bool supports_extraction_type(const std::string& device_id, ExtractionType extraction_type) const;
    
    /**
     * @brief Get list of supported extraction types for device
     * @param device_id Device to query
     * @return Vector of supported extraction types
     */
    std::vector<ExtractionType> get_supported_extractions(const std::string& device_id) const;

    // === DIAGNOSTIC AND DEBUGGING ===
    
    /**
     * @brief Run diagnostic tests on device connection
     * @param device_id Device to test
     * @return Diagnostic results as human-readable string
     * 
     * This helps troubleshoot connection issues during forensic operations
     */
    std::string run_device_diagnostics(const std::string& device_id) const;
    
    /**
     * @brief Get detailed connection log for device
     * @param device_id Device to query
     * @return Complete log of connection attempts and results
     * 
     * ISO 27037: Detailed logging required for evidence integrity
     */
    std::string get_device_connection_log(const std::string& device_id) const;

private:
    // === INTERNAL DATA STRUCTURES ===
    
    /**
     * @brief Internal device tracking structure
     * 
     * This extends DeviceInfo with internal state management data
     * that shouldn't be exposed to external callers
     */
    struct ManagedDevice {
        DeviceInfo info;
        DeviceState current_state;
        std::chrono::system_clock::time_point last_seen;
        std::chrono::system_clock::time_point state_change_time;
        uint32_t connection_attempts;
        std::string connection_log;
        std::vector<ExtractionType> supported_extractions;
        
        // Internal state management
        std::atomic<bool> is_connected{false};
        std::atomic<bool> is_busy{false};
        std::mutex device_mutex;
    };

    // === CONFIGURATION AND STATE ===
    ServiceConfig config_;
    std::atomic<ServiceStatus> service_status_{ServiceStatus::INITIALIZING};
    std::atomic<bool> should_stop_{false};
    
    // Device tracking
    mutable std::mutex devices_mutex_;
    std::unordered_map<std::string, std::unique_ptr<ManagedDevice>> managed_devices_;
    
    // Background service thread
    std::unique_ptr<std::thread> monitoring_thread_;
    
    // Event callbacks
    std::mutex callbacks_mutex_;
    std::vector<DeviceEventCallback> device_event_callbacks_;

    // === INTERNAL IMPLEMENTATION METHODS ===
    
    /**
     * @brief Main monitoring loop (runs in background thread)
     * 
     * NASA Power of 10: Bounded execution time, no infinite loops
     */
    void monitoring_loop();
    
    /**
     * @brief Perform actual device detection
     * @return Number of devices found in this scan
     * 
     * MOCK IMPLEMENTATION NOTE: In Phase 3, this will simulate device
     * detection. Phase 4+ will implement real USB/ADB detection.
     */
    uint32_t perform_device_scan();
    
    /**
     * @brief Update device state and notify callbacks
     * @param device_id Device whose state is changing
     * @param new_state New state to transition to
     * 
     * TEACHING NOTE: This is the heart of the state machine.
     * All state transitions go through here for consistent logging.
     */
    void update_device_state(const std::string& device_id, DeviceState new_state);
    
    /**
     * @brief Notify all registered callbacks of device event
     * @param device Device that changed
     * @param old_state Previous state
     * @param new_state Current state
     */
    void notify_device_event(const DeviceInfo& device, DeviceState old_state, DeviceState new_state);
    
    /**
     * @brief Mock device information generation
     * @param device_id Base device identifier
     * @return Simulated device information
     * 
     * PHASE 3 IMPLEMENTATION: This creates realistic device info
     * for testing the service layer without real devices
     */
    DeviceInfo create_mock_device_info(const std::string& device_id) const;
    
    /**
     * @brief Determine supported extraction types for device
     * @param device Device to analyze
     * @return Vector of supported extraction methods
     * 
     * TEACHING NOTE: This logic determines what extraction options
     * are available based on device OS, security patch level, etc.
     */
    std::vector<ExtractionType> determine_supported_extractions(const DeviceInfo& device) const;

    // === VALIDATION AND SECURITY ===
    
    /**
     * @brief Validate device ID format
     * @param device_id ID to validate
     * @return true if ID format is valid
     * 
     * SEI CERT C++: Input validation prevents injection attacks
     */
    bool is_valid_device_id(const std::string& device_id) const;
    
    /**
     * @brief Log security event for audit trail
     * @param event_type Type of security event
     * @param device_id Related device (if applicable)
     * @param message Detailed event description
     * 
     * ISO 27037: All security events must be logged
     */
    void log_security_event(const std::string& event_type, 
                           const std::string& device_id, 
                           const std::string& message) const;
};

} // namespace service
} // namespace james

#endif // JAMES_DEVICE_MANAGER_H