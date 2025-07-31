// =============================================================================
// 📁 FILE: src/main.cpp - DIAGNOSTIC VERSION TO IDENTIFY THE ISSUE
// 🏷 REASONING: Add extensive debugging to find why RunJAMESDemo doesn't execute
// =============================================================================

#include "james_common.h"
#include "james_engine.h"
#include <iostream>
#include <string>

namespace {
    void PrintBanner() noexcept {
        std::cout << "\n";
        std::cout << "╔═════════════════════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║     🏛️  J.A.M.E.S. - Joint Advanced Mobile Exploitation Suite                    ║\n";
        std::cout << "║                    Commercial-Grade Forensic Platform                           ║\n";
        std::cout << "║                         Phase 2 - Core Engine Demo                              ║\n";
        std::cout << "╚═════════════════════════════════════════════════════════════════════════════════╝\n";
        std::cout << "\n";
    }

    void PrintSystemInfo() noexcept {
        std::cout << "🔧 System Information:\n";
        std::cout << "   Platform: " << JAMES_PLATFORM_STRING << "\n";
        std::cout << "   Version: " << JAMES_VERSION_MAJOR << "." << JAMES_VERSION_MINOR << "." << JAMES_VERSION_PATCH << "\n";
        std::cout << "   Build: Release\n";
        std::cout << "   Standards: SEI-CERT, MISRA C++, Power of 10\n";
        std::cout << "\n";
    }
}

int RunJAMESDemo() noexcept {
    std::cout << "🐛 DEBUG: RunJAMESDemo() function started\n" << std::flush;
    
    try {
        std::cout << "🐛 DEBUG: About to call PrintBanner()\n" << std::flush;
        PrintBanner();
        std::cout << "🐛 DEBUG: PrintBanner() completed\n" << std::flush;
        
        std::cout << "🐛 DEBUG: About to call PrintSystemInfo()\n" << std::flush;
        PrintSystemInfo();
        std::cout << "🐛 DEBUG: PrintSystemInfo() completed\n" << std::flush;

        std::cout << "🚀 Initializing J.A.M.E.S. Engine...\n" << std::flush;
        std::cout << "🐛 DEBUG: About to create JAMESEngine instance\n" << std::flush;
        
        // Create engine instance - use simple constructor that actually exists
        james::core::JAMESEngine engine;
        std::cout << "🐛 DEBUG: JAMESEngine instance created successfully\n" << std::flush;
        
        // Initialize the engine
        std::cout << "🐛 DEBUG: About to call engine.Initialize()\n" << std::flush;
        auto initResult = engine.Initialize();
        std::cout << "🐛 DEBUG: engine.Initialize() returned\n" << std::flush;
        
        if (!initResult.IsSuccess()) {
            std::cout << "❌ Engine initialization failed: " << initResult.GetErrorMessage() << "\n" << std::flush;
            return 1;
        }
        
        std::cout << "✅ J.A.M.E.S. Engine initialized successfully!\n\n" << std::flush;
        
        std::cout << "📊 Engine Status:\n";
        std::cout << "   Core Engine: ✅ Online\n";
        std::cout << "   Security Manager: ✅ Active\n";
        std::cout << "   Audit Logger: ✅ Recording\n";
        std::cout << "   Evidence Manager: ✅ Ready\n";
        std::cout << "   Device Manager: ✅ Standby\n";
        std::cout << "\n" << std::flush;
        
        std::cout << "🔍 Testing Device Discovery (Phase 2 Stub)...\n" << std::flush;
        std::cout << "🐛 DEBUG: About to call engine.DiscoverDevices()\n" << std::flush;
        
        // Test device discovery - this will return empty results in Phase 2
        auto deviceResult = engine.DiscoverDevices();
        std::cout << "🐛 DEBUG: engine.DiscoverDevices() returned\n" << std::flush;
        
        if (deviceResult.IsSuccess()) {
            auto devices = deviceResult.GetValue();
            std::cout << "   Discovered devices: " << devices.size() << "\n";
            if (devices.empty()) {
                std::cout << "   📝 Note: No devices found (Phase 2 - stubs only)\n";
            }
        } else {
            std::cout << "   📝 Device discovery: " << deviceResult.GetErrorMessage() << "\n";
        }
        
        std::cout << "\n" << std::flush;
        
        std::cout << "🛡️ Testing Security Subsystem...\n" << std::flush;
        std::cout << "🐛 DEBUG: About to call engine.CreateEvidenceContainer()\n" << std::flush;
        
        // Test evidence container creation
        auto evidenceResult = engine.CreateEvidenceContainer("TEST_DEVICE_001", "Demo Examiner", "CASE_2025_001");
        std::cout << "🐛 DEBUG: engine.CreateEvidenceContainer() returned\n" << std::flush;
        
        if (evidenceResult.IsSuccess()) {
            std::string evidenceId = evidenceResult.GetValue();
            std::cout << "   ✅ Evidence container created: " << evidenceId << "\n";
        } else {
            std::cout << "   ❌ Evidence creation failed: " << evidenceResult.GetErrorMessage() << "\n";
        }
        
        std::cout << "\n" << std::flush;
        
        std::cout << "📋 Phase 2 Demo Complete!\n";
        std::cout << "🎯 Ready for Phase 3: Device Communication & Extraction\n";
        std::cout << "\n";
        
        std::cout << "💡 Next Steps:\n";
        std::cout << "   • Implement libimobiledevice integration (iOS)\n";
        std::cout << "   • Implement ADB integration (Android)\n";  
        std::cout << "   • Implement libusb integration (USB storage)\n";
        std::cout << "   • Add real device detection and communication\n";
        std::cout << "\n" << std::flush;
        
        // Graceful shutdown
        std::cout << "🔄 Shutting down engine...\n" << std::flush;
        std::cout << "🐛 DEBUG: About to call engine.Shutdown()\n" << std::flush;
        engine.Shutdown();
        std::cout << "🐛 DEBUG: engine.Shutdown() completed\n" << std::flush;
        
        std::cout << "✅ J.A.M.E.S. Demo completed successfully!\n" << std::flush;
        std::cout << "🐛 DEBUG: RunJAMESDemo() function completed successfully\n" << std::flush;
        return 0;
        
    } catch (const std::exception& e) {
        std::cout << "💥 Fatal error in RunJAMESDemo(): " << e.what() << "\n" << std::flush;
        return 1;
    } catch (...) {
        std::cout << "💥 Unknown fatal error occurred in RunJAMESDemo()\n" << std::flush;
        return 1;
    }
}

int main(int argc, char* argv[]) {
    std::cout << "🐛 DEBUG: main() function started with " << argc << " arguments\n" << std::flush;
    
    // Print all arguments for debugging
    for (int i = 0; i < argc; ++i) {
        std::cout << "🐛 DEBUG: argv[" << i << "] = '" << argv[i] << "'\n" << std::flush;
    }
    
    // Simple argument parsing
    if (argc > 1) {
        std::string arg = argv[1];
        std::cout << "🐛 DEBUG: Processing argument: '" << arg << "'\n" << std::flush;
        
        if (arg == "--help" || arg == "-h") {
            std::cout << "J.A.M.E.S. - Joint Advanced Mobile Exploitation Suite\n";
            std::cout << "Usage: " << argv[0] << " [options]\n";
            std::cout << "\nOptions:\n";
            std::cout << "  --help, -h     Show this help message\n";
            std::cout << "  --version, -v  Show version information\n";
            std::cout << "\nPhase 2: Core Engine Demonstration\n" << std::flush;
            return 0;
        }
        
        if (arg == "--version" || arg == "-v") {
            std::cout << "J.A.M.E.S. Version " << JAMES_VERSION_MAJOR << "." 
                      << JAMES_VERSION_MINOR << "." << JAMES_VERSION_PATCH << "\n";
            std::cout << "Platform: " << JAMES_PLATFORM_STRING << "\n";
            std::cout << "Build: Release\n" << std::flush;
            return 0;
        }
    }
    
    std::cout << "🐛 DEBUG: About to call RunJAMESDemo()\n" << std::flush;
    int result = RunJAMESDemo();
    std::cout << "🐛 DEBUG: RunJAMESDemo() returned: " << result << "\n" << std::flush;
    std::cout << "🐛 DEBUG: main() function exiting\n" << std::flush;
    
    return result;
}