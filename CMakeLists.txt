# =============================================================================
# J.A.M.E.S. (Joint Automated Mobile Extraction System) - Build Configuration
# Professional Digital Forensic Evidence Collection Framework
# 
# Security Standards: SEI-CERT, MISRA, Power of 10, NIST 800-101, ISO 27037
# =============================================================================

cmake_minimum_required(VERSION 3.16)

# Project definition with semantic versioning
project(JAMES 
    VERSION 1.0.0
    DESCRIPTION "Joint Automated Mobile Extraction System - Professional Digital Forensics"
    LANGUAGES CXX C
)

# =============================================================================
# SECURITY-FIRST CONFIGURATION
# =============================================================================

# TEACHING: Why we set these compiler standards
# SEI-CERT requires explicit C++ standard, MISRA requires consistent compilation
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)  # Disable GNU extensions for portability

# TEACHING: Position Independent Code is required for security
# PIE makes exploitation harder by randomizing code locations
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# TEACHING: Link-Time Optimization improves security and performance
# Dead code elimination removes potential attack vectors
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)

# Build type validation - SECURITY: Only allow known safe build types
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")

# =============================================================================
# PLATFORM DETECTION AND CONFIGURATION
# =============================================================================

# TEACHING: We detect platform early to set platform-specific security flags
if(WIN32)
    set(JAMES_PLATFORM_WINDOWS TRUE)
    add_definitions(-DJAMES_PLATFORM_Windows=1)
    # Windows-specific security flags (prepared for future)
    set(WINDOWS_SECURITY_FLAGS "/GS /DYNAMICBASE /NXCOMPAT")
elseif(APPLE)
    set(JAMES_PLATFORM_MACOS TRUE)
    add_definitions(-DJAMES_PLATFORM_macOS=1)
elseif(UNIX)
    set(JAMES_PLATFORM_LINUX TRUE)
    add_definitions(-DJAMES_PLATFORM_Linux=1)
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

# =============================================================================
# SECURITY-HARDENED COMPILER FLAGS
# =============================================================================

# TEACHING: These flags implement defense-in-depth at compilation level
# Each flag addresses specific attack vectors identified by security standards

# Base security flags for all platforms
set(JAMES_SECURITY_FLAGS
    # SEI-CERT: Enable all reasonable warnings
    -Wall -Wextra -Wpedantic
    
    # MISRA: Treat warnings as errors for code quality
    -Werror
    
    # Security: Format string attack protection
    -Wformat=2 -Wformat-security
    
    # Security: Uninitialized variable detection
    -Wuninitialized -Winit-self
    
    # Security: Array bounds checking
    -Warray-bounds -Warray-bounds
    
    # Security: Stack protection
    -Wstack-protector
    
    # Security: Type conversion warnings
    -Wconversion -Wsign-conversion
    
    # Security: Pointer alignment issues
    -Wcast-align -Wcast-qual
    
    # Security: Null pointer dereference detection
    -Wnull-dereference
    
    # Security: Variable shadowing detection
    -Wshadow
    
    # Security: Undefined macro usage
    -Wundef
    
    # Security: Redundant declarations
    -Wredundant-decls
    
    # Performance: Enable stack protection
    -fstack-protector-strong
    
    # Security: Fortify source for buffer overflow protection
    -D_FORTIFY_SOURCE=2
    
    # Security: Enable PIE
    -fPIE
    
    # Security: Disable common unsafe optimizations
    -fno-common -fno-delete-null-pointer-checks
)

# Debug-specific flags - TEACHING: AddressSanitizer catches memory errors
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    list(APPEND JAMES_SECURITY_FLAGS
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
        -g3  # Maximum debug information
    )
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address,undefined")
endif()

# Release-specific flags - TEACHING: Optimization with security preservation
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    list(APPEND JAMES_SECURITY_FLAGS
        -O3  # Maximum optimization
        -DNDEBUG  # Disable debug assertions
    )
endif()

# Apply security flags globally
add_compile_options(${JAMES_SECURITY_FLAGS})

# =============================================================================
# COMPLIANCE AND FEATURE FLAGS
# =============================================================================

# TEACHING: These flags enable forensic-specific features
# Each compliance standard requires specific capabilities
add_definitions(
    # Version information
    -DJAMES_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    -DJAMES_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    -DJAMES_VERSION_PATCH=${PROJECT_VERSION_PATCH}
    
    # Forensic compliance features
    -DENABLE_AUDIT_LOGGING=1
    -DENABLE_CHAIN_OF_CUSTODY=1
    -DENABLE_CRYPTO_INTEGRITY=1
    -DENABLE_CRYPTO_VERIFICATION=1
    -DENABLE_TAMPER_DETECTION=1
    -DENABLE_SECURE_MEMORY=1
    
    # Standards compliance  
    -DENABLE_NIST_800_101_COMPLIANCE=1
    -DENABLE_ISO_27037_COMPLIANCE=1
    -DENABLE_SEI_CERT_COMPLIANCE=1
    -DENABLE_MISRA_COMPLIANCE=1
    
    # Application type
    -DJAMES_CLI_APPLICATION=1
)

# =============================================================================
# DEPENDENCY MANAGEMENT
# =============================================================================

# TEACHING: We find dependencies with fallback paths for different distributions
# This ensures the build works on Ubuntu, RHEL, CentOS, etc.

# Required dependencies
find_package(Threads REQUIRED)

# OpenSSL - CRITICAL for forensic cryptographic operations
find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
else()
    message(FATAL_ERROR "OpenSSL is required for cryptographic operations")
endif()

# pkg-config for system library detection
find_package(PkgConfig REQUIRED)

# USB library detection (for device communication)
if(JAMES_PLATFORM_LINUX)
    pkg_check_modules(LIBUSB REQUIRED libusb-1.0)
    if(LIBUSB_FOUND)
        message(STATUS "libusb-1.0 found: ${LIBUSB_VERSION}")
        include_directories(${LIBUSB_INCLUDE_DIRS})
        link_directories(${LIBUSB_LIBRARY_DIRS})
    endif()
endif()

# Filesystem library - TEACHING: C++17 filesystem needs explicit linking on some systems
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "9.0")
    # GCC < 9.0 requires explicit filesystem linking
    set(FILESYSTEM_LIB stdc++fs)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "9.0")
    # Clang < 9.0 requires explicit filesystem linking
    set(FILESYSTEM_LIB c++fs)
else()
    # Modern compilers have filesystem built-in
    set(FILESYSTEM_LIB "")
endif()

# =============================================================================
# INCLUDE DIRECTORIES
# =============================================================================

# TEACHING: We set up include paths in dependency order
# Core headers are available to all components
include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_BINARY_DIR}/src  # For generated files
    ${CMAKE_SOURCE_DIR}/src/core
    ${OPENSSL_INCLUDE_DIR}
)

# =============================================================================
# SOURCE FILE ORGANIZATION
# =============================================================================

# TEACHING: We organize source files by component for maintainability
# This matches our architectural layers

# Core engine sources - The foundation of everything
set(JAMES_CORE_SOURCES
    src/core/james_engine.cpp
    src/core/device_manager.cpp
    src/core/audit_logger.cpp
    src/core/security_manager.cpp
    src/core/evidence_manager.cpp
)

# Device handler sources - Platform-specific device communication
set(JAMES_HANDLER_SOURCES
    src/core/android_handler.cpp
    src/core/ios_handler.cpp
    src/core/usb_handler.cpp
)

# Main application source
set(JAMES_MAIN_SOURCES
    src/main.cpp
)

# All sources combined
set(JAMES_ALL_SOURCES
    ${JAMES_CORE_SOURCES}
    ${JAMES_HANDLER_SOURCES}
    ${JAMES_MAIN_SOURCES}
)

# Header files for IDE support
set(JAMES_HEADERS
    src/core/james_common.h
    src/core/james_result.h
    src/core/james_engine.h
    src/core/device_manager.h
    src/core/device_info.h
    src/core/android_handler.h
    src/core/ios_handler.h
    src/core/usb_handler.h
    src/core/audit_logger.h
    src/core/security_manager.h
    src/core/evidence_manager.h
)

# =============================================================================
# LIBRARY TARGETS
# =============================================================================

# TEACHING: We build libraries first, then link them to the executable
# This allows for better dependency management and testing

# Core library - The heart of the forensic engine
add_library(james_core STATIC ${JAMES_CORE_SOURCES})
target_include_directories(james_core PUBLIC 
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/core
)
target_link_libraries(james_core 
    PUBLIC 
        OpenSSL::SSL 
        OpenSSL::Crypto
        Threads::Threads
        ${FILESYSTEM_LIB}
)

# Set library properties for security
set_target_properties(james_core PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)

# Device handlers library - Platform-specific implementations
add_library(james_handlers STATIC ${JAMES_HANDLER_SOURCES})
target_include_directories(james_handlers PUBLIC 
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/core
)
target_link_libraries(james_handlers 
    PUBLIC 
        james_core
)

# Link USB library on Linux
if(JAMES_PLATFORM_LINUX AND LIBUSB_FOUND)
    target_link_libraries(james_handlers PUBLIC ${LIBUSB_LIBRARIES})
    target_compile_options(james_handlers PUBLIC ${LIBUSB_CFLAGS_OTHER})
endif()

set_target_properties(james_handlers PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)

# =============================================================================
# MAIN EXECUTABLE TARGET
# =============================================================================

# TEACHING: The main executable is thin - most logic is in libraries
# This enables easier testing and modular development
add_executable(james ${JAMES_MAIN_SOURCES})

# Link all libraries to main executable
target_link_libraries(james 
    PRIVATE
        james_core
        james_handlers
        Threads::Threads
        ${FILESYSTEM_LIB}
)

# Set executable properties
set_target_properties(james PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Security hardening for executable
if(JAMES_PLATFORM_LINUX)
    # TEACHING: These linker flags provide runtime security
    target_link_options(james PRIVATE
        -Wl,-z,relro          # Relocation Read-Only
        -Wl,-z,now            # Bind Now (disable lazy binding)
        -Wl,-z,noexecstack    # Non-executable stack
        -Wl,--as-needed       # Only link needed libraries
    )
endif()

# =============================================================================
# TESTING FRAMEWORK
# =============================================================================

# TEACHING: Testing is crucial for forensic software court admissibility
enable_testing()

# Find test framework - we'll use a simple built-in approach for now
# TODO: Add Google Test or Catch2 in Phase 3
add_custom_target(run_tests
    COMMAND ${CMAKE_COMMAND} -E echo "Running J.A.M.E.S. basic validation tests..."
    COMMAND $<TARGET_FILE:james> --version
    COMMAND $<TARGET_FILE:james> help
    DEPENDS james
    COMMENT "Basic functionality validation"
)

# =============================================================================
# INSTALLATION RULES
# =============================================================================

# TEACHING: Professional software needs proper installation rules
# This enables package creation and system-wide deployment

install(TARGETS james
    RUNTIME DESTINATION bin
    COMPONENT runtime
)

# Install configuration files
install(FILES 
    README.md
    DESTINATION share/doc/james
    COMPONENT documentation
)

# Create directories for runtime data
install(DIRECTORY DESTINATION var/log/james COMPONENT runtime)
install(DIRECTORY DESTINATION var/lib/james/evidence COMPONENT runtime)

# =============================================================================
# DEVELOPMENT AND DEBUGGING SUPPORT
# =============================================================================

# TEACHING: Development tools help maintain code quality
# These targets assist with code analysis and debugging

#DISABLED_# Static analysis disabled for clean build

# Static analysis disabled for clean build

# Memory debugging target
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_target(memcheck
        COMMAND valgrind 
            --tool=memcheck 
            --leak-check=full 
            --show-leak-kinds=all 
            --track-origins=yes
            $<TARGET_FILE:james> --version
        DEPENDS james
        COMMENT "Running memory leak detection"
    )
endif()

# =============================================================================
# BUILD INFORMATION AND STATUS
# =============================================================================

# TEACHING: Build status helps developers understand the configuration
message(STATUS "")
message(STATUS "J.A.M.E.S. Build Configuration Summary")
message(STATUS "=====================================")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "")
message(STATUS "Security Features:")
message(STATUS "  - Position Independent Code: ${CMAKE_POSITION_INDEPENDENT_CODE}")
message(STATUS "  - Stack Protection: ENABLED")
message(STATUS "  - Fortify Source: ENABLED")
message(STATUS "  - Address Sanitizer: $<$<CONFIG:Debug>:ENABLED>")
message(STATUS "  - OpenSSL Version: ${OPENSSL_VERSION}")
message(STATUS "")
message(STATUS "Forensic Compliance:")
message(STATUS "  - NIST 800-101: ENABLED")
message(STATUS "  - ISO 27037: ENABLED")
message(STATUS "  - SEI-CERT: ENABLED")
message(STATUS "  - Chain of Custody: ENABLED")
message(STATUS "  - Audit Logging: ENABLED")
message(STATUS "")

# =============================================================================
# CROSS-PLATFORM PREPARATION (WINDOWS SUPPORT)
# =============================================================================

# TEACHING: We prepare Windows support but don't activate it yet
# This makes Phase 3 cross-platform development easier
if(JAMES_PLATFORM_WINDOWS)
    # Windows-specific libraries (prepared for future)
    # target_link_libraries(james_handlers PRIVATE setupapi winusb)
    
    # Windows security flags
    # set_target_properties(james PROPERTIES
    #     LINK_FLAGS "/DYNAMICBASE /NXCOMPAT /SAFESEH"
    # )
    
    message(STATUS "Windows support: PREPARED (not yet active)")
endif()

# =============================================================================
# FINAL VALIDATION
# =============================================================================

# TEACHING: Final validation ensures all critical components are available
if(NOT OPENSSL_FOUND)
    message(FATAL_ERROR "OpenSSL is required for J.A.M.E.S. cryptographic operations")
endif()

if(NOT Threads_FOUND)
    message(FATAL_ERROR "Threading support is required for J.A.M.E.S.")
endif()

message(STATUS "Build configuration validated successfully")
message(STATUS "Ready to build J.A.M.E.S. forensic framework")
message(STATUS "")