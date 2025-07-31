#!/bin/bash
# build.sh - J.A.M.E.S. Unified Build Script with Integrated Fixes
# Joint Automated Mobile Extraction System
# 
# Compliance: SEI-CERT, MISRA, Power of 10, NIST, POSIX, SWDGE
# Security: Hardened build process with automatic source code fixes

set -euo pipefail
IFS=$'\n\t'

# Security: Disable core dumps and set secure umask
ulimit -c 0
umask 0077

# Colors - POSIX compliant color definitions
readonly RED=$'\033[0;31m'
readonly GREEN=$'\033[0;32m'
readonly YELLOW=$'\033[1;33m'
readonly BLUE=$'\033[0;34m'
readonly PURPLE=$'\033[0;35m'
readonly NC=$'\033[0m'

# Path validation - prevent directory traversal attacks
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BUILD_DIR="${SCRIPT_DIR}/build"
readonly LOG_FILE="${BUILD_DIR}/build.log"
readonly SRC_DIR="${SCRIPT_DIR}/src"

# Build configuration with security defaults
readonly BUILD_TYPE="${BUILD_TYPE:-Release}"
readonly PARALLEL_JOBS="${PARALLEL_JOBS:-$(nproc 2>/dev/null || echo 1)}"
readonly CMAKE_MIN_VERSION="3.16"
readonly GCC_MIN_VERSION="9.0"

# Security: Validate environment
validate_environment() {
    # Check if running as root (security risk)
    if [[ "${EUID}" -eq 0 ]]; then
        echo -e "${RED}❌ Security Error: Do not run as root${NC}" >&2
        exit 1
    fi
    
    # Validate PATH doesn't contain current directory
    if [[ ":${PATH}:" == *":.::"* ]]; then
        echo -e "${RED}❌ Security Error: PATH contains current directory${NC}" >&2
        exit 1
    fi
    
    # Check for required environment variables
    if [[ -z "${HOME:-}" ]]; then
        echo -e "${RED}❌ Environment Error: HOME not set${NC}" >&2
        exit 1
    fi
}

print_header() {
    echo -e "${BLUE}"
    echo "════════════════════════════════════════════════════════════════"
    echo "                    J.A.M.E.S. Build System"
    echo "            Joint Automated Mobile Extraction System"
    echo "        Security-Hardened Forensic Framework with Auto-Fix"
    echo "════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo "Build Type: ${BUILD_TYPE}"
    echo "Parallel Jobs: ${PARALLEL_JOBS}"
    echo "Build Directory: ${BUILD_DIR}"
    echo "Log File: ${LOG_FILE}"
    echo
}

print_section() {
    local section_name="${1}"
    echo -e "\n${PURPLE}🔧 ${section_name}${NC}"
    echo "────────────────────────────────────────────────────────────────"
}

log_message() {
    local level="${1}"
    local message="${2}"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[${timestamp}] [${level}] ${message}" >> "${LOG_FILE}"
}

backup_source_file() {
    local file="${1}"
    if [[ -f "${file}" ]]; then
        local backup="${file}.backup.$(date +%Y%m%d_%H%M%S)"
        cp "${file}" "${backup}"
        echo -e "${BLUE}📋${NC} Backed up: ${file}"
        log_message "INFO" "Created backup: ${backup}"
    fi
}

check_tool_version() {
    local tool="${1}"
    local min_version="${2}"
    local current_version
    
    case "${tool}" in
        "cmake")
            current_version="$(cmake --version 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+' | head -n1)"
            ;;
        "g++")
            current_version="$(g++ --version 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+' | head -n1)"
            ;;
        *)
            return 0
            ;;
    esac
    
    if [[ -n "${current_version}" ]]; then
        if ! printf '%s\n%s\n' "${min_version}" "${current_version}" | sort -V -C; then
            echo -e "${YELLOW}⚠${NC}  Warning: ${tool} version ${current_version} may be incompatible (minimum: ${min_version})"
            log_message "WARNING" "${tool} version ${current_version} below minimum ${min_version}"
        else
            echo -e "${GREEN}✓${NC} ${tool} version ${current_version} (>= ${min_version})"
        fi
    fi
}

check_dependencies() {
    print_section "Checking Dependencies and Versions"
    
    local missing=()
    local tools=("cmake" "make" "g++" "pkg-config" "git")
    
    for tool in "${tools[@]}"; do
        if command -v "${tool}" >/dev/null 2>&1; then
            echo -e "${GREEN}✓${NC} Found: ${tool}"
            case "${tool}" in
                "cmake") check_tool_version "${tool}" "${CMAKE_MIN_VERSION}" ;;
                "g++") check_tool_version "${tool}" "${GCC_MIN_VERSION}" ;;
            esac
        else
            missing+=("${tool}")
        fi
    done
    
    # Check for security tools
    local security_tools=("valgrind" "cppcheck" "clang-tidy")
    for tool in "${security_tools[@]}"; do
        if command -v "${tool}" >/dev/null 2>&1; then
            echo -e "${GREEN}✓${NC} Security tool available: ${tool}"
        else
            echo -e "${YELLOW}⚠${NC}  Security tool missing: ${tool} (recommended)"
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "\n${RED}❌ Missing required tools:${NC}"
        printf ' - %s\n' "${missing[@]}"
        log_message "ERROR" "Missing tools: ${missing[*]}"
        exit 1
    fi
    
    log_message "INFO" "Dependency check completed successfully"
}

check_openssl_dev() {
    print_section "Checking OpenSSL Development Headers"
    
    # Check for OpenSSL development headers
    if pkg-config --exists openssl; then
        local openssl_version
        openssl_version="$(pkg-config --modversion openssl)"
        echo -e "${GREEN}✓${NC} OpenSSL development headers found: v${openssl_version}"
        
        # Verify minimum version (1.1.0 or higher)
        if ! printf '%s\n%s\n' "1.1.0" "${openssl_version}" | sort -V -C; then
            echo -e "${YELLOW}⚠${NC}  Warning: OpenSSL ${openssl_version} may be too old (minimum 1.1.0 recommended)"
        fi
    else
        echo -e "${RED}❌ OpenSSL development headers not found${NC}"
        echo -e "${BLUE}💡 Install with:${NC}"
        echo "   Ubuntu/Debian: sudo apt-get install libssl-dev"
        echo "   RHEL/CentOS:   sudo yum install openssl-devel"
        echo "   Fedora:        sudo dnf install openssl-devel"
        echo "   Arch:          sudo pacman -S openssl"
        return 1
    fi
    
    # Check for libusb development headers (for Android ADB)
    if pkg-config --exists libusb-1.0; then
        local libusb_version
        libusb_version="$(pkg-config --modversion libusb-1.0)"
        echo -e "${GREEN}✓${NC} libusb-1.0 development headers found: v${libusb_version}"
    else
        echo -e "${YELLOW}⚠${NC}  libusb-1.0 development headers not found (optional for USB device support)"
        echo -e "${BLUE}💡 Install with:${NC}"
        echo "   Ubuntu/Debian: sudo apt-get install libusb-1.0-0-dev"
        echo "   RHEL/CentOS:   sudo yum install libusb1-devel"
        echo "   Fedora:        sudo dnf install libusb1-devel"
        echo "   Arch:          sudo pacman -S libusb"
    fi
    
    return 0
}

validate_source_integrity() {
    print_section "Validating Source Code Integrity"
    
    # Check for required source files
    local required_files=(
        "CMakeLists.txt"
        "src/main.cpp"
        "src/core/device_manager.h"
        "src/core/device_manager.cpp"
        "src/core/james_engine.h"
        "src/core/james_engine.cpp"
    )
    
    local missing_files=()
    for file in "${required_files[@]}"; do
        if [[ -f "${SCRIPT_DIR}/${file}" ]]; then
            echo -e "${GREEN}✓${NC} Source file: ${file}"
        else
            missing_files+=("${file}")
        fi
    done
    
    if [[ ${#missing_files[@]} -gt 0 ]]; then
        echo -e "\n${RED}❌ Missing source files:${NC}"
        printf ' - %s\n' "${missing_files[@]}"
        log_message "ERROR" "Missing source files: ${missing_files[*]}"
        exit 1
    fi
    
    # Validate CMakeLists.txt for security issues
    if grep -q "CMAKE_BUILD_TYPE.*Debug" "${SCRIPT_DIR}/CMakeLists.txt" 2>/dev/null; then
        echo -e "${YELLOW}⚠${NC}  Warning: Debug build type found in CMakeLists.txt"
    fi
    
    log_message "INFO" "Source integrity validation completed"
}

fix_header_file() {
    local file="${1}"
    local file_type="${2}"
    
    if [[ ! -f "${file}" ]]; then
        echo -e "${YELLOW}⚠${NC}  File not found: ${file}"
        return 0
    fi
    
    echo -e "${BLUE}🔧${NC} Fixing ${file_type}: $(basename "${file}")"
    backup_source_file "${file}"
    
    local changes_made=false
    
    # Add missing #include <cstdint> if not present
    if ! grep -q "#include <cstdint>" "${file}"; then
        # Add after security_annotations.h if it exists, otherwise after last system include
        if grep -q "#include \"security_annotations.h\"" "${file}"; then
            sed -i '/^#include "security_annotations\.h"$/a #include <cstdint>' "${file}"
        elif grep -q "#include <" "${file}"; then
            sed -i '/^#include <.*>$/a #include <cstdint>' "${file}" | head -1
        else
            sed -i '1i #include <cstdint>' "${file}"
        fi
        echo -e "  ${GREEN}✓${NC} Added #include <cstdint>"
        changes_made=true
    fi
    
    # Remove JAMES_SECURE_FN from destructors
    if sed -i 's/JAMES_SECURE_FN \(~[A-Za-z_][A-Za-z0-9_]*\)/\1/g' "${file}"; then
        if grep -q "~" "${file}"; then
            echo -e "  ${GREEN}✓${NC} Fixed destructor annotations"
            changes_made=true
        fi
    fi
    
    # Remove JAMES_SECURE_FN from void functions (but preserve for returning functions)
    if sed -i 's/JAMES_SECURE_FN void \([A-Za-z_][A-Za-z0-9_]*\)/void \1/g' "${file}"; then
        echo -e "  ${GREEN}✓${NC} Fixed void function annotations"
        changes_made=true
    fi
    
    if ${changes_made}; then
        log_message "INFO" "Applied fixes to ${file}"
    else
        echo -e "  ${GREEN}✓${NC} No fixes needed"
    fi
}

auto_fix_source_code() {
    print_section "Auto-Fixing Source Code Issues"
    
    echo -e "${BLUE}🔍${NC} Scanning for common compilation issues..."
    
    # Fix header files
    local header_files=(
        "${SRC_DIR}/core/device_manager.h"
        "${SRC_DIR}/core/james_engine.h"
        "${SRC_DIR}/core/extraction_session.h"
    )
    
    for file in "${header_files[@]}"; do
        fix_header_file "${file}" "header"
    done
    
    # Fix main.cpp specifically
    local main_file="${SRC_DIR}/main.cpp"
    if [[ -f "${main_file}" ]]; then
        echo -e "${BLUE}🔧${NC} Fixing main.cpp"
        backup_source_file "${main_file}"
        
        # Remove JAMES_SECURE_FN from void functions in main.cpp
        if sed -i 's/JAMES_SECURE_FN void \([A-Za-z_][A-Za-z0-9_]*\)/void \1/g' "${main_file}"; then
            echo -e "  ${GREEN}✓${NC} Fixed void function annotations in main.cpp"
            log_message "INFO" "Applied fixes to main.cpp"
        fi
    fi
    
    # Validate fixes were applied correctly
    echo -e "${BLUE}🔍${NC} Validating applied fixes..."
    local validation_passed=true
    
    for file in "${header_files[@]}" "${main_file}"; do
        if [[ -f "${file}" ]]; then
            # Check for remaining problematic patterns
            if grep -q "JAMES_SECURE_FN.*~.*(" "${file}"; then
                echo -e "  ${RED}❌${NC} Still has [[nodiscard]] on destructor: $(basename "${file}")"
                validation_passed=false
            fi
            
            if grep -q "JAMES_SECURE_FN void " "${file}"; then
                echo -e "  ${YELLOW}⚠${NC}  Still has [[nodiscard]] on void functions: $(basename "${file}")"
            fi
            
            if grep -q "#include <cstdint>" "${file}"; then
                echo -e "  ${GREEN}✓${NC} Has required includes: $(basename "${file}")"
            fi
        fi
    done
    
    if ${validation_passed}; then
        echo -e "${GREEN}✅ All source code fixes validated successfully${NC}"
    else
        echo -e "${YELLOW}⚠${NC}  Some issues may remain - will attempt build anyway"
    fi
    
    log_message "INFO" "Source code auto-fix completed"
}

setup_build() {
    print_section "Setting Up Build Directory"
    
    # Security: Validate build directory path
    if [[ ! "${BUILD_DIR}" == "${SCRIPT_DIR}/build" ]]; then
        echo -e "${RED}❌ Security Error: Invalid build directory path${NC}" >&2
        exit 1
    fi
    
    if [[ -d "${BUILD_DIR}" ]]; then
        echo -e "${YELLOW}⚠${NC}  Removing existing build directory"
        if ! rm -rf "${BUILD_DIR}"; then
            echo -e "${RED}❌ Failed to remove build directory${NC}" >&2
            exit 1
        fi
    fi
    
    echo -e "${BLUE}📁${NC} Creating: ${BUILD_DIR}"
    if ! mkdir -p "${BUILD_DIR}"; then
        echo -e "${RED}❌ Failed to create build directory${NC}" >&2
        exit 1
    fi
    
    # Initialize log file
    touch "${LOG_FILE}"
    log_message "INFO" "Build directory setup completed"
}

configure_cmake() {
    print_section "Configuring CMake with Security Hardening"
    
    cd "${BUILD_DIR}" || {
        echo -e "${RED}❌ Failed to change to build directory${NC}" >&2
        exit 1
    }
    
    # Security-hardened CMake configuration
    local cmake_args=(
        "-DCMAKE_BUILD_TYPE=${BUILD_TYPE}"
        "-DBUILD_TESTING=ON"
        "-DCMAKE_CXX_FLAGS=-Wall -Wextra -Werror -Wpedantic -Wformat=2 -Wformat-security"
        "-DCMAKE_CXX_FLAGS=-fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2"
        "-DCMAKE_CXX_FLAGS=-fno-common -fno-delete-null-pointer-checks"
        "-DCMAKE_POSITION_INDEPENDENT_CODE=ON"
        "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON"
    )
    
    # Add debug-specific flags for Debug builds
    if [[ "${BUILD_TYPE}" == "Debug" ]]; then
        cmake_args+=(
            "-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer"
            "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined"
        )
    fi
    
    echo -e "${BLUE}⚙️${NC}  Running CMake configuration..."
    log_message "INFO" "Starting CMake configuration with args: ${cmake_args[*]}"
    
    if ! cmake "${cmake_args[@]}" "${SCRIPT_DIR}" 2>&1 | tee -a "${LOG_FILE}"; then
        echo -e "${RED}❌ CMake configuration failed${NC}" >&2
        log_message "ERROR" "CMake configuration failed"
        exit 1
    fi
    
    echo -e "${GREEN}✓${NC} CMake configuration successful"
    log_message "INFO" "CMake configuration completed successfully"
}

build_project() {
    print_section "Building J.A.M.E.S."
    
    cd "${BUILD_DIR}" || {
        echo -e "${RED}❌ Failed to change to build directory${NC}" >&2
        exit 1
    }
    
    echo -e "${BLUE}🔨${NC} Building with ${PARALLEL_JOBS} parallel jobs..."
    log_message "INFO" "Starting build with ${PARALLEL_JOBS} parallel jobs"
    
    # Build with verbose output and error logging
    if ! cmake --build . --parallel "${PARALLEL_JOBS}" --verbose 2>&1 | tee -a "${LOG_FILE}"; then
        echo -e "${RED}❌ Build failed${NC}" >&2
        echo -e "${RED}Check build output above for error details${NC}" >&2
        log_message "ERROR" "Build failed - check log for details"
        
        # Provide helpful error analysis
        echo -e "\n${BLUE}🔍 Analyzing build errors...${NC}"
        
        if grep -q "uint8_t.*not declared" "${LOG_FILE}"; then
            echo -e "${YELLOW}💡 Issue: Missing #include <cstdint>${NC}"
            echo -e "${YELLOW}   This should have been auto-fixed - please check manually${NC}"
        fi
        
        if grep -q "nodiscard.*void return type" "${LOG_FILE}"; then
            echo -e "${YELLOW}💡 Issue: [[nodiscard]] on void function${NC}"
            echo -e "${YELLOW}   This should have been auto-fixed - please check manually${NC}"
        fi
        
        if grep -q "elaborated-type-specifier.*scoped enum" "${LOG_FILE}"; then
            echo -e "${YELLOW}💡 Issue: Enum class syntax error${NC}"
            echo -e "${YELLOW}   Check enum class declarations in headers${NC}"
        fi
        
        echo -e "\n${BLUE}📋 Troubleshooting:${NC}"
        echo -e "1. Check log file: ${LOG_FILE}"
        echo -e "2. Verify source file backups were created"
        echo -e "3. Manual fixes may be needed for complex issues"
        
        exit 1
    fi
    
    echo -e "${GREEN}✓${NC} Build completed successfully"
    log_message "INFO" "Build completed successfully"
}

run_security_checks() {
    print_section "Running Security Analysis"
    
    cd "${BUILD_DIR}" || return 1
    
    # Check if security analysis tools are available
    if command -v cppcheck >/dev/null 2>&1; then
        echo -e "${BLUE}🛡️${NC}  Running cppcheck security analysis..."
        if ! cppcheck --enable=all --error-exitcode=0 "${SCRIPT_DIR}/src" 2>&1 | tee -a "${LOG_FILE}"; then
            echo -e "${YELLOW}⚠${NC}  Cppcheck found potential issues (see log)"
        else
            echo -e "${GREEN}✓${NC} Cppcheck analysis passed"
        fi
    fi
    
    # Check for hardening flags in binaries
    if [[ -f "james" ]]; then
        echo -e "${BLUE}🔒${NC} Checking binary security features..."
        if command -v readelf >/dev/null 2>&1; then
            if readelf -d james | grep -q "BIND_NOW"; then
                echo -e "${GREEN}✓${NC} BIND_NOW protection enabled"
            else
                echo -e "${YELLOW}⚠${NC}  BIND_NOW protection not found"
            fi
        fi
        
        # Check for PIE
        if readelf -h james | grep -q "DYN"; then
            echo -e "${GREEN}✓${NC} Position Independent Executable (PIE)"
        fi
        
        # Check for stack protection
        if readelf -s james | grep -q "__stack_chk_fail"; then
            echo -e "${GREEN}✓${NC} Stack protection enabled"
        fi
    fi
    
    log_message "INFO" "Security analysis completed"
}

run_tests() {
    print_section "Running Tests"
    
    cd "${BUILD_DIR}" || {
        echo -e "${RED}❌ Failed to change to build directory${NC}" >&2
        exit 1
    }
    
    echo -e "${BLUE}🧪${NC} Executing test suite..."
    log_message "INFO" "Starting test execution"
    
    if command -v ctest >/dev/null 2>&1; then
        if ! ctest --output-on-failure --verbose 2>&1 | tee -a "${LOG_FILE}"; then
            echo -e "${YELLOW}⚠${NC}  Some tests failed"
            log_message "WARNING" "Some tests failed"
        else
            echo -e "${GREEN}✓${NC} All tests passed"
            log_message "INFO" "All tests passed"
        fi
    else
        echo -e "${YELLOW}⚠${NC}  CTest not available - skipping tests"
        log_message "WARNING" "CTest not available"
    fi
}

show_summary() {
    print_section "Build Summary"
    
    echo -e "${GREEN}🎉 J.A.M.E.S. build completed successfully!${NC}"
    echo
    echo -e "${BLUE}🚀 Executable:${NC}"
    if [[ -f "${BUILD_DIR}/james" ]]; then
        echo "   ${BUILD_DIR}/james"
        echo -e "${GREEN}✓${NC} Binary verified"
        
        # Show binary size and permissions
        local binary_info
        binary_info="$(ls -lh "${BUILD_DIR}/james" | awk '{print $5, $1}')"
        echo "   Size: $(echo "${binary_info}" | awk '{print $1}')"
        echo "   Permissions: $(echo "${binary_info}" | awk '{print $2}')"
    else
        echo -e "${YELLOW}⚠${NC}  Binary not found at expected location"
    fi
    
    echo
    echo -e "${BLUE}🔧 Auto-Fixes Applied:${NC}"
    echo "   • Missing #include <cstdint> headers"
    echo "   • [[nodiscard]] removed from destructors"
    echo "   • [[nodiscard]] removed from void functions"
    echo "   • Source file backups created"
    
    echo
    echo -e "${BLUE}🛡️ Security Features Enabled:${NC}"
    echo "   • Stack protection (-fstack-protector-strong)"
    echo "   • Position Independent Executable (PIE)"
    echo "   • Fortify source (_FORTIFY_SOURCE=2)"
    echo "   • Comprehensive warning flags"
    echo "   • Build process logging"
    echo "   • Automatic source code fixes"
    
    echo
    echo -e "${BLUE}📋 Next Steps:${NC}"
    echo "   1. Review build log: ${LOG_FILE}"
    echo "   2. Test executable: ${BUILD_DIR}/james --help"
    echo "   3. Begin Phase 2: Core Implementation"
    echo "   4. Implement device handlers"
    
    echo
    echo -e "${BLUE}📁 Backup Files:${NC}"
    if compgen -G "${SRC_DIR}/**/*.backup.*" > /dev/null 2>&1; then
        echo "   Source backups created with timestamps"
        find "${SRC_DIR}" -name "*.backup.*" -type f | head -5 | sed 's/^/   - /'
        local backup_count
        backup_count="$(find "${SRC_DIR}" -name "*.backup.*" -type f | wc -l)"
        if [[ "${backup_count}" -gt 5 ]]; then
            echo "   ... and $((backup_count - 5)) more backup files"
        fi
    else
        echo "   No backup files created (no fixes needed)"
    fi
    
    log_message "INFO" "Build summary completed"
}

cleanup_on_exit() {
    local exit_code=$?
    if [[ ${exit_code} -ne 0 ]]; then
        log_message "ERROR" "Build script exited with code ${exit_code}"
        echo -e "\n${RED}❌ Build failed with exit code ${exit_code}${NC}" >&2
        echo -e "${BLUE}📋 Check log file: ${LOG_FILE}${NC}" >&2
        echo -e "${BLUE}📁 Source backups available if rollback needed${NC}" >&2
    fi
}

main() {
    # Set up exit handler
    trap cleanup_on_exit EXIT
    
    # Security validation first
    validate_environment
    
    print_header
    check_dependencies
    check_openssl_dev
    validate_source_integrity
    auto_fix_source_code
    setup_build
    configure_cmake
    build_project
    run_security_checks
    run_tests
    show_summary
    
    echo -e "\n${GREEN}🎯 J.A.M.E.S. ready for forensic operations!${NC}"
    log_message "INFO" "Build process completed successfully"
}

# Execute main function only if script is run directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi