#!/bin/bash
# auto_fix_headers.sh - Automated C++ Header Fixes for J.A.M.E.S.
# Fixes compilation errors identified in the build process

set -euo pipefail

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SRC_DIR="${SCRIPT_DIR}/src"

print_section() {
    echo -e "\n${BLUE}🔧 $1${NC}"
    echo "────────────────────────────────────────────────────────────────"
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp "$file" "$file.backup.$(date +%Y%m%d_%H%M%S)"
        echo -e "${BLUE}📋${NC} Backed up: $file"
    fi
}

fix_device_manager_header() {
    local file="${SRC_DIR}/core/device_manager.h"
    
    if [[ ! -f "$file" ]]; then
        echo -e "${YELLOW}⚠${NC}  File not found: $file"
        return 1
    fi
    
    print_section "Fixing device_manager.h"
    backup_file "$file"
    
    # Add missing #include <cstdint> after security_annotations.h
    if ! grep -q "#include <cstdint>" "$file"; then
        sed -i '/^#include "security_annotations\.h"$/a #include <cstdint>' "$file"
        echo -e "${GREEN}✓${NC} Added #include <cstdint>"
    fi
    
    # Remove JAMES_SECURE_FN from destructor
    sed -i 's/JAMES_SECURE_FN ~DeviceManager()/~DeviceManager()/' "$file"
    echo -e "${GREEN}✓${NC} Removed [[nodiscard]] from destructor"
    
    # Verify the enum class syntax is correct
    if grep -q "enum class DeviceType : uint8_t" "$file"; then
        echo -e "${GREEN}✓${NC} Enum class syntax verified"
    else
        echo -e "${YELLOW}⚠${NC}  Please verify enum class DeviceType syntax"
    fi
}

fix_james_engine_header() {
    local file="${SRC_DIR}/core/james_engine.h"
    
    if [[ ! -f "$file" ]]; then
        echo -e "${YELLOW}⚠${NC}  File not found: $file"
        return 1
    fi
    
    print_section "Fixing james_engine.h"
    backup_file "$file"
    
    # Add missing #include <cstdint> if not present
    if ! grep -q "#include <cstdint>" "$file"; then
        # Add after the last system include or first local include
        if grep -q "#include <" "$file"; then
            sed -i '/^#include <.*>$/a #include <cstdint>' "$file" | head -1
        else
            sed -i '/^#include ".*"$/i #include <cstdint>' "$file" | head -1
        fi
        echo -e "${GREEN}✓${NC} Added #include <cstdint>"
    fi
    
    # Remove JAMES_SECURE_FN from destructor
    sed -i 's/JAMES_SECURE_FN ~JAMESEngine()/~JAMESEngine()/' "$file"
    echo -e "${GREEN}✓${NC} Removed [[nodiscard]] from destructor"
    
    # Remove JAMES_SECURE_FN from void Shutdown() function
    sed -i 's/JAMES_SECURE_FN void Shutdown()/void Shutdown()/' "$file"
    echo -e "${GREEN}✓${NC} Removed [[nodiscard]] from void Shutdown()"
}

fix_extraction_session_header() {
    local file="${SRC_DIR}/core/extraction_session.h"
    
    if [[ ! -f "$file" ]]; then
        echo -e "${YELLOW}⚠${NC}  File not found: $file"
        return 1
    fi
    
    print_section "Fixing extraction_session.h"
    backup_file "$file"
    
    # Add missing #include <cstdint> if not present
    if ! grep -q "#include <cstdint>" "$file"; then
        if grep -q "#include <" "$file"; then
            sed -i '/^#include <.*>$/a #include <cstdint>' "$file" | head -1
        else
            sed -i '/^#include ".*"$/i #include <cstdint>' "$file" | head -1
        fi
        echo -e "${GREEN}✓${NC} Added #include <cstdint>"
    fi
    
    # Remove JAMES_SECURE_FN from destructor
    sed -i 's/JAMES_SECURE_FN ~ExtractionSession()/~ExtractionSession()/' "$file"
    echo -e "${GREEN}✓${NC} Removed [[nodiscard]] from destructor"
    
    # Remove JAMES_SECURE_FN from any void functions
    sed -i 's/JAMES_SECURE_FN void /void /g' "$file"
    echo -e "${GREEN}✓${NC} Removed [[nodiscard]] from void functions"
}

fix_security_annotations() {
    local file="${SRC_DIR}/core/security_annotations.h"
    
    if [[ ! -f "$file" ]]; then
        echo -e "${YELLOW}⚠${NC}  File not found: $file - this may be OK"
        return 0
    fi
    
    print_section "Checking security_annotations.h"
    
    # Check if JAMES_SECURE_FN is properly defined
    if grep -q "JAMES_SECURE_FN" "$file"; then
        echo -e "${BLUE}📋${NC} JAMES_SECURE_FN macro found in security annotations"
        
        # If it's defined as [[nodiscard]], suggest improvement
        if grep -q "JAMES_SECURE_FN.*nodiscard" "$file"; then
            echo -e "${YELLOW}💡${NC} Consider making JAMES_SECURE_FN conditional for void functions"
        fi
    else
        echo -e "${YELLOW}⚠${NC}  JAMES_SECURE_FN not found in security annotations"
    fi
}

validate_fixes() {
    print_section "Validating Applied Fixes"
    
    local files=(
        "${SRC_DIR}/core/device_manager.h"
        "${SRC_DIR}/core/james_engine.h" 
        "${SRC_DIR}/core/extraction_session.h"
    )
    
    local all_good=true
    
    for file in "${files[@]}"; do
        if [[ -f "$file" ]]; then
            echo -e "${BLUE}🔍${NC} Checking $file..."
            
            # Check for cstdint include
            if grep -q "#include <cstdint>" "$file"; then
                echo -e "  ${GREEN}✓${NC} Has #include <cstdint>"
            else
                echo -e "  ${RED}❌${NC} Missing #include <cstdint>"
                all_good=false
            fi
            
            # Check for problematic destructor patterns
            if grep -q "JAMES_SECURE_FN.*~.*(" "$file"; then
                echo -e "  ${RED}❌${NC} Still has [[nodiscard]] on destructor"
                all_good=false
            else
                echo -e "  ${GREEN}✓${NC} Destructor fixed"
            fi
            
            # Check for void functions with JAMES_SECURE_FN
            if grep -q "JAMES_SECURE_FN void " "$file"; then
                echo -e "  ${YELLOW}⚠${NC}  Still has [[nodiscard]] on void functions"
            else
                echo -e "  ${GREEN}✓${NC} Void functions fixed"
            fi
            
        else
            echo -e "${YELLOW}⚠${NC}  File not found: $file"
        fi
    done
    
    if $all_good; then
        echo -e "\n${GREEN}🎉 All fixes applied successfully!${NC}"
        return 0
    else
        echo -e "\n${YELLOW}⚠${NC}  Some issues may remain - please review manually"
        return 1
    fi
}

show_manual_steps() {
    print_section "Manual Steps (if needed)"
    
    echo -e "${BLUE}📋 If automated fixes didn't work completely:${NC}"
    echo
    echo "1. Add missing includes manually:"
    echo "   Add '#include <cstdint>' after other includes in:"
    echo "   - src/core/device_manager.h"
    echo "   - src/core/james_engine.h"
    echo "   - src/core/extraction_session.h"
    echo
    echo "2. Fix destructor declarations:"
    echo "   Change 'JAMES_SECURE_FN ~ClassName()' to '~ClassName()'"
    echo
    echo "3. Fix void function declarations:"
    echo "   Change 'JAMES_SECURE_FN void FunctionName()' to 'void FunctionName()'"
    echo
    echo "4. Keep [[nodiscard]] only for functions that return values"
    echo
    echo -e "${BLUE}📋 Backup files created with timestamp suffix${NC}"
}

main() {
    echo -e "${BLUE}"
    echo "════════════════════════════════════════════════════════════════"
    echo "                 J.A.M.E.S. Header Fix Utility"
    echo "           Automated C++ Compilation Error Fixes"
    echo "════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    
    if [[ ! -d "$SRC_DIR" ]]; then
        echo -e "${RED}❌ Source directory not found: $SRC_DIR${NC}"
        echo "Please run this script from the J.A.M.E.S. root directory"
        exit 1
    fi
    
    fix_device_manager_header
    fix_james_engine_header
    fix_extraction_session_header
    fix_security_annotations
    
    echo
    validate_fixes
    
    show_manual_steps
    
    echo -e "\n${GREEN}🎯 Header fixes completed!${NC}"
    echo -e "${BLUE}💡 Now try running the build script again${NC}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi