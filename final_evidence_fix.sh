#!/bin/bash
# final_evidence_fix.sh - Fix the last 2 unused parameter errors
# This will complete the build successfully

set -euo pipefail

readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

echo -e "${BLUE}🔧 Applying final evidence_manager.cpp fixes...${NC}"

# Backup the file
cp src/core/evidence_manager.cpp src/core/evidence_manager.cpp.backup.final.$(date +%Y%m%d_%H%M%S)

# Method 1: Try simple sed replacement
echo -e "${BLUE}Attempting sed fix...${NC}"
if sed -i 's/const std::string& evidenceId)/const std::string\& \/\*evidenceId\*\/)/g' src/core/evidence_manager.cpp; then
    echo -e "${GREEN}✅ sed fix applied${NC}"
else
    echo -e "${BLUE}sed failed, applying manual fix...${NC}"
    
    # Method 2: Python-based fix (more reliable)
    python3 << 'EOF'
# Read the file
with open('src/core/evidence_manager.cpp', 'r') as f:
    content = f.read()

# Replace the two problematic function signatures
content = content.replace(
    'const std::string& evidenceId) noexcept {',
    'const std::string& /*evidenceId*/) noexcept {'
)

# Write back
with open('src/core/evidence_manager.cpp', 'w') as f:
    f.write(content)

print("Python fix applied successfully")
EOF
fi

echo -e "${GREEN}✅ Final fixes applied!${NC}"
echo -e "${BLUE}🚀 Running final build test...${NC}"

# Automatic build test
if rm -rf build && ./build.sh; then
    echo -e "\n${GREEN}🎉🎉🎉 SUCCESS! J.A.M.E.S. BUILT SUCCESSFULLY! 🎉🎉🎉${NC}"
    echo -e "${BLUE}Testing the executable...${NC}"
    
    echo -e "\n${GREEN}Version check:${NC}"
    ./build/james --version
    
    echo -e "\n${GREEN}Help menu:${NC}"
    ./build/james help
    
    echo -e "\n${GREEN}🎯 CONGRATULATIONS! Your forensic framework is ready!${NC}"
else
    echo -e "\n${BLUE}Build test failed - please run manually: rm -rf build && ./build.sh${NC}"
fi