// =============================================================================
// 📁 FILE: install_dependencies.sh - NEW DEPENDENCY INSTALLER
// 🏷 REASONING: Automated dependency installation script
// =============================================================================

#!/bin/bash
# install_dependencies.sh - J.A.M.E.S. Dependency Installer
# Automatically installs required development packages

set -euo pipefail

readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'  
readonly BLUE='\033[0;34m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    elif [[ -f /etc/redhat-release ]]; then
        echo "rhel"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

install_ubuntu_debian() {
    echo -e "${BLUE}📦 Installing dependencies for Ubuntu/Debian${NC}"
    
    sudo apt-get update
    sudo apt-get install -y \
        build-essential \
        cmake \
        pkg-config \
        libssl-dev \
        libusb-1.0-0-dev \
        git \
        valgrind \
        cppcheck \
        clang-tidy
    
    echo -e "${GREEN}✅ Ubuntu/Debian dependencies installed${NC}"
}

install_rhel_centos() {
    echo -e "${BLUE}📦 Installing dependencies for RHEL/CentOS${NC}"
    
    sudo yum install -y \
        gcc-c++ \
        cmake \
        pkgconfig \
        openssl-devel \
        libusb1-devel \
        git \
        valgrind \
        cppcheck
    
    echo -e "${GREEN}✅ RHEL/CentOS dependencies installed${NC}"
}

install_fedora() {
    echo -e "${BLUE}📦 Installing dependencies for Fedora${NC}"
    
    sudo dnf install -y \
        gcc-c++ \
        cmake \
        pkgconfig \
        openssl-devel \
        libusb1-devel \
        git \
        valgrind \
        cppcheck \
        clang-tools-extra
    
    echo -e "${GREEN}✅ Fedora dependencies installed${NC}"
}

install_arch() {
    echo -e "${BLUE}📦 Installing dependencies for Arch Linux${NC}"
    
    sudo pacman -S --noconfirm \
        base-devel \
        cmake \
        pkgconf \
        openssl \
        libusb \
        git \
        valgrind \
        cppcheck \
        clang
    
    echo -e "${GREEN}✅ Arch Linux dependencies installed${NC}"
}

main() {
    echo -e "${BLUE}"
    echo "════════════════════════════════════════════════════════════════"
    echo "              J.A.M.E.S. Dependency Installer"
    echo "        Installing Required Development Packages"
    echo "════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    
    local distro
    distro="$(detect_distro)"
    
    case "$distro" in
        ubuntu|debian)
            install_ubuntu_debian
            ;;
        rhel|centos)
            install_rhel_centos
            ;;
        fedora)
            install_fedora
            ;;
        arch)
            install_arch
            ;;
        *)
            echo -e "${RED}❌ Unsupported distribution: $distro${NC}"
            echo -e "${YELLOW}💡 Please install manually:${NC}"
            echo "   - C++ compiler (g++ or clang++)"
            echo "   - CMake (3.16+)"
            echo "   - OpenSSL development headers"
            echo "   - libusb-1.0 development headers"
            echo "   - pkg-config"
            exit 1
            ;;
    esac
    
    echo -e "\n${GREEN}🎉 All dependencies installed successfully!${NC}"
    echo -e "${BLUE}🚀 Next steps:${NC}"
    echo "   1. Run: ./build.sh"
    echo "   2. Test: ./build/james --version"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi