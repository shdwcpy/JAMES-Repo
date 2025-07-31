# src/core/CMakeLists.txt - J.A.M.E.S. Core Engine

cmake_minimum_required(VERSION 3.20)

project(JAMESCore 
    DESCRIPTION "J.A.M.E.S. core forensic engine"
    LANGUAGES CXX
)

set(JAMES_CORE_SOURCES
    james_engine.cpp
    device_manager.cpp
    extraction_session.cpp
    crypto/hash_chain.cpp
    crypto/tamper_detection.cpp
    crypto/evidence_crypto.cpp
    utils/logger.cpp
    utils/config_manager.cpp
    evidence/chain_of_custody.cpp
    evidence/evidence_container.cpp
)

set(JAMES_CORE_HEADERS
    james_engine.h
    device_manager.h
    extraction_session.h
    security_annotations.h
    crypto/hash_chain.h
    crypto/tamper_detection.h
    crypto/evidence_crypto.h
    utils/logger.h
    utils/config_manager.h
    evidence/chain_of_custody.h
    evidence/evidence_container.h
)

add_library(james_core STATIC
    ${JAMES_CORE_SOURCES}
    ${JAMES_CORE_HEADERS}
)

add_library(JAMES::Core ALIAS james_core)

target_include_directories(james_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(james_core
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

target_compile_definitions(james_core
    PUBLIC
        JAMES_CORE_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
        JAMES_CORE_VERSION_MINOR=${PROJECT_VERSION_MINOR}
        ENABLE_SECURE_MEMORY=1
        ENABLE_CRYPTO_VERIFICATION=1
        ENABLE_AUDIT_LOGGING=1
)
