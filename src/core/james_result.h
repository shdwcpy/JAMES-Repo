// =============================================================================
// 📁 FILE: src/core/james_result.h - ERROR HANDLING FOUNDATION  
// 🏷 REASONING: Forensic-grade error handling with audit trail support
// =============================================================================

#pragma once

#include <string>
#include <memory>
#include <type_traits>

namespace james {

// TEACHING: Why we need custom result types in forensics
// Standard exceptions can lose critical error context needed for court evidence
// This Result<T> pattern ensures all errors are captured and logged properly
template<typename T>
class JAMESResult {
private:
    bool m_isSuccess;
    T m_value;
    std::string m_errorMessage;
    JAMESResultCode m_errorCode;
    std::string m_contextInfo;
    
public:
    // Success constructor
    explicit JAMESResult(T&& value) noexcept
        : m_isSuccess(true)
        , m_value(std::forward<T>(value))
        , m_errorCode(JAMESResultCode::SUCCESS) {}
    
    explicit JAMESResult(const T& value) noexcept
        : m_isSuccess(true)
        , m_value(value)
        , m_errorCode(JAMESResultCode::SUCCESS) {}
    
    // Error constructor
    JAMESResult(JAMESResultCode errorCode, const std::string& errorMessage) noexcept
        : m_isSuccess(false)
        , m_value{}
        , m_errorMessage(errorMessage)
        , m_errorCode(errorCode) {}
    
    // Error constructor with context
    JAMESResult(JAMESResultCode errorCode, const std::string& errorMessage, 
                const std::string& context) noexcept
        : m_isSuccess(false)
        , m_value{}
        , m_errorMessage(errorMessage)
        , m_errorCode(errorCode)
        , m_contextInfo(context) {}
    
    // Copy constructor
    JAMESResult(const JAMESResult& other) noexcept
        : m_isSuccess(other.m_isSuccess)
        , m_value(other.m_value)
        , m_errorMessage(other.m_errorMessage)
        , m_errorCode(other.m_errorCode)
        , m_contextInfo(other.m_contextInfo) {}
    
    // Move constructor
    JAMESResult(JAMESResult&& other) noexcept
        : m_isSuccess(other.m_isSuccess)
        , m_value(std::move(other.m_value))
        , m_errorMessage(std::move(other.m_errorMessage))
        , m_errorCode(other.m_errorCode)
        , m_contextInfo(std::move(other.m_contextInfo)) {}
    
    // Assignment operators
    JAMESResult& operator=(const JAMESResult& other) noexcept {
        if (this != &other) {
            m_isSuccess = other.m_isSuccess;
            m_value = other.m_value;
            m_errorMessage = other.m_errorMessage;
            m_errorCode = other.m_errorCode;
            m_contextInfo = other.m_contextInfo;
        }
        return *this;
    }
    
    JAMESResult& operator=(JAMESResult&& other) noexcept {
        if (this != &other) {
            m_isSuccess = other.m_isSuccess;
            m_value = std::move(other.m_value);
            m_errorMessage = std::move(other.m_errorMessage);
            m_errorCode = other.m_errorCode;
            m_contextInfo = std::move(other.m_contextInfo);
        }
        return *this;
    }
    
    // Query methods
    [[nodiscard]] bool IsSuccess() const noexcept { return m_isSuccess; }
    [[nodiscard]] bool IsFailure() const noexcept { return !m_isSuccess; }
    [[nodiscard]] JAMESResultCode GetErrorCode() const noexcept { return m_errorCode; }
    [[nodiscard]] const std::string& GetErrorMessage() const noexcept { return m_errorMessage; }
    [[nodiscard]] const std::string& GetContextInfo() const noexcept { return m_contextInfo; }
    
    // Value access - SECURITY: Only available on success
    [[nodiscard]] const T& GetValue() const& {
        if (JAMES_UNLIKELY(!m_isSuccess)) {
            throw std::logic_error("Attempted to access value of failed result: " + m_errorMessage);
        }
        return m_value;
    }
    
    [[nodiscard]] T&& GetValue() && {
        if (JAMES_UNLIKELY(!m_isSuccess)) {
            throw std::logic_error("Attempted to access value of failed result: " + m_errorMessage);
        }
        return std::move(m_value);
    }
    
    // Safe value access with default
    [[nodiscard]] T GetValueOr(const T& defaultValue) const noexcept {
        return m_isSuccess ? m_value : defaultValue;
    }
    
    // Factory methods for cleaner code
    static JAMESResult<T> Success(T&& value) noexcept {
        return JAMESResult<T>(std::forward<T>(value));
    }
    
    static JAMESResult<T> Success(const T& value) noexcept {
        return JAMESResult<T>(value);
    }
    
    static JAMESResult<T> Failure(const std::string& message) noexcept {
        return JAMESResult<T>(JAMESResultCode::UNKNOWN_ERROR, message);
    }
    
    static JAMESResult<T> Failure(JAMESResultCode code, const std::string& message) noexcept {
        return JAMESResult<T>(code, message);
    }
    
    static JAMESResult<T> Failure(JAMESResultCode code, const std::string& message, 
                                  const std::string& context) noexcept {
        return JAMESResult<T>(code, message, context);
    }
    
    // Transform result to different type
    template<typename U>
    [[nodiscard]] JAMESResult<U> Transform(std::function<U(const T&)> transformer) const noexcept {
        if (m_isSuccess) {
            try {
                return JAMESResult<U>::Success(transformer(m_value));
            } catch (const std::exception& e) {
                return JAMESResult<U>::Failure(JAMESResultCode::UNKNOWN_ERROR, 
                    "Transform operation failed: " + std::string(e.what()));
            }
        } else {
            return JAMESResult<U>::Failure(m_errorCode, m_errorMessage, m_contextInfo);
        }
    }
    
    // Chain operations (monadic bind)
    template<typename U>
    [[nodiscard]] JAMESResult<U> AndThen(std::function<JAMESResult<U>(const T&)> operation) const noexcept {
        if (m_isSuccess) {
            return operation(m_value);
        } else {
            return JAMESResult<U>::Failure(m_errorCode, m_errorMessage, m_contextInfo);
        }
    }
    
    // Get full error description for forensic logging
    [[nodiscard]] std::string GetFullErrorDescription() const noexcept {
        if (m_isSuccess) return "SUCCESS";
        
        std::ostringstream oss;
        oss << "[" << static_cast<int>(m_errorCode) << "] " << m_errorMessage;
        if (!m_contextInfo.empty()) {
            oss << " (Context: " << m_contextInfo << ")";
        }
        return oss.str();
    }
    
    // Conversion to bool for easy checking
    explicit operator bool() const noexcept {
        return m_isSuccess;
    }
};

// Specialized version for void results
template<>
class JAMESResult<void> {
private:
    bool m_isSuccess;
    std::string m_errorMessage;
    JAMESResultCode m_errorCode;
    std::string m_contextInfo;
    
public:
    // Success constructor
    JAMESResult() noexcept
        : m_isSuccess(true)
        , m_errorCode(JAMESResultCode::SUCCESS) {}
    
    // Error constructors
    JAMESResult(JAMESResultCode errorCode, const std::string& errorMessage) noexcept
        : m_isSuccess(false)
        , m_errorMessage(errorMessage)
        , m_errorCode(errorCode) {}
    
    JAMESResult(JAMESResultCode errorCode, const std::string& errorMessage, 
                const std::string& context) noexcept
        : m_isSuccess(false)
        , m_errorMessage(errorMessage)
        , m_errorCode(errorCode)
        , m_contextInfo(context) {}
    
    // Query methods
    [[nodiscard]] bool IsSuccess() const noexcept { return m_isSuccess; }
    [[nodiscard]] bool IsFailure() const noexcept { return !m_isSuccess; }
    [[nodiscard]] JAMESResultCode GetErrorCode() const noexcept { return m_errorCode; }
    [[nodiscard]] const std::string& GetErrorMessage() const noexcept { return m_errorMessage; }
    [[nodiscard]] const std::string& GetContextInfo() const noexcept { return m_contextInfo; }
    
    // Factory methods
    static JAMESResult<void> Success() noexcept {
        return JAMESResult<void>();
    }
    
    static JAMESResult<void> Failure(const std::string& message) noexcept {
        return JAMESResult<void>(JAMESResultCode::UNKNOWN_ERROR, message);
    }
    
    static JAMESResult<void> Failure(JAMESResultCode code, const std::string& message) noexcept {
        return JAMESResult<void>(code, message);
    }
    
    static JAMESResult<void> Failure(JAMESResultCode code, const std::string& message, 
                                     const std::string& context) noexcept {
        return JAMESResult<void>(code, message, context);
    }
    
    // Get full error description
    [[nodiscard]] std::string GetFullErrorDescription() const noexcept {
        if (m_isSuccess) return "SUCCESS";
        
        std::ostringstream oss;
        oss << "[" << static_cast<int>(m_errorCode) << "] " << m_errorMessage;
        if (!m_contextInfo.empty()) {
            oss << " (Context: " << m_contextInfo << ")";
        }
        return oss.str();
    }
    
    // Conversion to bool
    explicit operator bool() const noexcept {
        return m_isSuccess;
    }
};

} // namespace james