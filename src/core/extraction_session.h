/**
 * @file extraction_session.h
 * @brief J.A.M.E.S. Extraction Session
 * 
 * ⚠️ Placeholder Implementation – Phase 1
 */

#ifndef JAMES_CORE_EXTRACTION_SESSION_H_
#define JAMES_CORE_EXTRACTION_SESSION_H_

#include <string>
#include "security_annotations.h"
#include <cstdint>

namespace james {
namespace core {

class JAMES_SECURE_CLASS ExtractionSession {
public:
    enum class SessionState : uint8_t {
        kCreated = 0,
        kActive,
        kPaused,
        kCompleted,
        kError
    };
    
    JAMES_SECURE_FN explicit ExtractionSession(const std::string& session_id) noexcept;
    ~ExtractionSession() noexcept;
    
    JAMES_SECURE_FN bool Start() noexcept;
    JAMES_SECURE_FN bool Pause() noexcept;
    JAMES_SECURE_FN bool Stop() noexcept;
    JAMES_SECURE_FN SessionState GetState() const noexcept;
    
private:
    JAMES_PLACEHOLDER_IMPL
    std::string session_id_;
    SessionState state_{SessionState::kCreated};
};

} // namespace core
} // namespace james

#endif // JAMES_CORE_EXTRACTION_SESSION_H_
