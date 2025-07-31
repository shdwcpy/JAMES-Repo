/**
 * @file security_annotations.h
 * @brief Security annotation macros for J.A.M.E.S. forensic code
 * 
 * ⚠️ Placeholder Implementation – Phase 1
 */

#ifndef JAMES_CORE_SECURITY_ANNOTATIONS_H_
#define JAMES_CORE_SECURITY_ANNOTATIONS_H_

// Security classification macros
#define JAMES_SECURE_FN [[nodiscard]]
#define JAMES_SECURE_CLASS
#define JAMES_CRITICAL_SECTION
#define JAMES_EVIDENCE_DATA
#define JAMES_SECURE_MEMORY

// Compliance annotations
#define NIST_800_101_COMPLIANT
#define ISO_27037_COMPLIANT
#define SEI_CERT_COMPLIANT
#define MISRA_COMPLIANT

// Placeholder marker
#define JAMES_PLACEHOLDER_IMPL // ⚠️ Remove in production

#endif // JAMES_CORE_SECURITY_ANNOTATIONS_H_
