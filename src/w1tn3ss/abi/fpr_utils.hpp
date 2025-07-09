#pragma once

#include <QBDI.h>
#include <cstring>

namespace w1::abi {

// platform-agnostic utilities for accessing FPR state
// qbdi has different FPRState structures on different platforms

#ifdef _WIN32
// on windows, qbdi defines xmm registers as individual char[16] arrays
// we need to cast them to access as float/double values

// helper to get xmm register pointer by index
inline const char* get_xmm_ptr(const QBDI::FPRState* fpr, size_t reg_idx) {
  switch (reg_idx) {
  case 0:
    return fpr->xmm0;
  case 1:
    return fpr->xmm1;
  case 2:
    return fpr->xmm2;
  case 3:
    return fpr->xmm3;
  case 4:
    return fpr->xmm4;
  case 5:
    return fpr->xmm5;
  case 6:
    return fpr->xmm6;
  case 7:
    return fpr->xmm7;
#if defined(_M_X64) || defined(__x86_64__)
  // x86_64 has additional xmm8-xmm15 registers
  case 8:
    return fpr->xmm8;
  case 9:
    return fpr->xmm9;
  case 10:
    return fpr->xmm10;
  case 11:
    return fpr->xmm11;
  case 12:
    return fpr->xmm12;
  case 13:
    return fpr->xmm13;
  case 14:
    return fpr->xmm14;
  case 15:
    return fpr->xmm15;
#endif
  default:
    return nullptr;
  }
}

inline float get_xmm_float(const QBDI::FPRState* fpr, size_t reg_idx) {
  const char* xmm_ptr = get_xmm_ptr(fpr, reg_idx);
  if (!xmm_ptr) {
    return 0.0f;
  }

  float result;
  std::memcpy(&result, xmm_ptr, sizeof(float));
  return result;
}

inline double get_xmm_double(const QBDI::FPRState* fpr, size_t reg_idx) {
  const char* xmm_ptr = get_xmm_ptr(fpr, reg_idx);
  if (!xmm_ptr) {
    return 0.0;
  }

  double result;
  std::memcpy(&result, xmm_ptr, sizeof(double));
  return result;
}

inline void get_xmm_bytes(const QBDI::FPRState* fpr, size_t reg_idx, void* dest) {
  const char* xmm_ptr = get_xmm_ptr(fpr, reg_idx);
  if (!xmm_ptr) {
    std::memset(dest, 0, 16);
    return;
  }

  std::memcpy(dest, xmm_ptr, 16);
}

#else
// On Unix platforms (Linux/macOS), QBDI typically defines XMM as an array of unions

inline float get_xmm_float(const QBDI::FPRState* fpr, size_t reg_idx) {
  if (reg_idx >= 16) {
    return 0.0f;
  }
  return fpr->xmm[reg_idx].reg32[0];
}

inline double get_xmm_double(const QBDI::FPRState* fpr, size_t reg_idx) {
  if (reg_idx >= 16) {
    return 0.0;
  }
  return fpr->xmm[reg_idx].reg64[0];
}

inline void get_xmm_bytes(const QBDI::FPRState* fpr, size_t reg_idx, void* dest) {
  if (reg_idx >= 16) {
    std::memset(dest, 0, 16);
    return;
  }
  std::memcpy(dest, &fpr->xmm[reg_idx], 16);
}

#endif

} // namespace w1::abi