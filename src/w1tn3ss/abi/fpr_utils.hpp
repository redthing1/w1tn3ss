#pragma once

#include <QBDI.h>
#include <cstring>

namespace w1::abi {

// Platform-agnostic utilities for accessing FPR state
// QBDI has different FPRState structures on different platforms

#ifdef _WIN32
// On Windows x64, QBDI defines XMM registers as individual char[16] arrays
// We need to cast them to access as float/double values

inline float get_xmm_float(const QBDI::FPRState* fpr, size_t reg_idx) {
  if (reg_idx >= 16) {
    return 0.0f;
  }

  const char* xmm_ptr = nullptr;
  switch (reg_idx) {
  case 0:
    xmm_ptr = fpr->xmm0;
    break;
  case 1:
    xmm_ptr = fpr->xmm1;
    break;
  case 2:
    xmm_ptr = fpr->xmm2;
    break;
  case 3:
    xmm_ptr = fpr->xmm3;
    break;
  case 4:
    xmm_ptr = fpr->xmm4;
    break;
  case 5:
    xmm_ptr = fpr->xmm5;
    break;
  case 6:
    xmm_ptr = fpr->xmm6;
    break;
  case 7:
    xmm_ptr = fpr->xmm7;
    break;
  case 8:
    xmm_ptr = fpr->xmm8;
    break;
  case 9:
    xmm_ptr = fpr->xmm9;
    break;
  case 10:
    xmm_ptr = fpr->xmm10;
    break;
  case 11:
    xmm_ptr = fpr->xmm11;
    break;
  case 12:
    xmm_ptr = fpr->xmm12;
    break;
  case 13:
    xmm_ptr = fpr->xmm13;
    break;
  case 14:
    xmm_ptr = fpr->xmm14;
    break;
  case 15:
    xmm_ptr = fpr->xmm15;
    break;
  default:
    return 0.0f;
  }

  float result;
  std::memcpy(&result, xmm_ptr, sizeof(float));
  return result;
}

inline double get_xmm_double(const QBDI::FPRState* fpr, size_t reg_idx) {
  if (reg_idx >= 16) {
    return 0.0;
  }

  const char* xmm_ptr = nullptr;
  switch (reg_idx) {
  case 0:
    xmm_ptr = fpr->xmm0;
    break;
  case 1:
    xmm_ptr = fpr->xmm1;
    break;
  case 2:
    xmm_ptr = fpr->xmm2;
    break;
  case 3:
    xmm_ptr = fpr->xmm3;
    break;
  case 4:
    xmm_ptr = fpr->xmm4;
    break;
  case 5:
    xmm_ptr = fpr->xmm5;
    break;
  case 6:
    xmm_ptr = fpr->xmm6;
    break;
  case 7:
    xmm_ptr = fpr->xmm7;
    break;
  case 8:
    xmm_ptr = fpr->xmm8;
    break;
  case 9:
    xmm_ptr = fpr->xmm9;
    break;
  case 10:
    xmm_ptr = fpr->xmm10;
    break;
  case 11:
    xmm_ptr = fpr->xmm11;
    break;
  case 12:
    xmm_ptr = fpr->xmm12;
    break;
  case 13:
    xmm_ptr = fpr->xmm13;
    break;
  case 14:
    xmm_ptr = fpr->xmm14;
    break;
  case 15:
    xmm_ptr = fpr->xmm15;
    break;
  default:
    return 0.0;
  }

  double result;
  std::memcpy(&result, xmm_ptr, sizeof(double));
  return result;
}

inline void get_xmm_bytes(const QBDI::FPRState* fpr, size_t reg_idx, void* dest) {
  if (reg_idx >= 16) {
    std::memset(dest, 0, 16);
    return;
  }

  const char* xmm_ptr = nullptr;
  switch (reg_idx) {
  case 0:
    xmm_ptr = fpr->xmm0;
    break;
  case 1:
    xmm_ptr = fpr->xmm1;
    break;
  case 2:
    xmm_ptr = fpr->xmm2;
    break;
  case 3:
    xmm_ptr = fpr->xmm3;
    break;
  case 4:
    xmm_ptr = fpr->xmm4;
    break;
  case 5:
    xmm_ptr = fpr->xmm5;
    break;
  case 6:
    xmm_ptr = fpr->xmm6;
    break;
  case 7:
    xmm_ptr = fpr->xmm7;
    break;
  case 8:
    xmm_ptr = fpr->xmm8;
    break;
  case 9:
    xmm_ptr = fpr->xmm9;
    break;
  case 10:
    xmm_ptr = fpr->xmm10;
    break;
  case 11:
    xmm_ptr = fpr->xmm11;
    break;
  case 12:
    xmm_ptr = fpr->xmm12;
    break;
  case 13:
    xmm_ptr = fpr->xmm13;
    break;
  case 14:
    xmm_ptr = fpr->xmm14;
    break;
  case 15:
    xmm_ptr = fpr->xmm15;
    break;
  default:
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