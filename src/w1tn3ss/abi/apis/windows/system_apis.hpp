#pragma once

#include "../../api_knowledge_db.hpp"
#include <vector>

// include dll-specific api definitions
#include "kernel32_apis.hpp"
#include "ucrtbase_apis.hpp"
#include "ntdll_apis.hpp"
#include "user32_apis.hpp"

namespace w1::abi::apis::windows {

/**
 * @brief windows system api definitions aggregator
 *
 * aggregates api definitions from multiple windows dlls:
 * - kernel32.dll: process, thread, memory, file operations, i/o completion
 * - ucrtbase.dll: universal c runtime (modern c library functions)
 * - ntdll.dll: native nt apis (low-level system services)
 * - user32.dll: window management, ui, message handling
 *
 * note: windows apis typically use stdcall on x86 and microsoft convention on x64
 *       the calling convention detector will handle this automatically
 */

// legacy api definitions (now moved to individual dll files)
// kept here temporarily for backward compatibility

// aggregate all windows apis from dll-specific files
inline std::vector<api_info> get_all_windows_apis() {
  std::vector<api_info> apis;

  // kernel32.dll - process, thread, memory, file, i/o completion, error handling
  apis.insert(apis.end(), windows_kernel32_apis.begin(), windows_kernel32_apis.end());

  // ucrtbase.dll - universal c runtime (string, memory, math, i/o functions)
  apis.insert(apis.end(), windows_ucrtbase_apis.begin(), windows_ucrtbase_apis.end());

  // ntdll.dll - native nt apis (low-level system services)
  apis.insert(apis.end(), windows_ntdll_apis.begin(), windows_ntdll_apis.end());

  // user32.dll - window management, ui, message handling
  apis.insert(apis.end(), windows_user32_apis.begin(), windows_user32_apis.end());

  return apis;
}

} // namespace w1::abi::apis::windows