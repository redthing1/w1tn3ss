#pragma once

#include "abi/api_knowledge_db.hpp"
#include <vector>

// include dll-specific api definitions
#include "kernel32_apis.hpp"
#include "ucrtbase_apis.hpp"
#include "ntdll_apis.hpp"
#include "user32_apis.hpp"
#include "advapi32_apis.hpp"
#include "ws2_32_apis.hpp"
#include "psapi_apis.hpp"
#include "winmm_apis.hpp"

namespace w1::abi::apis::windows {

/**
 * @brief windows system api definitions aggregator
 *
 * aggregates api definitions from multiple windows dlls:
 * - kernel32.dll: process, thread, memory, file operations, i/o completion, ipc, synchronization
 * - ucrtbase.dll: universal c runtime (modern c library functions)
 * - ntdll.dll: native nt apis (low-level system services)
 * - user32.dll: window management, ui, message handling
 * - advapi32.dll: security, tokens, services, registry, crypto, event logging
 * - ws2_32.dll: winsock api, sockets, network communication, dns resolution
 * - psapi.dll: process status api, process/module enumeration, memory analysis
 * - winmm.dll: multimedia timing apis, audio/device detection for vm analysis
 *
 * note: windows apis typically use stdcall on x86 and microsoft convention on x64
 *       the calling convention detector will handle this automatically
 */

// legacy api definitions (now moved to individual dll files)
// kept here temporarily for backward compatibility

// aggregate all windows apis from dll-specific files
inline std::vector<api_info> get_all_windows_apis() {
  std::vector<api_info> apis;

  // kernel32.dll - process, thread, memory, file, i/o completion, ipc, synchronization, error handling
  apis.insert(apis.end(), windows_kernel32_apis.begin(), windows_kernel32_apis.end());

  // ucrtbase.dll - universal c runtime (string, memory, math, i/o functions)
  apis.insert(apis.end(), windows_ucrtbase_apis.begin(), windows_ucrtbase_apis.end());

  // ntdll.dll - native nt apis (low-level system services)
  apis.insert(apis.end(), windows_ntdll_apis.begin(), windows_ntdll_apis.end());

  // user32.dll - window management, ui, message handling
  apis.insert(apis.end(), windows_user32_apis.begin(), windows_user32_apis.end());

  // advapi32.dll - security, tokens, services, registry, crypto, event logging
  apis.insert(apis.end(), windows_advapi32_apis.begin(), windows_advapi32_apis.end());

  // ws2_32.dll - winsock api, sockets, network communication, dns resolution
  apis.insert(apis.end(), windows_ws2_32_apis.begin(), windows_ws2_32_apis.end());

  // psapi.dll - process status api, process/module enumeration, memory analysis
  apis.insert(apis.end(), windows_psapi_apis.begin(), windows_psapi_apis.end());

  // winmm.dll - multimedia timing apis, audio/device detection for vm analysis
  apis.insert(apis.end(), windows_winmm_apis.begin(), windows_winmm_apis.end());

  return apis;
}

} // namespace w1::abi::apis::windows