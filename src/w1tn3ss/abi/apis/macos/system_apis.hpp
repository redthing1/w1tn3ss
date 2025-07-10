#pragma once

#include "libsystem_c_apis.hpp"
#include "libsystem_kernel_apis.hpp"
#include "libsystem_malloc_apis.hpp"
#include "libsystem_pthread_apis.hpp"
#include "libsystem_m_apis.hpp"
#include "libdyld_apis.hpp"

namespace w1::abi::apis::macos {

/**
 * @brief aggregated macOS system apis from all libraries
 *
 * this combines apis from:
 * - libsystem_c.dylib (standard c library)
 * - libsystem_kernel.dylib (system calls)
 * - libsystem_malloc.dylib (heap management)
 * - libsystem_pthread.dylib (threading)
 * - libsystem_m.dylib (math functions)
 * - libdyld.dylib (dynamic linking)
 *
 * discover apis using (for example):
 * nm -gU /path/to/dyld_dmp/usr/lib/system/libsystem_c.dylib | grep printf
 *
 */
static std::vector<api_info> get_all_macos_system_apis() {
  std::vector<api_info> all_apis;

  // aggregate all apis from different libraries
  all_apis.insert(all_apis.end(), macos_libsystem_c_apis.begin(), macos_libsystem_c_apis.end());
  all_apis.insert(all_apis.end(), macos_libsystem_kernel_apis.begin(), macos_libsystem_kernel_apis.end());
  all_apis.insert(all_apis.end(), macos_libsystem_malloc_apis.begin(), macos_libsystem_malloc_apis.end());
  all_apis.insert(all_apis.end(), macos_libsystem_pthread_apis.begin(), macos_libsystem_pthread_apis.end());
  all_apis.insert(all_apis.end(), macos_libsystem_m_apis.begin(), macos_libsystem_m_apis.end());
  all_apis.insert(all_apis.end(), macos_libdyld_apis.begin(), macos_libdyld_apis.end());

  return all_apis;
}

// for backward compatibility, provide the old name
static const auto macos_system_apis = get_all_macos_system_apis();

} // namespace w1::abi::apis::macos