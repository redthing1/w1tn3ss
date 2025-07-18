#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <QBDI.h>
#include <w1tn3ss/util/module_scanner.hpp>
#include <nlohmann/json.hpp>

namespace w1 {
namespace dump {

struct dump_metadata {
  uint32_t version = 1;
  uint64_t timestamp;
  std::string os;        // "darwin", "linux", "windows"
  std::string arch;      // "x86_64", "arm64", etc.
  uint32_t pointer_size; // 4 or 8
  uint64_t pid;
  std::string process_name;
};

struct thread_state {
  uint64_t thread_id;
  // we'll serialize gpr/fpr as arrays since they're platform-specific
  std::vector<uint64_t> gpr_values; // general purpose registers
  std::vector<uint64_t> fpr_values; // floating point registers
};

struct memory_region {
  uint64_t start;
  uint64_t end;
  uint32_t permissions;    // qbdi permission flags
  std::string module_name; // associated module, empty if none

  // region classification based on observable characteristics
  bool is_stack = false;     // contains current sp
  bool is_code = false;      // executable region
  bool is_data = false;      // r/rw region belonging to module
  bool is_anonymous = false; // rw region not belonging to any module

  // optional: actual memory contents
  std::vector<uint8_t> data; // only if requested
};

// simplified module info for serialization
struct module_info_serializable {
  std::string path;
  std::string name;
  uint64_t base_address;
  uint64_t size;
  std::string type; // converted from enum
  bool is_system_library;
  uint32_t permissions;
};

struct w1dump {
  dump_metadata metadata;
  thread_state thread;
  std::vector<memory_region> regions;
  std::vector<module_info_serializable> modules;
};

// json serialization support
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(dump_metadata, version, timestamp, os, arch, pointer_size, pid, process_name)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(thread_state, thread_id, gpr_values, fpr_values)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(
    memory_region, start, end, permissions, module_name, is_stack, is_code, is_data, is_anonymous, data
)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(
    module_info_serializable, path, name, base_address, size, type, is_system_library, permissions
)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(w1dump, metadata, thread, regions, modules)

} // namespace dump
} // namespace w1