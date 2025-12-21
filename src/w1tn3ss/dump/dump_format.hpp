#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace w1::dump {

struct dump_metadata {
  uint32_t version = 1;
  uint64_t timestamp = 0;
  std::string os;
  std::string arch;
  uint32_t pointer_size = 0;
  uint64_t pid = 0;
  std::string process_name;
};

struct thread_state {
  uint64_t thread_id = 0;
  std::vector<uint64_t> gpr_values;
  std::vector<uint64_t> fpr_values;
};

struct memory_region {
  uint64_t start = 0;
  uint64_t end = 0;
  uint32_t permissions = 0;
  std::string module_name;
  bool is_stack = false;
  bool is_code = false;
  bool is_data = false;
  bool is_anonymous = false;
  std::vector<uint8_t> data;
};

struct module_info {
  std::string path;
  std::string name;
  uint64_t base_address = 0;
  uint64_t size = 0;
  std::string type;
  bool is_system = false;
  uint32_t permissions = 0;
};

struct process_dump {
  dump_metadata metadata;
  thread_state thread;
  std::vector<memory_region> regions;
  std::vector<module_info> modules;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(dump_metadata, version, timestamp, os, arch, pointer_size, pid, process_name)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(thread_state, thread_id, gpr_values, fpr_values)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(
    memory_region, start, end, permissions, module_name, is_stack, is_code, is_data, is_anonymous, data
)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(
    module_info, path, name, base_address, size, type, is_system, permissions
)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(process_dump, metadata, thread, regions, modules)

} // namespace w1::dump
