#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#include <QBDI/Config.h>

namespace w1::rewind {

constexpr uint16_t k_trace_version = 4;
constexpr std::array<uint8_t, 8> k_trace_magic = {'W', '1', 'R', 'W', 'N', 'D', '4', '\0'};

enum class trace_arch : uint16_t {
  unknown = 0,
  x86_64 = 0x0101,
  x86 = 0x0102,
  aarch64 = 0x0201,
  arm = 0x0202,
};

enum trace_flags : uint64_t {
  trace_flag_instructions = 1ull << 0,
  trace_flag_register_deltas = 1ull << 1,
  trace_flag_memory_access = 1ull << 2,
  trace_flag_memory_values = 1ull << 3,
  trace_flag_boundaries = 1ull << 4,
  trace_flag_stack_window = 1ull << 5,
};

enum class record_kind : uint16_t {
  register_table = 1,
  module_table = 2,
  thread_start = 3,
  instruction = 4,
  register_deltas = 5,
  memory_access = 6,
  boundary = 7,
  thread_end = 8,
};

struct trace_header {
  uint16_t version = k_trace_version;
  trace_arch architecture = trace_arch::unknown;
  uint32_t pointer_size = 0;
  uint64_t flags = 0;
};

struct record_header {
  record_kind kind = record_kind::instruction;
  uint16_t flags = 0;
  uint32_t size = 0;
};

struct register_table_record {
  std::vector<std::string> names;
};

struct module_record {
  uint64_t id = 0;
  uint64_t base = 0;
  uint64_t size = 0;
  uint32_t permissions = 0;
  std::string path;
};

struct module_table_record {
  std::vector<module_record> modules;
};

struct thread_start_record {
  uint64_t thread_id = 0;
  std::string name;
};

struct instruction_record {
  uint64_t sequence = 0;
  uint64_t thread_id = 0;
  uint64_t module_id = 0;
  uint64_t module_offset = 0;
  uint32_t size = 0;
  uint32_t flags = 0;
};

struct register_delta {
  uint16_t reg_id = 0;
  uint64_t value = 0;
};

struct register_delta_record {
  uint64_t sequence = 0;
  uint64_t thread_id = 0;
  std::vector<register_delta> deltas;
};

enum class memory_access_kind : uint8_t { read = 1, write = 2 };

struct memory_access_record {
  uint64_t sequence = 0;
  uint64_t thread_id = 0;
  memory_access_kind kind = memory_access_kind::read;
  uint64_t address = 0;
  uint32_t size = 0;
  bool value_known = false;
  bool value_truncated = false;
  std::vector<uint8_t> data;
};

struct boundary_record {
  uint64_t boundary_id = 0;
  uint64_t sequence = 0;
  uint64_t thread_id = 0;
  std::vector<register_delta> registers;
  std::vector<uint8_t> stack_window;
  std::string reason;
};

struct thread_end_record {
  uint64_t thread_id = 0;
};

using trace_record = std::variant<
    register_table_record, module_table_record, thread_start_record, instruction_record, register_delta_record,
    memory_access_record, boundary_record, thread_end_record>;

inline trace_arch detect_trace_arch() {
#if defined(QBDI_ARCH_X86_64)
  return trace_arch::x86_64;
#elif defined(QBDI_ARCH_X86)
  return trace_arch::x86;
#elif defined(QBDI_ARCH_AARCH64)
  return trace_arch::aarch64;
#elif defined(QBDI_ARCH_ARM)
  return trace_arch::arm;
#else
  return trace_arch::unknown;
#endif
}

inline uint32_t detect_pointer_size() { return static_cast<uint32_t>(sizeof(void*)); }

} // namespace w1::rewind
