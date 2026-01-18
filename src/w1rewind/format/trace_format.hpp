#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace w1::rewind {

constexpr uint16_t k_trace_version = 6;
constexpr std::array<uint8_t, 8> k_trace_magic = {'W', '1', 'R', 'W', 'N', 'D', '6', '\0'};
constexpr uint32_t k_trace_chunk_bytes = 8 * 1024 * 1024;
constexpr uint64_t k_stack_snapshot_above_cap = 0x200;

struct stack_snapshot_layout {
  uint64_t base = 0;
  uint64_t size = 0;
  uint64_t below = 0;
  uint64_t above = 0;
};

inline stack_snapshot_layout compute_stack_snapshot_layout(uint64_t sp, uint64_t window_bytes) {
  stack_snapshot_layout layout{};
  if (window_bytes == 0) {
    return layout;
  }

  uint64_t above = window_bytes / 4;
  if (above > k_stack_snapshot_above_cap) {
    above = k_stack_snapshot_above_cap;
  }
  if (above > window_bytes) {
    above = window_bytes;
  }

  uint64_t below = window_bytes - above;
  if (sp < below) {
    below = sp;
  }

  layout.base = sp - below;
  layout.size = below + above;
  layout.below = below;
  layout.above = above;
  return layout;
}

enum class trace_arch : uint16_t {
  unknown = 0,
  x86_64 = 0x0101,
  x86 = 0x0102,
  aarch64 = 0x0201,
  arm = 0x0202,
};

enum class module_perm : uint32_t {
  none = 0,
  read = 1u << 0,
  write = 1u << 1,
  exec = 1u << 2,
};

inline module_perm operator|(module_perm lhs, module_perm rhs) {
  return static_cast<module_perm>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}

inline module_perm operator&(module_perm lhs, module_perm rhs) {
  return static_cast<module_perm>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}

enum trace_flags : uint64_t {
  trace_flag_instructions = 1ull << 0,
  trace_flag_register_deltas = 1ull << 1,
  trace_flag_memory_access = 1ull << 2,
  trace_flag_memory_values = 1ull << 3,
  trace_flag_snapshots = 1ull << 4,
  trace_flag_stack_snapshot = 1ull << 5,
  trace_flag_blocks = 1ull << 6,
};

enum class trace_compression : uint32_t {
  none = 0,
  zstd = 1,
};

enum class record_kind : uint16_t {
  register_table = 1,
  module_table = 2,
  thread_start = 3,
  instruction = 4,
  register_deltas = 5,
  memory_access = 6,
  snapshot = 7,
  thread_end = 8,
  block_definition = 9,
  block_exec = 10,
};

struct trace_header {
  uint16_t version = k_trace_version;
  trace_arch architecture = trace_arch::unknown;
  uint32_t pointer_size = 0;
  uint64_t flags = 0;
  trace_compression compression = trace_compression::none;
  uint32_t chunk_size = 0;
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
  module_perm permissions = module_perm::none;
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

struct block_definition_record {
  uint64_t block_id = 0;
  uint64_t module_id = 0;
  uint64_t module_offset = 0;
  uint32_t size = 0;
};

struct block_exec_record {
  uint64_t sequence = 0;
  uint64_t thread_id = 0;
  uint64_t block_id = 0;
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

struct snapshot_record {
  uint64_t snapshot_id = 0;
  uint64_t sequence = 0;
  uint64_t thread_id = 0;
  std::vector<register_delta> registers;
  std::vector<uint8_t> stack_snapshot;
  std::string reason;
};

struct thread_end_record {
  uint64_t thread_id = 0;
};

using trace_record = std::variant<
    register_table_record, module_table_record, thread_start_record, instruction_record, block_definition_record,
    block_exec_record, register_delta_record, memory_access_record, snapshot_record, thread_end_record>;

inline trace_arch detect_trace_arch() {
#if defined(__x86_64__) || defined(_M_X64)
  return trace_arch::x86_64;
#elif defined(__i386__) || defined(_M_IX86)
  return trace_arch::x86;
#elif defined(__aarch64__) || defined(_M_ARM64)
  return trace_arch::aarch64;
#elif defined(__arm__) || defined(_M_ARM)
  return trace_arch::arm;
#else
  return trace_arch::unknown;
#endif
}

inline uint32_t detect_pointer_size() { return static_cast<uint32_t>(sizeof(void*)); }

} // namespace w1::rewind
