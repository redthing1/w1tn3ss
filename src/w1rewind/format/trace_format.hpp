#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#include "w1base/arch_spec.hpp"

namespace w1::rewind {

constexpr uint16_t k_trace_version = 16;
constexpr std::array<uint8_t, 8> k_trace_magic = {'W', '1', 'R', 'W', 'N', 'D', '1', '1'};
constexpr uint32_t k_trace_chunk_bytes = 8 * 1024 * 1024;
constexpr uint32_t k_register_regnum_unknown = 0xFFFFFFFFu;

enum class module_perm : uint32_t {
  none = 0,
  read = 1u << 0,
  write = 1u << 1,
  exec = 1u << 2,
};

enum class module_format : uint8_t {
  unknown = 0,
  elf = 1,
  macho = 2,
  pe = 3,
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
  module_table = 2,
  thread_start = 3,
  instruction = 4,
  register_deltas = 5,
  memory_access = 6,
  snapshot = 7,
  thread_end = 8,
  block_definition = 9,
  block_exec = 10,
  target_info = 11,
  register_spec = 12,
  memory_map = 13,
  register_bytes = 14,
  target_environment = 15,
  module_load = 16,
  module_unload = 17,
};

struct trace_header {
  uint16_t version = k_trace_version;
  w1::arch::arch_spec arch{};
  uint64_t flags = 0;
  trace_compression compression = trace_compression::none;
  uint32_t chunk_size = 0;
};

struct record_header {
  record_kind kind = record_kind::instruction;
  uint16_t flags = 0;
  uint32_t size = 0;
};

struct target_info_record {
  std::string os;
  std::string abi;
  std::string cpu;
};

struct target_environment_record {
  std::string os_version;
  std::string os_build;
  std::string os_kernel;
  std::string hostname;
  uint64_t pid = 0;
  uint32_t addressing_bits = 0;
  uint32_t low_mem_addressing_bits = 0;
  uint32_t high_mem_addressing_bits = 0;
};

enum register_flags : uint16_t {
  register_flag_pc = 1u << 0,
  register_flag_sp = 1u << 1,
  register_flag_flags = 1u << 2,
  register_flag_fp = 1u << 3,
};

enum class register_class : uint8_t {
  unknown = 0,
  gpr = 1,
  fpr = 2,
  simd = 3,
  flags = 4,
  system = 5,
};

enum class register_value_kind : uint8_t {
  unknown = 0,
  u64 = 1,
  bytes = 2,
};

struct register_spec {
  uint16_t reg_id = 0;
  std::string name;
  uint16_t bits = 0;
  uint16_t flags = 0;
  std::string gdb_name;
  register_class reg_class = register_class::unknown;
  register_value_kind value_kind = register_value_kind::unknown;
  uint32_t dwarf_regnum = k_register_regnum_unknown;
  uint32_t ehframe_regnum = k_register_regnum_unknown;
};

struct register_spec_record {
  std::vector<register_spec> registers;
};

enum module_record_flags : uint32_t {
  module_record_flag_link_base_valid = 1u << 0,
  module_record_flag_main = 1u << 1,
  module_record_flag_file_backed = 1u << 2,
};

struct module_record {
  uint64_t id = 0;
  uint64_t base = 0;
  uint64_t size = 0;
  module_perm permissions = module_perm::none;
  module_format format = module_format::unknown;
  std::string identity;
  uint32_t identity_age = 0;
  uint32_t flags = 0;
  uint64_t link_base = 0;
  std::string path;
};

struct module_table_record {
  std::vector<module_record> modules;
};

struct module_load_record {
  module_record module;
};

struct module_unload_record {
  uint64_t module_id = 0;
  uint64_t base = 0;
  uint64_t size = 0;
  std::string path;
};

struct memory_region_record {
  uint64_t base = 0;
  uint64_t size = 0;
  module_perm permissions = module_perm::none;
  uint64_t image_id = 0;
  std::string name;
};

struct memory_map_record {
  std::vector<memory_region_record> regions;
};

struct thread_start_record {
  uint64_t thread_id = 0;
  std::string name;
};

struct instruction_record {
  uint64_t sequence = 0;
  uint64_t thread_id = 0;
  uint64_t address = 0;
  uint32_t size = 0;
  uint32_t flags = 0;
};

enum instruction_flags : uint32_t {
  trace_inst_flag_mode_valid = 1u << 0,
  trace_inst_flag_thumb = 1u << 1,
};

struct block_definition_record {
  uint64_t block_id = 0;
  uint64_t address = 0;
  uint32_t size = 0;
  uint32_t flags = 0;
};

enum block_flags : uint32_t {
  trace_block_flag_mode_valid = 1u << 0,
  trace_block_flag_thumb = 1u << 1,
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

struct register_bytes_entry {
  uint16_t reg_id = 0;
  uint32_t offset = 0;
  uint16_t size = 0;
};

struct register_bytes_record {
  uint64_t sequence = 0;
  uint64_t thread_id = 0;
  std::vector<register_bytes_entry> entries;
  std::vector<uint8_t> data;
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

struct stack_segment {
  uint64_t base = 0;
  uint64_t size = 0;
  std::vector<uint8_t> bytes;
};

struct snapshot_record {
  uint64_t snapshot_id = 0;
  uint64_t sequence = 0;
  uint64_t thread_id = 0;
  std::vector<register_delta> registers;
  std::vector<stack_segment> stack_segments;
  std::string reason;
};

struct thread_end_record {
  uint64_t thread_id = 0;
};

using trace_record = std::variant<
    target_info_record, target_environment_record, register_spec_record, module_table_record, module_load_record,
    module_unload_record, memory_map_record, thread_start_record, instruction_record, block_definition_record,
    block_exec_record, register_delta_record, register_bytes_record, memory_access_record, snapshot_record,
    thread_end_record>;

} // namespace w1::rewind
