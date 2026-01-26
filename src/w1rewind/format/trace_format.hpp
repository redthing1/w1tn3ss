#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace w1::rewind {

constexpr uint16_t k_trace_version = 4;
constexpr std::array<uint8_t, 8> k_trace_magic = {'W', '1', 'R', 'T', 'R', 'A', 'C', 'E'};
constexpr std::array<uint8_t, 8> k_trace_footer_magic = {'W', '1', 'R', 'F', 'T', 'R', '0', '0'};
constexpr std::array<uint8_t, 8> k_trace_index_magic = {'W', '1', 'R', 'I', 'N', 'D', 'X', '0'};
constexpr std::array<uint8_t, 8> k_trace_checkpoint_magic = {'W', '1', 'R', 'C', 'H', 'K', 'P', '0'};
constexpr uint16_t k_trace_index_version = 1;
constexpr uint16_t k_trace_checkpoint_version = 2;

enum class endian : uint8_t { unknown = 0, little = 1, big = 2 };

enum class compression : uint16_t { none = 0, zstd = 1 };

enum class mapping_perm : uint8_t { none = 0, read = 1u << 0, write = 1u << 1, exec = 1u << 2 };

enum class mapping_event_kind : uint8_t { map = 0, unmap = 1, protect = 2 };

inline mapping_perm operator|(mapping_perm lhs, mapping_perm rhs) {
  return static_cast<mapping_perm>(static_cast<uint8_t>(lhs) | static_cast<uint8_t>(rhs));
}

inline mapping_perm operator&(mapping_perm lhs, mapping_perm rhs) {
  return static_cast<mapping_perm>(static_cast<uint8_t>(lhs) & static_cast<uint8_t>(rhs));
}

struct file_header {
  uint16_t version = k_trace_version;
  uint16_t header_size = 0;
  uint32_t flags = 0;
  std::array<uint8_t, 16> trace_uuid{};
  uint32_t default_chunk_size = 0;
  uint32_t reserved = 0;
};

struct chunk_header {
  uint32_t compressed_size = 0;
  uint32_t uncompressed_size = 0;
  compression codec = compression::none;
  uint16_t flags = 0;
  uint32_t reserved = 0;
};

struct chunk_dir_entry {
  uint64_t chunk_file_offset = 0;
  uint32_t compressed_size = 0;
  uint32_t uncompressed_size = 0;
  compression codec = compression::none;
  uint16_t flags = 0;
};

constexpr uint64_t k_chunk_dir_entry_size =
    sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t);

struct chunk_footer {
  uint16_t version = k_trace_version;
  uint16_t footer_size = 0;
  uint32_t chunk_count = 0;
  uint64_t directory_offset = 0;
  uint64_t directory_size = 0;
  uint32_t reserved = 0;
};

struct record_header {
  uint32_t type_id = 0;
  uint16_t version = 0;
  uint16_t flags = 0;
  uint32_t payload_size = 0;
};

constexpr uint32_t fnv1a_32(std::string_view text) {
  uint32_t hash = 2166136261u;
  for (unsigned char value : text) {
    hash ^= value;
    hash *= 16777619u;
  }
  return hash;
}

constexpr uint32_t k_record_type_dictionary = fnv1a_32("w1r/record_type_dictionary");
constexpr uint32_t k_record_type_arch_descriptor = fnv1a_32("w1r/arch_descriptor");
constexpr uint32_t k_record_type_environment = fnv1a_32("w1r/environment");
constexpr uint32_t k_record_type_address_space = fnv1a_32("w1r/address_space");
constexpr uint32_t k_record_type_register_file = fnv1a_32("w1r/register_file");
constexpr uint32_t k_record_type_image = fnv1a_32("w1r/image");
constexpr uint32_t k_record_type_image_metadata = fnv1a_32("w1r/image_metadata");
constexpr uint32_t k_record_type_image_blob = fnv1a_32("w1r/image_blob");
constexpr uint32_t k_record_type_mapping = fnv1a_32("w1r/mapping");
constexpr uint32_t k_record_type_thread_start = fnv1a_32("w1r/thread_start");
constexpr uint32_t k_record_type_thread_end = fnv1a_32("w1r/thread_end");
constexpr uint32_t k_record_type_flow_instruction = fnv1a_32("w1r/flow_instruction");
constexpr uint32_t k_record_type_block_definition = fnv1a_32("w1r/block_definition");
constexpr uint32_t k_record_type_block_exec = fnv1a_32("w1r/block_exec");
constexpr uint32_t k_record_type_reg_write = fnv1a_32("w1r/reg_write");
constexpr uint32_t k_record_type_mem_access = fnv1a_32("w1r/mem_access");
constexpr uint32_t k_record_type_snapshot = fnv1a_32("w1r/snapshot");
constexpr uint32_t k_record_type_meta = fnv1a_32("w1r/meta");

struct record_type_dictionary_entry {
  uint32_t type_id = 0;
  std::string name;
};

struct record_type_dictionary_record {
  std::vector<record_type_dictionary_entry> entries;
};

struct arch_mode_entry {
  uint16_t mode_id = 0;
  std::string name;
};

struct arch_descriptor_record {
  std::string arch_id;
  endian byte_order = endian::unknown;
  uint16_t pointer_bits = 0;
  uint16_t address_bits = 0;
  std::vector<arch_mode_entry> modes;
  std::string gdb_arch;
  std::string gdb_feature;
};

struct environment_record {
  std::string os_id;
  std::string abi;
  std::string cpu;
  std::string hostname;
  uint64_t pid = 0;
  std::vector<std::pair<std::string, std::string>> attrs;
};

struct address_space_record {
  uint32_t space_id = 0;
  std::string name;
  uint16_t address_bits = 0;
  endian byte_order = endian::unknown;
  uint8_t flags = 0;
};

enum register_flags : uint16_t {
  register_flag_pc = 1u << 0,
  register_flag_sp = 1u << 1,
  register_flag_flags = 1u << 2,
  register_flag_fp = 1u << 3,
};

constexpr uint32_t k_register_regnum_unknown = 0xffffffffu;

struct register_spec {
  uint32_t reg_id = 0;
  std::string name;
  uint16_t bit_size = 0;
  uint16_t flags = 0;
  std::string gdb_name;
  uint32_t dwarf_regnum = k_register_regnum_unknown;
  uint32_t gcc_regnum = k_register_regnum_unknown;
};

struct register_file_record {
  uint32_t regfile_id = 0;
  std::string name;
  std::vector<register_spec> registers;
};

struct image_record {
  uint64_t image_id = 0;
  uint32_t flags = 0;
  std::string kind;
  std::string name;
  std::string identity;
  std::string path;
  std::vector<std::pair<std::string, std::string>> attrs;
};

enum image_flags : uint32_t {
  image_flag_none = 0,
  image_flag_main = 1u << 0,
  image_flag_file_backed = 1u << 1,
};

enum image_metadata_flags : uint32_t {
  image_meta_has_uuid = 1u << 0,
  image_meta_has_entry_point = 1u << 1,
  image_meta_has_link_base = 1u << 2,
  image_meta_has_macho_header = 1u << 3,
  image_meta_has_segments = 1u << 4,
  image_meta_has_identity_age = 1u << 5,
};

struct image_macho_header {
  uint32_t magic = 0;
  uint32_t cputype = 0;
  uint32_t cpusubtype = 0;
  uint32_t filetype = 0;
};

struct image_segment_record {
  std::string name;
  uint64_t vmaddr = 0;
  uint64_t vmsize = 0;
  uint64_t fileoff = 0;
  uint64_t filesize = 0;
  uint32_t maxprot = 0;
};

struct image_metadata_record {
  uint64_t image_id = 0;
  uint32_t flags = 0;
  std::string format;
  std::string uuid;
  uint32_t identity_age = 0;
  uint64_t entry_point = 0;
  uint64_t link_base = 0;
  image_macho_header macho_header{};
  std::vector<image_segment_record> segments;
};

struct image_blob_record {
  uint64_t image_id = 0;
  uint64_t offset = 0;
  std::vector<uint8_t> data;
};

struct mapping_record {
  mapping_event_kind kind = mapping_event_kind::map;
  uint32_t space_id = 0;
  uint64_t base = 0;
  uint64_t size = 0;
  mapping_perm perms = mapping_perm::none;
  uint8_t flags = 0;
  uint64_t image_id = 0;
  uint64_t image_offset = 0;
  std::string name;
};

struct thread_start_record {
  uint64_t thread_id = 0;
  std::string name;
};

struct thread_end_record {
  uint64_t thread_id = 0;
};

struct flow_instruction_record {
  uint64_t thread_id = 0;
  uint64_t sequence = 0;
  uint32_t space_id = 0;
  uint16_t mode_id = 0;
  uint16_t flags = 0;
  uint64_t address = 0;
  uint32_t size = 0;
};

struct block_definition_record {
  uint64_t block_id = 0;
  uint32_t space_id = 0;
  uint16_t mode_id = 0;
  uint16_t flags = 0;
  uint64_t address = 0;
  uint32_t size = 0;
};

struct block_exec_record {
  uint64_t thread_id = 0;
  uint64_t sequence = 0;
  uint64_t block_id = 0;
};

enum class reg_ref_kind : uint8_t { reg_id = 0, reg_name = 1 };

enum mem_access_flags : uint8_t {
  mem_access_value_known = 1u << 0,
  mem_access_value_truncated = 1u << 1,
};

struct reg_write_entry {
  reg_ref_kind ref_kind = reg_ref_kind::reg_id;
  uint8_t reserved = 0;
  uint32_t byte_offset = 0;
  uint32_t byte_size = 0;
  uint32_t reg_id = 0;
  std::string reg_name;
  std::vector<uint8_t> value;
};

struct reg_write_record {
  uint64_t thread_id = 0;
  uint64_t sequence = 0;
  uint32_t regfile_id = 0;
  std::vector<reg_write_entry> entries;
};

enum class mem_access_op : uint8_t { read = 1, write = 2 };

struct mem_access_record {
  uint64_t thread_id = 0;
  uint64_t sequence = 0;
  uint32_t space_id = 0;
  mem_access_op op = mem_access_op::read;
  uint8_t flags = 0;
  uint64_t address = 0;
  uint32_t access_size = 0;
  std::vector<uint8_t> value;
};

struct memory_segment {
  uint32_t space_id = 0;
  uint64_t base = 0;
  std::vector<uint8_t> bytes;
};

struct snapshot_record {
  uint64_t thread_id = 0;
  uint64_t sequence = 0;
  uint32_t regfile_id = 0;
  std::vector<reg_write_entry> registers;
  std::vector<memory_segment> memory_segments;
};

enum class meta_scope_kind : uint8_t { global = 0, thread = 1, image = 2, address_space = 3 };

struct meta_record {
  meta_scope_kind scope_kind = meta_scope_kind::global;
  uint64_t scope_id = 0;
  std::string key;
  std::string value;
};

using trace_record = std::variant<
    record_type_dictionary_record, arch_descriptor_record, environment_record, address_space_record,
    register_file_record, image_record, image_metadata_record, image_blob_record, mapping_record, thread_start_record,
    thread_end_record, flow_instruction_record, block_definition_record, block_exec_record, reg_write_record,
    mem_access_record, snapshot_record, meta_record>;

} // namespace w1::rewind
