#pragma once

#include <array>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "doctest/doctest.hpp"

#include "w1base/arch_spec.hpp"
#include "w1rewind/format/register_metadata.hpp"
#include "w1rewind/format/trace_format.hpp"
#include "w1rewind/record/trace_builder.hpp"
#include "w1rewind/trace/trace_file_writer.hpp"

namespace w1::rewind::test_helpers {

constexpr uint32_t k_min_test_chunk_size = 256;

inline std::filesystem::path temp_path(const char* name) { return std::filesystem::temp_directory_path() / name; }

inline w1::arch::arch_spec parse_arch_or_fail(std::string_view text) {
  w1::arch::arch_spec spec{};
  std::string error;
  REQUIRE(w1::arch::parse_arch_spec(text, spec, error));
  return spec;
}

inline endian to_trace_endian(w1::arch::byte_order order) {
  switch (order) {
  case w1::arch::byte_order::little:
    return endian::little;
  case w1::arch::byte_order::big:
    return endian::big;
  case w1::arch::byte_order::unknown:
  default:
    return endian::unknown;
  }
}

inline file_header make_header(uint32_t flags = 0, uint32_t chunk_size = 0) {
  file_header header{};
  header.flags = flags;
  header.trace_uuid[0] = 1;
  if (chunk_size != 0 && chunk_size < k_min_test_chunk_size) {
    header.default_chunk_size = k_min_test_chunk_size;
  } else {
    header.default_chunk_size = chunk_size;
  }
  return header;
}

inline arch_descriptor_record make_arch_descriptor(std::string_view arch_id, const w1::arch::arch_spec& arch) {
  arch_descriptor_record record{};
  record.arch_id = std::string(arch_id);
  record.byte_order = to_trace_endian(arch.arch_byte_order);
  record.pointer_bits = static_cast<uint16_t>(arch.pointer_bits);
  record.address_bits = record.pointer_bits;
  if (!record.arch_id.empty()) {
    record.modes.push_back({0, record.arch_id});
  }
  record.gdb_arch = std::string(w1::arch::gdb_arch_name(arch));
  record.gdb_feature = std::string(w1::arch::gdb_feature_name(arch));
  return record;
}

inline environment_record make_environment() {
  environment_record env{};
  env.os_id = "test";
  env.abi = "test";
  env.cpu = "test";
  env.hostname = "test-host";
  env.pid = 42;
  env.attrs.emplace_back("os_version", "1.0");
  env.attrs.emplace_back("os_build", "test-build");
  env.attrs.emplace_back("os_kernel", "test-kernel");
  return env;
}

inline address_space_record make_address_space(uint32_t space_id, const w1::arch::arch_spec& arch) {
  address_space_record record{};
  record.space_id = space_id;
  record.name = space_id == 0 ? "default" : ("space-" + std::to_string(space_id));
  record.address_bits = static_cast<uint16_t>(arch.pointer_bits);
  record.byte_order = to_trace_endian(arch.arch_byte_order);
  record.flags = 0;
  return record;
}

inline register_spec make_register_spec(uint32_t reg_id, std::string_view name, uint16_t bit_size) {
  register_spec spec{};
  spec.reg_id = reg_id;
  spec.name = std::string(name);
  spec.bit_size = bit_size;
  spec.flags = 0;
  if (is_pc_name(name)) {
    spec.flags |= register_flag_pc;
  }
  if (is_sp_name(name)) {
    spec.flags |= register_flag_sp;
  }
  if (is_flags_name(name)) {
    spec.flags |= register_flag_flags;
  }
  spec.gdb_name = std::string(name);
  return spec;
}

inline bool is_fp_name(const w1::arch::arch_spec& arch, std::string_view name) {
  switch (arch.arch_mode) {
  case w1::arch::mode::x86_64:
    return name == "rbp";
  case w1::arch::mode::x86_32:
    return name == "ebp";
  case w1::arch::mode::aarch64:
    return name == "x29" || name == "fp";
  default:
    break;
  }
  return false;
}

inline uint16_t register_flags_for_name(const w1::arch::arch_spec& arch, std::string_view name) {
  uint16_t flags = 0;
  if (is_pc_name(name)) {
    flags |= register_flag_pc;
  }
  if (is_sp_name(name)) {
    flags |= register_flag_sp;
  }
  if (is_flags_name(name)) {
    flags |= register_flag_flags;
  }
  if (is_fp_name(arch, name)) {
    flags |= register_flag_fp;
  }
  return flags;
}

inline uint16_t register_bits_for_name(const w1::arch::arch_spec& arch, std::string_view name, uint16_t pointer_bits) {
  if (arch.arch_mode == w1::arch::mode::x86_64 || arch.arch_mode == w1::arch::mode::x86_32) {
    if (name == "eflags" || name == "rflags") {
      return 32;
    }
    if (name == "fs" || name == "gs") {
      return 16;
    }
  }
  if (arch.arch_mode == w1::arch::mode::aarch64) {
    if (name == "nzcv") {
      return 32;
    }
  }
  if (arch.arch_mode == w1::arch::mode::arm || arch.arch_mode == w1::arch::mode::thumb) {
    if (name == "cpsr") {
      return 32;
    }
  }
  return pointer_bits == 0 ? 64 : pointer_bits;
}

inline std::string gdb_name_for_register(std::string_view name, const w1::arch::arch_spec& arch) {
  if (arch.arch_mode == w1::arch::mode::aarch64 && name == "nzcv") {
    return "cpsr";
  }
  if (name == "rflags") {
    return "eflags";
  }
  return std::string(name);
}

inline std::optional<uint32_t> parse_x_register(std::string_view name) {
  if (name.size() < 2 || name[0] != 'x') {
    return std::nullopt;
  }
  uint32_t value = 0;
  for (size_t i = 1; i < name.size(); ++i) {
    char c = name[i];
    if (c < '0' || c > '9') {
      return std::nullopt;
    }
    value = value * 10 + static_cast<uint32_t>(c - '0');
  }
  return value;
}

inline std::optional<uint32_t> dwarf_regnum_for_aarch64(std::string_view name) {
  if (name == "sp") {
    return 31u;
  }
  if (name == "pc") {
    return 32u;
  }
  if (name == "cpsr" || name == "nzcv") {
    return 33u;
  }
  if (name == "lr") {
    return 30u;
  }
  if (auto reg = parse_x_register(name)) {
    if (*reg <= 30u) {
      return *reg;
    }
  }
  return std::nullopt;
}

inline std::optional<uint32_t> dwarf_regnum_for_x86_64(std::string_view name) {
  if (name == "rax") {
    return 0u;
  }
  if (name == "rdx") {
    return 1u;
  }
  if (name == "rcx") {
    return 2u;
  }
  if (name == "rbx") {
    return 3u;
  }
  if (name == "rsi") {
    return 4u;
  }
  if (name == "rdi") {
    return 5u;
  }
  if (name == "rbp") {
    return 6u;
  }
  if (name == "rsp") {
    return 7u;
  }
  if (name == "r8") {
    return 8u;
  }
  if (name == "r9") {
    return 9u;
  }
  if (name == "r10") {
    return 10u;
  }
  if (name == "r11") {
    return 11u;
  }
  if (name == "r12") {
    return 12u;
  }
  if (name == "r13") {
    return 13u;
  }
  if (name == "r14") {
    return 14u;
  }
  if (name == "r15") {
    return 15u;
  }
  if (name == "rip") {
    return 16u;
  }
  if (name == "eflags") {
    return 49u;
  }
  return std::nullopt;
}

inline std::optional<uint32_t> dwarf_regnum_for_arch(
    const w1::arch::arch_spec& arch, std::string_view name
) {
  switch (arch.arch_mode) {
  case w1::arch::mode::aarch64:
    return dwarf_regnum_for_aarch64(name);
  case w1::arch::mode::x86_64:
    return dwarf_regnum_for_x86_64(name);
  default:
    break;
  }
  return std::nullopt;
}

inline register_spec make_register_spec(
    const w1::arch::arch_spec& arch, uint32_t reg_id, std::string_view name, uint16_t pointer_bits
) {
  register_spec spec{};
  spec.reg_id = reg_id;
  spec.name = std::string(name);
  spec.bit_size = register_bits_for_name(arch, name, pointer_bits);
  spec.flags = register_flags_for_name(arch, name);
  spec.gdb_name = gdb_name_for_register(name, arch);
  if (auto regnum = dwarf_regnum_for_arch(arch, spec.gdb_name)) {
    spec.dwarf_regnum = *regnum;
    spec.gcc_regnum = *regnum;
  }
  return spec;
}

inline std::vector<register_spec> make_register_specs(
    const std::vector<std::string>& names, const w1::arch::arch_spec& arch
) {
  uint16_t bit_size = static_cast<uint16_t>(arch.pointer_bits == 0 ? 64 : arch.pointer_bits);
  std::vector<register_spec> specs;
  specs.reserve(names.size());
  for (size_t i = 0; i < names.size(); ++i) {
    specs.push_back(make_register_spec(arch, static_cast<uint32_t>(i), names[i], bit_size));
  }
  return specs;
}

inline std::vector<std::string> minimal_registers(const w1::arch::arch_spec& arch) {
  switch (arch.arch_mode) {
  case w1::arch::mode::x86_64:
    return {"rip"};
  case w1::arch::mode::x86_32:
    return {"eip"};
  case w1::arch::mode::aarch64:
  case w1::arch::mode::arm:
  case w1::arch::mode::thumb:
    return {"pc"};
  default:
    break;
  }
  return {"pc"};
}

inline register_file_record make_register_file(
    uint32_t regfile_id, const std::vector<std::string>& names, const w1::arch::arch_spec& arch
) {
  register_file_record record{};
  record.regfile_id = regfile_id;
  record.name = regfile_id == 0 ? "default" : ("regfile-" + std::to_string(regfile_id));
  record.registers = make_register_specs(names, arch);
  return record;
}

struct trace_builder_handle {
  std::shared_ptr<trace_file_writer> writer;
  trace_builder builder;
};

inline trace_builder_handle open_trace(
    const std::filesystem::path& path, const file_header& header,
    redlog::logger log = redlog::get_logger("test.w1rewind.trace")
) {
  trace_file_writer_config config;
  config.path = path.string();
  config.log = log;
  config.codec = compression::none;
  config.chunk_size = header.default_chunk_size;

  auto writer = make_trace_file_writer(config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  trace_builder_config builder_config;
  builder_config.sink = writer;
  builder_config.log = log;
  trace_builder builder(builder_config);
  REQUIRE(builder.begin_trace(header));

  return {writer, std::move(builder)};
}

inline void write_basic_metadata(
    trace_builder& builder, std::string_view arch_id, const w1::arch::arch_spec& arch,
    const std::vector<std::string>& names
) {
  REQUIRE(builder.emit_arch_descriptor(make_arch_descriptor(arch_id, arch)));
  REQUIRE(builder.emit_environment(make_environment()));
  REQUIRE(builder.emit_address_space(make_address_space(0, arch)));
  REQUIRE(builder.emit_register_file(make_register_file(0, names, arch)));
}

inline void write_image_mapping(
    trace_builder& builder, uint64_t image_id, uint64_t base, uint64_t size,
    const std::string& path = "test_module", uint32_t space_id = 0
) {
  image_record image{};
  image.image_id = image_id;
  image.kind = "test";
  image.name = path;
  image.identity = path;
  image.path = path;
  REQUIRE(builder.emit_image(image));

  mapping_record mapping{};
  mapping.kind = mapping_event_kind::map;
  mapping.space_id = space_id;
  mapping.base = base;
  mapping.size = size;
  mapping.perms = mapping_perm::read | mapping_perm::exec;
  mapping.image_id = image_id;
  mapping.image_offset = 0;
  mapping.name = path;
  REQUIRE(builder.emit_mapping(mapping));
}

inline void write_thread_start(trace_builder& builder, uint64_t thread_id, const std::string& name) {
  thread_start_record start{};
  start.thread_id = thread_id;
  start.name = name;
  REQUIRE(builder.emit_thread_start(start));
}

inline void write_thread_end(trace_builder& builder, uint64_t thread_id) {
  thread_end_record end{};
  end.thread_id = thread_id;
  REQUIRE(builder.emit_thread_end(end));
}

inline void write_block_def(
    trace_builder& builder, uint64_t block_id, uint64_t address, uint32_t size, uint32_t space_id = 0,
    uint16_t mode_id = 0, uint16_t flags = 0
) {
  block_definition_record record{};
  record.block_id = block_id;
  record.address = address;
  record.size = size;
  record.space_id = space_id;
  record.mode_id = mode_id;
  record.flags = flags;
  REQUIRE(builder.emit_block_definition(record));
}

inline void write_block_exec(trace_builder& builder, uint64_t thread_id, uint64_t sequence, uint64_t block_id) {
  block_exec_record record{};
  record.sequence = sequence;
  record.thread_id = thread_id;
  record.block_id = block_id;
  REQUIRE(builder.emit_block_exec(record));
}

inline void write_instruction(
    trace_builder& builder, uint64_t thread_id, uint64_t sequence, uint64_t address, uint32_t size = 4,
    uint32_t space_id = 0, uint16_t mode_id = 0, uint16_t flags = 0
) {
  flow_instruction_record record{};
  record.sequence = sequence;
  record.thread_id = thread_id;
  record.address = address;
  record.size = size;
  record.space_id = space_id;
  record.mode_id = mode_id;
  record.flags = flags;
  REQUIRE(builder.emit_flow_instruction(record));
}

inline std::vector<uint8_t> encode_value(uint64_t value, uint32_t byte_size, endian order) {
  std::vector<uint8_t> bytes(byte_size, 0);
  if (order == endian::big) {
    for (uint32_t i = 0; i < byte_size; ++i) {
      bytes[byte_size - 1 - i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFFu);
    }
  } else {
    for (uint32_t i = 0; i < byte_size; ++i) {
      bytes[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFFu);
    }
  }
  return bytes;
}

inline reg_write_entry make_reg_write_entry(
    uint32_t reg_id, uint64_t value, uint32_t byte_size = 8, uint32_t byte_offset = 0,
    endian order = endian::little
) {
  reg_write_entry entry{};
  entry.ref_kind = reg_ref_kind::reg_id;
  entry.reg_id = reg_id;
  entry.byte_offset = byte_offset;
  entry.byte_size = byte_size;
  entry.value = encode_value(value, byte_size, order);
  return entry;
}

inline void write_register_delta(
    trace_builder& builder, uint64_t thread_id, uint64_t sequence, uint32_t reg_id, uint64_t value,
    uint32_t regfile_id = 0, uint32_t byte_size = 8, endian order = endian::little
) {
  reg_write_record record{};
  record.thread_id = thread_id;
  record.sequence = sequence;
  record.regfile_id = regfile_id;
  record.entries = {make_reg_write_entry(reg_id, value, byte_size, 0, order)};
  REQUIRE(builder.emit_reg_write(record));
}

inline void write_memory_access(
    trace_builder& builder, uint64_t thread_id, uint64_t sequence, mem_access_op op, uint64_t address,
    std::vector<uint8_t> value, uint32_t space_id = 0
) {
  mem_access_record record{};
  record.thread_id = thread_id;
  record.sequence = sequence;
  record.space_id = space_id;
  record.op = op;
  record.flags = mem_access_value_known;
  record.address = address;
  record.access_size = static_cast<uint32_t>(value.size());
  record.value = std::move(value);
  REQUIRE(builder.emit_mem_access(record));
}

inline void write_snapshot(
    trace_builder& builder, uint64_t thread_id, uint64_t sequence, std::vector<reg_write_entry> regs,
    std::vector<memory_segment> segments, uint32_t regfile_id = 0
) {
  snapshot_record record{};
  record.thread_id = thread_id;
  record.sequence = sequence;
  record.regfile_id = regfile_id;
  record.registers = std::move(regs);
  record.memory_segments = std::move(segments);
  REQUIRE(builder.emit_snapshot(record));
}

} // namespace w1::rewind::test_helpers
