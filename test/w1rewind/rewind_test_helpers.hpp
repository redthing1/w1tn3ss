#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "doctest/doctest.hpp"

#include "w1rewind/format/trace_format.hpp"
#include "w1rewind/record/trace_writer.hpp"
#include "w1rewind/format/register_numbering.hpp"
#include "w1rewind/replay/replay_registers.hpp"

namespace w1::rewind::test_helpers {

inline std::filesystem::path temp_path(const char* name) { return std::filesystem::temp_directory_path() / name; }

inline w1::arch::arch_spec parse_arch_or_fail(std::string_view text) {
  w1::arch::arch_spec spec{};
  std::string error;
  REQUIRE(w1::arch::parse_arch_spec(text, spec, error));
  return spec;
}

inline bool is_pc_name(const std::string& name) { return name == "pc" || name == "rip" || name == "eip"; }

inline bool is_sp_name(const std::string& name) { return name == "sp" || name == "rsp" || name == "esp"; }

inline bool is_flags_name(const std::string& name) {
  return name == "eflags" || name == "rflags" || name == "nzcv" || name == "cpsr";
}

inline std::string gdb_name_for_register(const std::string& name) {
  if (name == "nzcv") {
    return "cpsr";
  }
  if (name == "rflags") {
    return "eflags";
  }
  return name;
}

inline target_info_record make_target_info() {
  target_info_record target{};
  target.os = "test";
  target.abi = "test";
  target.cpu = "test";
  return target;
}

inline target_environment_record make_target_environment() {
  target_environment_record env{};
  env.os_version = "1.0";
  env.os_build = "test-build";
  env.os_kernel = "test-kernel";
  env.hostname = "test-host";
  env.pid = 42;
  env.addressing_bits = 48;
  env.low_mem_addressing_bits = 48;
  env.high_mem_addressing_bits = 48;
  return env;
}

inline std::vector<register_spec> make_register_specs(
    const std::vector<std::string>& names, const w1::arch::arch_spec& arch
) {
  uint32_t pointer_size = arch.pointer_bits == 0 ? 0 : arch.pointer_bits / 8;
  std::vector<register_spec> specs;
  specs.reserve(names.size());
  for (size_t i = 0; i < names.size(); ++i) {
    register_spec spec{};
    spec.reg_id = static_cast<uint16_t>(i);
    spec.name = names[i];
    spec.bits = static_cast<uint16_t>(register_bitsize(arch, names[i], pointer_size));
    spec.flags = 0;
    if (is_pc_name(names[i])) {
      spec.flags |= register_flag_pc;
    }
    if (is_sp_name(names[i])) {
      spec.flags |= register_flag_sp;
    }
    if (is_flags_name(names[i])) {
      spec.flags |= register_flag_flags;
    }
    spec.gdb_name = gdb_name_for_register(names[i]);
    spec.reg_class = is_flags_name(names[i]) ? register_class::flags : register_class::gpr;
    spec.value_kind = register_value_kind::u64;
    if (auto numbering = lookup_register_numbering(arch, spec.gdb_name)) {
      spec.dwarf_regnum = numbering->dwarf_regnum;
      spec.ehframe_regnum = numbering->ehframe_regnum;
    } else if (spec.gdb_name != spec.name) {
      if (auto fallback = lookup_register_numbering(arch, spec.name)) {
        spec.dwarf_regnum = fallback->dwarf_regnum;
        spec.ehframe_regnum = fallback->ehframe_regnum;
      }
    }
    specs.push_back(std::move(spec));
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

inline void write_target_info(trace_writer& writer) {
  auto target = make_target_info();
  REQUIRE(writer.write_target_info(target));
}

inline void write_target_environment(trace_writer& writer) {
  auto env = make_target_environment();
  REQUIRE(writer.write_target_environment(env));
}

inline void write_register_specs(
    trace_writer& writer, const std::vector<std::string>& names, const w1::arch::arch_spec& arch
) {
  register_spec_record record{};
  record.registers = make_register_specs(names, arch);
  REQUIRE(writer.write_register_spec(record));
}

inline void write_basic_metadata(
    trace_writer& writer, const w1::arch::arch_spec& arch, const std::vector<std::string>& names
) {
  write_target_info(writer);
  write_target_environment(writer);
  write_register_specs(writer, names, arch);
}

inline void write_module_table(
    trace_writer& writer, uint64_t module_id, uint64_t base, const std::string& path = "test_module"
) {
  module_record module{};
  module.id = module_id;
  module.base = base;
  module.size = 0x1000;
  module.permissions = module_perm::read | module_perm::exec;
  module.path = path;

  module_table_record table{};
  table.modules.push_back(module);
  REQUIRE(writer.write_module_table(table));
}

inline void write_thread_start(trace_writer& writer, uint64_t thread_id, const std::string& name) {
  thread_start_record start{};
  start.thread_id = thread_id;
  start.name = name;
  REQUIRE(writer.write_thread_start(start));
}

inline void write_thread_end(trace_writer& writer, uint64_t thread_id) {
  thread_end_record end{};
  end.thread_id = thread_id;
  REQUIRE(writer.write_thread_end(end));
}

inline void write_block_def(
    trace_writer& writer, uint64_t block_id, uint64_t address, uint32_t size, uint32_t flags = 0
) {
  block_definition_record record{};
  record.block_id = block_id;
  record.address = address;
  record.size = size;
  record.flags = flags;
  REQUIRE(writer.write_block_definition(record));
}

inline void write_block_exec(trace_writer& writer, uint64_t thread_id, uint64_t sequence, uint64_t block_id) {
  block_exec_record record{};
  record.sequence = sequence;
  record.thread_id = thread_id;
  record.block_id = block_id;
  REQUIRE(writer.write_block_exec(record));
}

inline void write_instruction(
    trace_writer& writer, uint64_t thread_id, uint64_t sequence, uint64_t address, uint32_t flags = 0
) {
  instruction_record record{};
  record.sequence = sequence;
  record.thread_id = thread_id;
  record.address = address;
  record.size = 4;
  record.flags = flags;
  REQUIRE(writer.write_instruction(record));
}

inline void write_register_table(trace_writer& writer, std::vector<std::string> names) {
  register_table_record reg_table{};
  reg_table.names = std::move(names);
  REQUIRE(writer.write_register_table(reg_table));
}

inline void write_register_delta(
    trace_writer& writer, uint64_t thread_id, uint64_t sequence, uint16_t reg_id, uint64_t value
) {
  register_delta_record deltas{};
  deltas.sequence = sequence;
  deltas.thread_id = thread_id;
  deltas.deltas = {register_delta{reg_id, value}};
  REQUIRE(writer.write_register_deltas(deltas));
}

} // namespace w1::rewind::test_helpers
