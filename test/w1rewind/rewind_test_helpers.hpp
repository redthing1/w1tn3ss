#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "doctest/doctest.hpp"

#include "w1rewind/format/trace_format.hpp"
#include "w1rewind/record/trace_writer.hpp"
#include "w1rewind/replay/replay_registers.hpp"

namespace w1::rewind::test_helpers {

inline std::filesystem::path temp_path(const char* name) {
  return std::filesystem::temp_directory_path() / name;
}

inline std::string arch_id_for_trace(trace_arch arch) {
  switch (arch) {
  case trace_arch::x86_64:
    return "x86_64";
  case trace_arch::x86:
    return "x86";
  case trace_arch::aarch64:
    return "aarch64";
  case trace_arch::arm:
    return "arm";
  default:
    break;
  }
  return "unknown";
}

inline std::string gdb_arch_for_trace(trace_arch arch) {
  switch (arch) {
  case trace_arch::x86_64:
    return "i386:x86-64";
  case trace_arch::x86:
    return "i386";
  case trace_arch::aarch64:
    return "aarch64";
  case trace_arch::arm:
    return "arm";
  default:
    break;
  }
  return {};
}

inline std::string gdb_feature_for_trace(trace_arch arch) {
  switch (arch) {
  case trace_arch::x86_64:
  case trace_arch::x86:
    return "org.gnu.gdb.i386.core";
  case trace_arch::aarch64:
    return "org.gnu.gdb.aarch64.core";
  case trace_arch::arm:
    return "org.gnu.gdb.arm.core";
  default:
    break;
  }
  return "org.w1tn3ss.rewind";
}

inline bool is_pc_name(const std::string& name) {
  return name == "pc" || name == "rip" || name == "eip";
}

inline bool is_sp_name(const std::string& name) {
  return name == "sp" || name == "rsp" || name == "esp";
}

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

inline target_info_record make_target_info(trace_arch arch, uint32_t pointer_size) {
  target_info_record target{};
  target.arch_id = arch_id_for_trace(arch);
  target.pointer_bits = pointer_size * 8;
  target.endianness = trace_endianness::little;
  target.os = "test";
  target.abi = "test";
  target.cpu = "test";
  target.gdb_arch = gdb_arch_for_trace(arch);
  target.gdb_feature = gdb_feature_for_trace(arch);
  return target;
}

inline std::vector<register_spec> make_register_specs(
    const std::vector<std::string>& names,
    trace_arch arch,
    uint32_t pointer_size
) {
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
    specs.push_back(std::move(spec));
  }
  return specs;
}

inline std::vector<std::string> minimal_registers(trace_arch arch) {
  switch (arch) {
  case trace_arch::x86_64:
    return {"rip"};
  case trace_arch::x86:
    return {"eip"};
  case trace_arch::aarch64:
  case trace_arch::arm:
    return {"pc"};
  default:
    break;
  }
  return {"pc"};
}

inline void write_target_info(trace_writer& writer, trace_arch arch, uint32_t pointer_size) {
  auto target = make_target_info(arch, pointer_size);
  REQUIRE(writer.write_target_info(target));
}

inline void write_register_specs(
    trace_writer& writer,
    const std::vector<std::string>& names,
    trace_arch arch,
    uint32_t pointer_size
) {
  register_spec_record record{};
  record.registers = make_register_specs(names, arch, pointer_size);
  REQUIRE(writer.write_register_spec(record));
}

inline void write_basic_metadata(
    trace_writer& writer,
    trace_arch arch,
    uint32_t pointer_size,
    const std::vector<std::string>& names
) {
  write_target_info(writer, arch, pointer_size);
  write_register_specs(writer, names, arch, pointer_size);
}

inline void write_module_table(
    trace_writer& writer,
    uint64_t module_id,
    uint64_t base,
    const std::string& path = "test_module"
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
    trace_writer& writer,
    uint64_t block_id,
    uint64_t address,
    uint32_t size
) {
  block_definition_record record{};
  record.block_id = block_id;
  record.address = address;
  record.size = size;
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
    trace_writer& writer,
    uint64_t thread_id,
    uint64_t sequence,
    uint64_t address
) {
  instruction_record record{};
  record.sequence = sequence;
  record.thread_id = thread_id;
  record.address = address;
  record.size = 4;
  record.flags = 0;
  REQUIRE(writer.write_instruction(record));
}

inline void write_register_table(trace_writer& writer, std::vector<std::string> names) {
  register_table_record reg_table{};
  reg_table.names = std::move(names);
  REQUIRE(writer.write_register_table(reg_table));
}

inline void write_register_delta(
    trace_writer& writer,
    uint64_t thread_id,
    uint64_t sequence,
    uint16_t reg_id,
    uint64_t value
) {
  register_delta_record deltas{};
  deltas.sequence = sequence;
  deltas.thread_id = thread_id;
  deltas.deltas = {register_delta{reg_id, value}};
  REQUIRE(writer.write_register_deltas(deltas));
}

} // namespace w1::rewind::test_helpers
