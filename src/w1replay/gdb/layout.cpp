#include "layout.hpp"

#include <algorithm>
#include <limits>

#include "w1rewind/format/register_metadata.hpp"

namespace w1replay::gdb {

namespace {

std::vector<std::string> minimal_register_names(const w1::arch::arch_spec& arch) {
  switch (arch.arch_mode) {
  case w1::arch::mode::x86_64:
    return {"rip", "rsp", "rflags"};
  case w1::arch::mode::x86_32:
    return {"eip", "esp", "eflags"};
  case w1::arch::mode::aarch64:
    return {"pc", "sp", "nzcv"};
  case w1::arch::mode::arm:
  case w1::arch::mode::thumb:
    return {"pc", "sp", "cpsr"};
  default:
    break;
  }
  return {"pc", "sp"};
}

std::vector<w1::rewind::register_spec> build_minimal_register_specs(const w1::arch::arch_spec& arch) {
  uint32_t pointer_size = arch.pointer_bits == 0 ? 0 : arch.pointer_bits / 8;
  if (pointer_size == 0) {
    return {};
  }
  auto names = minimal_register_names(arch);
  std::vector<w1::rewind::register_spec> specs;
  specs.reserve(names.size());
  for (size_t i = 0; i < names.size(); ++i) {
    specs.push_back(
        w1::rewind::build_register_spec(arch, static_cast<uint16_t>(i), names[i], pointer_size)
    );
  }
  return specs;
}

} // namespace

register_layout build_register_layout(
    const w1::arch::arch_spec& arch, const std::vector<w1::rewind::register_spec>& register_specs
) {
  register_layout layout{};
  layout.architecture = std::string(w1::arch::gdb_arch_name(arch));
  layout.feature_name = std::string(w1::arch::gdb_feature_name(arch));
  if (layout.feature_name.empty()) {
    layout.feature_name = "org.w1tn3ss.rewind";
  }

  if (layout.architecture.empty()) {
    return layout;
  }

  std::vector<w1::rewind::register_spec> fallback_specs;
  const auto* specs = &register_specs;
  if (specs->empty()) {
    fallback_specs = build_minimal_register_specs(arch);
    specs = &fallback_specs;
  }
  if (specs->empty()) {
    return layout;
  }

  layout.registers.reserve(specs->size());
  for (size_t i = 0; i < specs->size(); ++i) {
    const auto& spec = (*specs)[i];
    register_desc desc{};
    desc.name = spec.gdb_name.empty() ? spec.name : spec.gdb_name;
    desc.bits = spec.bits;
    desc.trace_index = static_cast<size_t>(spec.reg_id);
    desc.is_pc = (spec.flags & w1::rewind::register_flag_pc) != 0;
    desc.is_sp = (spec.flags & w1::rewind::register_flag_sp) != 0;
    desc.is_flags = (spec.flags & w1::rewind::register_flag_flags) != 0;
    if (spec.dwarf_regnum != w1::rewind::k_register_regnum_unknown &&
        spec.dwarf_regnum <= static_cast<uint32_t>(std::numeric_limits<int>::max())) {
      desc.dwarf_regnum = static_cast<int>(spec.dwarf_regnum);
    }
    if (spec.ehframe_regnum != w1::rewind::k_register_regnum_unknown &&
        spec.ehframe_regnum <= static_cast<uint32_t>(std::numeric_limits<int>::max())) {
      desc.ehframe_regnum = static_cast<int>(spec.ehframe_regnum);
    }
    desc.reg_class = spec.reg_class;
    desc.value_kind = spec.value_kind;
    layout.registers.push_back(std::move(desc));
    if (layout.registers.back().is_pc) {
      layout.pc_reg_num = static_cast<int>(i);
    }
    if (layout.registers.back().is_sp) {
      layout.sp_reg_num = static_cast<int>(i);
    }
  }

  if (layout.pc_reg_num < 0) {
    for (size_t i = 0; i < layout.registers.size(); ++i) {
      if (w1::rewind::is_pc_name(layout.registers[i].name)) {
        layout.pc_reg_num = static_cast<int>(i);
        layout.registers[i].is_pc = true;
        break;
      }
    }
  }

  if (layout.sp_reg_num < 0) {
    for (size_t i = 0; i < layout.registers.size(); ++i) {
      if (w1::rewind::is_sp_name(layout.registers[i].name)) {
        layout.sp_reg_num = static_cast<int>(i);
        layout.registers[i].is_sp = true;
        break;
      }
    }
  }

  return layout;
}

} // namespace w1replay::gdb
