#include "layout.hpp"

#include <algorithm>

namespace w1replay::gdb {

namespace {

bool is_pc_name(const std::string& name) {
  return name == "pc" || name == "rip" || name == "eip";
}

bool is_sp_name(const std::string& name) {
  return name == "sp" || name == "rsp" || name == "esp";
}

} // namespace

register_layout build_register_layout(
    const w1::rewind::target_info_record& target,
    const std::vector<w1::rewind::register_spec>& register_specs
) {
  register_layout layout{};
  layout.architecture = target.gdb_arch;
  layout.feature_name = target.gdb_feature;
  if (layout.feature_name.empty()) {
    layout.feature_name = "org.w1tn3ss.rewind";
  }

  if (layout.architecture.empty() || register_specs.empty()) {
    return layout;
  }

  layout.registers.reserve(register_specs.size());
  for (size_t i = 0; i < register_specs.size(); ++i) {
    const auto& spec = register_specs[i];
    register_desc desc{};
    desc.name = spec.gdb_name.empty() ? spec.name : spec.gdb_name;
    desc.bits = spec.bits;
    desc.trace_index = static_cast<size_t>(spec.reg_id);
    desc.is_pc = (spec.flags & w1::rewind::register_flag_pc) != 0;
    desc.is_sp = (spec.flags & w1::rewind::register_flag_sp) != 0;
    desc.is_flags = (spec.flags & w1::rewind::register_flag_flags) != 0;
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
      if (is_pc_name(layout.registers[i].name)) {
        layout.pc_reg_num = static_cast<int>(i);
        layout.registers[i].is_pc = true;
        break;
      }
    }
  }

  if (layout.sp_reg_num < 0) {
    for (size_t i = 0; i < layout.registers.size(); ++i) {
      if (is_sp_name(layout.registers[i].name)) {
        layout.sp_reg_num = static_cast<int>(i);
        layout.registers[i].is_sp = true;
        break;
      }
    }
  }

  return layout;
}

} // namespace w1replay::gdb
