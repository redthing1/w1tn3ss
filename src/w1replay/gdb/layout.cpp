#include "layout.hpp"

#include "w1rewind/replay/replay_context.hpp"

namespace w1replay::gdb {

namespace {} // namespace

register_layout build_register_layout(
    const w1::rewind::replay_context& context, const std::vector<w1::rewind::register_spec>& register_specs
) {
  register_layout layout{};

  if (context.arch.has_value()) {
    if (!context.arch->gdb_arch.empty()) {
      layout.architecture = context.arch->gdb_arch;
    }
    if (!context.arch->gdb_feature.empty()) {
      layout.feature_name = context.arch->gdb_feature;
    }
  }

  if (layout.feature_name.empty()) {
    layout.feature_name = "org.w1tn3ss.w1r";
  }

  if (layout.architecture.empty() || register_specs.empty()) {
    return layout;
  }

  layout.registers.reserve(register_specs.size());
  for (size_t i = 0; i < register_specs.size(); ++i) {
    const auto& spec = register_specs[i];
    register_desc desc{};
    desc.name = spec.gdb_name.empty() ? spec.name : spec.gdb_name;
    desc.bits = spec.bit_size;
    desc.trace_index = i;
    desc.is_pc = (spec.flags & w1::rewind::register_flag_pc) != 0;
    desc.is_sp = (spec.flags & w1::rewind::register_flag_sp) != 0;
    desc.is_flags = (spec.flags & w1::rewind::register_flag_flags) != 0;
    desc.is_fp = (spec.flags & w1::rewind::register_flag_fp) != 0;
    if (spec.dwarf_regnum != w1::rewind::k_register_regnum_unknown) {
      desc.dwarf_regnum = static_cast<int>(spec.dwarf_regnum);
    }
    if (spec.gcc_regnum != w1::rewind::k_register_regnum_unknown) {
      desc.gcc_regnum = static_cast<int>(spec.gcc_regnum);
    }
    layout.registers.push_back(std::move(desc));
  }

  for (size_t i = 0; i < layout.registers.size(); ++i) {
    if (layout.registers[i].is_pc) {
      layout.pc_reg_num = static_cast<int>(i);
    }
    if (layout.registers[i].is_sp) {
      layout.sp_reg_num = static_cast<int>(i);
    }
  }

  return layout;
}

} // namespace w1replay::gdb
