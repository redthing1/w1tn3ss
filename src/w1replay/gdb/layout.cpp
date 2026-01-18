#include "layout.hpp"

#include <algorithm>
#include <initializer_list>

#include "w1rewind/replay/replay_registers.hpp"

namespace w1replay::gdb {

namespace {

struct reg_spec {
  const char* gdb_name;
  std::initializer_list<const char*> trace_names;
  uint32_t bits;
  bool is_pc;
  bool is_sp;
};

std::string arch_name_for_trace(w1::rewind::trace_arch arch) {
  switch (arch) {
  case w1::rewind::trace_arch::x86_64:
    return "i386:x86-64";
  case w1::rewind::trace_arch::x86:
    return "i386";
  case w1::rewind::trace_arch::aarch64:
    return "aarch64";
  case w1::rewind::trace_arch::arm:
    return "arm";
  default:
    break;
  }
  return "";
}

std::string feature_name_for_trace(w1::rewind::trace_arch arch) {
  switch (arch) {
  case w1::rewind::trace_arch::x86_64:
  case w1::rewind::trace_arch::x86:
    return "org.gnu.gdb.i386.core";
  case w1::rewind::trace_arch::aarch64:
    return "org.gnu.gdb.aarch64.core";
  case w1::rewind::trace_arch::arm:
    return "org.gnu.gdb.arm.core";
  default:
    break;
  }
  return "org.w1tn3ss.rewind";
}

std::optional<size_t> find_trace_index(
    const std::vector<std::string>& trace_registers,
    std::initializer_list<const char*> names
) {
  for (const char* name : names) {
    auto found = w1::rewind::find_register_id(trace_registers, name);
    if (found.has_value()) {
      return static_cast<size_t>(*found);
    }
  }
  return std::nullopt;
}

void add_reg(
    register_layout& layout,
    const std::vector<std::string>& trace_registers,
    const std::string& gdb_name,
    std::initializer_list<const char*> trace_names,
    uint32_t bits,
    bool is_pc,
    bool is_sp
) {
  register_desc desc{};
  desc.name = gdb_name;
  desc.bits = bits;
  desc.trace_index = find_trace_index(trace_registers, trace_names);
  desc.is_pc = is_pc;
  desc.is_sp = is_sp;
  layout.registers.push_back(std::move(desc));
  if (is_pc) {
    layout.pc_reg_num = static_cast<int>(layout.registers.size() - 1);
  }
  if (is_sp) {
    layout.sp_reg_num = static_cast<int>(layout.registers.size() - 1);
  }
}

void add_reg_from_spec(
    register_layout& layout,
    const std::vector<std::string>& trace_registers,
    const reg_spec& spec
) {
  add_reg(layout, trace_registers, spec.gdb_name, spec.trace_names, spec.bits, spec.is_pc, spec.is_sp);
}

constexpr reg_spec k_x86_64_regs[] = {
    {"rax", {"rax"}, 64, false, false},
    {"rbx", {"rbx"}, 64, false, false},
    {"rcx", {"rcx"}, 64, false, false},
    {"rdx", {"rdx"}, 64, false, false},
    {"rsi", {"rsi"}, 64, false, false},
    {"rdi", {"rdi"}, 64, false, false},
    {"rbp", {"rbp"}, 64, false, false},
    {"rsp", {"rsp"}, 64, false, true},
    {"r8", {"r8"}, 64, false, false},
    {"r9", {"r9"}, 64, false, false},
    {"r10", {"r10"}, 64, false, false},
    {"r11", {"r11"}, 64, false, false},
    {"r12", {"r12"}, 64, false, false},
    {"r13", {"r13"}, 64, false, false},
    {"r14", {"r14"}, 64, false, false},
    {"r15", {"r15"}, 64, false, false},
    {"rip", {"rip"}, 64, true, false},
    {"eflags", {"rflags", "eflags"}, 32, false, false},
    {"cs", {"cs"}, 16, false, false},
    {"ss", {"ss"}, 16, false, false},
    {"ds", {"ds"}, 16, false, false},
    {"es", {"es"}, 16, false, false},
    {"fs", {"fs"}, 16, false, false},
    {"gs", {"gs"}, 16, false, false},
};

constexpr reg_spec k_x86_regs[] = {
    {"eax", {"eax"}, 32, false, false},
    {"ecx", {"ecx"}, 32, false, false},
    {"edx", {"edx"}, 32, false, false},
    {"ebx", {"ebx"}, 32, false, false},
    {"esp", {"esp"}, 32, false, true},
    {"ebp", {"ebp"}, 32, false, false},
    {"esi", {"esi"}, 32, false, false},
    {"edi", {"edi"}, 32, false, false},
    {"eip", {"eip"}, 32, true, false},
    {"eflags", {"eflags"}, 32, false, false},
    {"cs", {"cs"}, 16, false, false},
    {"ss", {"ss"}, 16, false, false},
    {"ds", {"ds"}, 16, false, false},
    {"es", {"es"}, 16, false, false},
    {"fs", {"fs"}, 16, false, false},
    {"gs", {"gs"}, 16, false, false},
};

} // namespace

register_layout build_register_layout(
    w1::rewind::trace_arch arch,
    uint32_t pointer_size,
    const std::vector<std::string>& trace_registers
) {
  register_layout layout{};
  layout.architecture = arch_name_for_trace(arch);
  layout.feature_name = feature_name_for_trace(arch);

  switch (arch) {
  case w1::rewind::trace_arch::aarch64: {
    for (int i = 0; i <= 29; ++i) {
      std::string name = "x" + std::to_string(i);
      add_reg(layout, trace_registers, name, {name.c_str()}, 64, false, false);
    }
    add_reg(layout, trace_registers, "x30", {"x30", "lr"}, 64, false, false);
    add_reg(layout, trace_registers, "sp", {"sp"}, 64, false, true);
    add_reg(layout, trace_registers, "pc", {"pc"}, 64, true, false);
    add_reg(layout, trace_registers, "cpsr", {"cpsr", "nzcv"}, 32, false, false);
    return layout;
  }
  case w1::rewind::trace_arch::x86_64: {
    for (const auto& spec : k_x86_64_regs) {
      add_reg_from_spec(layout, trace_registers, spec);
    }
    return layout;
  }
  case w1::rewind::trace_arch::x86: {
    for (const auto& spec : k_x86_regs) {
      add_reg_from_spec(layout, trace_registers, spec);
    }
    return layout;
  }
  case w1::rewind::trace_arch::arm: {
    for (int i = 0; i <= 12; ++i) {
      std::string name = "r" + std::to_string(i);
      add_reg(layout, trace_registers, name, {name.c_str()}, 32, false, false);
    }
    add_reg(layout, trace_registers, "sp", {"sp"}, 32, false, true);
    add_reg(layout, trace_registers, "lr", {"lr"}, 32, false, false);
    add_reg(layout, trace_registers, "pc", {"pc"}, 32, true, false);
    add_reg(layout, trace_registers, "cpsr", {"cpsr"}, 32, false, false);
    return layout;
  }
  default:
    break;
  }

  if (!trace_registers.empty()) {
    layout.registers.reserve(trace_registers.size());
    for (size_t i = 0; i < trace_registers.size(); ++i) {
      register_desc desc{};
      desc.name = trace_registers[i];
      desc.bits = w1::rewind::register_bitsize(arch, trace_registers[i], pointer_size);
      desc.trace_index = i;
      layout.registers.push_back(std::move(desc));
    }
    if (auto pc = w1::rewind::resolve_pc_reg_id(arch, trace_registers)) {
      layout.pc_reg_num = static_cast<int>(*pc);
      layout.registers[static_cast<size_t>(*pc)].is_pc = true;
    }
    if (auto sp = w1::rewind::resolve_stack_reg_id(arch, trace_registers)) {
      layout.sp_reg_num = static_cast<int>(*sp);
      layout.registers[static_cast<size_t>(*sp)].is_sp = true;
    }
  }

  return layout;
}

} // namespace w1replay::gdb
