#include "reg.hpp"

#include <w1tn3ss/util/register_access.hpp>
#include <redlog.hpp>

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace w1::tracers::script::bindings {

namespace {

using reg_type = w1::registers::reg;

std::string normalize_reg_name(const std::string& name) {
  std::string lower = name;
  std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });
  return lower;
}

const std::unordered_map<std::string, reg_type>& reg_map() {
  static const std::unordered_map<std::string, reg_type> map = {
      {"pc", reg_type::pc},
      {"sp", reg_type::sp},
#if defined(QBDI_ARCH_X86_64)
      {"rax", reg_type::rax},
      {"rbx", reg_type::rbx},
      {"rcx", reg_type::rcx},
      {"rdx", reg_type::rdx},
      {"rsi", reg_type::rsi},
      {"rdi", reg_type::rdi},
      {"rbp", reg_type::rbp},
      {"rsp", reg_type::rsp},
      {"r8", reg_type::r8},
      {"r9", reg_type::r9},
      {"r10", reg_type::r10},
      {"r11", reg_type::r11},
      {"r12", reg_type::r12},
      {"r13", reg_type::r13},
      {"r14", reg_type::r14},
      {"r15", reg_type::r15},
      {"rip", reg_type::rip},
#elif defined(QBDI_ARCH_AARCH64)
      {"x0", reg_type::x0},
      {"x1", reg_type::x1},
      {"x2", reg_type::x2},
      {"x3", reg_type::x3},
      {"x4", reg_type::x4},
      {"x5", reg_type::x5},
      {"x6", reg_type::x6},
      {"x7", reg_type::x7},
      {"x8", reg_type::x8},
      {"x9", reg_type::x9},
      {"x10", reg_type::x10},
      {"x11", reg_type::x11},
      {"x12", reg_type::x12},
      {"x13", reg_type::x13},
      {"x14", reg_type::x14},
      {"x15", reg_type::x15},
      {"x16", reg_type::x16},
      {"x17", reg_type::x17},
      {"x18", reg_type::x18},
      {"x19", reg_type::x19},
      {"x20", reg_type::x20},
      {"x21", reg_type::x21},
      {"x22", reg_type::x22},
      {"x23", reg_type::x23},
      {"x24", reg_type::x24},
      {"x25", reg_type::x25},
      {"x26", reg_type::x26},
      {"x27", reg_type::x27},
      {"x28", reg_type::x28},
      {"x29", reg_type::x29},
      {"lr", reg_type::lr},
#elif defined(QBDI_ARCH_ARM)
      {"r0", reg_type::r0},
      {"r1", reg_type::r1},
      {"r2", reg_type::r2},
      {"r3", reg_type::r3},
      {"r4", reg_type::r4},
      {"r5", reg_type::r5},
      {"r6", reg_type::r6},
      {"r7", reg_type::r7},
      {"r8", reg_type::r8},
      {"r9", reg_type::r9},
      {"r10", reg_type::r10},
      {"r11", reg_type::r11},
      {"r12", reg_type::r12},
      {"r13", reg_type::r13},
      {"r14", reg_type::r14},
      {"r15", reg_type::r15},
#elif defined(QBDI_ARCH_X86)
      {"eax", reg_type::eax},
      {"ebx", reg_type::ebx},
      {"ecx", reg_type::ecx},
      {"edx", reg_type::edx},
      {"esi", reg_type::esi},
      {"edi", reg_type::edi},
      {"ebp", reg_type::ebp},
      {"esp", reg_type::esp},
      {"eip", reg_type::eip},
#endif
  };
  return map;
}

const std::vector<std::string>& reg_names() {
  static const std::vector<std::string> names = []() {
    std::vector<std::string> list;
    list.reserve(reg_map().size());
    for (const auto& entry : reg_map()) {
      list.push_back(entry.first);
    }
    std::sort(list.begin(), list.end());
    return list;
  }();
  return names;
}

std::optional<reg_type> parse_reg(const std::string& name) {
  std::string key = normalize_reg_name(name);
  auto it = reg_map().find(key);
  if (it == reg_map().end()) {
    return std::nullopt;
  }
  return it->second;
}

std::optional<QBDI::rword> get_register_value(QBDI::GPRState* gpr, reg_type reg) {
  if (!gpr) {
    return std::nullopt;
  }

  switch (reg) {
  case reg_type::pc:
    return w1::registers::get_pc(gpr);
  case reg_type::sp:
    return w1::registers::get_sp(gpr);
#if defined(QBDI_ARCH_X86_64)
  case reg_type::rax:
    return gpr->rax;
  case reg_type::rbx:
    return gpr->rbx;
  case reg_type::rcx:
    return gpr->rcx;
  case reg_type::rdx:
    return gpr->rdx;
  case reg_type::rsi:
    return gpr->rsi;
  case reg_type::rdi:
    return gpr->rdi;
  case reg_type::rbp:
    return gpr->rbp;
  case reg_type::rsp:
    return gpr->rsp;
  case reg_type::r8:
    return gpr->r8;
  case reg_type::r9:
    return gpr->r9;
  case reg_type::r10:
    return gpr->r10;
  case reg_type::r11:
    return gpr->r11;
  case reg_type::r12:
    return gpr->r12;
  case reg_type::r13:
    return gpr->r13;
  case reg_type::r14:
    return gpr->r14;
  case reg_type::r15:
    return gpr->r15;
  case reg_type::rip:
    return gpr->rip;
#elif defined(QBDI_ARCH_AARCH64)
  case reg_type::x0:
    return gpr->x0;
  case reg_type::x1:
    return gpr->x1;
  case reg_type::x2:
    return gpr->x2;
  case reg_type::x3:
    return gpr->x3;
  case reg_type::x4:
    return gpr->x4;
  case reg_type::x5:
    return gpr->x5;
  case reg_type::x6:
    return gpr->x6;
  case reg_type::x7:
    return gpr->x7;
  case reg_type::x8:
    return gpr->x8;
  case reg_type::x9:
    return gpr->x9;
  case reg_type::x10:
    return gpr->x10;
  case reg_type::x11:
    return gpr->x11;
  case reg_type::x12:
    return gpr->x12;
  case reg_type::x13:
    return gpr->x13;
  case reg_type::x14:
    return gpr->x14;
  case reg_type::x15:
    return gpr->x15;
  case reg_type::x16:
    return gpr->x16;
  case reg_type::x17:
    return gpr->x17;
  case reg_type::x18:
    return gpr->x18;
  case reg_type::x19:
    return gpr->x19;
  case reg_type::x20:
    return gpr->x20;
  case reg_type::x21:
    return gpr->x21;
  case reg_type::x22:
    return gpr->x22;
  case reg_type::x23:
    return gpr->x23;
  case reg_type::x24:
    return gpr->x24;
  case reg_type::x25:
    return gpr->x25;
  case reg_type::x26:
    return gpr->x26;
  case reg_type::x27:
    return gpr->x27;
  case reg_type::x28:
    return gpr->x28;
  case reg_type::x29:
    return gpr->x29;
  case reg_type::lr:
    return gpr->lr;
#elif defined(QBDI_ARCH_ARM)
  case reg_type::r0:
    return gpr->r0;
  case reg_type::r1:
    return gpr->r1;
  case reg_type::r2:
    return gpr->r2;
  case reg_type::r3:
    return gpr->r3;
  case reg_type::r4:
    return gpr->r4;
  case reg_type::r5:
    return gpr->r5;
  case reg_type::r6:
    return gpr->r6;
  case reg_type::r7:
    return gpr->r7;
  case reg_type::r8:
    return gpr->r8;
  case reg_type::r9:
    return gpr->r9;
  case reg_type::r10:
    return gpr->r10;
  case reg_type::r11:
    return gpr->r11;
  case reg_type::r12:
    return gpr->r12;
  case reg_type::r13:
    return gpr->r13;
  case reg_type::r14:
    return gpr->r14;
  case reg_type::r15:
    return gpr->r15;
#elif defined(QBDI_ARCH_X86)
  case reg_type::eax:
    return gpr->eax;
  case reg_type::ebx:
    return gpr->ebx;
  case reg_type::ecx:
    return gpr->ecx;
  case reg_type::edx:
    return gpr->edx;
  case reg_type::esi:
    return gpr->esi;
  case reg_type::edi:
    return gpr->edi;
  case reg_type::ebp:
    return gpr->ebp;
  case reg_type::esp:
    return gpr->esp;
  case reg_type::eip:
    return gpr->eip;
#endif
  }

  return std::nullopt;
}

bool set_register_value(QBDI::GPRState* gpr, reg_type reg, QBDI::rword value) {
  if (!gpr) {
    return false;
  }

  switch (reg) {
#if defined(QBDI_ARCH_X86_64)
  case reg_type::pc:
  case reg_type::rip:
    gpr->rip = value;
    return true;
  case reg_type::sp:
  case reg_type::rsp:
    gpr->rsp = value;
    return true;
  case reg_type::rax:
    gpr->rax = value;
    return true;
  case reg_type::rbx:
    gpr->rbx = value;
    return true;
  case reg_type::rcx:
    gpr->rcx = value;
    return true;
  case reg_type::rdx:
    gpr->rdx = value;
    return true;
  case reg_type::rsi:
    gpr->rsi = value;
    return true;
  case reg_type::rdi:
    gpr->rdi = value;
    return true;
  case reg_type::rbp:
    gpr->rbp = value;
    return true;
  case reg_type::r8:
    gpr->r8 = value;
    return true;
  case reg_type::r9:
    gpr->r9 = value;
    return true;
  case reg_type::r10:
    gpr->r10 = value;
    return true;
  case reg_type::r11:
    gpr->r11 = value;
    return true;
  case reg_type::r12:
    gpr->r12 = value;
    return true;
  case reg_type::r13:
    gpr->r13 = value;
    return true;
  case reg_type::r14:
    gpr->r14 = value;
    return true;
  case reg_type::r15:
    gpr->r15 = value;
    return true;
#elif defined(QBDI_ARCH_AARCH64)
  case reg_type::pc:
    gpr->pc = value;
    return true;
  case reg_type::sp:
    gpr->sp = value;
    return true;
  case reg_type::x0:
    gpr->x0 = value;
    return true;
  case reg_type::x1:
    gpr->x1 = value;
    return true;
  case reg_type::x2:
    gpr->x2 = value;
    return true;
  case reg_type::x3:
    gpr->x3 = value;
    return true;
  case reg_type::x4:
    gpr->x4 = value;
    return true;
  case reg_type::x5:
    gpr->x5 = value;
    return true;
  case reg_type::x6:
    gpr->x6 = value;
    return true;
  case reg_type::x7:
    gpr->x7 = value;
    return true;
  case reg_type::x8:
    gpr->x8 = value;
    return true;
  case reg_type::x9:
    gpr->x9 = value;
    return true;
  case reg_type::x10:
    gpr->x10 = value;
    return true;
  case reg_type::x11:
    gpr->x11 = value;
    return true;
  case reg_type::x12:
    gpr->x12 = value;
    return true;
  case reg_type::x13:
    gpr->x13 = value;
    return true;
  case reg_type::x14:
    gpr->x14 = value;
    return true;
  case reg_type::x15:
    gpr->x15 = value;
    return true;
  case reg_type::x16:
    gpr->x16 = value;
    return true;
  case reg_type::x17:
    gpr->x17 = value;
    return true;
  case reg_type::x18:
    gpr->x18 = value;
    return true;
  case reg_type::x19:
    gpr->x19 = value;
    return true;
  case reg_type::x20:
    gpr->x20 = value;
    return true;
  case reg_type::x21:
    gpr->x21 = value;
    return true;
  case reg_type::x22:
    gpr->x22 = value;
    return true;
  case reg_type::x23:
    gpr->x23 = value;
    return true;
  case reg_type::x24:
    gpr->x24 = value;
    return true;
  case reg_type::x25:
    gpr->x25 = value;
    return true;
  case reg_type::x26:
    gpr->x26 = value;
    return true;
  case reg_type::x27:
    gpr->x27 = value;
    return true;
  case reg_type::x28:
    gpr->x28 = value;
    return true;
  case reg_type::x29:
    gpr->x29 = value;
    return true;
  case reg_type::lr:
    gpr->lr = value;
    return true;
#elif defined(QBDI_ARCH_ARM)
  case reg_type::pc:
  case reg_type::r15:
    gpr->r15 = value;
    return true;
  case reg_type::sp:
  case reg_type::r13:
    gpr->r13 = value;
    return true;
  case reg_type::r0:
    gpr->r0 = value;
    return true;
  case reg_type::r1:
    gpr->r1 = value;
    return true;
  case reg_type::r2:
    gpr->r2 = value;
    return true;
  case reg_type::r3:
    gpr->r3 = value;
    return true;
  case reg_type::r4:
    gpr->r4 = value;
    return true;
  case reg_type::r5:
    gpr->r5 = value;
    return true;
  case reg_type::r6:
    gpr->r6 = value;
    return true;
  case reg_type::r7:
    gpr->r7 = value;
    return true;
  case reg_type::r8:
    gpr->r8 = value;
    return true;
  case reg_type::r9:
    gpr->r9 = value;
    return true;
  case reg_type::r10:
    gpr->r10 = value;
    return true;
  case reg_type::r11:
    gpr->r11 = value;
    return true;
  case reg_type::r12:
    gpr->r12 = value;
    return true;
  case reg_type::r14:
    gpr->r14 = value;
    return true;
#elif defined(QBDI_ARCH_X86)
  case reg_type::pc:
  case reg_type::eip:
    gpr->eip = value;
    return true;
  case reg_type::sp:
  case reg_type::esp:
    gpr->esp = value;
    return true;
  case reg_type::eax:
    gpr->eax = value;
    return true;
  case reg_type::ebx:
    gpr->ebx = value;
    return true;
  case reg_type::ecx:
    gpr->ecx = value;
    return true;
  case reg_type::edx:
    gpr->edx = value;
    return true;
  case reg_type::esi:
    gpr->esi = value;
    return true;
  case reg_type::edi:
    gpr->edi = value;
    return true;
  case reg_type::ebp:
    gpr->ebp = value;
    return true;
#endif
  default:
    return false;
  }
}

} // namespace

void setup_reg_bindings(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up reg bindings");

  sol::table reg = lua.create_table();

  reg.set_function("pc", [](QBDI::GPRState* gpr) -> sol::optional<QBDI::rword> {
    if (!gpr) {
      return sol::nullopt;
    }
    return w1::registers::get_pc(gpr);
  });

  reg.set_function("sp", [](QBDI::GPRState* gpr) -> sol::optional<QBDI::rword> {
    if (!gpr) {
      return sol::nullopt;
    }
    return w1::registers::get_sp(gpr);
  });

  reg.set_function("get", [](QBDI::GPRState* gpr, const std::string& name) -> sol::optional<QBDI::rword> {
    auto reg_opt = parse_reg(name);
    if (!reg_opt) {
      return sol::nullopt;
    }
    auto value = get_register_value(gpr, *reg_opt);
    if (!value) {
      return sol::nullopt;
    }
    return sol::optional<QBDI::rword>(*value);
  });

  reg.set_function("set", [](QBDI::GPRState* gpr, const std::string& name, QBDI::rword value) -> bool {
    auto reg_opt = parse_reg(name);
    if (!reg_opt) {
      return false;
    }
    return set_register_value(gpr, *reg_opt, value);
  });

  reg.set_function("names", [&lua]() -> sol::table {
    sol::table list = lua.create_table();
    const auto& names = reg_names();
    for (size_t i = 0; i < names.size(); ++i) {
      list[i + 1] = names[i];
    }
    return list;
  });

  w1_module["reg"] = reg;
}

} // namespace w1::tracers::script::bindings
