#include "register_capture.hpp"
#include "register_access.hpp"
#include <algorithm>

namespace w1::util {


bool register_state::get_register(const std::string& name, uint64_t& value) const {
  auto it = registers_.find(name);
  if (it != registers_.end()) {
    value = it->second;
    return true;
  }
  return false;
}

uint64_t register_state::get_stack_pointer() const {
  // use architectural names based on platform
#if defined(QBDI_ARCH_X86_64)
  return registers_.at("rsp");
#elif defined(QBDI_ARCH_AARCH64) || defined(QBDI_ARCH_ARM)
  return registers_.at("sp");
#elif defined(QBDI_ARCH_X86)
  return registers_.at("esp");
#else
  return 0;
#endif
}

uint64_t register_state::get_instruction_pointer() const {
  // use architectural names based on platform
#if defined(QBDI_ARCH_X86_64)
  return registers_.at("rip");
#elif defined(QBDI_ARCH_AARCH64) || defined(QBDI_ARCH_ARM)
  return registers_.at("pc");
#elif defined(QBDI_ARCH_X86)
  return registers_.at("eip");
#else
  return 0;
#endif
}

// returns the architectural register commonly used as frame pointer
// note: actual frame pointer usage and semantics are abi-specific
uint64_t register_state::get_frame_pointer() const {
#if defined(QBDI_ARCH_X86_64)
  return registers_.at("rbp");
#elif defined(QBDI_ARCH_AARCH64)
  return registers_.at("x29");
#elif defined(QBDI_ARCH_ARM)
  return registers_.at("r11");  // could also be r7 on some abis
#elif defined(QBDI_ARCH_X86)
  return registers_.at("ebp");
#else
  return 0;
#endif
}

std::vector<std::string> register_state::get_register_names() const {
  std::vector<std::string> names;
  names.reserve(registers_.size());

  for (const auto& [name, _] : registers_) {
    names.push_back(name);
  }

  std::sort(names.begin(), names.end());
  return names;
}

std::unordered_map<std::string, uint64_t> register_state::get_all_registers() const { return registers_; }

// implementation of register_capturer
register_state register_capturer::capture(const QBDI::GPRState* gpr) {
  register_state state;

  if (!gpr) {
    return state;
  }

#if defined(QBDI_ARCH_X86_64)
  capture_x86_64(state, gpr);
#elif defined(QBDI_ARCH_AARCH64)
  capture_aarch64(state, gpr);
#elif defined(QBDI_ARCH_ARM)
  capture_arm32(state, gpr);
#elif defined(QBDI_ARCH_X86)
  capture_x86(state, gpr);
#endif

  return state;
}

void register_capturer::capture_x86_64(register_state& state, const QBDI::GPRState* gpr) {
#if defined(QBDI_ARCH_X86_64)
  state.arch_ = register_state::architecture::X86_64;

  // general purpose registers
  state.registers_["rax"] = gpr->rax;
  state.registers_["rbx"] = gpr->rbx;
  state.registers_["rcx"] = gpr->rcx;
  state.registers_["rdx"] = gpr->rdx;
  state.registers_["rsi"] = gpr->rsi;
  state.registers_["rdi"] = gpr->rdi;
  state.registers_["r8"] = gpr->r8;
  state.registers_["r9"] = gpr->r9;
  state.registers_["r10"] = gpr->r10;
  state.registers_["r11"] = gpr->r11;
  state.registers_["r12"] = gpr->r12;
  state.registers_["r13"] = gpr->r13;
  state.registers_["r14"] = gpr->r14;
  state.registers_["r15"] = gpr->r15;

  // special purpose registers
  state.registers_["rbp"] = gpr->rbp;
  state.registers_["rsp"] = gpr->rsp;
  state.registers_["rip"] = gpr->rip;
  state.registers_["eflags"] = gpr->eflags;
  state.registers_["fs"] = gpr->fs;
  state.registers_["gs"] = gpr->gs;
#else
  // not x86_64 - this should not be called
  state.arch_ = register_state::architecture::UNKNOWN;
#endif
}

void register_capturer::capture_aarch64(register_state& state, const QBDI::GPRState* gpr) {
#if defined(QBDI_ARCH_AARCH64)
  state.arch_ = register_state::architecture::AARCH64;

  // general purpose registers x0-x28
  for (int i = 0; i < 29; ++i) {
    state.registers_["x" + std::to_string(i)] = (&gpr->x0)[i];
  }

  // special registers
  state.registers_["x29"] = gpr->x29; // frame pointer
  state.registers_["lr"] = gpr->lr;   // x30 - link register
  state.registers_["sp"] = gpr->sp;
  state.registers_["pc"] = gpr->pc;
  state.registers_["nzcv"] = gpr->nzcv;
#else
  // not aarch64 - this should not be called
  state.arch_ = register_state::architecture::UNKNOWN;
#endif
}

void register_capturer::capture_arm32(register_state& state, const QBDI::GPRState* gpr) {
#if defined(QBDI_ARCH_ARM)
  state.arch_ = register_state::architecture::ARM32;

  // general purpose registers r0-r12
  state.registers_["r0"] = gpr->r0;
  state.registers_["r1"] = gpr->r1;
  state.registers_["r2"] = gpr->r2;
  state.registers_["r3"] = gpr->r3;
  state.registers_["r4"] = gpr->r4;
  state.registers_["r5"] = gpr->r5;
  state.registers_["r6"] = gpr->r6;
  state.registers_["r7"] = gpr->r7;
  state.registers_["r8"] = gpr->r8;
  state.registers_["r9"] = gpr->r9;
  state.registers_["r10"] = gpr->r10;
  state.registers_["r11"] = gpr->r11; // frame pointer
  state.registers_["r12"] = gpr->r12;

  // special registers
  state.registers_["sp"] = gpr->sp; // r13
  state.registers_["lr"] = gpr->lr; // r14
  state.registers_["pc"] = gpr->pc; // r15
  state.registers_["cpsr"] = gpr->cpsr;
#else
  // not arm32 - this should not be called
  state.arch_ = register_state::architecture::UNKNOWN;
#endif
}

void register_capturer::capture_x86(register_state& state, const QBDI::GPRState* gpr) {
#if defined(QBDI_ARCH_X86)
  state.arch_ = register_state::architecture::X86;

  // general purpose registers
  state.registers_["eax"] = gpr->eax;
  state.registers_["ebx"] = gpr->ebx;
  state.registers_["ecx"] = gpr->ecx;
  state.registers_["edx"] = gpr->edx;
  state.registers_["esi"] = gpr->esi;
  state.registers_["edi"] = gpr->edi;

  // special purpose registers
  state.registers_["ebp"] = gpr->ebp;
  state.registers_["esp"] = gpr->esp;
  state.registers_["eip"] = gpr->eip;
  state.registers_["eflags"] = gpr->eflags;
#else
  // not x86 - this should not be called
  state.arch_ = register_state::architecture::UNKNOWN;
#endif
}

} // namespace w1::util