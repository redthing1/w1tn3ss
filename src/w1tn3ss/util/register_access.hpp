#pragma once

#include <QBDI.h>
#include <cstdint>
#include <optional>
#include <type_traits>

// architectural register access utilities
// this provides platform-aware access to cpu registers that exist
// at the hardware/architecture level, independent of any calling convention
//
// this file should only contain:
// - program counter (pc/rip/eip) - architectural control flow register
// - stack pointer (sp/rsp/esp) - architectural stack register
// - direct register access by architectural name (rax, x0, etc)
//
// this file must not contain:
// - return value registers (abi-specific)
// - argument registers (abi-specific)
// - frame pointer (usage is abi-specific)
// - any calling convention assumptions
//
// for abi-aware operations, use the calling convention layer

namespace w1::registers {

// zero-cost platform-aware accessors for common registers
inline QBDI::rword get_pc(const QBDI::GPRState* gpr) {
#if defined(QBDI_ARCH_X86_64)
  return gpr->rip;
#elif defined(QBDI_ARCH_AARCH64)
  return gpr->pc;
#elif defined(QBDI_ARCH_ARM)
  return gpr->pc;
#elif defined(QBDI_ARCH_X86)
  return gpr->eip;
#else
  static_assert(false, "unsupported architecture");
#endif
}

inline QBDI::rword get_sp(const QBDI::GPRState* gpr) {
#if defined(QBDI_ARCH_X86_64)
  return gpr->rsp;
#elif defined(QBDI_ARCH_AARCH64)
  return gpr->sp;
#elif defined(QBDI_ARCH_ARM)
  return gpr->sp;
#elif defined(QBDI_ARCH_X86)
  return gpr->esp;
#else
  static_assert(false, "unsupported architecture");
#endif
}

// type-safe register enumeration
enum class reg : uint8_t {
  // architectural registers only
  pc,
  sp,

// platform-specific names also available
#if defined(QBDI_ARCH_X86_64)
  rax,
  rbx,
  rcx,
  rdx,
  rsi,
  rdi,
  rbp,
  rsp,
  r8,
  r9,
  r10,
  r11,
  r12,
  r13,
  r14,
  r15,
  rip
#elif defined(QBDI_ARCH_AARCH64)
  x0,
  x1,
  x2,
  x3,
  x4,
  x5,
  x6,
  x7,
  x8,
  x9,
  x10,
  x11,
  x12,
  x13,
  x14,
  x15,
  x16,
  x17,
  x18,
  x19,
  x20,
  x21,
  x22,
  x23,
  x24,
  x25,
  x26,
  x27,
  x28,
  x29,
  lr
#elif defined(QBDI_ARCH_ARM)
  r0,
  r1,
  r2,
  r3,
  r4,
  r5,
  r6,
  r7,
  r8,
  r9,
  r10,
  r11,
  r12,
  r13,
  r14,
  r15
#elif defined(QBDI_ARCH_X86)
  eax,
  ebx,
  ecx,
  edx,
  esi,
  edi,
  ebp,
  esp,
  eip
#endif
};

// compile-time register access
template <reg R> inline QBDI::rword get(const QBDI::GPRState* gpr) {
  if constexpr (R == reg::pc) {
    return get_pc(gpr);
  } else if constexpr (R == reg::sp) {
    return get_sp(gpr);
  }
#if defined(QBDI_ARCH_X86_64)
  else if constexpr (R == reg::rax) {
    return gpr->rax;
  } else if constexpr (R == reg::rbx) {
    return gpr->rbx;
  } else if constexpr (R == reg::rcx) {
    return gpr->rcx;
  } else if constexpr (R == reg::rdx) {
    return gpr->rdx;
  } else if constexpr (R == reg::rsi) {
    return gpr->rsi;
  } else if constexpr (R == reg::rdi) {
    return gpr->rdi;
  } else if constexpr (R == reg::rbp) {
    return gpr->rbp;
  } else if constexpr (R == reg::rsp) {
    return gpr->rsp;
  } else if constexpr (R == reg::r8) {
    return gpr->r8;
  } else if constexpr (R == reg::r9) {
    return gpr->r9;
  } else if constexpr (R == reg::r10) {
    return gpr->r10;
  } else if constexpr (R == reg::r11) {
    return gpr->r11;
  } else if constexpr (R == reg::r12) {
    return gpr->r12;
  } else if constexpr (R == reg::r13) {
    return gpr->r13;
  } else if constexpr (R == reg::r14) {
    return gpr->r14;
  } else if constexpr (R == reg::r15) {
    return gpr->r15;
  } else if constexpr (R == reg::rip) {
    return gpr->rip;
  }
#elif defined(QBDI_ARCH_AARCH64)
  else if constexpr (R == reg::x0) {
    return gpr->x0;
  } else if constexpr (R == reg::x1) {
    return gpr->x1;
  } else if constexpr (R == reg::x2) {
    return gpr->x2;
  } else if constexpr (R == reg::x3) {
    return gpr->x3;
  } else if constexpr (R == reg::x4) {
    return gpr->x4;
  } else if constexpr (R == reg::x5) {
    return gpr->x5;
  } else if constexpr (R == reg::x6) {
    return gpr->x6;
  } else if constexpr (R == reg::x7) {
    return gpr->x7;
  } else if constexpr (R == reg::x8) {
    return gpr->x8;
  } else if constexpr (R == reg::x9) {
    return gpr->x9;
  } else if constexpr (R == reg::x10) {
    return gpr->x10;
  } else if constexpr (R == reg::x11) {
    return gpr->x11;
  } else if constexpr (R == reg::x12) {
    return gpr->x12;
  } else if constexpr (R == reg::x13) {
    return gpr->x13;
  } else if constexpr (R == reg::x14) {
    return gpr->x14;
  } else if constexpr (R == reg::x15) {
    return gpr->x15;
  } else if constexpr (R == reg::x16) {
    return gpr->x16;
  } else if constexpr (R == reg::x17) {
    return gpr->x17;
  } else if constexpr (R == reg::x18) {
    return gpr->x18;
  } else if constexpr (R == reg::x19) {
    return gpr->x19;
  } else if constexpr (R == reg::x20) {
    return gpr->x20;
  } else if constexpr (R == reg::x21) {
    return gpr->x21;
  } else if constexpr (R == reg::x22) {
    return gpr->x22;
  } else if constexpr (R == reg::x23) {
    return gpr->x23;
  } else if constexpr (R == reg::x24) {
    return gpr->x24;
  } else if constexpr (R == reg::x25) {
    return gpr->x25;
  } else if constexpr (R == reg::x26) {
    return gpr->x26;
  } else if constexpr (R == reg::x27) {
    return gpr->x27;
  } else if constexpr (R == reg::x28) {
    return gpr->x28;
  } else if constexpr (R == reg::x29) {
    return gpr->x29;
  } else if constexpr (R == reg::lr) {
    return gpr->lr;
  }
#elif defined(QBDI_ARCH_ARM)
  else if constexpr (R == reg::r0) {
    return gpr->r0;
  } else if constexpr (R == reg::r1) {
    return gpr->r1;
  } else if constexpr (R == reg::r2) {
    return gpr->r2;
  } else if constexpr (R == reg::r3) {
    return gpr->r3;
  } else if constexpr (R == reg::r4) {
    return gpr->r4;
  } else if constexpr (R == reg::r5) {
    return gpr->r5;
  } else if constexpr (R == reg::r6) {
    return gpr->r6;
  } else if constexpr (R == reg::r7) {
    return gpr->r7;
  } else if constexpr (R == reg::r8) {
    return gpr->r8;
  } else if constexpr (R == reg::r9) {
    return gpr->r9;
  } else if constexpr (R == reg::r10) {
    return gpr->r10;
  } else if constexpr (R == reg::r11) {
    return gpr->r11;
  } else if constexpr (R == reg::r12) {
    return gpr->r12;
  } else if constexpr (R == reg::r13) {
    return gpr->r13;
  } else if constexpr (R == reg::r14) {
    return gpr->r14;
  } else if constexpr (R == reg::r15) {
    return gpr->r15;
  }
#elif defined(QBDI_ARCH_X86)
  else if constexpr (R == reg::eax) {
    return gpr->eax;
  } else if constexpr (R == reg::ebx) {
    return gpr->ebx;
  } else if constexpr (R == reg::ecx) {
    return gpr->ecx;
  } else if constexpr (R == reg::edx) {
    return gpr->edx;
  } else if constexpr (R == reg::esi) {
    return gpr->esi;
  } else if constexpr (R == reg::edi) {
    return gpr->edi;
  } else if constexpr (R == reg::ebp) {
    return gpr->ebp;
  } else if constexpr (R == reg::esp) {
    return gpr->esp;
  } else if constexpr (R == reg::eip) {
    return gpr->eip;
  }
#endif
  else {
    static_assert(std::is_same_v<std::true_type, std::false_type>, "invalid register");
  }
}

// runtime register access when register is not known at compile time
inline QBDI::rword get(const QBDI::GPRState* gpr, reg r) {
  switch (r) {
  case reg::pc:
    return get_pc(gpr);
  case reg::sp:
    return get_sp(gpr);
#if defined(QBDI_ARCH_X86_64)
  case reg::rax:
    return gpr->rax;
  case reg::rbx:
    return gpr->rbx;
  case reg::rcx:
    return gpr->rcx;
  case reg::rdx:
    return gpr->rdx;
  case reg::rsi:
    return gpr->rsi;
  case reg::rdi:
    return gpr->rdi;
  case reg::rbp:
    return gpr->rbp;
  case reg::rsp:
    return gpr->rsp;
  case reg::r8:
    return gpr->r8;
  case reg::r9:
    return gpr->r9;
  case reg::r10:
    return gpr->r10;
  case reg::r11:
    return gpr->r11;
  case reg::r12:
    return gpr->r12;
  case reg::r13:
    return gpr->r13;
  case reg::r14:
    return gpr->r14;
  case reg::r15:
    return gpr->r15;
  case reg::rip:
    return gpr->rip;
#elif defined(QBDI_ARCH_AARCH64)
  case reg::x0:
    return gpr->x0;
  case reg::x1:
    return gpr->x1;
  case reg::x2:
    return gpr->x2;
  case reg::x3:
    return gpr->x3;
  case reg::x4:
    return gpr->x4;
  case reg::x5:
    return gpr->x5;
  case reg::x6:
    return gpr->x6;
  case reg::x7:
    return gpr->x7;
  case reg::x8:
    return gpr->x8;
  case reg::x9:
    return gpr->x9;
  case reg::x10:
    return gpr->x10;
  case reg::x11:
    return gpr->x11;
  case reg::x12:
    return gpr->x12;
  case reg::x13:
    return gpr->x13;
  case reg::x14:
    return gpr->x14;
  case reg::x15:
    return gpr->x15;
  case reg::x16:
    return gpr->x16;
  case reg::x17:
    return gpr->x17;
  case reg::x18:
    return gpr->x18;
  case reg::x19:
    return gpr->x19;
  case reg::x20:
    return gpr->x20;
  case reg::x21:
    return gpr->x21;
  case reg::x22:
    return gpr->x22;
  case reg::x23:
    return gpr->x23;
  case reg::x24:
    return gpr->x24;
  case reg::x25:
    return gpr->x25;
  case reg::x26:
    return gpr->x26;
  case reg::x27:
    return gpr->x27;
  case reg::x28:
    return gpr->x28;
  case reg::x29:
    return gpr->x29;
  case reg::lr:
    return gpr->lr;
#elif defined(QBDI_ARCH_ARM)
  case reg::r0:
    return gpr->r0;
  case reg::r1:
    return gpr->r1;
  case reg::r2:
    return gpr->r2;
  case reg::r3:
    return gpr->r3;
  case reg::r4:
    return gpr->r4;
  case reg::r5:
    return gpr->r5;
  case reg::r6:
    return gpr->r6;
  case reg::r7:
    return gpr->r7;
  case reg::r8:
    return gpr->r8;
  case reg::r9:
    return gpr->r9;
  case reg::r10:
    return gpr->r10;
  case reg::r11:
    return gpr->r11;
  case reg::r12:
    return gpr->r12;
  case reg::r13:
    return gpr->r13;
  case reg::r14:
    return gpr->r14;
  case reg::r15:
    return gpr->r15;
#elif defined(QBDI_ARCH_X86)
  case reg::eax:
    return gpr->eax;
  case reg::ebx:
    return gpr->ebx;
  case reg::ecx:
    return gpr->ecx;
  case reg::edx:
    return gpr->edx;
  case reg::esi:
    return gpr->esi;
  case reg::edi:
    return gpr->edi;
  case reg::ebp:
    return gpr->ebp;
  case reg::esp:
    return gpr->esp;
  case reg::eip:
    return gpr->eip;
#endif
  default:
    return 0;
  }
}

} // namespace w1::registers