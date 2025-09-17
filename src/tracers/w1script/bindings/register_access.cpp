#include "register_access.hpp"
#include <w1tn3ss/util/register_access.hpp>
#include <redlog.hpp>
#include <unordered_map>
#include <string>
#include <cctype>

namespace w1::tracers::script::bindings {

// helper to convert string register name to enum
static std::optional<w1::registers::reg> string_to_reg(const std::string& name) {
  static const std::unordered_map<std::string, w1::registers::reg> reg_map = {
      // common architectural names
      {"pc", w1::registers::reg::pc},   {"sp", w1::registers::reg::sp},

#if defined(QBDI_ARCH_X86_64)
      {"rax", w1::registers::reg::rax}, {"rbx", w1::registers::reg::rbx}, {"rcx", w1::registers::reg::rcx},
      {"rdx", w1::registers::reg::rdx}, {"rsi", w1::registers::reg::rsi}, {"rdi", w1::registers::reg::rdi},
      {"rbp", w1::registers::reg::rbp}, {"rsp", w1::registers::reg::rsp}, {"r8", w1::registers::reg::r8},
      {"r9", w1::registers::reg::r9},   {"r10", w1::registers::reg::r10}, {"r11", w1::registers::reg::r11},
      {"r12", w1::registers::reg::r12}, {"r13", w1::registers::reg::r13}, {"r14", w1::registers::reg::r14},
      {"r15", w1::registers::reg::r15}, {"rip", w1::registers::reg::rip},
#elif defined(QBDI_ARCH_AARCH64)
      {"x0", w1::registers::reg::x0},   {"x1", w1::registers::reg::x1},   {"x2", w1::registers::reg::x2},
      {"x3", w1::registers::reg::x3},   {"x4", w1::registers::reg::x4},   {"x5", w1::registers::reg::x5},
      {"x6", w1::registers::reg::x6},   {"x7", w1::registers::reg::x7},   {"x8", w1::registers::reg::x8},
      {"x9", w1::registers::reg::x9},   {"x10", w1::registers::reg::x10}, {"x11", w1::registers::reg::x11},
      {"x12", w1::registers::reg::x12}, {"x13", w1::registers::reg::x13}, {"x14", w1::registers::reg::x14},
      {"x15", w1::registers::reg::x15}, {"x16", w1::registers::reg::x16}, {"x17", w1::registers::reg::x17},
      {"x18", w1::registers::reg::x18}, {"x19", w1::registers::reg::x19}, {"x20", w1::registers::reg::x20},
      {"x21", w1::registers::reg::x21}, {"x22", w1::registers::reg::x22}, {"x23", w1::registers::reg::x23},
      {"x24", w1::registers::reg::x24}, {"x25", w1::registers::reg::x25}, {"x26", w1::registers::reg::x26},
      {"x27", w1::registers::reg::x27}, {"x28", w1::registers::reg::x28}, {"x29", w1::registers::reg::x29},
      {"lr", w1::registers::reg::lr},
#elif defined(QBDI_ARCH_ARM)
      {"r0", w1::registers::reg::r0},   {"r1", w1::registers::reg::r1},   {"r2", w1::registers::reg::r2},
      {"r3", w1::registers::reg::r3},   {"r4", w1::registers::reg::r4},   {"r5", w1::registers::reg::r5},
      {"r6", w1::registers::reg::r6},   {"r7", w1::registers::reg::r7},   {"r8", w1::registers::reg::r8},
      {"r9", w1::registers::reg::r9},   {"r10", w1::registers::reg::r10}, {"r11", w1::registers::reg::r11},
      {"r12", w1::registers::reg::r12}, {"r13", w1::registers::reg::r13}, {"r14", w1::registers::reg::r14},
      {"r15", w1::registers::reg::r15},
#elif defined(QBDI_ARCH_X86)
      {"eax", w1::registers::reg::eax}, {"ebx", w1::registers::reg::ebx}, {"ecx", w1::registers::reg::ecx},
      {"edx", w1::registers::reg::edx}, {"esi", w1::registers::reg::esi}, {"edi", w1::registers::reg::edi},
      {"ebp", w1::registers::reg::ebp}, {"esp", w1::registers::reg::esp}, {"eip", w1::registers::reg::eip},
#endif
  };

  auto it = reg_map.find(name);
  if (it != reg_map.end()) {
    return it->second;
  }
  return std::nullopt;
}

// helper to set register value
static bool set_register(QBDI::GPRState* gpr, w1::registers::reg r, QBDI::rword value) {
  switch (r) {
#if defined(QBDI_ARCH_X86_64)
  case w1::registers::reg::rax:
    gpr->rax = value;
    return true;
  case w1::registers::reg::rbx:
    gpr->rbx = value;
    return true;
  case w1::registers::reg::rcx:
    gpr->rcx = value;
    return true;
  case w1::registers::reg::rdx:
    gpr->rdx = value;
    return true;
  case w1::registers::reg::rsi:
    gpr->rsi = value;
    return true;
  case w1::registers::reg::rdi:
    gpr->rdi = value;
    return true;
  case w1::registers::reg::rbp:
    gpr->rbp = value;
    return true;
  case w1::registers::reg::rsp:
    gpr->rsp = value;
    return true;
  case w1::registers::reg::r8:
    gpr->r8 = value;
    return true;
  case w1::registers::reg::r9:
    gpr->r9 = value;
    return true;
  case w1::registers::reg::r10:
    gpr->r10 = value;
    return true;
  case w1::registers::reg::r11:
    gpr->r11 = value;
    return true;
  case w1::registers::reg::r12:
    gpr->r12 = value;
    return true;
  case w1::registers::reg::r13:
    gpr->r13 = value;
    return true;
  case w1::registers::reg::r14:
    gpr->r14 = value;
    return true;
  case w1::registers::reg::r15:
    gpr->r15 = value;
    return true;
  case w1::registers::reg::rip:
    gpr->rip = value;
    return true;
#elif defined(QBDI_ARCH_AARCH64)
  case w1::registers::reg::x0:
    gpr->x0 = value;
    return true;
  case w1::registers::reg::x1:
    gpr->x1 = value;
    return true;
  case w1::registers::reg::x2:
    gpr->x2 = value;
    return true;
  case w1::registers::reg::x3:
    gpr->x3 = value;
    return true;
  case w1::registers::reg::x4:
    gpr->x4 = value;
    return true;
  case w1::registers::reg::x5:
    gpr->x5 = value;
    return true;
  case w1::registers::reg::x6:
    gpr->x6 = value;
    return true;
  case w1::registers::reg::x7:
    gpr->x7 = value;
    return true;
  case w1::registers::reg::x8:
    gpr->x8 = value;
    return true;
  case w1::registers::reg::x9:
    gpr->x9 = value;
    return true;
  case w1::registers::reg::x10:
    gpr->x10 = value;
    return true;
  case w1::registers::reg::x11:
    gpr->x11 = value;
    return true;
  case w1::registers::reg::x12:
    gpr->x12 = value;
    return true;
  case w1::registers::reg::x13:
    gpr->x13 = value;
    return true;
  case w1::registers::reg::x14:
    gpr->x14 = value;
    return true;
  case w1::registers::reg::x15:
    gpr->x15 = value;
    return true;
  case w1::registers::reg::x16:
    gpr->x16 = value;
    return true;
  case w1::registers::reg::x17:
    gpr->x17 = value;
    return true;
  case w1::registers::reg::x18:
    gpr->x18 = value;
    return true;
  case w1::registers::reg::x19:
    gpr->x19 = value;
    return true;
  case w1::registers::reg::x20:
    gpr->x20 = value;
    return true;
  case w1::registers::reg::x21:
    gpr->x21 = value;
    return true;
  case w1::registers::reg::x22:
    gpr->x22 = value;
    return true;
  case w1::registers::reg::x23:
    gpr->x23 = value;
    return true;
  case w1::registers::reg::x24:
    gpr->x24 = value;
    return true;
  case w1::registers::reg::x25:
    gpr->x25 = value;
    return true;
  case w1::registers::reg::x26:
    gpr->x26 = value;
    return true;
  case w1::registers::reg::x27:
    gpr->x27 = value;
    return true;
  case w1::registers::reg::x28:
    gpr->x28 = value;
    return true;
  case w1::registers::reg::x29:
    gpr->x29 = value;
    return true;
  case w1::registers::reg::sp:
    gpr->sp = value;
    return true;
  case w1::registers::reg::lr:
    gpr->lr = value;
    return true;
  case w1::registers::reg::pc:
    gpr->pc = value;
    return true;
#elif defined(QBDI_ARCH_ARM)
  case w1::registers::reg::r0:
    gpr->r0 = value;
    return true;
  case w1::registers::reg::r1:
    gpr->r1 = value;
    return true;
  case w1::registers::reg::r2:
    gpr->r2 = value;
    return true;
  case w1::registers::reg::r3:
    gpr->r3 = value;
    return true;
  case w1::registers::reg::r4:
    gpr->r4 = value;
    return true;
  case w1::registers::reg::r5:
    gpr->r5 = value;
    return true;
  case w1::registers::reg::r6:
    gpr->r6 = value;
    return true;
  case w1::registers::reg::r7:
    gpr->r7 = value;
    return true;
  case w1::registers::reg::r8:
    gpr->r8 = value;
    return true;
  case w1::registers::reg::r9:
    gpr->r9 = value;
    return true;
  case w1::registers::reg::r10:
    gpr->r10 = value;
    return true;
  case w1::registers::reg::r11:
    gpr->r11 = value;
    return true;
  case w1::registers::reg::r12:
    gpr->r12 = value;
    return true;
  case w1::registers::reg::r13:
    gpr->r13 = value;
    return true;
  case w1::registers::reg::r14:
    gpr->r14 = value;
    return true;
  case w1::registers::reg::r15:
    gpr->r15 = value;
    return true;
  case w1::registers::reg::sp:
    gpr->sp = value;
    return true;
  case w1::registers::reg::pc:
    gpr->pc = value;
    return true;
#elif defined(QBDI_ARCH_X86)
  case w1::registers::reg::eax:
    gpr->eax = value;
    return true;
  case w1::registers::reg::ebx:
    gpr->ebx = value;
    return true;
  case w1::registers::reg::ecx:
    gpr->ecx = value;
    return true;
  case w1::registers::reg::edx:
    gpr->edx = value;
    return true;
  case w1::registers::reg::esi:
    gpr->esi = value;
    return true;
  case w1::registers::reg::edi:
    gpr->edi = value;
    return true;
  case w1::registers::reg::ebp:
    gpr->ebp = value;
    return true;
  case w1::registers::reg::esp:
    gpr->esp = value;
    return true;
  case w1::registers::reg::eip:
    gpr->eip = value;
    return true;
#endif
  default:
    return false;
  }
}

void setup_register_access(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up generic register access functions");

  // generic register getter
  w1_module.set_function("get_reg", [](QBDI::GPRState* gpr, const std::string& reg_name) -> sol::optional<QBDI::rword> {
    if (!gpr) {
      return sol::nullopt;
    }

    auto reg_opt = string_to_reg(reg_name);
    if (!reg_opt) {
      return sol::nullopt;
    }

    return w1::registers::get(gpr, *reg_opt);
  });

  // generic register setter
  w1_module.set_function("set_reg", [](QBDI::GPRState* gpr, const std::string& reg_name, QBDI::rword value) -> bool {
    if (!gpr) {
      return false;
    }

    auto reg_opt = string_to_reg(reg_name);
    if (!reg_opt) {
      return false;
    }

    return set_register(gpr, *reg_opt, value);
  });

  // convenience functions for common registers
  w1_module.set_function("get_pc", [](QBDI::GPRState* gpr) -> QBDI::rword {
    if (!gpr) {
      return 0;
    }
    return w1::registers::get_pc(gpr);
  });

  w1_module.set_function("get_sp", [](QBDI::GPRState* gpr) -> QBDI::rword {
    if (!gpr) {
      return 0;
    }
    return w1::registers::get_sp(gpr);
  });

  // legacy compatibility functions (deprecated)
  w1_module.set_function("get_reg_pc", [](QBDI::GPRState* gpr) -> QBDI::rword {
    if (!gpr) {
      return 0;
    }
    return w1::registers::get_pc(gpr);
  });

  // floating point helpers focus on x87 state used by x86 workloads
  w1_module.set_function(
      "get_fpr_word",
      [](QBDI::FPRState* fpr, const std::string& field) -> sol::optional<uint64_t> {
        if (!fpr) {
          return sol::nullopt;
        }

#if defined(QBDI_ARCH_X86) || defined(QBDI_ARCH_X86_64)
        std::string lowered;
        lowered.reserve(field.size());
        for (unsigned char ch : field) {
          lowered.push_back(static_cast<char>(std::tolower(ch)));
        }

        if (lowered == "fcw" || lowered == "rfcw" || lowered == "control") {
          return static_cast<uint64_t>(fpr->rfcw);
        }
        if (lowered == "fsw" || lowered == "rfsw" || lowered == "status") {
          return static_cast<uint64_t>(fpr->rfsw);
        }
        if (lowered == "ftw" || lowered == "tag") {
          return static_cast<uint64_t>(fpr->ftw);
        }
        if (lowered == "fop") {
          return static_cast<uint64_t>(fpr->fop);
        }
        if (lowered == "ip") {
          return static_cast<uint64_t>(fpr->ip);
        }
        if (lowered == "cs") {
          return static_cast<uint64_t>(fpr->cs);
        }
        if (lowered == "dp") {
          return static_cast<uint64_t>(fpr->dp);
        }
        if (lowered == "ds") {
          return static_cast<uint64_t>(fpr->ds);
        }
        if (lowered == "mxcsr") {
          return static_cast<uint64_t>(fpr->mxcsr);
        }
        if (lowered == "mxcsrmask" || lowered == "mxcsr_mask") {
          return static_cast<uint64_t>(fpr->mxcsrmask);
        }

        return sol::nullopt;
#else
        (void)field;
        return sol::nullopt;
#endif
      }
  );

  w1_module.set_function(
      "get_fpr_st_bytes",
      [](QBDI::FPRState* fpr, uint32_t index) -> sol::optional<std::string> {
        if (!fpr || index > 7) {
          return sol::nullopt;
        }

#if defined(QBDI_ARCH_X86) || defined(QBDI_ARCH_X86_64)
        const char* data = nullptr;
        switch (index) {
        case 0:
          data = fpr->stmm0.reg;
          break;
        case 1:
          data = fpr->stmm1.reg;
          break;
        case 2:
          data = fpr->stmm2.reg;
          break;
        case 3:
          data = fpr->stmm3.reg;
          break;
        case 4:
          data = fpr->stmm4.reg;
          break;
        case 5:
          data = fpr->stmm5.reg;
          break;
        case 6:
          data = fpr->stmm6.reg;
          break;
        case 7:
          data = fpr->stmm7.reg;
          break;
        default:
          return sol::nullopt;
        }

        return std::string(data, 10);
#else
        (void)index;
        return sol::nullopt;
#endif
      }
  );

  logger.dbg("generic register access functions registered");
}

} // namespace w1::tracers::script::bindings
