#include "w1h00k/backend/inline/inline_instrumentation.hpp"

#include <array>
#include <sstream>
#include <string>

#include "w1asmr/asmr.hpp"
#include "w1h00k/core/hook_args.hpp"

namespace w1::h00k::backend::instrument {
namespace {

struct abi_plan {
  const char* const* gpr = nullptr;
  size_t gpr_count = 0;
  const char* const* fpr = nullptr;
  size_t fpr_count = 0;
  size_t gpr_size = 0;
  size_t fpr_size = 0;
  size_t shadow_size = 0;
  size_t stack_align = 16;
  const char* arg_reg = nullptr;
};

constexpr std::array<const char*, 9> kSysvGpr = {
    "rdi", "rsi", "rdx", "rcx", "r8", "r9", "rax", "r10", "r11"};
constexpr std::array<const char*, 8> kSysvFpr = {
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"};
constexpr std::array<const char*, 7> kWin64Gpr = {"rcx", "rdx", "r8", "r9", "rax", "r10", "r11"};
constexpr std::array<const char*, 4> kWin64Fpr = {"xmm0", "xmm1", "xmm2", "xmm3"};
constexpr std::array<const char*, 6> kWin64FprVector = {"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"};
constexpr std::array<const char*, 3> kX86Gpr = {"ecx", "edx", "eax"};
constexpr std::array<const char*, 20> kArm64Gpr = {
    "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",  "x8",  "x9",
    "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x30"};
constexpr std::array<const char*, 8> kArm64Fpr = {"q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7"};

size_t align_up(size_t value, size_t alignment) {
  if (alignment == 0) {
    return value;
  }
  const size_t mask = alignment - 1;
  return (value + mask) & ~mask;
}

std::string hex(uint64_t value) {
  std::ostringstream oss;
  oss << "0x" << std::hex << value;
  return oss.str();
}

void append_mov_imm64(std::ostringstream& oss, const char* reg, uint64_t value) {
  const uint16_t part0 = static_cast<uint16_t>(value & 0xFFFFu);
  const uint16_t part1 = static_cast<uint16_t>((value >> 16) & 0xFFFFu);
  const uint16_t part2 = static_cast<uint16_t>((value >> 32) & 0xFFFFu);
  const uint16_t part3 = static_cast<uint16_t>((value >> 48) & 0xFFFFu);
  oss << "movz " << reg << ", #" << hex(part0) << "\n";
  oss << "movk " << reg << ", #" << hex(part1) << ", lsl #16\n";
  oss << "movk " << reg << ", #" << hex(part2) << ", lsl #32\n";
  oss << "movk " << reg << ", #" << hex(part3) << ", lsl #48\n";
}

abi_plan plan_for(const w1::arch::arch_spec& arch, hook_call_abi abi, bool& ok) {
  ok = true;
  abi_plan plan{};
  switch (arch.arch_mode) {
    case w1::arch::mode::x86_64:
      plan.gpr_size = 8;
      plan.fpr_size = 16;
      if (abi == hook_call_abi::win64 || abi == hook_call_abi::win64_vectorcall) {
        plan.gpr = kWin64Gpr.data();
        plan.gpr_count = kWin64Gpr.size();
        if (abi == hook_call_abi::win64_vectorcall) {
          plan.fpr = kWin64FprVector.data();
          plan.fpr_count = kWin64FprVector.size();
        } else {
          plan.fpr = kWin64Fpr.data();
          plan.fpr_count = kWin64Fpr.size();
        }
        plan.shadow_size = 32;
        plan.arg_reg = "rcx";
      } else if (abi == hook_call_abi::sysv) {
        plan.gpr = kSysvGpr.data();
        plan.gpr_count = kSysvGpr.size();
        plan.fpr = kSysvFpr.data();
        plan.fpr_count = kSysvFpr.size();
        plan.arg_reg = "rdi";
      } else {
        ok = false;
      }
      return plan;
    case w1::arch::mode::x86_32:
      if (abi != hook_call_abi::sysv && abi != hook_call_abi::win32_cdecl && abi != hook_call_abi::win32_stdcall &&
          abi != hook_call_abi::win32_fastcall && abi != hook_call_abi::win32_thiscall) {
        ok = false;
        return plan;
      }
      plan.gpr = kX86Gpr.data();
      plan.gpr_count = kX86Gpr.size();
      plan.gpr_size = 4;
      plan.fpr_size = 16;
      return plan;
    case w1::arch::mode::aarch64:
      if (abi != hook_call_abi::aapcs64) {
        ok = false;
        return plan;
      }
      plan.gpr = kArm64Gpr.data();
      plan.gpr_count = kArm64Gpr.size();
      plan.gpr_size = 8;
      plan.fpr = kArm64Fpr.data();
      plan.fpr_count = kArm64Fpr.size();
      plan.fpr_size = 16;
      plan.arg_reg = "x0";
      return plan;
    default:
      ok = false;
      return plan;
  }
}

bool assemble_stub(const w1::arch::arch_spec& arch,
                   const std::string& text,
                   uint64_t address,
                   std::vector<uint8_t>& out) {
  auto ctx = w1::asmr::asm_context::for_arch(arch);
  if (!ctx.ok()) {
    return false;
  }
  auto bytes = ctx.value.assemble(text, address);
  if (!bytes.ok()) {
    return false;
  }
  out = std::move(bytes.value);
  return true;
}

bool build_x86_64_stub(const stub_request& request, const stub_layout& layout, const abi_plan& plan,
                       std::vector<uint8_t>& out) {
  const size_t args_abi_off = offsetof(hook_arg_handle, abi);
  const size_t args_reserved_off = offsetof(hook_arg_handle, reserved);
  const size_t args_int_off = offsetof(hook_arg_handle, int_regs);
  const size_t args_flt_off = offsetof(hook_arg_handle, flt_regs);
  const size_t args_stack_off = offsetof(hook_arg_handle, stack);

  const size_t info_original_off = offsetof(hook_info, original_target);
  const size_t info_target_off = offsetof(hook_info, target);
  const size_t info_trampoline_off = offsetof(hook_info, trampoline);
  const size_t info_replacement_off = offsetof(hook_info, replacement);
  const size_t info_user_data_off = offsetof(hook_info, user_data);
  const size_t info_args_off = offsetof(hook_info, args);

  std::ostringstream oss;
  oss << "sub rsp, " << layout.stack_size << "\n";
  for (size_t i = 0; i < plan.gpr_count; ++i) {
    oss << "mov qword ptr [rsp + " << (layout.gpr_offset + i * plan.gpr_size) << "], " << plan.gpr[i] << "\n";
  }
  for (size_t i = 0; i < plan.fpr_count; ++i) {
    oss << "movdqu [rsp + " << (layout.fpr_offset + i * plan.fpr_size) << "], " << plan.fpr[i] << "\n";
  }

  oss << "mov dword ptr [rsp + " << (layout.args_offset + args_abi_off) << "], "
      << static_cast<uint32_t>(request.abi) << "\n";
  oss << "mov dword ptr [rsp + " << (layout.args_offset + args_reserved_off) << "], 0\n";

  oss << "lea rax, [rsp + " << layout.gpr_offset << "]\n";
  oss << "mov qword ptr [rsp + " << (layout.args_offset + args_int_off) << "], rax\n";
  if (layout.fpr_count > 0) {
    oss << "lea rax, [rsp + " << layout.fpr_offset << "]\n";
  } else {
    oss << "xor rax, rax\n";
  }
  oss << "mov qword ptr [rsp + " << (layout.args_offset + args_flt_off) << "], rax\n";
  oss << "lea rax, [rsp + " << layout.stack_size << "]\n";
  oss << "mov qword ptr [rsp + " << (layout.args_offset + args_stack_off) << "], rax\n";

  oss << "lea rax, [rsp + " << layout.args_offset << "]\n";
  oss << "mov qword ptr [rsp + " << (layout.info_offset + info_args_off) << "], rax\n";
  oss << "mov rax, " << hex(request.target) << "\n";
  oss << "mov qword ptr [rsp + " << (layout.info_offset + info_original_off) << "], rax\n";
  oss << "mov qword ptr [rsp + " << (layout.info_offset + info_target_off) << "], rax\n";
  oss << "mov rax, " << hex(request.trampoline) << "\n";
  oss << "mov qword ptr [rsp + " << (layout.info_offset + info_trampoline_off) << "], rax\n";
  oss << "mov rax, " << hex(request.replacement) << "\n";
  oss << "mov qword ptr [rsp + " << (layout.info_offset + info_replacement_off) << "], rax\n";
  oss << "mov rax, " << hex(request.user_data) << "\n";
  oss << "mov qword ptr [rsp + " << (layout.info_offset + info_user_data_off) << "], rax\n";

  oss << "lea " << plan.arg_reg << ", [rsp + " << layout.info_offset << "]\n";
  oss << "mov rax, " << hex(request.prehook) << "\n";
  oss << "call rax\n";

  for (size_t i = 0; i < plan.fpr_count; ++i) {
    oss << "movdqu " << plan.fpr[i] << ", [rsp + " << (layout.fpr_offset + i * plan.fpr_size) << "]\n";
  }
  for (size_t i = 0; i < plan.gpr_count; ++i) {
    oss << "mov " << plan.gpr[i] << ", qword ptr [rsp + " << (layout.gpr_offset + i * plan.gpr_size) << "]\n";
  }

  oss << "add rsp, " << layout.stack_size << "\n";
  oss << "jmp " << hex(request.trampoline) << "\n";

  return assemble_stub(request.arch, oss.str(), request.stub_address, out);
}

bool build_x86_32_stub(const stub_request& request, const stub_layout& layout, const abi_plan& plan,
                       std::vector<uint8_t>& out) {
  const size_t args_abi_off = offsetof(hook_arg_handle, abi);
  const size_t args_reserved_off = offsetof(hook_arg_handle, reserved);
  const size_t args_int_off = offsetof(hook_arg_handle, int_regs);
  const size_t args_flt_off = offsetof(hook_arg_handle, flt_regs);
  const size_t args_stack_off = offsetof(hook_arg_handle, stack);

  const size_t info_original_off = offsetof(hook_info, original_target);
  const size_t info_target_off = offsetof(hook_info, target);
  const size_t info_trampoline_off = offsetof(hook_info, trampoline);
  const size_t info_replacement_off = offsetof(hook_info, replacement);
  const size_t info_user_data_off = offsetof(hook_info, user_data);
  const size_t info_args_off = offsetof(hook_info, args);

  std::ostringstream oss;
  oss << "sub esp, " << layout.stack_size << "\n";
  for (size_t i = 0; i < plan.gpr_count; ++i) {
    oss << "mov dword ptr [esp + " << (layout.gpr_offset + i * plan.gpr_size) << "], " << plan.gpr[i] << "\n";
  }

  oss << "mov dword ptr [esp + " << (layout.args_offset + args_abi_off) << "], "
      << static_cast<uint32_t>(request.abi) << "\n";
  oss << "mov dword ptr [esp + " << (layout.args_offset + args_reserved_off) << "], 0\n";

  oss << "lea eax, [esp + " << layout.gpr_offset << "]\n";
  oss << "mov dword ptr [esp + " << (layout.args_offset + args_int_off) << "], eax\n";
  oss << "xor eax, eax\n";
  oss << "mov dword ptr [esp + " << (layout.args_offset + args_flt_off) << "], eax\n";
  oss << "lea eax, [esp + " << layout.stack_size << "]\n";
  oss << "mov dword ptr [esp + " << (layout.args_offset + args_stack_off) << "], eax\n";

  oss << "lea eax, [esp + " << layout.args_offset << "]\n";
  oss << "mov dword ptr [esp + " << (layout.info_offset + info_args_off) << "], eax\n";
  oss << "mov eax, " << hex(static_cast<uint32_t>(request.target)) << "\n";
  oss << "mov dword ptr [esp + " << (layout.info_offset + info_original_off) << "], eax\n";
  oss << "mov dword ptr [esp + " << (layout.info_offset + info_target_off) << "], eax\n";
  oss << "mov eax, " << hex(static_cast<uint32_t>(request.trampoline)) << "\n";
  oss << "mov dword ptr [esp + " << (layout.info_offset + info_trampoline_off) << "], eax\n";
  oss << "mov eax, " << hex(static_cast<uint32_t>(request.replacement)) << "\n";
  oss << "mov dword ptr [esp + " << (layout.info_offset + info_replacement_off) << "], eax\n";
  oss << "mov eax, " << hex(static_cast<uint32_t>(request.user_data)) << "\n";
  oss << "mov dword ptr [esp + " << (layout.info_offset + info_user_data_off) << "], eax\n";

  oss << "lea eax, [esp + " << layout.info_offset << "]\n";
  oss << "push eax\n";
  oss << "mov eax, " << hex(static_cast<uint32_t>(request.prehook)) << "\n";
  oss << "call eax\n";
  oss << "add esp, 4\n";

  for (size_t i = 0; i < plan.gpr_count; ++i) {
    oss << "mov " << plan.gpr[i] << ", dword ptr [esp + " << (layout.gpr_offset + i * plan.gpr_size) << "]\n";
  }

  oss << "add esp, " << layout.stack_size << "\n";
  oss << "jmp " << hex(static_cast<uint32_t>(request.trampoline)) << "\n";

  return assemble_stub(request.arch, oss.str(), request.stub_address, out);
}

bool build_arm64_stub(const stub_request& request, const stub_layout& layout, const abi_plan& plan,
                      std::vector<uint8_t>& out) {
  const size_t args_abi_off = offsetof(hook_arg_handle, abi);
  const size_t args_reserved_off = offsetof(hook_arg_handle, reserved);
  const size_t args_int_off = offsetof(hook_arg_handle, int_regs);
  const size_t args_flt_off = offsetof(hook_arg_handle, flt_regs);
  const size_t args_stack_off = offsetof(hook_arg_handle, stack);

  const size_t info_original_off = offsetof(hook_info, original_target);
  const size_t info_target_off = offsetof(hook_info, target);
  const size_t info_trampoline_off = offsetof(hook_info, trampoline);
  const size_t info_replacement_off = offsetof(hook_info, replacement);
  const size_t info_user_data_off = offsetof(hook_info, user_data);
  const size_t info_args_off = offsetof(hook_info, args);

  std::ostringstream oss;
  oss << "sub sp, sp, #" << layout.stack_size << "\n";
  size_t gpr_offset = layout.gpr_offset;
  for (size_t i = 0; i + 1 < plan.gpr_count; i += 2) {
    oss << "stp " << plan.gpr[i] << ", " << plan.gpr[i + 1] << ", [sp, #" << gpr_offset << "]\n";
    gpr_offset += 16;
  }
  if ((plan.gpr_count % 2) != 0) {
    oss << "str " << plan.gpr[plan.gpr_count - 1] << ", [sp, #" << gpr_offset << "]\n";
  }

  size_t fpr_offset = layout.fpr_offset;
  for (size_t i = 0; i + 1 < plan.fpr_count; i += 2) {
    oss << "stp " << plan.fpr[i] << ", " << plan.fpr[i + 1] << ", [sp, #" << fpr_offset << "]\n";
    fpr_offset += 32;
  }
  if ((plan.fpr_count % 2) != 0) {
    oss << "str " << plan.fpr[plan.fpr_count - 1] << ", [sp, #" << fpr_offset << "]\n";
  }

  oss << "mov w16, #" << static_cast<uint32_t>(request.abi) << "\n";
  oss << "str w16, [sp, #" << (layout.args_offset + args_abi_off) << "]\n";
  oss << "mov w16, #0\n";
  oss << "str w16, [sp, #" << (layout.args_offset + args_reserved_off) << "]\n";
  oss << "add x16, sp, #" << layout.gpr_offset << "\n";
  oss << "str x16, [sp, #" << (layout.args_offset + args_int_off) << "]\n";
  if (layout.fpr_count > 0) {
    oss << "add x16, sp, #" << layout.fpr_offset << "\n";
  } else {
    oss << "mov x16, #0\n";
  }
  oss << "str x16, [sp, #" << (layout.args_offset + args_flt_off) << "]\n";
  oss << "add x16, sp, #" << layout.stack_size << "\n";
  oss << "str x16, [sp, #" << (layout.args_offset + args_stack_off) << "]\n";

  oss << "add x16, sp, #" << layout.args_offset << "\n";
  oss << "str x16, [sp, #" << (layout.info_offset + info_args_off) << "]\n";
  append_mov_imm64(oss, "x16", request.target);
  oss << "str x16, [sp, #" << (layout.info_offset + info_original_off) << "]\n";
  oss << "str x16, [sp, #" << (layout.info_offset + info_target_off) << "]\n";
  append_mov_imm64(oss, "x16", request.trampoline);
  oss << "str x16, [sp, #" << (layout.info_offset + info_trampoline_off) << "]\n";
  append_mov_imm64(oss, "x16", request.replacement);
  oss << "str x16, [sp, #" << (layout.info_offset + info_replacement_off) << "]\n";
  append_mov_imm64(oss, "x16", request.user_data);
  oss << "str x16, [sp, #" << (layout.info_offset + info_user_data_off) << "]\n";

  oss << "add x0, sp, #" << layout.info_offset << "\n";
  append_mov_imm64(oss, "x16", request.prehook);
  oss << "blr x16\n";

  fpr_offset = layout.fpr_offset;
  for (size_t i = 0; i + 1 < plan.fpr_count; i += 2) {
    oss << "ldp " << plan.fpr[i] << ", " << plan.fpr[i + 1] << ", [sp, #" << fpr_offset << "]\n";
    fpr_offset += 32;
  }
  if ((plan.fpr_count % 2) != 0) {
    oss << "ldr " << plan.fpr[plan.fpr_count - 1] << ", [sp, #" << fpr_offset << "]\n";
  }

  gpr_offset = layout.gpr_offset;
  for (size_t i = 0; i + 1 < plan.gpr_count; i += 2) {
    oss << "ldp " << plan.gpr[i] << ", " << plan.gpr[i + 1] << ", [sp, #" << gpr_offset << "]\n";
    gpr_offset += 16;
  }
  if ((plan.gpr_count % 2) != 0) {
    oss << "ldr " << plan.gpr[plan.gpr_count - 1] << ", [sp, #" << gpr_offset << "]\n";
  }

  oss << "add sp, sp, #" << layout.stack_size << "\n";
  oss << "b " << hex(request.trampoline) << "\n";

  return assemble_stub(request.arch, oss.str(), request.stub_address, out);
}

} // namespace

hook_call_abi resolve_call_abi(hook_call_abi requested, const w1::arch::arch_spec& arch) {
  if (requested != hook_call_abi::native) {
    return requested;
  }

  switch (arch.arch_mode) {
    case w1::arch::mode::aarch64:
      return hook_call_abi::aapcs64;
    case w1::arch::mode::x86_64:
#if defined(_WIN32)
      return hook_call_abi::win64;
#else
      return hook_call_abi::sysv;
#endif
    case w1::arch::mode::x86_32:
      return
#if defined(_WIN32)
          hook_call_abi::win32_cdecl;
#else
          hook_call_abi::sysv;
#endif
    default:
      return hook_call_abi::native;
  }
}

bool abi_supported(hook_call_abi abi, const w1::arch::arch_spec& arch) {
  switch (arch.arch_mode) {
    case w1::arch::mode::x86_64:
#if defined(_WIN32)
      return abi == hook_call_abi::win64 || abi == hook_call_abi::win64_vectorcall;
#else
      return abi == hook_call_abi::sysv;
#endif
    case w1::arch::mode::x86_32:
      return
#if defined(_WIN32)
          (abi == hook_call_abi::win32_cdecl || abi == hook_call_abi::win32_stdcall ||
           abi == hook_call_abi::win32_fastcall || abi == hook_call_abi::win32_thiscall);
#else
          abi == hook_call_abi::sysv;
#endif
    case w1::arch::mode::aarch64:
      return abi == hook_call_abi::aapcs64;
    default:
      return false;
  }
}

stub_layout make_layout(const w1::arch::arch_spec& arch, hook_call_abi abi, bool& ok) {
  abi_plan plan = plan_for(arch, abi, ok);
  stub_layout layout{};
  if (!ok) {
    return layout;
  }

  size_t offset = plan.shadow_size;
  if (plan.gpr_count > 0) {
    offset = align_up(offset, plan.gpr_size);
    layout.gpr_offset = offset;
    layout.gpr_count = plan.gpr_count;
    offset += plan.gpr_count * plan.gpr_size;
  }

  if (plan.fpr_count > 0) {
    offset = align_up(offset, plan.fpr_size);
    layout.fpr_offset = offset;
    layout.fpr_count = plan.fpr_count;
    offset += plan.fpr_count * plan.fpr_size;
  }

  offset = align_up(offset, alignof(hook_arg_handle));
  layout.args_offset = offset;
  offset += sizeof(hook_arg_handle);

  offset = align_up(offset, alignof(hook_info));
  layout.info_offset = offset;
  offset += sizeof(hook_info);

  layout.shadow_size = plan.shadow_size;
  layout.stack_size = align_up(offset, plan.stack_align);
  if (arch.arch_mode == w1::arch::mode::x86_64) {
    // Keep RSP 16-byte aligned before the prehook call (entry RSP is 8 mod 16).
    if ((layout.stack_size % 16) == 0) {
      layout.stack_size += 8;
    }
  }
  return layout;
}

size_t stub_reserve_size(const w1::arch::arch_spec& arch, hook_call_abi abi) {
  (void)arch;
  (void)abi;
  return 512;
}

bool build_stub(const stub_request& request, const stub_layout& layout, std::vector<uint8_t>& out) {
  bool ok = false;
  abi_plan plan = plan_for(request.arch, request.abi, ok);
  if (!ok) {
    return false;
  }

  switch (request.arch.arch_mode) {
    case w1::arch::mode::x86_64:
      return build_x86_64_stub(request, layout, plan, out);
    case w1::arch::mode::x86_32:
      return build_x86_32_stub(request, layout, plan, out);
    case w1::arch::mode::aarch64:
      return build_arm64_stub(request, layout, plan, out);
    default:
      return false;
  }
}

} // namespace w1::h00k::backend::instrument
