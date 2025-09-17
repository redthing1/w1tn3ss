#include "thiscall.hpp"

namespace w1::abi::conventions {

x86_calling_convention::register_sources x86_thiscall::collect_registers(
    const extraction_context& ctx
) const {
  register_sources regs{};
  regs.integer.push_back(ctx.gpr->ecx & 0xFFFFFFFFULL);
  return regs;
}

std::optional<x86_thiscall::variadic_info> x86_thiscall::get_variadic_info(
    const extraction_context&, size_t
) const {
  return std::nullopt;
}

x86_thiscall::register_info x86_thiscall::get_register_info() const {
  return {
      .callee_saved_gpr = {"ebx", "esi", "edi", "ebp"},
      .caller_saved_gpr = {"eax", "ecx", "edx"},
      .callee_saved_fpr = {},
      .caller_saved_fpr = {},
      .return_register = "eax",
      .argument_registers = {"ecx"}
  };
}

} // namespace w1::abi::conventions
