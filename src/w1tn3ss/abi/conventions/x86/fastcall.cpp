#include "fastcall.hpp"

namespace w1::abi::conventions {

x86_calling_convention::register_sources x86_fastcall::collect_registers(const extraction_context& ctx) const {
  register_sources regs{};
  regs.integer.push_back(ctx.gpr->ecx & 0xFFFFFFFFULL);
  regs.integer.push_back(ctx.gpr->edx & 0xFFFFFFFFULL);
  return regs;
}

std::optional<x86_fastcall::variadic_info> x86_fastcall::get_variadic_info(const extraction_context&, size_t) const {
  return std::nullopt;
}

x86_fastcall::register_info x86_fastcall::get_register_info() const {
  return {
      .callee_saved_gpr = {"ebx", "esi", "edi", "ebp"},
      .caller_saved_gpr = {"eax", "ecx", "edx"},
      .callee_saved_fpr = {},
      .caller_saved_fpr = {},
      .return_register = "eax",
      .argument_registers = {"ecx", "edx"}
  };
}

} // namespace w1::abi::conventions
