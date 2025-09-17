#include "cdecl.hpp"

namespace w1::abi::conventions {

std::optional<x86_cdecl::variadic_info> x86_cdecl::get_variadic_info(
    const extraction_context& ctx, size_t fixed_arg_count
) const {
  variadic_info info{};
  info.fixed_args = fixed_arg_count;
  info.gp_offset = 0;
  info.fp_offset = 0;
  info.overflow_arg_area = (ctx.gpr->esp & 0xFFFFFFFFULL) + 4 + fixed_arg_count * 4;
  info.reg_save_area = 0;
  return info;
}

x86_cdecl::register_info x86_cdecl::get_register_info() const {
  return {
      .callee_saved_gpr = {"ebx", "esi", "edi", "ebp"},
      .caller_saved_gpr = {"eax", "ecx", "edx"},
      .callee_saved_fpr = {},
      .caller_saved_fpr = {},
      .return_register = "eax",
      .argument_registers = {}
  };
}

} // namespace w1::abi::conventions
