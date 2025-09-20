#include "stdcall.hpp"

namespace w1::abi::conventions {

std::optional<x86_stdcall::variadic_info> x86_stdcall::get_variadic_info(const extraction_context&, size_t) const {
  return std::nullopt;
}

x86_stdcall::register_info x86_stdcall::get_register_info() const {
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
