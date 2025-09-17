#include "vectorcall.hpp"

#include "abi/fpr_utils.hpp"

#include <cstring>

namespace w1::abi::conventions {

x86_calling_convention::register_sources x86_vectorcall::collect_registers(
    const extraction_context& ctx
) const {
  register_sources regs{};
  regs.integer.push_back(ctx.gpr->ecx & 0xFFFFFFFFULL);
  regs.integer.push_back(ctx.gpr->edx & 0xFFFFFFFFULL);

  for (size_t i = 0; i < 6; ++i) {
    std::array<uint8_t, 16> bytes{};
    get_xmm_bytes(ctx.fpr, i, bytes.data());
    regs.vector.push_back(bytes);
  }

  return regs;
}

double x86_vectorcall::get_float_return(const QBDI::FPRState* fpr) const {
  return get_xmm_double(fpr, 0);
}

x86_vectorcall::typed_arg x86_vectorcall::get_typed_return(
    const QBDI::GPRState* gpr, const QBDI::FPRState* fpr, arg_type type
) const {
  x86_vectorcall::typed_arg ret = x86_calling_convention::get_typed_return(gpr, fpr, type);
  ret.from_stack = false;
  ret.stack_offset = 0;

  switch (type) {
  case arg_type::FLOAT:
    ret.value.f32 = get_xmm_float(fpr, 0);
    break;
  case arg_type::DOUBLE:
    ret.value.f64 = get_xmm_double(fpr, 0);
    break;
  case arg_type::SIMD:
    get_xmm_bytes(fpr, 0, ret.value.simd);
    break;
  default:
    break;
  }

  return ret;
}

std::optional<x86_vectorcall::variadic_info> x86_vectorcall::get_variadic_info(
    const extraction_context&, size_t
) const {
  return std::nullopt;
}

x86_vectorcall::register_info x86_vectorcall::get_register_info() const {
  return {
      .callee_saved_gpr = {"ebx", "esi", "edi", "ebp"},
      .caller_saved_gpr = {"eax", "ecx", "edx"},
      .callee_saved_fpr = {},
      .caller_saved_fpr = {"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"},
      .return_register = "xmm0",
      .argument_registers = {"ecx", "edx", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"}
  };
}

} // namespace w1::abi::conventions
