#include "system_v.hpp"
#include <redlog.hpp>

namespace w1::abi::conventions {

std::vector<uint64_t> x86_64_system_v::extract_integer_args(const extraction_context& ctx, size_t count) const {

  std::vector<uint64_t> args;
  args.reserve(count);

  // extract register arguments
  size_t reg_args = std::min(count, int_arg_regs.size());
  for (size_t i = 0; i < reg_args; i++) {
    args.push_back(reinterpret_cast<const QBDI::rword*>(ctx.gpr)[int_arg_regs[i]]);
  }

  // extract stack arguments if needed
  if (count > int_arg_regs.size()) {
    // stack arguments start after return address
    // each argument takes 8 bytes on stack
    const uint64_t stack_base = ctx.gpr->rsp + 8; // skip return address

    for (size_t i = int_arg_regs.size(); i < count; i++) {
      uint64_t stack_offset = (i - int_arg_regs.size()) * 8;
      args.push_back(ctx.read_stack(stack_base + stack_offset));
    }
  }

  return args;
}

std::vector<x86_64_system_v::typed_arg> x86_64_system_v::extract_typed_args(
    const extraction_context& ctx, const std::vector<arg_type>& types
) const {

  std::vector<typed_arg> args;
  args.reserve(types.size());

  size_t int_reg_idx = 0;
  size_t float_reg_idx = 0;
  size_t stack_offset = 0;

  for (size_t i = 0; i < types.size(); i++) {
    typed_arg arg;
    arg.type = types[i];

    switch (types[i]) {
    case arg_type::INTEGER:
    case arg_type::POINTER:
      if (int_reg_idx < int_arg_regs.size()) {
        // from register
        arg.value.integer = reinterpret_cast<const QBDI::rword*>(ctx.gpr)[int_arg_regs[int_reg_idx]];
        arg.from_stack = false;
        int_reg_idx++;
      } else {
        // from stack
        arg.value.integer = ctx.read_stack(ctx.gpr->rsp + 8 + stack_offset);
        arg.from_stack = true;
        arg.stack_offset = stack_offset;
        stack_offset += 8;
      }
      break;

    case arg_type::FLOAT:
      if (float_reg_idx < max_float_reg_args) {
        // from xmm register
        arg.value.f32 = ctx.fpr->xmm[float_reg_idx].reg32[0];
        arg.from_stack = false;
        float_reg_idx++;
      } else {
        // from stack
        uint32_t val = static_cast<uint32_t>(ctx.read_stack(ctx.gpr->rsp + 8 + stack_offset));
        arg.value.f32 = *reinterpret_cast<float*>(&val);
        arg.from_stack = true;
        arg.stack_offset = stack_offset;
        stack_offset += 8; // still takes 8 bytes on stack
      }
      break;

    case arg_type::DOUBLE:
      if (float_reg_idx < max_float_reg_args) {
        // from xmm register
        arg.value.f64 = ctx.fpr->xmm[float_reg_idx].reg64[0];
        arg.from_stack = false;
        float_reg_idx++;
      } else {
        // from stack
        uint64_t val = ctx.read_stack(ctx.gpr->rsp + 8 + stack_offset);
        arg.value.f64 = *reinterpret_cast<double*>(&val);
        arg.from_stack = true;
        arg.stack_offset = stack_offset;
        stack_offset += 8;
      }
      break;

    case arg_type::SIMD:
      if (float_reg_idx < max_float_reg_args) {
        // full xmm register
        memcpy(arg.value.simd, &ctx.fpr->xmm[float_reg_idx], 16);
        arg.from_stack = false;
        float_reg_idx++;
      } else {
        // from stack (16 bytes)
        for (int j = 0; j < 16; j++) {
          arg.value.simd[j] = static_cast<uint8_t>(ctx.read_stack(ctx.gpr->rsp + 8 + stack_offset + j) & 0xFF);
        }
        arg.from_stack = true;
        arg.stack_offset = stack_offset;
        stack_offset += 16;
      }
      break;

    case arg_type::STRUCT_BY_VALUE:
      // small structs may be passed in registers
      // larger structs are passed on stack
      // this is simplified - real implementation would need size info
      arg.value.struct_data.data[0] = ctx.read_stack(ctx.gpr->rsp + 8 + stack_offset);
      arg.value.struct_data.size = 8;
      arg.from_stack = true;
      arg.stack_offset = stack_offset;
      stack_offset += 8;
      break;

    case arg_type::STRUCT_BY_REF:
      // passed as pointer
      if (int_reg_idx < int_arg_regs.size()) {
        arg.value.integer = reinterpret_cast<const QBDI::rword*>(ctx.gpr)[int_arg_regs[int_reg_idx]];
        arg.from_stack = false;
        int_reg_idx++;
      } else {
        arg.value.integer = ctx.read_stack(ctx.gpr->rsp + 8 + stack_offset);
        arg.from_stack = true;
        arg.stack_offset = stack_offset;
        stack_offset += 8;
      }
      break;
    }

    args.push_back(arg);
  }

  return args;
}

x86_64_system_v::typed_arg x86_64_system_v::get_typed_return(
    const QBDI::GPRState* gpr, const QBDI::FPRState* fpr, arg_type type
) const {

  typed_arg ret;
  ret.type = type;
  ret.from_stack = false;

  switch (type) {
  case arg_type::INTEGER:
  case arg_type::POINTER:
  case arg_type::STRUCT_BY_REF:
    ret.value.integer = gpr->rax;
    break;

  case arg_type::FLOAT:
    ret.value.f32 = fpr->xmm[0].reg32[0];
    break;

  case arg_type::DOUBLE:
    ret.value.f64 = fpr->xmm[0].reg64[0];
    break;

  case arg_type::SIMD:
    memcpy(ret.value.simd, &fpr->xmm[0], 16);
    break;

  case arg_type::STRUCT_BY_VALUE:
    // small structs returned in rax/rdx
    ret.value.struct_data.data[0] = gpr->rax;
    ret.value.struct_data.data[1] = gpr->rdx;
    ret.value.struct_data.size = 16;
    break;
  }

  return ret;
}

std::optional<x86_64_system_v::variadic_info> x86_64_system_v::get_variadic_info(
    const extraction_context& ctx, size_t fixed_arg_count
) const {

  // system v uses a complex va_list structure
  // this is a simplified implementation
  variadic_info info;
  info.fixed_args = fixed_arg_count;
  info.gp_offset = fixed_arg_count * 8; // simplified
  info.fp_offset = 0;
  info.overflow_arg_area = ctx.gpr->rsp + 8; // after return address
  info.reg_save_area = 0;                    // would need to be set up by caller

  return info;
}

x86_64_system_v::register_info x86_64_system_v::get_register_info() const {
  return {
      .callee_saved_gpr = {"rbx", "rsp", "rbp", "r12", "r13", "r14", "r15"},
      .caller_saved_gpr = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"},
      .callee_saved_fpr = {}, // none
      .caller_saved_fpr =
          {"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12",
           "xmm13", "xmm14", "xmm15"},
      .return_register = "rax",
      .argument_registers = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"}
  };
}

std::vector<double> x86_64_system_v::extract_float_args(const extraction_context& ctx, size_t count) const {

  std::vector<double> args;
  args.reserve(count);

  // first 8 float/double args in xmm0-xmm7
  size_t reg_args = std::min(count, max_float_reg_args);
  for (size_t i = 0; i < reg_args; i++) {
    args.push_back(ctx.fpr->xmm[i].reg64[0]);
  }

  // remaining args on stack
  if (count > max_float_reg_args) {
    const uint64_t stack_base = ctx.gpr->rsp + 8; // skip return address

    for (size_t i = max_float_reg_args; i < count; i++) {
      uint64_t stack_offset = (i - max_float_reg_args) * 8;
      uint64_t val = ctx.read_stack(stack_base + stack_offset);
      args.push_back(*reinterpret_cast<double*>(&val));
    }
  }

  return args;
}

} // namespace w1::abi::conventions