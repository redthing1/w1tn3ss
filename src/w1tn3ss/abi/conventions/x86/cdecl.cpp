#include "cdecl.hpp"

namespace w1::abi::conventions {

std::vector<uint64_t> x86_cdecl::extract_integer_args(const extraction_context& ctx, size_t count) const {

  std::vector<uint64_t> args;
  args.reserve(count);

  // all arguments on stack, right after return address
  uint32_t esp = static_cast<uint32_t>(ctx.gpr->esp);

  // skip return address (4 bytes)
  for (size_t i = 0; i < count; ++i) {
    uint64_t addr = (esp + 4 + i * 4) & 0xFFFFFFFF;
    uint64_t val = ctx.read_stack(addr);
    args.push_back(val & 0xFFFFFFFF); // 32-bit values
  }

  return args;
}

std::vector<x86_cdecl::typed_arg> x86_cdecl::extract_typed_args(
    const extraction_context& ctx, const std::vector<arg_type>& types
) const {

  std::vector<typed_arg> args;
  args.reserve(types.size());

  uint32_t esp = static_cast<uint32_t>(ctx.gpr->esp);
  size_t stack_offset = 4; // skip return address

  for (const auto& type : types) {
    typed_arg arg;
    arg.type = type;
    arg.from_stack = true;
    arg.stack_offset = stack_offset - 4; // relative to return address

    uint64_t addr = (esp + stack_offset) & 0xFFFFFFFF;

    switch (type) {
    case arg_type::INTEGER:
    case arg_type::POINTER:
      arg.value.integer = ctx.read_stack(addr) & 0xFFFFFFFF;
      stack_offset += 4;
      break;

    case arg_type::FLOAT: {
      uint32_t val = static_cast<uint32_t>(ctx.read_stack(addr));
      arg.value.f32 = *reinterpret_cast<float*>(&val);
      stack_offset += 4;
    } break;

    case arg_type::DOUBLE: {
      // double takes 8 bytes on stack
      uint64_t val = ctx.read_stack(addr);
      uint64_t high = ctx.read_stack((addr + 4) & 0xFFFFFFFF);
      val = (val & 0xFFFFFFFF) | ((high & 0xFFFFFFFF) << 32);
      arg.value.f64 = *reinterpret_cast<double*>(&val);
      stack_offset += 8;
    } break;

    case arg_type::STRUCT_BY_VALUE:
      // simplified - would need size info
      arg.value.struct_data.data[0] = ctx.read_stack(addr) & 0xFFFFFFFF;
      arg.value.struct_data.size = 4;
      stack_offset += 4;
      break;

    case arg_type::STRUCT_BY_REF:
      arg.value.integer = ctx.read_stack(addr) & 0xFFFFFFFF;
      stack_offset += 4;
      break;

    case arg_type::SIMD:
      // not typically used in cdecl
      stack_offset += 16;
      break;
    }

    args.push_back(arg);
  }

  return args;
}

x86_cdecl::typed_arg x86_cdecl::get_typed_return(
    const QBDI::GPRState* gpr, const QBDI::FPRState* fpr, arg_type type
) const {

  typed_arg ret;
  ret.type = type;
  ret.from_stack = false;

  switch (type) {
  case arg_type::INTEGER:
  case arg_type::POINTER:
  case arg_type::STRUCT_BY_REF:
    ret.value.integer = gpr->eax & 0xFFFFFFFF; // eax
    break;

  case arg_type::FLOAT:
  case arg_type::DOUBLE:
    // x87 st(0) - simplified
    ret.value.f64 = 0.0;
    break;

  case arg_type::STRUCT_BY_VALUE:
    // small structs in eax:edx
    ret.value.struct_data.data[0] = gpr->eax & 0xFFFFFFFF;
    ret.value.struct_data.data[1] = gpr->edx & 0xFFFFFFFF;
    ret.value.struct_data.size = 8;
    break;

  case arg_type::SIMD:
    // not typically used
    break;
  }

  return ret;
}

std::optional<x86_cdecl::variadic_info> x86_cdecl::get_variadic_info(
    const extraction_context& ctx, size_t fixed_arg_count
) const {

  // simple stack-based varargs
  variadic_info info;
  info.fixed_args = fixed_arg_count;
  info.gp_offset = 0;
  info.fp_offset = 0;
  info.overflow_arg_area = (ctx.gpr->esp & 0xFFFFFFFF) + 4 + fixed_arg_count * 4;
  info.reg_save_area = 0;

  return info;
}

x86_cdecl::register_info x86_cdecl::get_register_info() const {
  return {
      .callee_saved_gpr = {"ebx", "esi", "edi", "ebp"},
      .caller_saved_gpr = {"eax", "ecx", "edx"},
      .callee_saved_fpr = {}, // x87 stack based
      .caller_saved_fpr = {},
      .return_register = "eax",
      .argument_registers = {} // all on stack
  };
}

std::vector<double> x86_cdecl::extract_float_args(const extraction_context& ctx, size_t count) const {

  std::vector<double> args;
  args.reserve(count);

  uint32_t esp = static_cast<uint32_t>(ctx.gpr->esp);
  size_t stack_offset = 4; // skip return address

  for (size_t i = 0; i < count; ++i) {
    uint64_t addr = (esp + stack_offset) & 0xFFFFFFFF;

    // doubles take 8 bytes
    uint64_t val = ctx.read_stack(addr);
    uint64_t high = ctx.read_stack((addr + 4) & 0xFFFFFFFF);
    val = (val & 0xFFFFFFFF) | ((high & 0xFFFFFFFF) << 32);
    args.push_back(*reinterpret_cast<double*>(&val));

    stack_offset += 8;
  }

  return args;
}

} // namespace w1::abi::conventions