#include "microsoft.hpp"
#include <redlog.hpp>
#include <w1tn3ss/abi/fpr_utils.hpp>

namespace w1::abi::conventions {

std::vector<uint64_t> x86_64_microsoft::extract_integer_args(const extraction_context& ctx, size_t count) const {

  std::vector<uint64_t> args;
  args.reserve(count);

  // extract register arguments (rcx, rdx, r8, r9)
  size_t reg_args = std::min(count, max_reg_args);
  for (size_t i = 0; i < reg_args; i++) {
    switch (i) {
    case 0:
      args.push_back(ctx.gpr->rcx);
      break;
    case 1:
      args.push_back(ctx.gpr->rdx);
      break;
    case 2:
      args.push_back(ctx.gpr->r8);
      break;
    case 3:
      args.push_back(ctx.gpr->r9);
      break;
    }
  }

  // extract stack arguments if needed
  if (count > max_reg_args) {
    // stack arguments start after shadow space (32 bytes) and return address (8 bytes)
    // so first stack arg is at rsp + 40
    const uint64_t stack_base = ctx.gpr->rsp + 40;

    for (size_t i = max_reg_args; i < count; i++) {
      // each argument takes 8 bytes on stack
      uint64_t stack_offset = (i - max_reg_args) * 8;
      args.push_back(ctx.read_stack(stack_base + stack_offset));
    }
  }

  return args;
}

std::vector<x86_64_microsoft::typed_arg> x86_64_microsoft::extract_typed_args(
    const extraction_context& ctx, const std::vector<arg_type>& types
) const {

  std::vector<typed_arg> args;
  args.reserve(types.size());

  size_t reg_idx = 0;
  size_t stack_offset = 0;

  for (size_t i = 0; i < types.size(); i++) {
    typed_arg arg;
    arg.type = types[i];

    if (reg_idx < max_reg_args) {
      // from register
      switch (types[i]) {
      case arg_type::INTEGER:
      case arg_type::POINTER:
      case arg_type::STRUCT_BY_REF:
        switch (reg_idx) {
        case 0:
          arg.value.integer = ctx.gpr->rcx;
          break;
        case 1:
          arg.value.integer = ctx.gpr->rdx;
          break;
        case 2:
          arg.value.integer = ctx.gpr->r8;
          break;
        case 3:
          arg.value.integer = ctx.gpr->r9;
          break;
        }
        arg.from_stack = false;
        break;

      case arg_type::FLOAT:
        // float passed in xmm register at same position
        arg.value.f32 = get_xmm_float(ctx.fpr, reg_idx);
        arg.from_stack = false;
        break;

      case arg_type::DOUBLE:
        // double passed in xmm register at same position
        arg.value.f64 = get_xmm_double(ctx.fpr, reg_idx);
        arg.from_stack = false;
        break;

      case arg_type::SIMD:
        // __m128 passed by reference in integer register
        switch (reg_idx) {
        case 0:
          arg.value.integer = ctx.gpr->rcx;
          break;
        case 1:
          arg.value.integer = ctx.gpr->rdx;
          break;
        case 2:
          arg.value.integer = ctx.gpr->r8;
          break;
        case 3:
          arg.value.integer = ctx.gpr->r9;
          break;
        }
        arg.from_stack = false;
        break;

      case arg_type::STRUCT_BY_VALUE:
        // structures > 8 bytes passed by reference
        switch (reg_idx) {
        case 0:
          arg.value.integer = ctx.gpr->rcx;
          break;
        case 1:
          arg.value.integer = ctx.gpr->rdx;
          break;
        case 2:
          arg.value.integer = ctx.gpr->r8;
          break;
        case 3:
          arg.value.integer = ctx.gpr->r9;
          break;
        }
        arg.from_stack = false;
        break;
      }
      reg_idx++;
    } else {
      // from stack (after shadow space)
      const uint64_t stack_base = ctx.gpr->rsp + 40; // 32 (shadow) + 8 (return addr)

      switch (types[i]) {
      case arg_type::INTEGER:
      case arg_type::POINTER:
      case arg_type::STRUCT_BY_REF:
      case arg_type::SIMD:            // passed by reference
      case arg_type::STRUCT_BY_VALUE: // passed by reference
        arg.value.integer = ctx.read_stack(stack_base + stack_offset);
        break;

      case arg_type::FLOAT: {
        uint32_t val = static_cast<uint32_t>(ctx.read_stack(stack_base + stack_offset));
        arg.value.f32 = *reinterpret_cast<float*>(&val);
      } break;

      case arg_type::DOUBLE: {
        uint64_t val = ctx.read_stack(stack_base + stack_offset);
        arg.value.f64 = *reinterpret_cast<double*>(&val);
      } break;
      }

      arg.from_stack = true;
      arg.stack_offset = stack_offset;
      stack_offset += 8; // all args take 8 bytes on stack
    }

    args.push_back(arg);
  }

  return args;
}

x86_64_microsoft::typed_arg x86_64_microsoft::get_typed_return(
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
    ret.value.f32 = get_xmm_float(fpr, 0);
    break;

  case arg_type::DOUBLE:
    ret.value.f64 = get_xmm_double(fpr, 0);
    break;

  case arg_type::SIMD:
    get_xmm_bytes(fpr, 0, ret.value.simd);
    break;

  case arg_type::STRUCT_BY_VALUE:
    // structures returned by hidden first parameter
    // rax contains address of returned structure
    ret.value.integer = gpr->rax;
    break;
  }

  return ret;
}

std::optional<x86_64_microsoft::variadic_info> x86_64_microsoft::get_variadic_info(
    const extraction_context& ctx, size_t fixed_arg_count
) const {

  // windows x64 varargs work differently than system v
  // all parameters are passed as if they were integers
  variadic_info info;
  info.fixed_args = fixed_arg_count;
  info.gp_offset = 0;
  info.fp_offset = 0;
  info.overflow_arg_area = ctx.gpr->rsp + 40; // after shadow space
  info.reg_save_area = ctx.gpr->rsp + 8;      // shadow space area

  return info;
}

x86_64_microsoft::register_info x86_64_microsoft::get_register_info() const {
  return {
      .callee_saved_gpr = {"rbx", "rbp", "rdi", "rsi", "rsp", "r12", "r13", "r14", "r15"},
      .caller_saved_gpr = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"},
      .callee_saved_fpr = {"xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"},
      .caller_saved_fpr = {"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"},
      .return_register = "rax",
      .argument_registers = {"rcx", "rdx", "r8", "r9"}
  };
}

std::vector<double> x86_64_microsoft::extract_float_args(const extraction_context& ctx, size_t count) const {

  std::vector<double> args;
  args.reserve(count);

  // first 4 float/double args in xmm0-xmm3
  size_t reg_args = std::min(count, max_reg_args);
  for (size_t i = 0; i < reg_args; i++) {
    args.push_back(get_xmm_double(ctx.fpr, i));
  }

  // remaining args on stack
  if (count > max_reg_args) {
    const uint64_t stack_base = ctx.gpr->rsp + 40; // after shadow space

    for (size_t i = max_reg_args; i < count; i++) {
      uint64_t stack_offset = (i - max_reg_args) * 8;
      uint64_t val = ctx.read_stack(stack_base + stack_offset);
      args.push_back(*reinterpret_cast<double*>(&val));
    }
  }

  return args;
}

void x86_64_microsoft::set_integer_args(
    QBDI::GPRState* gpr, const std::vector<uint64_t>& args,
    std::function<void(uint64_t addr, uint64_t value)> stack_writer
) const {
  // set arguments in rcx, rdx, r8, r9 registers
  if (args.size() > 0) {
    gpr->rcx = args[0];
  }
  if (args.size() > 1) {
    gpr->rdx = args[1];
  }
  if (args.size() > 2) {
    gpr->r8 = args[2];
  }
  if (args.size() > 3) {
    gpr->r9 = args[3];
  }

  // remaining arguments go on stack after shadow space
  if (args.size() > max_reg_args && stack_writer) {
    // stack args start after shadow space (32 bytes) and return address (8 bytes)
    uint64_t sp = gpr->rsp;
    for (size_t i = max_reg_args; i < args.size(); i++) {
      uint64_t stack_offset = 40 + (i - max_reg_args) * 8;
      stack_writer(sp + stack_offset, args[i]);
    }
  }
}

void x86_64_microsoft::set_typed_args(
    QBDI::GPRState* gpr, QBDI::FPRState* fpr, const std::vector<typed_arg>& args,
    std::function<void(uint64_t addr, uint64_t value)> stack_writer
) const {
  size_t reg_idx = 0;
  size_t stack_offset = 40; // after shadow space (32) + return addr (8)

  for (const auto& arg : args) {
    if (reg_idx < max_reg_args) {
      // arguments go in registers based on position, not type
      switch (arg.type) {
      case arg_type::INTEGER:
      case arg_type::POINTER:
      case arg_type::STRUCT_BY_REF:
      case arg_type::SIMD:            // passed by reference
      case arg_type::STRUCT_BY_VALUE: // passed by reference if > 8 bytes
        // set in integer register
        switch (reg_idx) {
        case 0:
          gpr->rcx = arg.value.integer;
          break;
        case 1:
          gpr->rdx = arg.value.integer;
          break;
        case 2:
          gpr->r8 = arg.value.integer;
          break;
        case 3:
          gpr->r9 = arg.value.integer;
          break;
        }
        break;

      case arg_type::FLOAT:
        // set in xmm register at same position
        set_xmm_float(fpr, reg_idx, arg.value.f32);
        // also set integer register for varargs compatibility
        switch (reg_idx) {
        case 0:
          memcpy(&gpr->rcx, &arg.value.f32, sizeof(float));
          break;
        case 1:
          memcpy(&gpr->rdx, &arg.value.f32, sizeof(float));
          break;
        case 2:
          memcpy(&gpr->r8, &arg.value.f32, sizeof(float));
          break;
        case 3:
          memcpy(&gpr->r9, &arg.value.f32, sizeof(float));
          break;
        }
        break;

      case arg_type::DOUBLE:
        // set in xmm register at same position
        set_xmm_double(fpr, reg_idx, arg.value.f64);
        // also set integer register for varargs compatibility
        switch (reg_idx) {
        case 0:
          memcpy(&gpr->rcx, &arg.value.f64, sizeof(double));
          break;
        case 1:
          memcpy(&gpr->rdx, &arg.value.f64, sizeof(double));
          break;
        case 2:
          memcpy(&gpr->r8, &arg.value.f64, sizeof(double));
          break;
        case 3:
          memcpy(&gpr->r9, &arg.value.f64, sizeof(double));
          break;
        }
        break;
      }
      reg_idx++;
    } else if (stack_writer) {
      // set on stack
      switch (arg.type) {
      case arg_type::INTEGER:
      case arg_type::POINTER:
      case arg_type::STRUCT_BY_REF:
      case arg_type::SIMD:
      case arg_type::STRUCT_BY_VALUE:
        stack_writer(gpr->rsp + stack_offset, arg.value.integer);
        break;

      case arg_type::FLOAT: {
        uint64_t val = 0;
        memcpy(&val, &arg.value.f32, sizeof(float));
        stack_writer(gpr->rsp + stack_offset, val);
        break;
      }

      case arg_type::DOUBLE: {
        uint64_t val;
        memcpy(&val, &arg.value.f64, sizeof(double));
        stack_writer(gpr->rsp + stack_offset, val);
        break;
      }
      }
      stack_offset += 8;
    }
  }
}

} // namespace w1::abi::conventions