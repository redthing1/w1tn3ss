#include "aarch64_aapcs.hpp"
#include <redlog.hpp>

namespace w1::abi::conventions {

std::vector<uint64_t> aarch64_aapcs::extract_integer_args(const extraction_context& ctx, size_t count) const {

  std::vector<uint64_t> args;
  args.reserve(count);

  // extract register arguments (x0-x7)
  size_t reg_args = std::min(count, size_t(8));
  for (size_t i = 0; i < reg_args; i++) {
    switch (i) {
    case 0:
      args.push_back(ctx.gpr->x0);
      break;
    case 1:
      args.push_back(ctx.gpr->x1);
      break;
    case 2:
      args.push_back(ctx.gpr->x2);
      break;
    case 3:
      args.push_back(ctx.gpr->x3);
      break;
    case 4:
      args.push_back(ctx.gpr->x4);
      break;
    case 5:
      args.push_back(ctx.gpr->x5);
      break;
    case 6:
      args.push_back(ctx.gpr->x6);
      break;
    case 7:
      args.push_back(ctx.gpr->x7);
      break;
    }
  }

  // extract stack arguments if needed
  if (count > 8) {
    // stack arguments start immediately at sp (no return address on stack)
    const uint64_t stack_base = ctx.gpr->sp;

    for (size_t i = 8; i < count; i++) {
      // each argument takes 8 bytes on stack
      uint64_t stack_offset = (i - 8) * 8;
      args.push_back(ctx.read_stack(stack_base + stack_offset));
    }
  }

  return args;
}

std::vector<aarch64_aapcs::typed_arg> aarch64_aapcs::extract_typed_args(
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
      if (int_reg_idx < 8) {
        // from register
        switch (int_reg_idx) {
        case 0:
          arg.value.integer = ctx.gpr->x0;
          break;
        case 1:
          arg.value.integer = ctx.gpr->x1;
          break;
        case 2:
          arg.value.integer = ctx.gpr->x2;
          break;
        case 3:
          arg.value.integer = ctx.gpr->x3;
          break;
        case 4:
          arg.value.integer = ctx.gpr->x4;
          break;
        case 5:
          arg.value.integer = ctx.gpr->x5;
          break;
        case 6:
          arg.value.integer = ctx.gpr->x6;
          break;
        case 7:
          arg.value.integer = ctx.gpr->x7;
          break;
        }
        arg.from_stack = false;
        int_reg_idx++;
      } else {
        // from stack
        arg.value.integer = ctx.read_stack(ctx.gpr->sp + stack_offset);
        arg.from_stack = true;
        arg.stack_offset = stack_offset;
        stack_offset += 8;
      }
      break;

    case arg_type::FLOAT:
      if (float_reg_idx < max_float_reg_args) {
        // from v register (s0-s7)
        // QBDI stores v registers as __uint128_t, we need to extract float
        const __uint128_t* v_regs = reinterpret_cast<const __uint128_t*>(ctx.fpr);
        uint32_t f32_val = static_cast<uint32_t>(v_regs[float_reg_idx]);
        arg.value.f32 = *reinterpret_cast<float*>(&f32_val);
        arg.from_stack = false;
        float_reg_idx++;
      } else {
        // from stack
        uint32_t val = static_cast<uint32_t>(ctx.read_stack(ctx.gpr->sp + stack_offset));
        arg.value.f32 = *reinterpret_cast<float*>(&val);
        arg.from_stack = true;
        arg.stack_offset = stack_offset;
        stack_offset += 8; // still takes 8 bytes on stack
      }
      break;

    case arg_type::DOUBLE:
      if (float_reg_idx < max_float_reg_args) {
        // from v register (d0-d7)
        // QBDI stores v registers as __uint128_t, we need to extract double
        const __uint128_t* v_regs = reinterpret_cast<const __uint128_t*>(ctx.fpr);
        uint64_t f64_val = static_cast<uint64_t>(v_regs[float_reg_idx]);
        arg.value.f64 = *reinterpret_cast<double*>(&f64_val);
        arg.from_stack = false;
        float_reg_idx++;
      } else {
        // from stack
        uint64_t val = ctx.read_stack(ctx.gpr->sp + stack_offset);
        arg.value.f64 = *reinterpret_cast<double*>(&val);
        arg.from_stack = true;
        arg.stack_offset = stack_offset;
        stack_offset += 8;
      }
      break;

    case arg_type::SIMD:
      if (float_reg_idx < max_float_reg_args) {
        // full v register (128-bit)
        const __uint128_t* v_regs = reinterpret_cast<const __uint128_t*>(ctx.fpr);
        memcpy(arg.value.simd, &v_regs[float_reg_idx], 16);
        arg.from_stack = false;
        float_reg_idx++;
      } else {
        // from stack (16 bytes)
        for (int j = 0; j < 16; j++) {
          arg.value.simd[j] = static_cast<uint8_t>(ctx.read_stack(ctx.gpr->sp + stack_offset + j) & 0xFF);
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
      if (int_reg_idx < 8) {
        switch (int_reg_idx) {
        case 0:
          arg.value.struct_data.data[0] = ctx.gpr->x0;
          break;
        case 1:
          arg.value.struct_data.data[0] = ctx.gpr->x1;
          break;
        case 2:
          arg.value.struct_data.data[0] = ctx.gpr->x2;
          break;
        case 3:
          arg.value.struct_data.data[0] = ctx.gpr->x3;
          break;
        case 4:
          arg.value.struct_data.data[0] = ctx.gpr->x4;
          break;
        case 5:
          arg.value.struct_data.data[0] = ctx.gpr->x5;
          break;
        case 6:
          arg.value.struct_data.data[0] = ctx.gpr->x6;
          break;
        case 7:
          arg.value.struct_data.data[0] = ctx.gpr->x7;
          break;
        }
        arg.value.struct_data.size = 8;
        arg.from_stack = false;
        int_reg_idx++;
      } else {
        arg.value.struct_data.data[0] = ctx.read_stack(ctx.gpr->sp + stack_offset);
        arg.value.struct_data.size = 8;
        arg.from_stack = true;
        arg.stack_offset = stack_offset;
        stack_offset += 8;
      }
      break;

    case arg_type::STRUCT_BY_REF:
      // passed as pointer
      if (int_reg_idx < 8) {
        switch (int_reg_idx) {
        case 0:
          arg.value.integer = ctx.gpr->x0;
          break;
        case 1:
          arg.value.integer = ctx.gpr->x1;
          break;
        case 2:
          arg.value.integer = ctx.gpr->x2;
          break;
        case 3:
          arg.value.integer = ctx.gpr->x3;
          break;
        case 4:
          arg.value.integer = ctx.gpr->x4;
          break;
        case 5:
          arg.value.integer = ctx.gpr->x5;
          break;
        case 6:
          arg.value.integer = ctx.gpr->x6;
          break;
        case 7:
          arg.value.integer = ctx.gpr->x7;
          break;
        }
        arg.from_stack = false;
        int_reg_idx++;
      } else {
        arg.value.integer = ctx.read_stack(ctx.gpr->sp + stack_offset);
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

aarch64_aapcs::typed_arg aarch64_aapcs::get_typed_return(
    const QBDI::GPRState* gpr, const QBDI::FPRState* fpr, arg_type type
) const {

  typed_arg ret;
  ret.type = type;
  ret.from_stack = false;

  switch (type) {
  case arg_type::INTEGER:
  case arg_type::POINTER:
  case arg_type::STRUCT_BY_REF:
    ret.value.integer = gpr->x0;
    break;

  case arg_type::FLOAT: {
    uint32_t f32_val = static_cast<uint32_t>(fpr->v0);
    ret.value.f32 = *reinterpret_cast<float*>(&f32_val);
  } break;

  case arg_type::DOUBLE: {
    uint64_t f64_val = static_cast<uint64_t>(fpr->v0);
    ret.value.f64 = *reinterpret_cast<double*>(&f64_val);
  } break;

  case arg_type::SIMD:
    memcpy(ret.value.simd, &fpr->v0, 16);
    break;

  case arg_type::STRUCT_BY_VALUE:
    // small structs returned in x0/x1
    ret.value.struct_data.data[0] = gpr->x0;
    ret.value.struct_data.data[1] = gpr->x1;
    ret.value.struct_data.size = 16;
    break;
  }

  return ret;
}

std::optional<aarch64_aapcs::variadic_info> aarch64_aapcs::get_variadic_info(
    const extraction_context& ctx, size_t fixed_arg_count
) const {

  // aarch64 uses a va_list structure similar to x86-64 system v
  variadic_info info;
  info.fixed_args = fixed_arg_count;
  info.gp_offset = fixed_arg_count * 8; // simplified
  info.fp_offset = 0;
  info.overflow_arg_area = ctx.gpr->sp; // stack args
  info.reg_save_area = 0;               // would need to be set up by caller

  return info;
}

aarch64_aapcs::register_info aarch64_aapcs::get_register_info() const {
  return {
      .callee_saved_gpr = {"x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "sp"},
      .caller_saved_gpr = {"x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",  "x8",  "x9",
                           "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x30"},
      .callee_saved_fpr = {"v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15"},
      .caller_saved_fpr = {"v0",  "v1",  "v2",  "v3",  "v4",  "v5",  "v6",  "v7",  "v16", "v17", "v18", "v19",
                           "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"},
      .return_register = "x0",
      .argument_registers = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"}
  };
}

std::vector<double> aarch64_aapcs::extract_float_args(const extraction_context& ctx, size_t count) const {

  std::vector<double> args;
  args.reserve(count);

  // first 8 float/double args in v0-v7
  size_t reg_args = std::min(count, max_float_reg_args);
  const __uint128_t* v_regs = reinterpret_cast<const __uint128_t*>(ctx.fpr);
  for (size_t i = 0; i < reg_args; i++) {
    uint64_t f64_val = static_cast<uint64_t>(v_regs[i]);
    args.push_back(*reinterpret_cast<double*>(&f64_val));
  }

  // remaining args on stack
  if (count > max_float_reg_args) {
    const uint64_t stack_base = ctx.gpr->sp;

    for (size_t i = max_float_reg_args; i < count; i++) {
      uint64_t stack_offset = (i - max_float_reg_args) * 8;
      uint64_t val = ctx.read_stack(stack_base + stack_offset);
      args.push_back(*reinterpret_cast<double*>(&val));
    }
  }

  return args;
}

void aarch64_aapcs::set_integer_args(
    QBDI::GPRState* gpr, const std::vector<uint64_t>& args,
    std::function<void(uint64_t addr, uint64_t value)> stack_writer
) const {
  // set arguments in x0-x7 registers
  if (args.size() > 0) {
    gpr->x0 = args[0];
  }
  if (args.size() > 1) {
    gpr->x1 = args[1];
  }
  if (args.size() > 2) {
    gpr->x2 = args[2];
  }
  if (args.size() > 3) {
    gpr->x3 = args[3];
  }
  if (args.size() > 4) {
    gpr->x4 = args[4];
  }
  if (args.size() > 5) {
    gpr->x5 = args[5];
  }
  if (args.size() > 6) {
    gpr->x6 = args[6];
  }
  if (args.size() > 7) {
    gpr->x7 = args[7];
  }

  // remaining arguments go on stack
  if (args.size() > max_int_reg_args && stack_writer) {
    uint64_t sp = gpr->sp;
    for (size_t i = max_int_reg_args; i < args.size(); i++) {
      uint64_t stack_offset = (i - max_int_reg_args) * 8;
      stack_writer(sp + stack_offset, args[i]);
    }
  }
}

void aarch64_aapcs::set_typed_args(
    QBDI::GPRState* gpr, QBDI::FPRState* fpr, const std::vector<typed_arg>& args,
    std::function<void(uint64_t addr, uint64_t value)> stack_writer
) const {
  size_t int_reg_idx = 0;
  size_t float_reg_idx = 0;
  size_t stack_offset = 0;

  for (const auto& arg : args) {
    switch (arg.type) {
    case arg_type::INTEGER:
    case arg_type::POINTER:
      if (int_reg_idx < max_int_reg_args) {
        // set in register
        switch (int_reg_idx) {
        case 0:
          gpr->x0 = arg.value.integer;
          break;
        case 1:
          gpr->x1 = arg.value.integer;
          break;
        case 2:
          gpr->x2 = arg.value.integer;
          break;
        case 3:
          gpr->x3 = arg.value.integer;
          break;
        case 4:
          gpr->x4 = arg.value.integer;
          break;
        case 5:
          gpr->x5 = arg.value.integer;
          break;
        case 6:
          gpr->x6 = arg.value.integer;
          break;
        case 7:
          gpr->x7 = arg.value.integer;
          break;
        }
        int_reg_idx++;
      } else if (stack_writer) {
        // set on stack
        stack_writer(gpr->sp + stack_offset, arg.value.integer);
        stack_offset += 8;
      }
      break;

    case arg_type::FLOAT:
    case arg_type::DOUBLE:
      if (float_reg_idx < max_float_reg_args) {
        // set in v register (lower 64 bits for double)
        __uint128_t* v_regs = reinterpret_cast<__uint128_t*>(fpr);
        uint64_t f64_val;
        if (arg.type == arg_type::FLOAT) {
          float f32 = arg.value.f32;
          memcpy(&f64_val, &f32, sizeof(float));
        } else {
          double f64 = arg.value.f64;
          memcpy(&f64_val, &f64, sizeof(double));
        }
        v_regs[float_reg_idx] = f64_val;
        float_reg_idx++;
      } else if (stack_writer) {
        // set on stack
        uint64_t val;
        if (arg.type == arg_type::FLOAT) {
          float f32 = arg.value.f32;
          memcpy(&val, &f32, sizeof(float));
        } else {
          double f64 = arg.value.f64;
          memcpy(&val, &f64, sizeof(double));
        }
        stack_writer(gpr->sp + stack_offset, val);
        stack_offset += 8;
      }
      break;

    case arg_type::SIMD:
      if (float_reg_idx < max_float_reg_args) {
        // set full v register (128-bit)
        __uint128_t* v_regs = reinterpret_cast<__uint128_t*>(fpr);
        memcpy(&v_regs[float_reg_idx], arg.value.simd, 16);
        float_reg_idx++;
      } else if (stack_writer) {
        // set on stack (16 bytes)
        // would need to write 2 64-bit values
        uint64_t* simd_data = reinterpret_cast<uint64_t*>(const_cast<uint8_t*>(arg.value.simd));
        stack_writer(gpr->sp + stack_offset, simd_data[0]);
        stack_writer(gpr->sp + stack_offset + 8, simd_data[1]);
        stack_offset += 16;
      }
      break;

    case arg_type::STRUCT_BY_VALUE:
      // small structs passed in integer registers
      for (size_t i = 0; i < arg.value.struct_data.size / 8 && int_reg_idx < max_int_reg_args; i++) {
        switch (int_reg_idx) {
        case 0:
          gpr->x0 = arg.value.struct_data.data[i];
          break;
        case 1:
          gpr->x1 = arg.value.struct_data.data[i];
          break;
        case 2:
          gpr->x2 = arg.value.struct_data.data[i];
          break;
        case 3:
          gpr->x3 = arg.value.struct_data.data[i];
          break;
        case 4:
          gpr->x4 = arg.value.struct_data.data[i];
          break;
        case 5:
          gpr->x5 = arg.value.struct_data.data[i];
          break;
        case 6:
          gpr->x6 = arg.value.struct_data.data[i];
          break;
        case 7:
          gpr->x7 = arg.value.struct_data.data[i];
          break;
        }
        int_reg_idx++;
      }
      break;

    case arg_type::STRUCT_BY_REF:
      // pass pointer in integer register
      if (int_reg_idx < max_int_reg_args) {
        switch (int_reg_idx) {
        case 0:
          gpr->x0 = arg.value.integer;
          break;
        case 1:
          gpr->x1 = arg.value.integer;
          break;
        case 2:
          gpr->x2 = arg.value.integer;
          break;
        case 3:
          gpr->x3 = arg.value.integer;
          break;
        case 4:
          gpr->x4 = arg.value.integer;
          break;
        case 5:
          gpr->x5 = arg.value.integer;
          break;
        case 6:
          gpr->x6 = arg.value.integer;
          break;
        case 7:
          gpr->x7 = arg.value.integer;
          break;
        }
        int_reg_idx++;
      } else if (stack_writer) {
        stack_writer(gpr->sp + stack_offset, arg.value.integer);
        stack_offset += 8;
      }
      break;
    }
  }
}

} // namespace w1::abi::conventions