#include "aarch64_windows.hpp"
#include <algorithm>
#include <cstring>

namespace w1::abi::conventions {

std::vector<uint64_t> aarch64_windows::extract_integer_args(
    const extraction_context& ctx, size_t count
) const {
  std::vector<uint64_t> args;
  args.reserve(count);

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

  if (count > 8) {
    const uint64_t stack_base = ctx.gpr->sp + get_shadow_space_size();
    for (size_t i = 8; i < count; i++) {
      uint64_t stack_offset = (i - 8) * 8;
      args.push_back(ctx.read_stack(stack_base + stack_offset));
    }
  }

  return args;
}

std::vector<aarch64_windows::typed_arg> aarch64_windows::extract_typed_args(
    const extraction_context& ctx, const std::vector<arg_type>& types
) const {
  std::vector<typed_arg> args;
  args.reserve(types.size());

  size_t int_reg_idx = 0;
  size_t float_reg_idx = 0;
  size_t stack_offset = 0;
  const uint64_t stack_base = ctx.gpr->sp + get_shadow_space_size();
  constexpr size_t max_float_reg_args = 8;

  auto read_stack_u64 = [&](typed_arg& arg) -> uint64_t {
    uint64_t value = ctx.read_stack(stack_base + stack_offset);
    arg.from_stack = true;
    arg.stack_offset = stack_offset;
    stack_offset += 8;
    return value;
  };

  for (const auto& type : types) {
    typed_arg arg;
    arg.type = type;
    arg.from_stack = false;
    arg.stack_offset = 0;

    switch (type) {
    case arg_type::INTEGER:
    case arg_type::POINTER:
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
        int_reg_idx++;
      } else {
        arg.value.integer = read_stack_u64(arg);
      }
      break;

    case arg_type::FLOAT:
      if (float_reg_idx < max_float_reg_args) {
        const __uint128_t* v_regs = reinterpret_cast<const __uint128_t*>(ctx.fpr);
        uint32_t f32_val = static_cast<uint32_t>(v_regs[float_reg_idx]);
        arg.value.f32 = *reinterpret_cast<float*>(&f32_val);
        float_reg_idx++;
      } else {
        uint32_t f32_val = static_cast<uint32_t>(read_stack_u64(arg));
        arg.value.f32 = *reinterpret_cast<float*>(&f32_val);
      }
      break;

    case arg_type::DOUBLE:
      if (float_reg_idx < max_float_reg_args) {
        const __uint128_t* v_regs = reinterpret_cast<const __uint128_t*>(ctx.fpr);
        uint64_t f64_val = static_cast<uint64_t>(v_regs[float_reg_idx]);
        arg.value.f64 = *reinterpret_cast<double*>(&f64_val);
        float_reg_idx++;
      } else {
        uint64_t f64_val = read_stack_u64(arg);
        arg.value.f64 = *reinterpret_cast<double*>(&f64_val);
      }
      break;

    case arg_type::SIMD:
      if (float_reg_idx < max_float_reg_args) {
        const __uint128_t* v_regs = reinterpret_cast<const __uint128_t*>(ctx.fpr);
        std::memcpy(arg.value.simd, &v_regs[float_reg_idx], 16);
        float_reg_idx++;
      } else {
        arg.from_stack = true;
        arg.stack_offset = stack_offset;
        for (int i = 0; i < 2; ++i) {
          uint64_t chunk = ctx.read_stack(stack_base + stack_offset + i * 8);
          std::memcpy(arg.value.simd + i * 8, &chunk, sizeof(uint64_t));
        }
        stack_offset += 16;
      }
      break;

    case arg_type::STRUCT_BY_VALUE:
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
        int_reg_idx++;
      } else {
        arg.value.struct_data.data[0] = read_stack_u64(arg);
        arg.value.struct_data.size = 8;
      }
      break;

    case arg_type::STRUCT_BY_REF:
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
        int_reg_idx++;
      } else {
        arg.value.integer = read_stack_u64(arg);
      }
      break;
    }

    args.push_back(arg);
  }

  return args;
}

std::vector<double> aarch64_windows::extract_float_args(
    const extraction_context& ctx, size_t count
) const {
  std::vector<double> result;
  result.reserve(count);

  const __uint128_t* v_regs = reinterpret_cast<const __uint128_t*>(ctx.fpr);
  size_t float_reg_idx = 0;
  constexpr size_t max_float_reg_args = 8;

  for (; float_reg_idx < std::min(count, max_float_reg_args); ++float_reg_idx) {
    uint64_t f64_val = static_cast<uint64_t>(v_regs[float_reg_idx]);
    result.push_back(*reinterpret_cast<double*>(&f64_val));
  }

  if (count > float_reg_idx) {
    const uint64_t stack_base = ctx.gpr->sp + get_shadow_space_size();
    size_t stack_offset = 0;
    for (size_t i = float_reg_idx; i < count; ++i) {
      uint64_t val = ctx.read_stack(stack_base + stack_offset);
      result.push_back(*reinterpret_cast<double*>(&val));
      stack_offset += 8;
    }
  }

  return result;
}

std::optional<aarch64_windows::variadic_info> aarch64_windows::get_variadic_info(
    const extraction_context& ctx, size_t fixed_arg_count
) const {
  variadic_info info;
  info.fixed_args = fixed_arg_count;
  info.gp_offset = std::min<size_t>(fixed_arg_count, 8) * 8;
  info.fp_offset = std::min<size_t>(fixed_arg_count, 8) * 16;
  info.overflow_arg_area = ctx.gpr->sp + get_shadow_space_size();
  info.reg_save_area = 0;
  return info;
}

calling_convention_base::register_info aarch64_windows::get_register_info() const {
  return {
      .callee_saved_gpr = {"x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29"},
      .caller_saved_gpr = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "lr"},
      .callee_saved_fpr = {"v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15"},
      .caller_saved_fpr = {"v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"},
      .return_register = "x0",
      .argument_registers = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"}
  };
}

bool aarch64_windows::is_native_for_current_platform() const {
#if defined(_WIN32) && (defined(_M_ARM64) || defined(__aarch64__))
  return true;
#else
  return false;
#endif
}

} // namespace w1::abi::conventions
