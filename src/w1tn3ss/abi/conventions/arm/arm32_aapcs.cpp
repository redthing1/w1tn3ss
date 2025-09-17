#include "arm32_aapcs.hpp"
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace w1::abi::conventions {

std::vector<uint64_t> arm32_aapcs::extract_integer_args(
    const extraction_context& ctx, size_t count
) const {
  std::vector<uint64_t> args;
  args.reserve(count);

  size_t reg_args = std::min(count, size_t(4));
  for (size_t i = 0; i < reg_args; ++i) {
    switch (i) {
    case 0:
      args.push_back(ctx.gpr->r0 & 0xFFFFFFFF);
      break;
    case 1:
      args.push_back(ctx.gpr->r1 & 0xFFFFFFFF);
      break;
    case 2:
      args.push_back(ctx.gpr->r2 & 0xFFFFFFFF);
      break;
    case 3:
      args.push_back(ctx.gpr->r3 & 0xFFFFFFFF);
      break;
    }
  }

  if (count > 4) {
    const uint64_t stack_base = ctx.gpr->sp;
    for (size_t i = 4; i < count; ++i) {
      uint64_t addr = stack_base + (i - 4) * 4;
      args.push_back(ctx.read_stack(addr) & 0xFFFFFFFF);
    }
  }

  return args;
}

std::vector<arm32_aapcs::typed_arg> arm32_aapcs::extract_typed_args(
    const extraction_context& ctx, const std::vector<arg_type>& types
) const {
  std::vector<typed_arg> result;
  result.reserve(types.size());

  size_t reg_idx = 0;
  uint64_t stack_base = ctx.gpr->sp;
  size_t stack_offset = 0;

  auto read_stack32 = [&](typed_arg& arg) -> uint32_t {
    uint64_t addr = stack_base + stack_offset;
    uint32_t value = static_cast<uint32_t>(ctx.read_stack(addr));
    arg.from_stack = true;
    arg.stack_offset = stack_offset;
    stack_offset += 4;
    return value;
  };

  auto read_stack64 = [&](typed_arg& arg) -> uint64_t {
    uint64_t addr = stack_base + stack_offset;
    uint64_t low = ctx.read_stack(addr) & 0xFFFFFFFF;
    uint64_t high = ctx.read_stack(addr + 4) & 0xFFFFFFFF;
    arg.from_stack = true;
    arg.stack_offset = stack_offset;
    stack_offset += 8;
    return low | (high << 32);
  };

  for (const auto& type : types) {
    typed_arg arg;
    arg.type = type;
    arg.from_stack = false;
    arg.stack_offset = 0;

    switch (type) {
    case arg_type::INTEGER:
    case arg_type::POINTER:
    case arg_type::STRUCT_BY_REF:
      if (reg_idx < 4) {
        switch (reg_idx) {
        case 0:
          arg.value.integer = ctx.gpr->r0 & 0xFFFFFFFF;
          break;
        case 1:
          arg.value.integer = ctx.gpr->r1 & 0xFFFFFFFF;
          break;
        case 2:
          arg.value.integer = ctx.gpr->r2 & 0xFFFFFFFF;
          break;
        case 3:
          arg.value.integer = ctx.gpr->r3 & 0xFFFFFFFF;
          break;
        }
        reg_idx++;
      } else {
        arg.value.integer = read_stack32(arg);
      }
      break;

    case arg_type::FLOAT: {
      uint32_t bits = (reg_idx < 4) ? static_cast<uint32_t>(
                                (reg_idx == 0 ? ctx.gpr->r0 : reg_idx == 1 ? ctx.gpr->r1 : reg_idx == 2 ? ctx.gpr->r2 : ctx.gpr->r3)
                            )
                            : read_stack32(arg);
      if (reg_idx < 4) {
        reg_idx++;
      }
      arg.value.f32 = *reinterpret_cast<float*>(&bits);
    } break;

    case arg_type::DOUBLE: {
      uint64_t bits = read_stack64(arg);
      arg.value.f64 = *reinterpret_cast<double*>(&bits);
    } break;

    case arg_type::SIMD:
      arg.from_stack = true;
      arg.stack_offset = stack_offset;
      for (int i = 0; i < 4; ++i) {
        uint32_t word = static_cast<uint32_t>(ctx.read_stack(stack_base + stack_offset + i * 4));
        std::memcpy(arg.value.simd + i * 4, &word, sizeof(uint32_t));
      }
      stack_offset += 16;
      break;

    case arg_type::STRUCT_BY_VALUE:
      arg.value.struct_data.data[0] = read_stack32(arg);
      arg.value.struct_data.size = 4;
      break;
    }

    result.push_back(arg);
  }

  return result;
}

double arm32_aapcs::get_float_return(const QBDI::FPRState*) const { return 0.0; }

calling_convention_base::typed_arg arm32_aapcs::get_typed_return(
    const QBDI::GPRState* gpr, const QBDI::FPRState*, arg_type type
) const {
  typed_arg ret;
  ret.type = type;
  ret.from_stack = false;
  ret.stack_offset = 0;

  switch (type) {
  case arg_type::INTEGER:
  case arg_type::POINTER:
  case arg_type::STRUCT_BY_REF:
    ret.value.integer = gpr->r0 & 0xFFFFFFFF;
    break;
  case arg_type::FLOAT:
  case arg_type::DOUBLE:
    ret.value.f64 = 0.0;
    break;
  case arg_type::STRUCT_BY_VALUE:
    ret.value.struct_data.data[0] = gpr->r0 & 0xFFFFFFFF;
    ret.value.struct_data.data[1] = gpr->r1 & 0xFFFFFFFF;
    ret.value.struct_data.size = 8;
    break;
  case arg_type::SIMD:
    std::memset(ret.value.simd, 0, sizeof(ret.value.simd));
    break;
  }

  return ret;
}

std::optional<arm32_aapcs::variadic_info> arm32_aapcs::get_variadic_info(
    const extraction_context&, size_t
) const {
  return std::nullopt;
}

calling_convention_base::register_info arm32_aapcs::get_register_info() const {
  return {
      .callee_saved_gpr = {"r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"},
      .caller_saved_gpr = {"r0", "r1", "r2", "r3", "ip", "lr"},
      .callee_saved_fpr = {},
      .caller_saved_fpr = {},
      .return_register = "r0",
      .argument_registers = {"r0", "r1", "r2", "r3"}
  };
}

bool arm32_aapcs::is_native_for_current_platform() const {
#if defined(__arm__) && !defined(__aarch64__)
  return true;
#else
  return false;
#endif
}

std::vector<double> arm32_aapcs::extract_float_args(
    const extraction_context& ctx, size_t count
) const {
  std::vector<double> result;
  result.reserve(count);

  uint64_t stack_base = ctx.gpr->sp;
  size_t stack_offset = 0;

  for (size_t i = 0; i < count; ++i) {
    uint64_t low = ctx.read_stack(stack_base + stack_offset) & 0xFFFFFFFF;
    uint64_t high = ctx.read_stack(stack_base + stack_offset + 4) & 0xFFFFFFFF;
    uint64_t bits = low | (high << 32);
    result.push_back(*reinterpret_cast<double*>(&bits));
    stack_offset += 8;
  }

  return result;
}

void arm32_aapcs::set_integer_args(
    QBDI::GPRState*, const std::vector<uint64_t>&,
    std::function<void(uint64_t, uint64_t)>
) const {
  throw std::runtime_error(
      "arm32 AAPCS calling convention is not yet implemented for gadget execution."
  );
}

void arm32_aapcs::set_typed_args(
    QBDI::GPRState*, QBDI::FPRState*, const std::vector<typed_arg>&,
    std::function<void(uint64_t, uint64_t)>
) const {
  throw std::runtime_error(
      "arm32 AAPCS calling convention is not yet implemented for gadget execution."
  );
}

void arm32_aapcs::set_integer_return(QBDI::GPRState* gpr, uint64_t value) const { gpr->r0 = static_cast<uint32_t>(value); }

void arm32_aapcs::set_float_return(QBDI::FPRState*, double) const {
  throw std::runtime_error(
      "arm32 AAPCS calling convention is not yet implemented for gadget execution."
  );
}

} // namespace w1::abi::conventions
