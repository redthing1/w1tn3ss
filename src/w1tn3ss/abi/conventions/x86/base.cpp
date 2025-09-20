#include "base.hpp"

#include <cstring>
#include <stdexcept>
#include <string>

#include <algorithm>

namespace w1::abi::conventions {

x86_stack_reader::x86_stack_reader(const calling_convention_base::extraction_context& ctx, size_t initial_offset_bytes)
    : ctx_(ctx), base_((static_cast<uint64_t>(ctx.gpr->esp) & 0xFFFFFFFFULL) + initial_offset_bytes) {}

uint32_t x86_stack_reader::read_u32(size_t relative_offset) const {
  uint64_t addr = (base_ + relative_offset) & 0xFFFFFFFFULL;
  return static_cast<uint32_t>(ctx_.read_stack(addr) & 0xFFFFFFFFULL);
}

uint32_t x86_stack_reader::pop_u32(size_t* stack_offset) {
  size_t current = offset_;
  offset_ += 4;
  if (stack_offset != nullptr) {
    *stack_offset = current;
  }
  return read_u32(current);
}

uint64_t x86_stack_reader::pop_u64(size_t* stack_offset) {
  size_t current = offset_;
  offset_ += 8;
  if (stack_offset != nullptr) {
    *stack_offset = current;
  }

  uint64_t low = read_u32(current);
  uint64_t high = read_u32(current + 4);
  return (high << 32) | low;
}

void x86_stack_reader::pop_bytes(uint8_t* dest, size_t size, size_t* stack_offset) {
  size_t current = offset_;
  if (stack_offset != nullptr) {
    *stack_offset = current;
  }

  size_t remaining = size;
  size_t cursor = 0;
  while (remaining > 0) {
    uint32_t word = pop_u32(nullptr);
    size_t to_copy = remaining < 4 ? remaining : size_t(4);
    std::memcpy(dest + cursor, &word, to_copy);
    cursor += to_copy;
    remaining -= to_copy;
  }
}

x86_calling_convention::register_sources x86_calling_convention::collect_registers(
    const extraction_context& ctx
) const {
  (void) ctx;
  return {};
}

std::vector<uint64_t> x86_calling_convention::extract_integer_args_common(
    const extraction_context& ctx, size_t count
) const {
  register_sources regs = collect_registers(ctx);
  x86_stack_reader stack(ctx, initial_stack_offset());

  std::vector<uint64_t> result;
  result.reserve(count);

  size_t int_idx = 0;
  for (size_t i = 0; i < count; ++i) {
    if (int_idx < regs.integer.size()) {
      result.push_back(regs.integer[int_idx++]);
    } else {
      result.push_back(stack.pop_u32(nullptr));
    }
  }

  return result;
}

std::vector<calling_convention_base::typed_arg> x86_calling_convention::extract_typed_args_common(
    const extraction_context& ctx, const std::vector<arg_type>& types
) const {
  register_sources regs = collect_registers(ctx);
  x86_stack_reader stack(ctx, initial_stack_offset());

  std::vector<typed_arg> result;
  result.reserve(types.size());

  size_t int_idx = 0;
  size_t vec_idx = 0;

  for (arg_type type : types) {
    typed_arg arg{};
    arg.type = type;
    arg.from_stack = false;
    arg.stack_offset = 0;

    switch (type) {
    case arg_type::INTEGER:
    case arg_type::POINTER:
    case arg_type::STRUCT_BY_REF: {
      if (int_idx < regs.integer.size()) {
        arg.value.integer = regs.integer[int_idx++];
      } else {
        size_t offset = 0;
        arg.value.integer = stack.pop_u32(&offset);
        arg.from_stack = true;
        arg.stack_offset = offset;
      }
      break;
    }

    case arg_type::FLOAT: {
      if (vec_idx < regs.vector.size()) {
        float value = 0.0f;
        std::memcpy(&value, regs.vector[vec_idx].data(), sizeof(float));
        arg.value.f32 = value;
        vec_idx++;
      } else {
        size_t offset = 0;
        uint32_t bits = stack.pop_u32(&offset);
        std::memcpy(&arg.value.f32, &bits, sizeof(float));
        arg.from_stack = true;
        arg.stack_offset = offset;
      }
      break;
    }

    case arg_type::DOUBLE: {
      if (vec_idx < regs.vector.size()) {
        double value = 0.0;
        std::memcpy(&value, regs.vector[vec_idx].data(), sizeof(double));
        arg.value.f64 = value;
        vec_idx++;
      } else {
        size_t offset = 0;
        uint64_t bits = stack.pop_u64(&offset);
        std::memcpy(&arg.value.f64, &bits, sizeof(double));
        arg.from_stack = true;
        arg.stack_offset = offset;
      }
      break;
    }

    case arg_type::SIMD: {
      if (vec_idx < regs.vector.size()) {
        std::memcpy(arg.value.simd, regs.vector[vec_idx].data(), 16);
        vec_idx++;
      } else {
        size_t offset = 0;
        stack.pop_bytes(arg.value.simd, 16, &offset);
        arg.from_stack = true;
        arg.stack_offset = offset;
      }
      break;
    }

    case arg_type::STRUCT_BY_VALUE: {
      size_t offset = 0;
      arg.value.struct_data.data[0] = stack.pop_u32(&offset);
      arg.value.struct_data.size = 4;
      arg.from_stack = true;
      arg.stack_offset = offset;
      break;
    }
    }

    result.push_back(arg);
  }

  return result;
}

std::vector<double> x86_calling_convention::extract_float_args_common(
    const extraction_context& ctx, size_t count
) const {
  register_sources regs = collect_registers(ctx);
  x86_stack_reader stack(ctx, initial_stack_offset());

  std::vector<double> result;
  result.reserve(count);

  size_t vec_idx = 0;
  for (size_t i = 0; i < count; ++i) {
    if (vec_idx < regs.vector.size()) {
      double value = 0.0;
      std::memcpy(&value, regs.vector[vec_idx].data(), sizeof(double));
      result.push_back(value);
      vec_idx++;
    } else {
      uint64_t bits = stack.pop_u64(nullptr);
      double value = 0.0;
      std::memcpy(&value, &bits, sizeof(double));
      result.push_back(value);
    }
  }

  return result;
}

void x86_calling_convention::throw_unimplemented(const char* what) const {
  throw std::runtime_error(std::string("x86 calling convention does not yet support ") + what);
}

uint64_t x86_calling_convention::get_integer_return(const QBDI::GPRState* gpr) const {
  return gpr->eax & 0xFFFFFFFFULL;
}

double x86_calling_convention::get_float_return(const QBDI::FPRState* fpr) const {
  (void) fpr;
  return 0.0;
}

calling_convention_base::typed_arg x86_calling_convention::get_typed_return(
    const QBDI::GPRState* gpr, const QBDI::FPRState* fpr, arg_type type
) const {
  (void) fpr;

  typed_arg ret{};
  ret.type = type;
  ret.from_stack = false;

  switch (type) {
  case arg_type::INTEGER:
  case arg_type::POINTER:
  case arg_type::STRUCT_BY_REF:
    ret.value.integer = get_integer_return(gpr);
    break;

  case arg_type::FLOAT:
  case arg_type::DOUBLE:
    ret.value.f64 = get_float_return(fpr);
    break;

  case arg_type::STRUCT_BY_VALUE:
    ret.value.struct_data.data[0] = gpr->eax & 0xFFFFFFFFULL;
    ret.value.struct_data.data[1] = gpr->edx & 0xFFFFFFFFULL;
    ret.value.struct_data.size = 8;
    break;

  case arg_type::SIMD:
    std::fill(std::begin(ret.value.simd), std::end(ret.value.simd), 0);
    break;
  }

  return ret;
}

uint64_t x86_calling_convention::get_stack_pointer(const QBDI::GPRState* gpr) const { return gpr->esp & 0xFFFFFFFFULL; }

uint64_t x86_calling_convention::get_frame_pointer(const QBDI::GPRState* gpr) const { return gpr->ebp & 0xFFFFFFFFULL; }

size_t x86_calling_convention::get_stack_alignment() const { return 4; }

uint64_t x86_calling_convention::get_return_address_location(const QBDI::GPRState* gpr) const {
  return gpr->esp & 0xFFFFFFFFULL;
}

std::vector<uint64_t> x86_calling_convention::extract_integer_args(const extraction_context& ctx, size_t count) const {
  return extract_integer_args_common(ctx, count);
}

std::vector<calling_convention_base::typed_arg> x86_calling_convention::extract_typed_args(
    const extraction_context& ctx, const std::vector<arg_type>& types
) const {
  return extract_typed_args_common(ctx, types);
}

std::vector<double> x86_calling_convention::extract_float_args(const extraction_context& ctx, size_t count) const {
  return extract_float_args_common(ctx, count);
}

void x86_calling_convention::set_integer_args(
    QBDI::GPRState*, const std::vector<uint64_t>&, std::function<void(uint64_t, uint64_t)>
) const {
  throw_unimplemented("setting integer arguments");
}

void x86_calling_convention::set_typed_args(
    QBDI::GPRState*, QBDI::FPRState*, const std::vector<typed_arg>&, std::function<void(uint64_t, uint64_t)>
) const {
  throw_unimplemented("setting typed arguments");
}

void x86_calling_convention::set_integer_return(QBDI::GPRState*, uint64_t) const {
  throw_unimplemented("setting integer return values");
}

void x86_calling_convention::set_float_return(QBDI::FPRState*, double) const {
  throw_unimplemented("setting float return values");
}

} // namespace w1::abi::conventions
