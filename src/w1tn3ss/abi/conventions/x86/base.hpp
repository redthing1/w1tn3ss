#pragma once

#include "abi/calling_convention_base.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace w1::abi::conventions {

// helper for sequential stack reads when unpacking x86 arguments
class x86_stack_reader {
public:
  x86_stack_reader(const calling_convention_base::extraction_context& ctx, size_t initial_offset_bytes);

  uint32_t pop_u32(size_t* stack_offset = nullptr);
  uint64_t pop_u64(size_t* stack_offset = nullptr);
  void pop_bytes(uint8_t* dest, size_t size, size_t* stack_offset = nullptr);

private:
  const calling_convention_base::extraction_context& ctx_;
  uint64_t base_; // base points to first argument slot (ret addr already skipped)
  size_t offset_ = 0;

  uint32_t read_u32(size_t relative_offset) const;
};

// shared functionality for 32-bit x86 calling conventions
class x86_calling_convention : public calling_convention_base {
protected:
  struct register_sources {
    std::vector<uint64_t> integer;
    std::vector<std::array<uint8_t, 16>> vector;
  };

  virtual register_sources collect_registers(const extraction_context& ctx) const;
  virtual size_t initial_stack_offset() const { return 4; }

  std::vector<uint64_t> extract_integer_args_common(const extraction_context& ctx, size_t count) const;
  std::vector<typed_arg> extract_typed_args_common(
      const extraction_context& ctx, const std::vector<arg_type>& types
  ) const;
  std::vector<double> extract_float_args_common(const extraction_context& ctx, size_t count) const;

  void throw_unimplemented(const char* what) const;

public:
  uint64_t get_integer_return(const QBDI::GPRState* gpr) const override;
  double get_float_return(const QBDI::FPRState* fpr) const override;
  typed_arg get_typed_return(
      const QBDI::GPRState* gpr, const QBDI::FPRState* fpr, arg_type type
  ) const override;

  uint64_t get_stack_pointer(const QBDI::GPRState* gpr) const override;
  uint64_t get_frame_pointer(const QBDI::GPRState* gpr) const override;
  size_t get_stack_alignment() const override;
  uint64_t get_return_address_location(const QBDI::GPRState* gpr) const override;

  std::vector<uint64_t> extract_integer_args(const extraction_context& ctx, size_t count) const override;
  std::vector<typed_arg> extract_typed_args(
      const extraction_context& ctx, const std::vector<arg_type>& types
  ) const override;
  std::vector<double> extract_float_args(const extraction_context& ctx, size_t count) const override;

  void set_integer_args(
      QBDI::GPRState* gpr, const std::vector<uint64_t>& args,
      std::function<void(uint64_t addr, uint64_t value)> stack_writer
  ) const override;
  void set_typed_args(
      QBDI::GPRState* gpr, QBDI::FPRState* fpr, const std::vector<typed_arg>& args,
      std::function<void(uint64_t addr, uint64_t value)> stack_writer
  ) const override;
  void set_integer_return(QBDI::GPRState* gpr, uint64_t value) const override;
  void set_float_return(QBDI::FPRState* fpr, double value) const override;
};

} // namespace w1::abi::conventions
