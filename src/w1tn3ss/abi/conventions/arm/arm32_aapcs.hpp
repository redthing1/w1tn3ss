#pragma once

#include "abi/calling_convention_base.hpp"
#include <functional>

namespace w1::abi::conventions {

class arm32_aapcs : public calling_convention_base {
public:
  calling_convention_id get_id() const override { return calling_convention_id::ARM32_AAPCS; }
  std::string get_name() const override { return "ARM32 AAPCS"; }
  architecture get_architecture() const override { return architecture::ARM32; }
  std::string get_description() const override { return "ARM 32-bit Procedure Call Standard (AAPCS)"; }

  std::vector<uint64_t> extract_integer_args(const extraction_context& ctx, size_t count) const override;

  std::vector<typed_arg> extract_typed_args(
      const extraction_context& ctx, const std::vector<arg_type>& types
  ) const override;

  uint64_t get_integer_return(const QBDI::GPRState* gpr) const override { return gpr->r0; }
  double get_float_return(const QBDI::FPRState* fpr) const override;
  typed_arg get_typed_return(const QBDI::GPRState* gpr, const QBDI::FPRState* fpr, arg_type type) const override;

  uint64_t get_stack_pointer(const QBDI::GPRState* gpr) const override { return gpr->sp; }
  uint64_t get_frame_pointer(const QBDI::GPRState* gpr) const override { return gpr->r11; }
  size_t get_stack_alignment() const override { return 8; }
  uint64_t get_return_address_location(const QBDI::GPRState* gpr) const override { return gpr->lr; }

  bool supports_varargs() const override { return false; }
  std::optional<variadic_info> get_variadic_info(const extraction_context& ctx, size_t fixed_arg_count) const override;

  register_info get_register_info() const override;
  bool is_native_for_current_platform() const override;
  stack_cleanup get_stack_cleanup() const override { return stack_cleanup::CALLER; }

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
