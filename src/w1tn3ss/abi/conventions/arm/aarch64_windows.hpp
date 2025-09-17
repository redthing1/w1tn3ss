#pragma once

#include "abi/conventions/arm/aarch64_aapcs.hpp"

namespace w1::abi::conventions {

class aarch64_windows : public aarch64_aapcs {
public:
  calling_convention_id get_id() const override { return calling_convention_id::AARCH64_WINDOWS; }
  std::string get_name() const override { return "AArch64 Windows"; }
  std::string get_description() const override {
    return "Windows ARM64 calling convention with 32-byte home space";
  }

  std::vector<uint64_t> extract_integer_args(const extraction_context& ctx, size_t count) const override;

  std::vector<typed_arg> extract_typed_args(
      const extraction_context& ctx, const std::vector<arg_type>& types
  ) const override;

  std::vector<double> extract_float_args(const extraction_context& ctx, size_t count) const override;

  std::optional<variadic_info> get_variadic_info(
      const extraction_context& ctx, size_t fixed_arg_count
  ) const override;

  register_info get_register_info() const override;
  bool is_native_for_current_platform() const override;
  size_t get_shadow_space_size() const override { return 32; }
  stack_cleanup get_stack_cleanup() const override { return stack_cleanup::CALLER; }
};

} // namespace w1::abi::conventions
