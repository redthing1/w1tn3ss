#pragma once

#include "abi/calling_convention_base.hpp"
#include <string>

namespace w1::abi::conventions {

// Generic placeholder used for conventions that are not yet fully implemented.
class placeholder_calling_convention : public calling_convention_base {
public:
  placeholder_calling_convention(
      calling_convention_id id,
      std::string name,
      architecture arch,
      std::string description,
      stack_cleanup cleanup = stack_cleanup::CALLER
  );

  calling_convention_id get_id() const override;
  std::string get_name() const override;
  architecture get_architecture() const override;
  std::string get_description() const override;

  std::vector<uint64_t> extract_integer_args(const extraction_context& ctx, size_t count) const override;

  std::vector<typed_arg> extract_typed_args(
      const extraction_context& ctx, const std::vector<arg_type>& types
  ) const override;

  uint64_t get_integer_return(const QBDI::GPRState* gpr) const override;
  double get_float_return(const QBDI::FPRState* fpr) const override;
  typed_arg get_typed_return(const QBDI::GPRState* gpr, const QBDI::FPRState* fpr, arg_type type) const override;

  uint64_t get_stack_pointer(const QBDI::GPRState* gpr) const override;
  uint64_t get_frame_pointer(const QBDI::GPRState* gpr) const override;
  size_t get_stack_alignment() const override;
  size_t get_red_zone_size() const override;
  size_t get_shadow_space_size() const override;
  uint64_t get_return_address_location(const QBDI::GPRState* gpr) const override;

  bool supports_varargs() const override;
  std::optional<variadic_info> get_variadic_info(
      const extraction_context& ctx, size_t fixed_arg_count
  ) const override;

  register_info get_register_info() const override;
  bool is_native_for_current_platform() const override;
  stack_cleanup get_stack_cleanup() const override;

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

protected:
  [[noreturn]] void throw_not_supported(const char* what) const;

private:
  calling_convention_id id_;
  std::string name_;
  architecture arch_;
  std::string description_;
  stack_cleanup cleanup_;
};

class unknown_calling_convention : public placeholder_calling_convention {
public:
  unknown_calling_convention();
};

class custom_calling_convention : public placeholder_calling_convention {
public:
  custom_calling_convention();
};

} // namespace w1::abi::conventions
