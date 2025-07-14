#pragma once

#include "abi/calling_convention_base.hpp"
#include <array>

namespace w1::abi::conventions {

/**
 * @brief aarch64 aapcs (arm 64-bit application binary interface)
 *
 * used on linux arm64, macos arm64, and other unix-like systems
 *
 * register usage:
 * - integer/pointer arguments: x0-x7 (first 8), then stack
 * - floating-point arguments: v0-v7 (first 8), then stack
 * - return value: x0/x1 (integer), v0/v1 (float)
 * - callee saved: x19-x29, sp
 * - caller saved: x0-x18, x30 (lr)
 *
 * stack layout:
 * - no red zone (unlike x86-64 system v)
 * - stack aligned to 16 bytes at function entry
 * - parameters beyond 8th passed on stack
 *
 * special registers:
 * - x29: frame pointer (fp)
 * - x30: link register (lr) - return address
 * - sp: stack pointer
 */
class aarch64_aapcs : public calling_convention_base {
public:
  // metadata
  calling_convention_id get_id() const override { return calling_convention_id::AARCH64_AAPCS; }

  std::string get_name() const override { return "AArch64 AAPCS"; }

  architecture get_architecture() const override { return architecture::AARCH64; }

  std::string get_description() const override {
    return "ARM 64-bit Application Binary Interface used on Linux and macOS";
  }

  // argument extraction
  std::vector<uint64_t> extract_integer_args(const extraction_context& ctx, size_t count) const override;

  std::vector<typed_arg> extract_typed_args(
      const extraction_context& ctx, const std::vector<arg_type>& types
  ) const override;

  // return values
  uint64_t get_integer_return(const QBDI::GPRState* gpr) const override {
    // return value in x0
    return gpr->x0;
  }

  double get_float_return(const QBDI::FPRState* fpr) const override {
    // return value in v0 (d0)
    uint64_t f64_val = static_cast<uint64_t>(fpr->v0);
    return *reinterpret_cast<double*>(&f64_val);
  }

  typed_arg get_typed_return(const QBDI::GPRState* gpr, const QBDI::FPRState* fpr, arg_type type) const override;

  // stack management
  uint64_t get_stack_pointer(const QBDI::GPRState* gpr) const override { return gpr->sp; }

  uint64_t get_frame_pointer(const QBDI::GPRState* gpr) const override {
    return gpr->x29; // fp register
  }

  size_t get_stack_alignment() const override {
    return 16; // 16-byte alignment
  }

  size_t get_red_zone_size() const override {
    return 0; // no red zone on arm64
  }

  uint64_t get_return_address_location(const QBDI::GPRState* gpr) const override {
    // return address is in lr (x30), not on stack
    return gpr->lr;
  }

  // variadic support
  bool supports_varargs() const override { return true; }

  std::optional<variadic_info> get_variadic_info(const extraction_context& ctx, size_t fixed_arg_count) const override;

  // register info
  register_info get_register_info() const override;

  bool is_native_for_current_platform() const override {
#if defined(__aarch64__) && !defined(_WIN32)
    return true;
#else
    return false;
#endif
  }

  stack_cleanup get_stack_cleanup() const override { return stack_cleanup::CALLER; }

  std::vector<double> extract_float_args(const extraction_context& ctx, size_t count) const override;

  // argument setting methods
  void set_integer_args(
      QBDI::GPRState* gpr, const std::vector<uint64_t>& args,
      std::function<void(uint64_t addr, uint64_t value)> stack_writer = nullptr
  ) const override;

  void set_typed_args(
      QBDI::GPRState* gpr, QBDI::FPRState* fpr, const std::vector<typed_arg>& args,
      std::function<void(uint64_t addr, uint64_t value)> stack_writer = nullptr
  ) const override;

  void set_integer_return(QBDI::GPRState* gpr, uint64_t value) const override { gpr->x0 = value; }

  void set_float_return(QBDI::FPRState* fpr, double value) const override {
    // set v0 (d0) register
    fpr->v0 = *reinterpret_cast<uint64_t*>(&value);
  }

private:
  // integer argument registers: x0-x7 (accessed directly)
  static constexpr size_t max_int_reg_args = 8;

  // floating point argument registers: v0-v7
  static constexpr size_t max_float_reg_args = 8;
};

} // namespace w1::abi::conventions