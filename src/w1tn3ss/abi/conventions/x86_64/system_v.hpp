#pragma once

#include "abi/calling_convention_base.hpp"
#include "abi/fpr_utils.hpp"
#include <array>

#if defined(__x86_64__) || defined(_M_X64)

namespace w1::abi::conventions {

/**
 * @brief system v amd64 abi implementation
 *
 * used on linux, macos, bsd, and other unix-like systems
 *
 * register usage:
 * - integer/pointer arguments: rdi, rsi, rdx, rcx, r8, r9 (first 6), then stack
 * - floating-point arguments: xmm0-xmm7 (first 8), then stack
 * - return value: rax/rdx (integer), xmm0/xmm1 (float)
 * - callee saved: rbx, rsp, rbp, r12-r15
 * - caller saved: rax, rcx, rdx, rsi, rdi, r8-r11, xmm0-xmm15
 *
 * stack layout:
 * - 128-byte red zone below rsp
 * - stack aligned to 16 bytes before call
 * - parameters beyond 6th passed on stack (right to left)
 */
class x86_64_system_v : public calling_convention_base {
public:
  // metadata
  calling_convention_id get_id() const override { return calling_convention_id::X86_64_SYSTEM_V; }

  std::string get_name() const override { return "x86-64 System V ABI"; }

  architecture get_architecture() const override { return architecture::X86_64; }

  std::string get_description() const override {
    return "System V AMD64 ABI used on Linux, macOS, and other Unix-like systems";
  }

  // argument extraction
  std::vector<uint64_t> extract_integer_args(const extraction_context& ctx, size_t count) const override;

  std::vector<typed_arg> extract_typed_args(
      const extraction_context& ctx, const std::vector<arg_type>& types
  ) const override;

  // return values
  uint64_t get_integer_return(const QBDI::GPRState* gpr) const override { return gpr->rax; }

  double get_float_return(const QBDI::FPRState* fpr) const override {
    // return value in xmm0
    return get_xmm_double(fpr, 0);
  }

  typed_arg get_typed_return(const QBDI::GPRState* gpr, const QBDI::FPRState* fpr, arg_type type) const override;

  // stack management
  uint64_t get_stack_pointer(const QBDI::GPRState* gpr) const override { return gpr->rsp; }

  uint64_t get_frame_pointer(const QBDI::GPRState* gpr) const override { return gpr->rbp; }

  size_t get_stack_alignment() const override {
    return 16; // 16-byte alignment
  }

  size_t get_red_zone_size() const override {
    return 128; // 128-byte red zone
  }

  uint64_t get_return_address_location(const QBDI::GPRState* gpr) const override {
    // return address is at [rsp]
    return gpr->rsp;
  }

  // variadic support
  bool supports_varargs() const override { return true; }

  std::optional<variadic_info> get_variadic_info(const extraction_context& ctx, size_t fixed_arg_count) const override;

  // register info
  register_info get_register_info() const override;

  bool is_native_for_current_platform() const override {
#if defined(__x86_64__) && !defined(_WIN64)
    return true;
#else
    return false;
#endif
  }

  stack_cleanup get_stack_cleanup() const override { return stack_cleanup::CALLER; }

  std::vector<double> extract_float_args(const extraction_context& ctx, size_t count) const override;

  // argument setting methods
  void set_integer_args(QBDI::GPRState* gpr, const std::vector<uint64_t>& args,
                       std::function<void(uint64_t addr, uint64_t value)> stack_writer = nullptr) const override;

  void set_typed_args(QBDI::GPRState* gpr, QBDI::FPRState* fpr, const std::vector<typed_arg>& args,
                     std::function<void(uint64_t addr, uint64_t value)> stack_writer = nullptr) const override;

  void set_integer_return(QBDI::GPRState* gpr, uint64_t value) const override {
    gpr->rax = value;
  }

  void set_float_return(QBDI::FPRState* fpr, double value) const override {
    // set xmm0 register
    memcpy(&fpr->xmm0, &value, sizeof(double));
  }

private:
  // integer argument registers: rdi, rsi, rdx, rcx, r8, r9 (accessed directly)
  static constexpr size_t max_int_reg_args = 6;

  // floating point argument registers: xmm0-xmm7
  static constexpr size_t max_float_reg_args = 8;
};

} // namespace w1::abi::conventions

#endif // defined(__x86_64__) || defined(_M_X64)