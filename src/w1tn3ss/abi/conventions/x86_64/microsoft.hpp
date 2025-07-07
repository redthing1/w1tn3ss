#pragma once

#include "../../calling_convention_base.hpp"
#include "../../fpr_utils.hpp"
#include <array>

namespace w1::abi::conventions {

/**
 * @brief microsoft x64 calling convention implementation
 *
 * used on windows x64 systems
 *
 * register usage:
 * - first 4 parameters: rcx, rdx, r8, r9 (integer or float)
 * - floating-point in same positions use xmm0, xmm1, xmm2, xmm3
 * - return value: rax (integer), xmm0 (float/double)
 * - caller saved: rax, rcx, rdx, r8-r11, xmm0-xmm5
 * - callee saved: rbx, rbp, rdi, rsi, rsp, r12-r15, xmm6-xmm15
 *
 * stack layout:
 * - 32-byte shadow space reserved by caller (for rcx, rdx, r8, r9)
 * - stack aligned to 16 bytes before call
 * - parameters beyond 4th passed on stack (right to left)
 *
 * special considerations:
 * - structures larger than 8 bytes passed by reference
 * - __m128 types passed by reference
 * - varargs use same convention but require different handling
 */
class x86_64_microsoft : public calling_convention_base {
public:
  // metadata
  calling_convention_id get_id() const override { return calling_convention_id::X86_64_MICROSOFT; }

  std::string get_name() const override { return "x86-64 Microsoft ABI"; }

  architecture get_architecture() const override { return architecture::X86_64; }

  std::string get_description() const override { return "Microsoft x64 calling convention used on Windows"; }

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

  size_t get_shadow_space_size() const override {
    return 32; // 4 * 8 bytes for rcx, rdx, r8, r9
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
#ifdef _WIN64
    return true;
#else
    return false;
#endif
  }

  stack_cleanup get_stack_cleanup() const override { return stack_cleanup::CALLER; }

  std::vector<double> extract_float_args(const extraction_context& ctx, size_t count) const override;

private:
  // first 4 params use rcx, rdx, r8, r9 (accessed directly)
  static constexpr size_t max_reg_args = 4;
};

} // namespace w1::abi::conventions