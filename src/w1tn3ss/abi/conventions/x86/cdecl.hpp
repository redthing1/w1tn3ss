#pragma once

#include "abi/calling_convention_base.hpp"

namespace w1::abi::conventions {

/**
 * @brief x86 cdecl calling convention
 *
 * the default c calling convention for x86
 *
 * characteristics:
 * - all arguments passed on stack (right to left)
 * - caller cleans up stack
 * - return value in eax (edx:eax for 64-bit values)
 * - callee saved: ebx, esi, edi, ebp
 * - caller saved: eax, ecx, edx
 */
class x86_cdecl : public calling_convention_base {
public:
  // metadata
  calling_convention_id get_id() const override { return calling_convention_id::X86_CDECL; }

  std::string get_name() const override { return "x86 cdecl"; }

  architecture get_architecture() const override { return architecture::X86; }

  std::string get_description() const override { return "C declaration calling convention for x86"; }

  // argument extraction
  std::vector<uint64_t> extract_integer_args(const extraction_context& ctx, size_t count) const override;

  std::vector<typed_arg> extract_typed_args(
      const extraction_context& ctx, const std::vector<arg_type>& types
  ) const override;

  // return values
  uint64_t get_integer_return(const QBDI::GPRState* gpr) const override {
    // return value in eax
    return gpr->eax & 0xFFFFFFFF;
  }

  double get_float_return(const QBDI::FPRState* fpr) const override {
    // x87 st(0) - simplified, would need proper x87 stack handling
    return 0.0;
  }

  typed_arg get_typed_return(const QBDI::GPRState* gpr, const QBDI::FPRState* fpr, arg_type type) const override;

  // stack management
  uint64_t get_stack_pointer(const QBDI::GPRState* gpr) const override {
    return gpr->esp & 0xFFFFFFFF; // esp
  }

  uint64_t get_frame_pointer(const QBDI::GPRState* gpr) const override {
    return gpr->ebp & 0xFFFFFFFF; // ebp
  }

  size_t get_stack_alignment() const override {
    return 4; // 4-byte alignment for x86
  }

  uint64_t get_return_address_location(const QBDI::GPRState* gpr) const override {
    // return address is at [esp]
    return gpr->esp & 0xFFFFFFFF;
  }

  // variadic support
  bool supports_varargs() const override { return true; }

  std::optional<variadic_info> get_variadic_info(const extraction_context& ctx, size_t fixed_arg_count) const override;

  // register info
  register_info get_register_info() const override;

  bool is_native_for_current_platform() const override {
#if defined(__i386__) && !defined(_WIN32)
    return true;
#else
    return false;
#endif
  }

  stack_cleanup get_stack_cleanup() const override {
    return stack_cleanup::CALLER; // caller cleans stack
  }

  std::vector<double> extract_float_args(const extraction_context& ctx, size_t count) const override;

  // argument setting methods - NOT IMPLEMENTED
  void set_integer_args(
      QBDI::GPRState* gpr, const std::vector<uint64_t>& args,
      std::function<void(uint64_t addr, uint64_t value)> stack_writer = nullptr
  ) const override;

  void set_typed_args(
      QBDI::GPRState* gpr, QBDI::FPRState* fpr, const std::vector<typed_arg>& args,
      std::function<void(uint64_t addr, uint64_t value)> stack_writer = nullptr
  ) const override;

  void set_integer_return(QBDI::GPRState* gpr, uint64_t value) const override;

  void set_float_return(QBDI::FPRState* fpr, double value) const override;
};

} // namespace w1::abi::conventions