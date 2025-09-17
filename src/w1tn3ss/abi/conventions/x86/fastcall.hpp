#pragma once

#include "abi/conventions/x86/base.hpp"

#include <optional>
#include <string>

namespace w1::abi::conventions {

class x86_fastcall : public x86_calling_convention {
public:
  calling_convention_id get_id() const override { return calling_convention_id::X86_FASTCALL; }
  std::string get_name() const override { return "x86 fastcall"; }
  architecture get_architecture() const override { return architecture::X86; }
  std::string get_description() const override {
    return "fastcall convention (first two args in ecx/edx)";
  }

  bool supports_varargs() const override { return false; }
  std::optional<variadic_info> get_variadic_info(
      const extraction_context& ctx, size_t fixed_arg_count
  ) const override;

  register_info get_register_info() const override;

  bool is_native_for_current_platform() const override {
#if defined(_WIN32) && !defined(_WIN64)
    return true;
#else
    return false;
#endif
  }

  stack_cleanup get_stack_cleanup() const override { return stack_cleanup::HYBRID; }

protected:
  register_sources collect_registers(const extraction_context& ctx) const override;
};

} // namespace w1::abi::conventions
