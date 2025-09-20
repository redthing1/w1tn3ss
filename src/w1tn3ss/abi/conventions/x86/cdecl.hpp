#pragma once

#include "abi/conventions/x86/base.hpp"

#include <optional>
#include <string>
#include <vector>

namespace w1::abi::conventions {

class x86_cdecl : public x86_calling_convention {
public:
  calling_convention_id get_id() const override { return calling_convention_id::X86_CDECL; }
  std::string get_name() const override { return "x86 cdecl"; }
  architecture get_architecture() const override { return architecture::X86; }
  std::string get_description() const override { return "c calling convention for 32-bit x86"; }

  bool supports_varargs() const override { return true; }
  std::optional<variadic_info> get_variadic_info(const extraction_context& ctx, size_t fixed_arg_count) const override;

  register_info get_register_info() const override;

  bool is_native_for_current_platform() const override {
#if defined(__i386__) && !defined(_WIN32)
    return true;
#else
    return false;
#endif
  }

  stack_cleanup get_stack_cleanup() const override { return stack_cleanup::CALLER; }
};

} // namespace w1::abi::conventions
