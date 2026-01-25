#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "w1base/arch_spec.hpp"
#include "w1h00k/hook.hpp"

namespace w1::h00k::backend::instrument {

struct stub_layout {
  size_t stack_size = 0;
  size_t gpr_offset = 0;
  size_t fpr_offset = 0;
  size_t args_offset = 0;
  size_t info_offset = 0;
  size_t shadow_size = 0;
  size_t gpr_count = 0;
  size_t fpr_count = 0;
};

struct stub_request {
  w1::arch::arch_spec arch{};
  hook_call_abi abi = hook_call_abi::native;
  uintptr_t target = 0;
  uintptr_t trampoline = 0;
  uintptr_t replacement = 0;
  uintptr_t prehook = 0;
  uintptr_t user_data = 0;
  uintptr_t stub_address = 0;
};

hook_call_abi resolve_call_abi(hook_call_abi requested, const w1::arch::arch_spec& arch);
bool abi_supported(hook_call_abi abi, const w1::arch::arch_spec& arch);
stub_layout make_layout(const w1::arch::arch_spec& arch, hook_call_abi abi, bool& ok);
size_t stub_reserve_size(const w1::arch::arch_spec& arch, hook_call_abi abi);
bool build_stub(const stub_request& request, const stub_layout& layout, std::vector<uint8_t>& out);

} // namespace w1::h00k::backend::instrument
