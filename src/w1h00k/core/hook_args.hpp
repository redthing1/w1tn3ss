#pragma once

#include <cstdint>
#include <type_traits>

#include "w1h00k/hook.hpp"

namespace w1::h00k {

struct hook_arg_handle {
  hook_call_abi abi = hook_call_abi::native;
  uint32_t reserved = 0;
  const void* int_regs = nullptr;
  const void* flt_regs = nullptr;
  const void* stack = nullptr;
};

static_assert(std::is_standard_layout_v<hook_arg_handle>);
static_assert(std::is_trivially_copyable_v<hook_arg_handle>);

} // namespace w1::h00k
