#pragma once

#include <vector>

#include "w1h00k/hook.hpp"

namespace w1::h00k::backend {

struct hook_plan {
  hook_request request{};
  void* resolved_target = nullptr;
  std::vector<uint8_t> patch_bytes{};
  std::vector<uint8_t> restore_bytes{};
  void* trampoline = nullptr;
};

struct prepare_result {
  hook_plan plan{};
  hook_error error = hook_error::unsupported;
};

class hook_backend {
public:
  virtual ~hook_backend() = default;
  virtual bool supports(const hook_request& request) const = 0;
  virtual prepare_result prepare(const hook_request& request) = 0;
  virtual hook_error commit(const hook_plan& plan) = 0;
  virtual hook_error revert(const hook_plan& plan) = 0;
};

} // namespace w1::h00k::backend
