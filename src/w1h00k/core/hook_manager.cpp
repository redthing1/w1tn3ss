#include "w1h00k/core/hook_manager.hpp"

namespace w1::h00k::core {
namespace {

bool is_valid_target(const hook_target& target) {
  return target.address != nullptr || target.symbol != nullptr;
}

} // namespace

hook_result hook_manager::attach(const hook_request& request, void** original) {
  if (!is_valid_target(request.target)) {
    if (original) {
      *original = nullptr;
    }
    return {{}, hook_error::invalid_target};
  }
  if (original) {
    *original = nullptr;
  }
  return {{}, hook_error::unsupported};
}

hook_error hook_manager::detach(hook_handle handle) {
  (void)handle;
  return hook_error::unsupported;
}

bool hook_manager::supports(const hook_request& request) const {
  return is_valid_target(request.target) && false;
}

} // namespace w1::h00k::core
