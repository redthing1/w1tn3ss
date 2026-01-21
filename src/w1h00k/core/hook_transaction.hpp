#pragma once

#include "w1h00k/hook.hpp"

namespace w1::h00k::core {

class hook_transaction {
public:
  hook_result attach(const hook_request& request, void** original);
  hook_error detach(hook_handle handle);
  hook_error commit();
};

} // namespace w1::h00k::core
