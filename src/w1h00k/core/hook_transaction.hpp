#pragma once

#include <vector>

#include "w1h00k/core/hook_manager.hpp"
#include "w1h00k/hook.hpp"

namespace w1::h00k::core {

class hook_transaction {
public:
  explicit hook_transaction(hook_manager& manager);
  ~hook_transaction();

  hook_result attach(const hook_request& request, void** original);
  hook_error detach(hook_handle handle);
  hook_error commit();

private:
  hook_manager* manager_ = nullptr;
  std::vector<prepared_hook> pending_attaches_{};
  std::vector<prepared_hook> pending_detaches_{};
  hook_error last_error_ = hook_error::ok;
};

} // namespace w1::h00k::core
