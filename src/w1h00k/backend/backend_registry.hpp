#pragma once

#include <memory>
#include <vector>

#include "w1h00k/backend/backend.hpp"

namespace w1::h00k::backend {

class backend_registry {
public:
  void register_backend(std::unique_ptr<hook_backend> backend);
  hook_backend* select(const hook_request& request) const;

private:
  std::vector<std::unique_ptr<hook_backend>> backends_{};
};

} // namespace w1::h00k::backend
