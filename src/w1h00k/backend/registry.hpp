#pragma once

#include <array>
#include <memory>

#include "w1h00k/backend/backend.hpp"

namespace w1::h00k::backend {

class backend_registry {
public:
  void register_backend(std::unique_ptr<hook_backend> backend);
  hook_backend* find(hook_technique technique) const;
  hook_backend* select(const hook_request& request) const;

private:
  std::array<std::unique_ptr<hook_backend>, static_cast<size_t>(hook_technique::count)> backends_{};
};

} // namespace w1::h00k::backend
