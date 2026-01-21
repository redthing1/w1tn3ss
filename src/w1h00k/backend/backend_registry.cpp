#include "w1h00k/backend/backend_registry.hpp"

namespace w1::h00k::backend {

void backend_registry::register_backend(std::unique_ptr<hook_backend> backend) {
  if (!backend) {
    return;
  }
  backends_.push_back(std::move(backend));
}

hook_backend* backend_registry::select(const hook_request& request) const {
  for (const auto& backend : backends_) {
    if (backend && backend->supports(request)) {
      return backend.get();
    }
  }
  return nullptr;
}

} // namespace w1::h00k::backend
