#include "w1h00k/backend/registry.hpp"

namespace w1::h00k::backend {

namespace {

constexpr std::array<hook_technique, static_cast<size_t>(hook_technique::count)> kTechniqueOrder = {
    hook_technique::inline_trampoline,
    hook_technique::interpose,
    hook_technique::plt_got,
    hook_technique::iat,
    hook_technique::table_swap,
};

} // namespace

void backend_registry::register_backend(std::unique_ptr<hook_backend> backend) {
  if (!backend) {
    return;
  }
  const auto index = static_cast<size_t>(backend->technique());
  if (index >= backends_.size()) {
    return;
  }
  backends_[index] = std::move(backend);
}

hook_backend* backend_registry::find(hook_technique technique) const {
  const auto index = static_cast<size_t>(technique);
  if (index >= backends_.size()) {
    return nullptr;
  }
  const auto& backend = backends_[index];
  return backend ? backend.get() : nullptr;
}

hook_backend* backend_registry::select(const hook_request& request) const {
  if (request.preferred == hook_technique::count) {
    return nullptr;
  }

  if (request.selection == hook_selection::strict) {
    if (!technique_allowed(request.allowed, request.preferred)) {
      return nullptr;
    }
    auto* backend = find(request.preferred);
    if (!backend || !backend->supports(request)) {
      return nullptr;
    }
    return backend;
  }

  if (technique_allowed(request.allowed, request.preferred)) {
    if (auto* backend = find(request.preferred); backend && backend->supports(request)) {
      return backend;
    }
  }

  for (auto technique : kTechniqueOrder) {
    if (technique == request.preferred) {
      continue;
    }
    if (!technique_allowed(request.allowed, technique)) {
      continue;
    }
    auto* backend = find(technique);
    if (backend && backend->supports(request)) {
      return backend;
    }
  }

  return nullptr;
}

} // namespace w1::h00k::backend
