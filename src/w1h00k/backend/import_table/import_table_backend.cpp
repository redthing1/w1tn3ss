#include "w1h00k/backend/import_table/import_table_backend.hpp"

#include <cstring>

#include "w1h00k/backend/pointer_auth.hpp"
#include "w1h00k/patcher/patcher.hpp"
#include "w1h00k/resolve/resolve.hpp"

namespace w1::h00k::backend {
namespace {

hook_technique backend_technique() {
#if defined(_WIN32)
  return hook_technique::iat;
#else
  return hook_technique::plt_got;
#endif
}

} // namespace

class import_table_backend final : public hook_backend {
public:
  hook_technique technique() const override { return backend_technique(); }

  bool supports(const hook_request& request) const override {
    if (request.kind == hook_kind::instrument || request.prehook != nullptr) {
      return false;
    }
    if (request.replacement == nullptr) {
      return false;
    }
    return request.target.kind == hook_target_kind::import_slot;
  }

  prepare_result prepare(const hook_request& request, void* resolved_target) override {
    prepare_result result{};
    if (!supports(request)) {
      result.error = hook_error::unsupported;
      return result;
    }
    if (!resolved_target) {
      result.error = hook_error::not_found;
      return result;
    }

    auto* slot = reinterpret_cast<void**>(resolved_target);
    void* original = *slot;
    void* replacement = sign_replacement_pointer(request.replacement, slot);

    std::vector<uint8_t> patch_bytes(sizeof(void*));
    std::memcpy(patch_bytes.data(), &replacement, sizeof(void*));

    std::vector<uint8_t> restore_bytes(sizeof(void*));
    std::memcpy(restore_bytes.data(), &original, sizeof(void*));

    result.plan.request = request;
    result.plan.resolved_target = resolved_target;
    result.plan.patch_bytes = std::move(patch_bytes);
    result.plan.restore_bytes = std::move(restore_bytes);
    result.plan.trampoline = sanitize_original_pointer(original);
    result.error = hook_error::ok;
    return result;
  }

  hook_error commit(const hook_plan& plan) override {
    if (!plan.resolved_target || plan.patch_bytes.empty()) {
      return hook_error::invalid_target;
    }
    data_patcher patcher;
    if (!patcher.write(plan.resolved_target, plan.patch_bytes.data(), plan.patch_bytes.size())) {
      return hook_error::patch_failed;
    }
    return hook_error::ok;
  }

  hook_error revert(const hook_plan& plan) override {
    if (!plan.resolved_target || plan.restore_bytes.empty()) {
      return hook_error::invalid_target;
    }
    data_patcher patcher;
    if (!patcher.restore(plan.resolved_target, plan.restore_bytes.data(), plan.restore_bytes.size())) {
      return hook_error::patch_failed;
    }
    return hook_error::ok;
  }
};

std::unique_ptr<hook_backend> make_import_table_backend() {
  return std::make_unique<import_table_backend>();
}

} // namespace w1::h00k::backend
