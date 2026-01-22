#include "w1h00k/backend/interpose/interpose_backend.hpp"

#include <cstring>
#include <unordered_set>

#include "w1h00k/backend/patch_batch.hpp"
#include "w1h00k/backend/pointer_auth.hpp"
#include "w1h00k/resolve/resolve.hpp"

namespace w1::h00k::backend {

class interpose_backend final : public hook_backend {
public:
  hook_technique technique() const override { return hook_technique::interpose; }

  bool supports(const hook_request& request) const override {
    if (request.kind == hook_kind::instrument || request.prehook != nullptr) {
      return false;
    }
    if (request.replacement == nullptr) {
      return false;
    }
    return request.target.kind == hook_target_kind::symbol;
  }

  prepare_result prepare(const hook_request& request, void* resolved_target) override {
    prepare_result result{};
    if (!supports(request)) {
      result.error = hook_error::unsupported;
      return result;
    }
    if (!request.target.symbol || request.target.symbol[0] == '\0') {
      result.error = hook_error::invalid_target;
      return result;
    }

    std::vector<patch_entry> patches;
    auto resolutions =
        resolve::resolve_imports(request.target.symbol, request.target.module, request.target.import_module);
    if (resolutions.empty()) {
      result.error = hook_error::not_found;
      return result;
    }

    patches.reserve(resolutions.size());
    std::unordered_set<void*> seen_slots;

    void* first_original = nullptr;
    for (const auto& resolved : resolutions) {
      if (!resolved.error.ok() || !resolved.slot) {
        continue;
      }

      void** slot = resolved.slot;
      if (!seen_slots.insert(slot).second) {
        continue;
      }

      void* original = *slot;
      void* replacement = sign_replacement_pointer(request.replacement, slot);

      patch_entry entry{};
      entry.target = slot;
      entry.patch_bytes.resize(sizeof(void*));
      std::memcpy(entry.patch_bytes.data(), &replacement, sizeof(void*));

      entry.restore_bytes.resize(sizeof(void*));
      std::memcpy(entry.restore_bytes.data(), &original, sizeof(void*));

      patches.push_back(std::move(entry));
      if (!first_original) {
        first_original = sanitize_original_pointer(original);
      }
    }

    if (patches.empty()) {
      result.error = hook_error::not_found;
      return result;
    }

    result.plan.request = request;
    result.plan.patches = std::move(patches);
    result.plan.resolved_target = resolved_target ? resolved_target : result.plan.patches.front().target;
    result.plan.trampoline = first_original ? first_original : resolved_target;
    result.error = hook_error::ok;
    return result;
  }

  hook_error commit(const hook_plan& plan) override {
    return apply_patch_entries(plan.patches);
  }

  hook_error revert(const hook_plan& plan) override {
    return revert_patch_entries(plan.patches);
  }
};

std::unique_ptr<hook_backend> make_interpose_backend() {
  return std::make_unique<interpose_backend>();
}

} // namespace w1::h00k::backend
