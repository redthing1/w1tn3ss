#include "w1h00k/backend/inline_backend.hpp"

#include <cstring>

#include "w1base/arch_spec.hpp"
#include "w1h00k/backend/inline/inline_detour.hpp"
#include "w1h00k/memory/memory.hpp"
#include "w1h00k/patcher.hpp"
#include "w1h00k/reloc/reloc_common.hpp"
#include "w1h00k/reloc/relocator.hpp"

namespace w1::h00k::backend {
namespace {

hook_technique_mask normalize_allowed(hook_technique_mask allowed) {
  if (allowed == 0) {
    return technique_mask(hook_technique::inline_trampoline);
  }
  return allowed;
}

} // namespace

class inline_trampoline_backend final : public hook_backend {
public:
  bool supports(const hook_request& request) const override {
    if (request.kind == hook_kind::instrument || request.prehook != nullptr) {
      return false;
    }
    if (request.replacement == nullptr) {
      return false;
    }
    const auto allowed = normalize_allowed(request.allowed);
    return (allowed & technique_mask(hook_technique::inline_trampoline)) != 0;
  }

  prepare_result prepare(const hook_request& request) override {
    prepare_result result{};
    if (!supports(request)) {
      result.error = hook_error::unsupported;
      return result;
    }
    if (request.target.address == nullptr) {
      result.error = hook_error::not_found;
      return result;
    }

    const auto arch = w1::arch::detect_host_arch_spec();
    const auto plan = inline_hook::plan_for(arch, reinterpret_cast<uint64_t>(request.target.address),
                                            reinterpret_cast<uint64_t>(request.replacement));
    if (plan.arch == inline_hook::arch_kind::unknown || plan.min_patch == 0 || plan.tail_size == 0) {
      result.error = hook_error::unsupported;
      return result;
    }

    const size_t alloc_size = reloc::detail::kMaxPatchBytes + plan.tail_size;
    auto block = memory::allocate_executable(alloc_size);
    if (!block.ok()) {
      result.error = hook_error::near_alloc_failed;
      return result;
    }

    auto reloc_result = reloc::relocate(request.target.address, plan.min_patch,
                                        reinterpret_cast<uint64_t>(block.address), arch);
    if (!reloc_result.ok()) {
      memory::free_executable(block);
      result.error = hook_error::relocation_failed;
      return result;
    }

    auto* original_bytes = reinterpret_cast<const uint8_t*>(request.target.address);
    if (!inline_hook::prologue_safe(plan, original_bytes, reloc_result.patch_size)) {
      memory::free_executable(block);
      result.error = hook_error::relocation_failed;
      return result;
    }

    const uint64_t resume_addr = reinterpret_cast<uint64_t>(request.target.address) + reloc_result.patch_size;
    std::vector<uint8_t> trampoline_bytes = std::move(reloc_result.trampoline_bytes);
    const uint64_t tramp_end = reinterpret_cast<uint64_t>(block.address) + trampoline_bytes.size();
    if (!inline_hook::append_trampoline_tail(plan, tramp_end, resume_addr, trampoline_bytes)) {
      memory::free_executable(block);
      result.error = hook_error::relocation_failed;
      return result;
    }

    code_patcher patcher;
    if (!patcher.write(block.address, trampoline_bytes.data(), trampoline_bytes.size())) {
      memory::free_executable(block);
      result.error = hook_error::patch_failed;
      return result;
    }

    std::vector<uint8_t> patch_bytes;
    if (!inline_hook::build_detour_patch(plan, reinterpret_cast<uint64_t>(request.target.address),
                                         reinterpret_cast<uint64_t>(request.replacement), reloc_result.patch_size,
                                         patch_bytes)) {
      memory::free_executable(block);
      result.error = hook_error::patch_failed;
      return result;
    }

    std::vector<uint8_t> restore_bytes(reloc_result.patch_size);
    std::memcpy(restore_bytes.data(), request.target.address, restore_bytes.size());

    result.plan.request = request;
    result.plan.resolved_target = request.target.address;
    result.plan.patch_bytes = std::move(patch_bytes);
    result.plan.restore_bytes = std::move(restore_bytes);
    result.plan.trampoline = block.address;
    result.plan.trampoline_size = block.size;
    result.error = hook_error::ok;
    return result;
  }

  hook_error commit(const hook_plan& plan) override {
    if (!plan.resolved_target || plan.patch_bytes.empty()) {
      return hook_error::invalid_target;
    }
    code_patcher patcher;
    if (!patcher.write(plan.resolved_target, plan.patch_bytes.data(), plan.patch_bytes.size())) {
      return hook_error::patch_failed;
    }
    return hook_error::ok;
  }

  hook_error revert(const hook_plan& plan) override {
    if (!plan.resolved_target || plan.restore_bytes.empty()) {
      return hook_error::invalid_target;
    }
    code_patcher patcher;
    if (!patcher.restore(plan.resolved_target, plan.restore_bytes.data(), plan.restore_bytes.size())) {
      return hook_error::patch_failed;
    }
    return hook_error::ok;
  }
};

std::unique_ptr<hook_backend> make_inline_trampoline_backend() {
  return std::make_unique<inline_trampoline_backend>();
}

} // namespace w1::h00k::backend
