#include "w1h00k/backend/inline/inline_backend.hpp"

#include <cstring>

#include "w1base/arch_spec.hpp"
#include "w1h00k/backend/inline/inline_detour.hpp"
#include "w1h00k/backend/inline/inline_instrumentation.hpp"
#include "w1h00k/memory/memory.hpp"
#include "w1h00k/patcher/patcher.hpp"
#include "w1h00k/reloc/relocator.hpp"

#if defined(__APPLE__) && __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

namespace w1::h00k::backend {
class inline_trampoline_backend final : public hook_backend {
public:
  hook_technique technique() const override { return hook_technique::inline_trampoline; }

  bool supports(const hook_request& request) const override {
    const bool wants_instrument = request.kind == hook_kind::instrument || request.prehook != nullptr;
    if (wants_instrument) {
      if (request.kind != hook_kind::instrument) {
        return false;
      }
      if (request.prehook == nullptr || request.replacement != nullptr) {
        return false;
      }
      if (request.target.kind != hook_target_kind::address && request.target.kind != hook_target_kind::symbol) {
        return false;
      }
      const auto arch = w1::arch::detect_host_arch_spec();
      const auto abi = instrument::resolve_call_abi(request.call_abi, arch);
      return instrument::abi_supported(abi, arch);
    }

    if (request.replacement == nullptr) {
      return false;
    }
    return request.target.kind == hook_target_kind::address || request.target.kind == hook_target_kind::symbol;
  }

  prepare_result prepare(const hook_request& request, void* resolved_target) override {
    prepare_result result{};
    if (!supports(request)) {
      result.error = hook_error::unsupported;
      return result;
    }
    if (resolved_target == nullptr) {
      result.error = hook_error::not_found;
      return result;
    }

    const auto arch = w1::arch::detect_host_arch_spec();
    const bool wants_instrument = request.kind == hook_kind::instrument;
    if (wants_instrument) {
      const auto abi = instrument::resolve_call_abi(request.call_abi, arch);
      if (!instrument::abi_supported(abi, arch)) {
        result.error = hook_error::unsupported;
        return result;
      }

      size_t max_patch = 0;
      size_t min_patch = 0;
      switch (arch.arch_mode) {
        case w1::arch::mode::x86_32:
          max_patch = 5;
          min_patch = 5;
          break;
        case w1::arch::mode::x86_64:
          max_patch = 14;
          min_patch = 5;
          break;
        case w1::arch::mode::aarch64:
          max_patch = 16;
          min_patch = 16;
          break;
        default:
          result.error = hook_error::unsupported;
          return result;
      }

      const size_t reloc_size = reloc::max_trampoline_size(max_patch, arch);
      if (reloc_size == 0) {
        result.error = hook_error::unsupported;
        return result;
      }

      const size_t stub_reserve = instrument::stub_reserve_size(arch, abi);
      const size_t alloc_size = reloc_size + stub_reserve;
      auto block = memory::allocate_executable(alloc_size);
      if (!block.ok()) {
        result.error = hook_error::near_alloc_failed;
        return result;
      }

      auto reloc_result =
          reloc::relocate(resolved_target, min_patch, reinterpret_cast<uint64_t>(block.address), arch);
      if (!reloc_result.ok()) {
        memory::free_executable(block);
        result.error = hook_error::relocation_failed;
        return result;
      }

      auto plan_hint = inline_hook::plan_for(arch, reinterpret_cast<uint64_t>(resolved_target),
                                             reinterpret_cast<uint64_t>(resolved_target));
      if (plan_hint.arch == inline_hook::arch_kind::unknown || plan_hint.tail_size == 0) {
        memory::free_executable(block);
        result.error = hook_error::unsupported;
        return result;
      }

      uint64_t stub_addr =
          reinterpret_cast<uint64_t>(block.address) + reloc_result.trampoline_bytes.size() + plan_hint.tail_size;
      auto plan = inline_hook::plan_for(arch, reinterpret_cast<uint64_t>(resolved_target), stub_addr);
      if (plan.arch == inline_hook::arch_kind::unknown || plan.min_patch == 0 || plan.tail_size == 0) {
        memory::free_executable(block);
        result.error = hook_error::unsupported;
        return result;
      }

      if (plan.min_patch > reloc_result.patch_size) {
        reloc_result =
            reloc::relocate(resolved_target, plan.min_patch, reinterpret_cast<uint64_t>(block.address), arch);
        if (!reloc_result.ok()) {
          memory::free_executable(block);
          result.error = hook_error::relocation_failed;
          return result;
        }
        stub_addr =
            reinterpret_cast<uint64_t>(block.address) + reloc_result.trampoline_bytes.size() + plan.tail_size;
        plan = inline_hook::plan_for(arch, reinterpret_cast<uint64_t>(resolved_target), stub_addr);
        if (plan.arch == inline_hook::arch_kind::unknown || plan.min_patch == 0 || plan.tail_size == 0 ||
            plan.min_patch > reloc_result.patch_size) {
          memory::free_executable(block);
          result.error = hook_error::unsupported;
          return result;
        }
      }

      auto* original_bytes = reinterpret_cast<const uint8_t*>(resolved_target);
      if (!inline_hook::prologue_safe(plan, original_bytes, reloc_result.patch_size)) {
        memory::free_executable(block);
        result.error = hook_error::relocation_failed;
        return result;
      }

      const uint64_t resume_addr = reinterpret_cast<uint64_t>(resolved_target) + reloc_result.patch_size;
      std::vector<uint8_t> trampoline_bytes = std::move(reloc_result.trampoline_bytes);
      const uint64_t tramp_end = reinterpret_cast<uint64_t>(block.address) + trampoline_bytes.size();
      if (!inline_hook::append_trampoline_tail(plan, tramp_end, resume_addr, trampoline_bytes)) {
        memory::free_executable(block);
        result.error = hook_error::relocation_failed;
        return result;
      }

      stub_addr = reinterpret_cast<uint64_t>(block.address) + trampoline_bytes.size();

      code_patcher patcher;
      if (!patcher.write(block.address, trampoline_bytes.data(), trampoline_bytes.size())) {
        memory::free_executable(block);
        result.error = hook_error::patch_failed;
        return result;
      }

      bool layout_ok = false;
      const auto layout = instrument::make_layout(arch, abi, layout_ok);
      if (!layout_ok) {
        memory::free_executable(block);
        result.error = hook_error::unsupported;
        return result;
      }

      instrument::stub_request stub_req{};
      stub_req.arch = arch;
      stub_req.abi = abi;
      stub_req.target = reinterpret_cast<uint64_t>(resolved_target);
      stub_req.trampoline = reinterpret_cast<uint64_t>(block.address);
      stub_req.replacement = reinterpret_cast<uint64_t>(request.replacement);
#if defined(__APPLE__) && __has_feature(ptrauth_calls)
      auto stripped = ptrauth_strip(request.prehook, ptrauth_key_function_pointer);
      stub_req.prehook = reinterpret_cast<uint64_t>(stripped);
#else
      stub_req.prehook = reinterpret_cast<uint64_t>(request.prehook);
#endif
      stub_req.user_data = reinterpret_cast<uint64_t>(request.user_data);
      stub_req.stub_address = stub_addr;

      std::vector<uint8_t> stub_bytes;
      if (!instrument::build_stub(stub_req, layout, stub_bytes)) {
        memory::free_executable(block);
        result.error = hook_error::unsupported;
        return result;
      }

      if (trampoline_bytes.size() + stub_bytes.size() > block.size) {
        memory::free_executable(block);
        result.error = hook_error::patch_failed;
        return result;
      }

      if (!patcher.write(reinterpret_cast<void*>(stub_addr), stub_bytes.data(), stub_bytes.size())) {
        memory::free_executable(block);
        result.error = hook_error::patch_failed;
        return result;
      }

      std::vector<uint8_t> patch_bytes;
      if (!inline_hook::build_detour_patch(plan, reinterpret_cast<uint64_t>(resolved_target), stub_addr,
                                           reloc_result.patch_size, patch_bytes)) {
        memory::free_executable(block);
        result.error = hook_error::patch_failed;
        return result;
      }

      std::vector<uint8_t> restore_bytes(reloc_result.patch_size);
      std::memcpy(restore_bytes.data(), resolved_target, restore_bytes.size());

      result.plan.request = request;
      result.plan.resolved_target = resolved_target;
      result.plan.patch_bytes = std::move(patch_bytes);
      result.plan.restore_bytes = std::move(restore_bytes);
      result.plan.trampoline = block.address;
      result.plan.trampoline_size = block.size;
      result.error = hook_error::ok;
      return result;
    }

    const auto plan = inline_hook::plan_for(arch, reinterpret_cast<uint64_t>(resolved_target),
                                            reinterpret_cast<uint64_t>(request.replacement));
    if (plan.arch == inline_hook::arch_kind::unknown || plan.min_patch == 0 || plan.tail_size == 0) {
      result.error = hook_error::unsupported;
      return result;
    }

    const size_t reloc_size = reloc::max_trampoline_size(plan.min_patch, arch);
    if (reloc_size == 0) {
      result.error = hook_error::unsupported;
      return result;
    }

    const size_t alloc_size = reloc_size + plan.tail_size;
    auto block = memory::allocate_executable(alloc_size);
    if (!block.ok()) {
      result.error = hook_error::near_alloc_failed;
      return result;
    }

    auto reloc_result = reloc::relocate(resolved_target, plan.min_patch, reinterpret_cast<uint64_t>(block.address),
                                        arch);
    if (!reloc_result.ok()) {
      memory::free_executable(block);
      result.error = hook_error::relocation_failed;
      return result;
    }

    auto* original_bytes = reinterpret_cast<const uint8_t*>(resolved_target);
    if (!inline_hook::prologue_safe(plan, original_bytes, reloc_result.patch_size)) {
      memory::free_executable(block);
      result.error = hook_error::relocation_failed;
      return result;
    }

    const uint64_t resume_addr = reinterpret_cast<uint64_t>(resolved_target) + reloc_result.patch_size;
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
    if (!inline_hook::build_detour_patch(plan, reinterpret_cast<uint64_t>(resolved_target),
                                         reinterpret_cast<uint64_t>(request.replacement), reloc_result.patch_size,
                                         patch_bytes)) {
      memory::free_executable(block);
      result.error = hook_error::patch_failed;
      return result;
    }

    std::vector<uint8_t> restore_bytes(reloc_result.patch_size);
    std::memcpy(restore_bytes.data(), resolved_target, restore_bytes.size());

    result.plan.request = request;
    result.plan.resolved_target = resolved_target;
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
