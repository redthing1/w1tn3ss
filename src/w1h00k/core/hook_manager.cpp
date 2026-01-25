#include "w1h00k/core/hook_manager.hpp"

#include <utility>

#include "w1h00k/backend/import_table/import_table_backend.hpp"
#include "w1h00k/backend/inline/inline_backend.hpp"
#include "w1h00k/backend/interpose/interpose_backend.hpp"
#include "w1h00k/memory/memory.hpp"
#include "w1h00k/core/plan_targets.hpp"
#include "w1h00k/resolve/resolve.hpp"

namespace w1::h00k::core {
namespace {

void free_trampoline(const backend::hook_plan& plan) {
  if (!plan.trampoline || plan.trampoline_size == 0) {
    return;
  }
  memory::free_executable({plan.trampoline, plan.trampoline_size});
}

} // namespace

hook_manager::hook_manager() {
  registry_.register_backend(backend::make_inline_trampoline_backend());
  registry_.register_backend(backend::make_interpose_backend());
  registry_.register_backend(backend::make_import_table_backend());
}

bool hook_manager::is_valid_target(const hook_target& target) const {
  switch (target.kind) {
    case hook_target_kind::address:
      return target.address != nullptr;
    case hook_target_kind::symbol:
      return target.symbol != nullptr;
    case hook_target_kind::import_slot:
      return target.slot != nullptr || target.symbol != nullptr;
    case hook_target_kind::table_slot:
      return target.table != nullptr;
  }
  return false;
}

hook_technique_mask hook_manager::normalize_allowed(const hook_request& request) const {
  if (request.allowed == 0) {
    return technique_mask(request.preferred);
  }
  return request.allowed;
}

void* hook_manager::resolve_target(const hook_target& target) const {
  switch (target.kind) {
    case hook_target_kind::address:
      return target.address;
    case hook_target_kind::symbol:
      return resolve::symbol_address(target.symbol, target.module);
    case hook_target_kind::import_slot:
      if (target.slot) {
        return target.slot;
      }
      if (target.symbol) {
        auto resolved = resolve::resolve_import(target.symbol, target.module, target.import_module);
        return resolved.slot;
      }
      return nullptr;
    case hook_target_kind::table_slot:
      if (!target.table) {
        return nullptr;
      }
      return static_cast<void*>(target.table + target.index);
  }
  return nullptr;
}

hook_handle hook_manager::reserve_handle() {
  return {next_id_++};
}

hook_error hook_manager::prepare_attach(const hook_request& request, prepared_hook& out, void** original,
                                        hook_error_info* out_error) {
  auto set_error = [&](hook_error code, const char* detail = nullptr) {
    if (out_error) {
      *out_error = {};
      out_error->code = code;
      out_error->detail = detail;
    }
  };

  if (!is_valid_target(request.target)) {
    if (original) {
      *original = nullptr;
    }
    set_error(hook_error::invalid_target);
    return hook_error::invalid_target;
  }

  hook_request normalized = request;
  normalized.allowed = normalize_allowed(request);

  auto* backend = registry_.select(normalized);
  if (!backend) {
    if (original) {
      *original = nullptr;
    }
    set_error(hook_error::unsupported);
    return hook_error::unsupported;
  }

  void* resolved = resolve_target(normalized.target);

  if (resolved && backend->technique() != hook_technique::interpose) {
    if (target_to_handle_.find(resolved) != target_to_handle_.end()) {
      if (original) {
        *original = nullptr;
      }
      set_error(hook_error::already_hooked);
      return hook_error::already_hooked;
    }
  }

  auto prepared = backend->prepare(normalized, resolved);
  if (!prepared.error.ok()) {
    if (original) {
      *original = nullptr;
    }
    if (out_error) {
      *out_error = prepared.error;
    }
    return prepared.error.code;
  }

  if (!prepared.plan.resolved_target) {
    prepared.plan.resolved_target = resolved;
  }
  bool has_target = false;
  bool collision = false;
  core::for_each_plan_target(prepared.plan, [&](void* target) {
    has_target = true;
    if (target_to_handle_.find(target) != target_to_handle_.end()) {
      collision = true;
    }
  });
  if (!has_target) {
    if (original) {
      *original = nullptr;
    }
    free_trampoline(prepared.plan);
    set_error(hook_error::invalid_target);
    return hook_error::invalid_target;
  }
  if (collision) {
    if (original) {
      *original = nullptr;
    }
    free_trampoline(prepared.plan);
    set_error(hook_error::already_hooked);
    return hook_error::already_hooked;
  }

  out.plan = std::move(prepared.plan);
  out.backend = backend;
  if (original) {
    *original = out.plan.trampoline;
  }
  set_error(hook_error::ok);
  return hook_error::ok;
}

hook_error hook_manager::prepare_detach(hook_handle handle, prepared_hook& out) {
  auto it = hooks_.find(handle.id);
  if (it == hooks_.end()) {
    return hook_error::not_found;
  }
  out = it->second;
  return hook_error::ok;
}

hook_error hook_manager::commit_attach(prepared_hook& prepared) {
  if (!prepared.backend) {
    return hook_error::unsupported;
  }
  auto err = prepared.backend->commit(prepared.plan);
  if (err != hook_error::ok) {
    return err;
  }

  if (prepared.handle.id == 0) {
    prepared.handle = reserve_handle();
  }

  hooks_[prepared.handle.id] = prepared;
  core::for_each_plan_target(prepared.plan, [&](void* target) {
    target_to_handle_[target] = prepared.handle.id;
  });
  return hook_error::ok;
}

hook_error hook_manager::commit_detach(const prepared_hook& prepared) {
  if (!prepared.backend) {
    return hook_error::not_found;
  }
  return prepared.backend->revert(prepared.plan);
}

void hook_manager::rollback_attach(const prepared_hook& prepared) {
  if (!prepared.backend) {
    return;
  }
  prepared.backend->revert(prepared.plan);
  if (prepared.handle.id != 0) {
    hooks_.erase(prepared.handle.id);
    core::for_each_plan_target(prepared.plan, [&](void* target) { target_to_handle_.erase(target); });
  }
  free_trampoline(prepared.plan);
}

void hook_manager::rollback_detach(const prepared_hook& prepared) {
  if (!prepared.backend) {
    return;
  }
  prepared.backend->commit(prepared.plan);
}

void hook_manager::finalize_detach(const prepared_hook& prepared) {
  if (prepared.handle.id != 0) {
    hooks_.erase(prepared.handle.id);
    core::for_each_plan_target(prepared.plan, [&](void* target) { target_to_handle_.erase(target); });
  }
  free_trampoline(prepared.plan);
}

hook_result hook_manager::attach(const hook_request& request, void** original) {
  std::lock_guard lock(mutex_);

  prepared_hook prepared{};
  hook_error_info error_info{};
  auto err = prepare_attach(request, prepared, original, &error_info);
  if (err != hook_error::ok) {
    return {{}, error_info};
  }

  err = commit_attach(prepared);
  if (err != hook_error::ok) {
    if (original) {
      *original = nullptr;
    }
    rollback_attach(prepared);
    return {{}, {err}};
  }

  hook_error_info ok_info{};
  ok_info.code = hook_error::ok;
  return {prepared.handle, ok_info};
}

hook_error hook_manager::detach(hook_handle handle) {
  std::lock_guard lock(mutex_);

  prepared_hook prepared{};
  auto err = prepare_detach(handle, prepared);
  if (err != hook_error::ok) {
    return err;
  }

  err = commit_detach(prepared);
  if (err != hook_error::ok) {
    return err;
  }

  finalize_detach(prepared);
  return hook_error::ok;
}

bool hook_manager::supports(const hook_request& request) const {
  if (!is_valid_target(request.target)) {
    return false;
  }
  hook_request normalized = request;
  normalized.allowed = normalize_allowed(request);
  auto* backend = registry_.select(normalized);
  return backend != nullptr;
}

} // namespace w1::h00k::core
