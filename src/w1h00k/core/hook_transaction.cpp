#include "w1h00k/core/hook_transaction.hpp"

#include "w1h00k/memory/memory.hpp"
#include "w1h00k/core/plan_targets.hpp"

#include <unordered_set>

namespace w1::h00k::core {

namespace {

void release_prepared(const prepared_hook& prepared) {
  if (!prepared.plan.trampoline || prepared.plan.trampoline_size == 0) {
    return;
  }
  memory::free_executable({prepared.plan.trampoline, prepared.plan.trampoline_size});
}

} // namespace

hook_transaction::hook_transaction(hook_manager& manager) : manager_(&manager) {}

hook_transaction::~hook_transaction() {
  for (const auto& prepared : pending_attaches_) {
    release_prepared(prepared);
  }
}

hook_result hook_transaction::attach(const hook_request& request, void** original) {
  if (last_error_ != hook_error::ok) {
    if (original) {
      *original = nullptr;
    }
    return {{}, {last_error_}};
  }

  std::lock_guard lock(manager_->mutex());
  prepared_hook prepared{};
  auto err = manager_->prepare_attach(request, prepared, original);
  if (err != hook_error::ok) {
    last_error_ = err;
    return {{}, {err}};
  }

  std::unordered_set<void*> new_targets;
  core::for_each_plan_target(prepared.plan, [&](void* target) { new_targets.insert(target); });
  if (new_targets.empty()) {
    release_prepared(prepared);
    last_error_ = hook_error::invalid_target;
    return {{}, {last_error_}};
  }

  for (const auto& existing : pending_attaches_) {
    bool collision = false;
    core::for_each_plan_target(existing.plan, [&](void* target) {
      if (new_targets.find(target) != new_targets.end()) {
        collision = true;
      }
    });
    if (collision) {
      release_prepared(prepared);
      last_error_ = hook_error::already_hooked;
      return {{}, {last_error_}};
    }
  }

  prepared.handle = manager_->reserve_handle();
  pending_attaches_.push_back(std::move(prepared));
  return {pending_attaches_.back().handle, {hook_error::ok}};
}

hook_error hook_transaction::detach(hook_handle handle) {
  if (last_error_ != hook_error::ok) {
    return last_error_;
  }

  std::lock_guard lock(manager_->mutex());
  prepared_hook prepared{};
  auto err = manager_->prepare_detach(handle, prepared);
  if (err != hook_error::ok) {
    last_error_ = err;
    return err;
  }

  for (const auto& existing : pending_detaches_) {
    if (existing.handle.id == prepared.handle.id) {
      last_error_ = hook_error::not_found;
      return last_error_;
    }
  }

  pending_detaches_.push_back(std::move(prepared));
  return hook_error::ok;
}

hook_error hook_transaction::commit() {
  if (last_error_ != hook_error::ok) {
    return last_error_;
  }

  std::lock_guard lock(manager_->mutex());
  std::vector<const prepared_hook*> committed_attaches;
  std::vector<const prepared_hook*> committed_detaches;

  for (auto& prepared : pending_attaches_) {
    auto err = manager_->commit_attach(prepared);
    if (err != hook_error::ok) {
      for (const auto* applied : committed_attaches) {
        manager_->rollback_attach(*applied);
      }
      last_error_ = err;
      return err;
    }
    committed_attaches.push_back(&prepared);
  }

  for (auto& prepared : pending_detaches_) {
    auto err = manager_->commit_detach(prepared);
    if (err != hook_error::ok) {
      for (const auto* applied : committed_detaches) {
        manager_->rollback_detach(*applied);
      }
      for (const auto* applied : committed_attaches) {
        manager_->rollback_attach(*applied);
      }
      last_error_ = err;
      return err;
    }
    committed_detaches.push_back(&prepared);
  }

  for (const auto& prepared : pending_detaches_) {
    manager_->finalize_detach(prepared);
  }

  pending_attaches_.clear();
  pending_detaches_.clear();
  return hook_error::ok;
}

} // namespace w1::h00k::core
