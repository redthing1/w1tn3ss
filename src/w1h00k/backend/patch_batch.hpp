#pragma once

#include <cstddef>
#include <vector>

#include "w1h00k/backend/backend.hpp"
#include "w1h00k/patcher/patcher.hpp"

namespace w1::h00k::backend {

inline hook_error apply_patch_entries(const std::vector<patch_entry>& entries) {
  if (entries.empty()) {
    return hook_error::invalid_target;
  }

  data_patcher patcher;
  size_t applied = 0;
  for (const auto& entry : entries) {
    if (!entry.target || entry.patch_bytes.empty()) {
      return hook_error::invalid_target;
    }
    if (!patcher.write(entry.target, entry.patch_bytes.data(), entry.patch_bytes.size())) {
      for (size_t i = 0; i < applied; ++i) {
        const auto& restore_entry = entries[i];
        if (restore_entry.target && !restore_entry.restore_bytes.empty()) {
          patcher.restore(restore_entry.target, restore_entry.restore_bytes.data(),
                          restore_entry.restore_bytes.size());
        }
      }
      return hook_error::patch_failed;
    }
    ++applied;
  }
  return hook_error::ok;
}

inline hook_error revert_patch_entries(const std::vector<patch_entry>& entries) {
  if (entries.empty()) {
    return hook_error::invalid_target;
  }

  data_patcher patcher;
  bool ok = true;
  for (const auto& entry : entries) {
    if (!entry.target || entry.restore_bytes.empty()) {
      ok = false;
      continue;
    }
    if (!patcher.restore(entry.target, entry.restore_bytes.data(), entry.restore_bytes.size())) {
      ok = false;
    }
  }
  return ok ? hook_error::ok : hook_error::patch_failed;
}

} // namespace w1::h00k::backend
