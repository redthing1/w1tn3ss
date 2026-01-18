#include "memory_merge.hpp"

#include <algorithm>

namespace w1replay::gdb {

bool merge_memory_bytes(
    const std::vector<std::optional<uint8_t>>& recorded,
    const std::vector<std::byte>& module_bytes,
    bool module_ok,
    std::span<std::byte> out
) {
  if (out.empty()) {
    return true;
  }
  if (recorded.size() < out.size()) {
    std::fill(out.begin(), out.end(), std::byte{0});
    return false;
  }
  if (module_ok && module_bytes.size() < out.size()) {
    std::fill(out.begin(), out.end(), std::byte{0});
    return false;
  }

  bool any_unknown = false;
  for (size_t i = 0; i < out.size(); ++i) {
    if (recorded[i].has_value()) {
      out[i] = static_cast<std::byte>(*recorded[i]);
      continue;
    }
    if (module_ok) {
      out[i] = module_bytes[i];
      continue;
    }
    out[i] = std::byte{0};
    any_unknown = true;
  }

  return !any_unknown;
}

} // namespace w1replay::gdb
