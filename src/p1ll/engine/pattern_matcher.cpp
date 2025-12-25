#include "pattern_matcher.hpp"
#include <algorithm>

namespace p1ll::engine {

pattern_matcher::pattern_matcher(pattern signature) : signature_(std::move(signature)) { build_shift_table(); }

void pattern_matcher::build_shift_table() {
  const size_t pattern_len = signature_.size();
  if (pattern_len == 0) {
    return;
  }

  shift_table_.fill(pattern_len);

  for (size_t i = 0; i + 1 < pattern_len; ++i) {
    if (signature_.mask[i]) {
      shift_table_[signature_.bytes[i]] = pattern_len - 1 - i;
    }
  }

  // wildcards require conservative shifts to avoid skipping matches
  for (size_t i = 0; i + 1 < pattern_len; ++i) {
    if (!signature_.mask[i]) {
      size_t wildcard_shift = pattern_len - 1 - i;
      for (size_t b = 0; b < 256; ++b) {
        shift_table_[b] = std::min(shift_table_[b], wildcard_shift);
      }
    }
  }

  for (size_t i = 0; i < 256; ++i) {
    if (shift_table_[i] == 0) {
      shift_table_[i] = 1;
    }
  }
}

std::vector<uint64_t> pattern_matcher::search(const uint8_t* data, size_t size) const {
  std::vector<uint64_t> results;
  if (!is_valid() || !data || size < signature_.size()) {
    return results;
  }

  const size_t pattern_len = signature_.size();
  size_t i = 0;
  while (i + pattern_len <= size) {
    if (match_at_position(data, i)) {
      results.push_back(i);
      i += 1;
    } else {
      size_t last_index = i + pattern_len - 1;
      size_t skip = shift_table_[data[last_index]];
      if (skip == 0) {
        skip = 1;
      }
      i += skip;
    }
  }

  return results;
}

std::optional<uint64_t> pattern_matcher::search_single(const uint8_t* data, size_t size) const {
  auto results = search(data, size);
  if (results.size() != 1) {
    return std::nullopt;
  }
  return results[0];
}

bool pattern_matcher::match_at_position(const uint8_t* data, size_t pos) const {
  const size_t pattern_len = signature_.size();
  for (int i = static_cast<int>(pattern_len) - 1; i >= 0; --i) {
    if (signature_.mask[i]) {
      if (signature_.bytes[i] != data[pos + i]) {
        return false;
      }
    }
  }
  return true;
}

} // namespace p1ll::engine
