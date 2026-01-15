#pragma once

#include "engine/pattern.hpp"
#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace p1ll::engine {

// boyer-moore-horspool matcher with wildcard support
class pattern_matcher {
public:
  explicit pattern_matcher(pattern signature);

  std::vector<uint64_t> search(const uint8_t* data, size_t size) const;
  std::optional<uint64_t> search_single(const uint8_t* data, size_t size) const;

  size_t pattern_size() const { return signature_.size(); }
  bool is_valid() const { return !signature_.empty(); }

private:
  pattern signature_;
  std::array<size_t, 256> shift_table_{};

  void build_shift_table();
  bool match_at_position(const uint8_t* data, size_t pos) const;
};

} // namespace p1ll::engine
