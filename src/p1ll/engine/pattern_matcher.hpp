#pragma once

#include "core/types.hpp"
#include <vector>
#include <array>
#include <cstdint>

namespace p1ll::engine {

// high-performance pattern matching with Boyer-Moore-Horspool algorithm
class pattern_matcher {
public:
  explicit pattern_matcher(const compiled_signature& signature);

  // search in memory region
  std::vector<uint64_t> search(const uint8_t* data, size_t size) const;

  // search expecting exactly one result
  uint64_t search_one(const uint8_t* data, size_t size) const;

  // search with single match enforcement - throws exception if multiple matches
  uint64_t search_single(const uint8_t* data, size_t size) const;

  // search in file data
  std::vector<size_t> search_file(const std::vector<uint8_t>& file_data) const;

  // get pattern size
  size_t pattern_size() const { return signature_.size(); }

  // check if pattern is valid
  bool is_valid() const { return !signature_.empty(); }

private:
  compiled_signature signature_;
  std::array<size_t, 256> shift_table_; // Boyer-Moore-Horspool shift table

  void build_shift_table();
  bool match_at_position(const uint8_t* data, size_t pos) const;
};

} // namespace p1ll::engine