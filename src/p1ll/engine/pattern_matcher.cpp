#include "pattern_matcher.hpp"
#include <redlog.hpp>
#include <algorithm>

namespace p1ll::engine {

pattern_matcher::pattern_matcher(pattern signature) : signature_(std::move(signature)) {
  auto log = redlog::get_logger("p1ll.pattern_matcher");
  if (signature_.empty()) {
    log.err("cannot create pattern matcher with empty signature");
    return;
  }

  build_shift_table();

  size_t wildcards =
      static_cast<size_t>(std::count(signature_.mask.begin(), signature_.mask.end(), static_cast<uint8_t>(0)));
  log.dbg(
      "created pattern matcher", redlog::field("pattern_size", signature_.size()), redlog::field("wildcards", wildcards)
  );
}

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

  size_t exact_bytes =
      static_cast<size_t>(std::count(signature_.mask.begin(), signature_.mask.end(), static_cast<uint8_t>(1)));
  if (pattern_len > 0 && exact_bytes < pattern_len / 2) {
    auto log = redlog::get_logger("p1ll.pattern_matcher");
    log.wrn(
        "pattern has many wildcards, performance may be suboptimal", redlog::field("exact_bytes", exact_bytes),
        redlog::field("total_bytes", pattern_len),
        redlog::field("wildcard_ratio", (pattern_len - exact_bytes) * 100 / pattern_len)
    );
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
    auto log = redlog::get_logger("p1ll.pattern_matcher");
    log.dbg(
        "search skipped - invalid input", redlog::field("valid", is_valid()),
        redlog::field("data_ptr", data != nullptr), redlog::field("size", size),
        redlog::field("pattern_size", signature_.size())
    );
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

  auto log = redlog::get_logger("p1ll.pattern_matcher");
  log.dbg(
      "pattern search completed", redlog::field("search_size", size), redlog::field("pattern_size", pattern_len),
      redlog::field("results", results.size())
  );
  return results;
}

std::optional<uint64_t> pattern_matcher::search_single(const uint8_t* data, size_t size) const {
  auto log = redlog::get_logger("p1ll.pattern_matcher");
  auto results = search(data, size);
  if (results.size() != 1) {
    if (results.empty()) {
      log.dbg("signature not found for single match requirement");
    } else {
      log.err(
          "multiple matches found for single signature", redlog::field("matches", results.size()),
          redlog::field("pattern_size", signature_.size())
      );
      if (static_cast<int>(redlog::get_level()) >= static_cast<int>(redlog::level::pedantic)) {
        for (size_t i = 0; i < results.size(); ++i) {
          log.ped("match location", redlog::field("index", i + 1), redlog::field("offset", results[i]));
        }
      }
    }
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
