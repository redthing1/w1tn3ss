#include "pattern_matcher.hpp"
#include "utils/pretty_hexdump.hpp"
#include <redlog.hpp>
#include <algorithm>

namespace p1ll::engine {

pattern_matcher::pattern_matcher(const compiled_signature& signature) : signature_(signature) {

  auto log = redlog::get_logger("p1ll.pattern_matcher");

  if (signature_.empty()) {
    log.err("cannot create pattern matcher with empty signature");
    return;
  }

  build_shift_table();

  log.dbg(
      "created pattern matcher", redlog::field("pattern_size", signature_.size()),
      redlog::field("wildcards", std::count(signature_.mask.begin(), signature_.mask.end(), false))
  );
}

void pattern_matcher::build_shift_table() {
  const size_t pattern_len = signature_.size();

  if (pattern_len == 0) {
    return;
  }

  // initialize all entries to pattern length (default skip)
  shift_table_.fill(pattern_len);

  // count exact bytes for performance optimization warning
  size_t exact_bytes = std::count(signature_.mask.begin(), signature_.mask.end(), true);

  // boyer-moore-horspool: process all characters except the last one
  // process exact bytes first
  for (size_t i = 0; i < pattern_len - 1; ++i) {
    if (signature_.mask[i]) { // exact byte only
      uint8_t byte = signature_.pattern[i];
      shift_table_[byte] = pattern_len - 1 - i;
    }
  }

  // handle wildcards: for each wildcard position, any byte can match there
  // we must use the minimum skip distance to ensure correctness
  for (size_t i = 0; i < pattern_len - 1; ++i) {
    if (!signature_.mask[i]) { // wildcard position
      size_t wildcard_skip = pattern_len - 1 - i;

      // for each possible byte value, take the minimum skip distance
      // this ensures we don't skip over potential matches
      for (size_t byte = 0; byte < 256; ++byte) {
        shift_table_[byte] = std::min(shift_table_[byte], wildcard_skip);
      }
    }
  }

  // log performance warning for wildcard-heavy patterns
  auto log = redlog::get_logger("p1ll.pattern_matcher");
  if (exact_bytes < pattern_len / 2) {
    log.warn(
        "pattern has many wildcards, performance may be suboptimal", redlog::field("exact_bytes", exact_bytes),
        redlog::field("total_bytes", pattern_len),
        redlog::field("wildcard_ratio", (pattern_len - exact_bytes) * 100 / pattern_len)
    );
  }

  // safety check: ensure minimum shift of 1 (should not be needed with correct algorithm)
  for (size_t i = 0; i < 256; ++i) {
    if (shift_table_[i] == 0) {
      shift_table_[i] = 1;
    }
  }
}

std::vector<uint64_t> pattern_matcher::search(const uint8_t* data, size_t size) const {
  auto log = redlog::get_logger("p1ll.pattern_matcher");

  std::vector<uint64_t> results;

  if (!is_valid() || !data || size < signature_.size()) {
    log.dbg(
        "search skipped - invalid input", redlog::field("valid", is_valid()),
        redlog::field("data_ptr", data != nullptr), redlog::field("size", size),
        redlog::field("pattern_size", signature_.size())
    );
    return results;
  }

  const size_t pattern_len = signature_.size();

  // boyer-moore-horspool search with proper bounds checking
  size_t i = 0;
  while (i + pattern_len <= size) {
    if (match_at_position(data, i)) {
      results.push_back(i);

      // show beautiful signature match hexdump at debug level
      if (redlog::get_level() <= redlog::level::debug) {
        std::string match_hexdump = utils::format_signature_match_hexdump(data, size, i, pattern_len, 0);
        log.dbg(
            "signature match found", redlog::field("match", results.size()), redlog::field("offset", i),
            redlog::field("pattern_size", pattern_len)
        );
      }

      i += 1; // move by 1 to find overlapping matches
    } else {
      // skip based on shift table using last character of current window
      size_t last_char_index = i + pattern_len - 1;
      size_t skip = shift_table_[data[last_char_index]];

      // ensure we make progress (prevent infinite loops)
      if (skip == 0) {
        skip = 1;
      }

      i += skip;
    }
  }

  log.dbg(
      "pattern search completed", redlog::field("search_size", size), redlog::field("pattern_size", pattern_len),
      redlog::field("results", results.size())
  );

  return results;
}

uint64_t pattern_matcher::search_one(const uint8_t* data, size_t size) const {
  auto results = search(data, size);
  return results.empty() ? static_cast<uint64_t>(-1) : results[0];
}

uint64_t pattern_matcher::search_single(const uint8_t* data, size_t size) const {
  auto log = redlog::get_logger("p1ll.pattern_matcher");
  auto results = search(data, size);

  if (results.empty()) {
    throw std::runtime_error("signature not found, expected exactly one match");
  }

  if (results.size() > 1) {
    log.err(
        "multiple matches found for single signature", redlog::field("matches", results.size()),
        redlog::field("pattern_size", pattern_size())
    );

    // log all match locations for debugging
    for (size_t i = 0; i < results.size(); ++i) {
      log.dbg("match location", redlog::field("index", i + 1), redlog::field("offset", results[i]));
    }

    throw std::runtime_error(
        "multiple matches found for single signature, expected exactly one match, found " +
        std::to_string(results.size())
    );
  }

  return results[0];
}

std::vector<size_t> pattern_matcher::search_file(const std::vector<uint8_t>& file_data) const {
  auto byte_results = search(file_data.data(), file_data.size());

  // convert uint64_t results to size_t for file offsets
  std::vector<size_t> results;
  results.reserve(byte_results.size());

  for (uint64_t addr : byte_results) {
    results.push_back(static_cast<size_t>(addr));
  }

  return results;
}

bool pattern_matcher::match_at_position(const uint8_t* data, size_t pos) const {
  const size_t pattern_len = signature_.size();

  // match from right to left for early mismatch detection
  for (int i = static_cast<int>(pattern_len) - 1; i >= 0; --i) {
    if (signature_.mask[i]) { // exact byte match required
      if (signature_.pattern[i] != data[pos + i]) {
        return false;
      }
    }
    // wildcards automatically match, skip check
  }

  return true;
}

} // namespace p1ll::engine