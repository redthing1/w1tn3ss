#include "scanner.hpp"
#include "pattern_matcher.hpp"
#include "pretty_logging.hpp"
#include <redlog.hpp>
#include <algorithm>
#include <filesystem>

namespace p1ll::engine {

namespace {

constexpr size_t k_chunk_size = 1024 * 1024;

size_t effective_max_matches(const scan_options& options) {
  if (!options.single) {
    return options.max_matches;
  }
  if (options.max_matches == 0) {
    return 2;
  }
  return std::max<size_t>(options.max_matches, 2);
}

} // namespace

scanner::scanner(const address_space& space) : space_(space) {}

result<std::vector<scan_result>> scanner::scan(const pattern& signature, const scan_options& options) const {
  if (signature.empty()) {
    return ok_result(std::vector<scan_result>{});
  }

  auto log = redlog::get_logger("p1ll.scanner");
  std::string signature_pattern = pretty_logging::render_signature_pattern(signature);

  auto regions = space_.regions(options.filter);
  if (!regions.ok()) {
    return error_result<std::vector<scan_result>>(regions.status.code, regions.status.message);
  }

  std::vector<scan_result> results;
  pattern_matcher matcher(signature);
  size_t overlap = signature.size() > 0 ? signature.size() - 1 : 0;
  size_t max_matches = effective_max_matches(options);

  for (const auto& region : regions.value) {
    if (region.size < signature.size() || !has_protection(region.protection, memory_protection::read)) {
      continue;
    }

    size_t offset = 0;
    while (offset < region.size) {
      size_t base_chunk_size = std::min(k_chunk_size, region.size - offset);
      size_t read_size = base_chunk_size;
      if (offset + base_chunk_size < region.size) {
        read_size = std::min(region.size - offset, base_chunk_size + overlap);
      }

      auto data_result = space_.read(region.base_address + offset, read_size);
      if (!data_result.ok()) {
        break;
      }

      auto offsets = matcher.search(data_result.value.data(), data_result.value.size());
      for (uint64_t match_offset : offsets) {
        if (match_offset >= base_chunk_size) {
          continue;
        }
        std::string region_name =
            region.name.empty() ? "[anonymous]" : std::filesystem::path(region.name).filename().string();
        uint64_t match_address = region.base_address + offset + match_offset;
        results.push_back(scan_result{match_address, region_name});

        pretty_logging::log_signature_match(
            log, signature_pattern, match_address, region_name, data_result.value.data(), data_result.value.size(),
            static_cast<size_t>(match_offset), signature.size(), region.base_address + offset
        );

        if (max_matches > 0 && results.size() >= max_matches) {
          break;
        }
      }

      if (max_matches > 0 && results.size() >= max_matches) {
        break;
      }

      if (base_chunk_size == 0) {
        break;
      }
      offset += base_chunk_size;
    }

    if (max_matches > 0 && results.size() >= max_matches) {
      break;
    }
  }

  if (options.single) {
    if (results.empty()) {
      return error_result<std::vector<scan_result>>(error_code::not_found, "signature not found");
    }
    if (results.size() > 1) {
      return error_result<std::vector<scan_result>>(error_code::multiple_matches, "multiple matches found");
    }
  }

  return ok_result(results);
}

} // namespace p1ll::engine
