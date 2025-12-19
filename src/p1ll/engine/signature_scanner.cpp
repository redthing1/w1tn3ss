#include "signature_scanner.hpp"
#include "engine/pattern_matcher.hpp"
#include "utils/hex_utils.hpp"
#include <algorithm>
#include <filesystem>
#include <redlog.hpp>

namespace p1ll::engine {

namespace {

constexpr size_t k_chunk_size = 1024 * 1024;

} // namespace

signature_scanner::signature_scanner(address_space& space) : space_(space) {}

std::optional<std::vector<search_result>> signature_scanner::scan(
    const compiled_signature& signature, const signature_query_filter& filter
) {
  auto log = redlog::get_logger("p1ll.signature_scanner");

  if (signature.empty()) {
    return std::vector<search_result>{};
  }

  auto regions_result = space_.regions(filter);
  if (!regions_result) {
    log.err("failed to enumerate address space regions");
    return std::nullopt;
  }

  std::vector<search_result> all_results;
  pattern_matcher matcher(signature);
  size_t overlap = signature.size() > 0 ? signature.size() - 1 : 0;

  for (const auto& region : *regions_result) {
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
      if (!data_result) {
        log.dbg(
            "failed to read chunk", redlog::field("base", utils::format_address(region.base_address + offset)),
            redlog::field("size", read_size)
        );
        break;
      }

      auto offsets = matcher.search(data_result->data(), data_result->size());
      for (uint64_t match_offset : offsets) {
        if (match_offset >= base_chunk_size) {
          continue;
        }
        std::string region_name =
            region.name.empty() ? "[anonymous]" : std::filesystem::path(region.name).filename().string();
        all_results.emplace_back(region.base_address + offset + match_offset, region_name, "");
      }

      if (base_chunk_size == 0) {
        break;
      }
      offset += base_chunk_size;
    }
  }

  log.dbg("signature scan completed", redlog::field("total_found", all_results.size()));
  return all_results;
}

std::optional<uint64_t> signature_scanner::scan_single(
    const compiled_signature& signature, const signature_query_filter& filter
) {
  auto log = redlog::get_logger("p1ll.signature_scanner");
  auto results = scan(signature, filter);
  if (!results || results->empty()) {
    log.dbg("single scan found no matches");
    return std::nullopt;
  }
  if (results->size() > 1) {
    log.err("single scan found multiple matches", redlog::field("matches", results->size()));
    return std::nullopt;
  }
  return (*results)[0].address;
}

} // namespace p1ll::engine
