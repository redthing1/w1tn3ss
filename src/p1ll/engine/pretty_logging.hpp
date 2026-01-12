#pragma once

#include "engine/pattern.hpp"
#include "engine/types.hpp"
#include "utils/hex_pattern.hpp"
#include "utils/hex_utils.hpp"
#include "utils/pretty_hexdump.hpp"
#include <redlog.hpp>
#include <string>
#include <vector>

namespace p1ll::engine::pretty_logging {

inline std::string render_signature_pattern(const pattern& signature) {
  return utils::format_signature_pattern(signature.bytes, signature.mask);
}

inline std::string render_patch_pattern(const plan_entry& entry) {
  return utils::format_patch_pattern(entry.patch_bytes, entry.patch_mask);
}

inline std::string render_region_desc(const memory_region& region) {
  return utils::format_memory_region(region.base_address, region.size, region.name);
}

inline void log_signature_match(
    redlog::logger& log, const std::string& signature_pattern, uint64_t match_address,
    const std::string& region_name, const uint8_t* data, size_t data_size, size_t match_offset, size_t pattern_size,
    uint64_t base_offset
) {
  log.vrb(
      "signature match", redlog::field("pattern", signature_pattern),
      redlog::field("address", utils::format_address(match_address)), redlog::field("region", region_name)
  );

  std::string match_hexdump =
      utils::format_signature_match_hexdump(data, data_size, match_offset, pattern_size, base_offset);
  if (!match_hexdump.empty()) {
    log.vrb(redlog::fmt("signature\n%s", match_hexdump));
  }
}

inline void log_patch_apply(
    redlog::logger& log, const plan_entry& entry, size_t bytes_written, const memory_region& region,
    const std::vector<uint8_t>& before, const std::vector<uint8_t>& after, uint64_t base_offset
) {
  std::string patch_pattern = render_patch_pattern(entry);
  std::string region_desc = render_region_desc(region);

  log.vrb(
      "patch applied", redlog::field("address", utils::format_address(entry.address)),
      redlog::field("bytes_written", bytes_written), redlog::field("signature", entry.spec.signature.pattern),
      redlog::field("patch", patch_pattern), redlog::field("region", region_desc)
  );

  std::string patch_hexdump = utils::format_patch_hexdump(before, after, base_offset);
  if (!patch_hexdump.empty()) {
    log.vrb(redlog::fmt("patch\n%s", patch_hexdump));
  }
}

} // namespace p1ll::engine::pretty_logging
