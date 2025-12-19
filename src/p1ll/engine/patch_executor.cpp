#include "patch_executor.hpp"
#include "utils/hex_utils.hpp"
#include "utils/pretty_hexdump.hpp"
#include <algorithm>
#include <redlog.hpp>

namespace p1ll::engine {

namespace {

static constexpr uint64_t k_context_alignment_mask = 0xF;
static constexpr uint64_t k_context_alignment_size = 16;

memory_protection calculate_write_protection(memory_protection current_protection, bool is_executable) {
  if (is_executable) {
    return static_cast<memory_protection>(
        (static_cast<int>(current_protection) & ~static_cast<int>(memory_protection::execute)) |
        static_cast<int>(memory_protection::write)
    );
  }
  return current_protection | memory_protection::write;
}

std::vector<uint8_t> merge_patch_bytes(
    const compiled_patch& patch, const std::vector<uint8_t>& original, size_t& bytes_written
) {
  std::vector<uint8_t> merged = original;
  bytes_written = 0;
  for (size_t i = 0; i < patch.data.size(); ++i) {
    if (patch.mask[i]) {
      merged[i] = patch.data[i];
      bytes_written++;
    }
  }
  return merged;
}

} // namespace

patch_executor::patch_executor(address_space& space) : space_(space) {}

patch_execution_result patch_executor::apply(const patch_plan_entry& entry) {
  auto log = redlog::get_logger("p1ll.patch_executor");
  patch_execution_result result;

  if (entry.patch.empty()) {
    result.success = true;
    return result;
  }

  auto region_result = space_.region_info(entry.address);
  if (!region_result) {
    result.add_error("failed to resolve memory region for patch");
    return result;
  }

  const auto& region = *region_result;
  if (entry.address > UINT64_MAX - entry.patch.data.size()) {
    result.add_error("patch address range overflow");
    return result;
  }

  uint64_t region_end = region.base_address + region.size;
  if (entry.address < region.base_address || entry.address + entry.patch.data.size() > region_end) {
    result.add_error("patch would cross region boundary");
    return result;
  }

  auto original_bytes_result = space_.read(entry.address, entry.patch.data.size());
  if (!original_bytes_result) {
    result.add_error("failed to read original bytes for patch");
    return result;
  }

  size_t bytes_written = 0;
  std::vector<uint8_t> merged_bytes = merge_patch_bytes(entry.patch, *original_bytes_result, bytes_written);
  result.bytes_written = bytes_written;

  memory_protection original_protection = region.protection;
  bool is_executable = has_protection(original_protection, memory_protection::execute);
  bool is_writable = has_protection(original_protection, memory_protection::write);
  bool needs_protection_change = !is_writable;

  if (needs_protection_change) {
    memory_protection write_protection = calculate_write_protection(original_protection, is_executable);
    if (!space_.set_protection(entry.address, merged_bytes.size(), write_protection)) {
      result.add_error("failed to change memory protection for patch");
      return result;
    }
  }

  size_t patch_size = merged_bytes.size();
  uint64_t aligned_start = entry.address & ~k_context_alignment_mask;
  uint64_t aligned_end = (entry.address + patch_size + k_context_alignment_size - 1) & ~k_context_alignment_mask;
  size_t context_size = static_cast<size_t>(aligned_end - aligned_start);

  std::vector<uint8_t> original_context;
  bool has_context = false;
  auto context_result = space_.read(aligned_start, context_size);
  if (context_result) {
    original_context = *context_result;
    has_context = true;
  }

  if (!space_.write(entry.address, merged_bytes)) {
    result.add_error("failed to write patch bytes");
    if (needs_protection_change) {
      space_.set_protection(entry.address, merged_bytes.size(), original_protection);
    }
    return result;
  }

  auto verify_result = space_.read(entry.address, merged_bytes.size());
  if (!verify_result || !std::equal(merged_bytes.begin(), merged_bytes.end(), verify_result->begin())) {
    result.add_error("patch verification failed");
    space_.write(entry.address, *original_bytes_result);
    if (needs_protection_change) {
      space_.set_protection(entry.address, merged_bytes.size(), original_protection);
    }
    return result;
  }

  if (has_context && redlog::get_level() <= redlog::level::debug) {
    auto modified_context_result = space_.read(aligned_start, context_size);
    if (modified_context_result) {
      std::string patch_hexdump =
          utils::format_patch_hexdump(original_context, *modified_context_result, aligned_start);
      log.vrb(redlog::fmt("patch\n%s", patch_hexdump));
    }
  } else if (redlog::get_level() <= redlog::level::debug) {
    std::string patch_hexdump = utils::format_patch_hexdump(*original_bytes_result, merged_bytes, entry.address);
    log.vrb(redlog::fmt("patch\n%s", patch_hexdump));
  }

  if (is_executable) {
    if (!space_.flush_instruction_cache(entry.address, merged_bytes.size())) {
      log.wrn("failed to flush instruction cache", redlog::field("address", utils::format_address(entry.address)));
    }
  }

  if (needs_protection_change) {
    if (!space_.set_protection(entry.address, merged_bytes.size(), original_protection)) {
      log.wrn("failed to restore original protection", redlog::field("address", utils::format_address(entry.address)));
    }
  }

  result.success = true;
  log.inf(
      "patch applied", redlog::field("address", utils::format_address(entry.address)),
      redlog::field("bytes_written", result.bytes_written)
  );
  return result;
}

} // namespace p1ll::engine
