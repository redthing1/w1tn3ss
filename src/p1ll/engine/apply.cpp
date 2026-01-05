#include "apply.hpp"
#include "pretty_logging.hpp"
#include <algorithm>
#include <redlog.hpp>
#include <span>
#include <utility>

namespace p1ll::engine {

namespace {

constexpr uint64_t k_context_alignment_mask = 0xF;
constexpr uint64_t k_context_alignment_size = 16;

size_t count_written_bytes(const std::vector<uint8_t>& mask) {
  return static_cast<size_t>(std::count_if(mask.begin(), mask.end(), [](uint8_t value) { return value != 0; }));
}

memory_protection remove_execute(memory_protection prot) {
  return static_cast<memory_protection>(static_cast<int>(prot) & ~static_cast<int>(memory_protection::execute));
}

bool build_patch_context(
    address_space& space, uint64_t address, const std::vector<uint8_t>& before, const std::vector<uint8_t>& after,
    std::vector<uint8_t>& context_before, std::vector<uint8_t>& context_after, uint64_t& context_base
) {
  if (before.size() != after.size() || before.empty()) {
    return false;
  }

  uint64_t patch_size = static_cast<uint64_t>(before.size());
  if (address > UINT64_MAX - patch_size) {
    return false;
  }
  if (address > UINT64_MAX - patch_size - (k_context_alignment_size - 1)) {
    return false;
  }

  uint64_t aligned_start = address & ~k_context_alignment_mask;
  uint64_t aligned_end = (address + patch_size + k_context_alignment_size - 1) & ~k_context_alignment_mask;
  if (aligned_end < aligned_start) {
    return false;
  }

  size_t context_size = static_cast<size_t>(aligned_end - aligned_start);
  if (context_size == 0) {
    return false;
  }

  auto context = space.read(aligned_start, context_size);
  if (!context.ok()) {
    return false;
  }

  context_before = std::move(context.value);
  context_after = context_before;

  size_t patch_offset = static_cast<size_t>(address - aligned_start);
  if (patch_offset > context_after.size() || context_after.size() - patch_offset < after.size()) {
    return false;
  }

  std::copy(after.begin(), after.end(), context_after.begin() + patch_offset);
  context_base = aligned_start;
  return true;
}

result<std::vector<uint8_t>> merge_patch_bytes(
    const std::vector<uint8_t>& patch_bytes, const std::vector<uint8_t>& patch_mask,
    const std::vector<uint8_t>& original
) {
  if (patch_bytes.size() != patch_mask.size() || patch_bytes.size() != original.size()) {
    return error_result<std::vector<uint8_t>>(error_code::invalid_argument, "patch size mismatch");
  }

  std::vector<uint8_t> merged = original;
  for (size_t i = 0; i < patch_bytes.size(); ++i) {
    if (patch_mask[i]) {
      merged[i] = patch_bytes[i];
    }
  }

  return ok_result(merged);
}

result<size_t> apply_entry(address_space& space, const plan_entry& entry, const apply_options& options) {
  auto log = redlog::get_logger("p1ll.apply");
  size_t patch_size = entry.patch_bytes.size();
  if (patch_size == 0) {
    return ok_result(static_cast<size_t>(0));
  }

  auto region = space.region_info(entry.address);
  if (!region.ok()) {
    return error_result<size_t>(region.status.code, "failed to resolve memory region");
  }

  if (entry.address > UINT64_MAX - patch_size) {
    return error_result<size_t>(error_code::invalid_argument, "patch address overflow");
  }
  uint64_t region_end = region.value.base_address + region.value.size;
  if (entry.address < region.value.base_address || entry.address + patch_size > region_end) {
    return error_result<size_t>(error_code::invalid_argument, "patch crosses region boundary");
  }

  auto original_bytes = space.read(entry.address, patch_size);
  if (!original_bytes.ok()) {
    return error_result<size_t>(original_bytes.status.code, "failed to read original bytes");
  }

  auto merged = merge_patch_bytes(entry.patch_bytes, entry.patch_mask, original_bytes.value);
  if (!merged.ok()) {
    return error_result<size_t>(merged.status.code, merged.status.message);
  }

  std::vector<uint8_t> context_before;
  std::vector<uint8_t> context_after;
  uint64_t context_base = entry.address;
  bool has_context = build_patch_context(
      space, entry.address, original_bytes.value, merged.value, context_before, context_after, context_base
  );

  memory_protection original_protection = region.value.protection;
  bool writable = has_protection(original_protection, memory_protection::write);
  bool executable = has_protection(original_protection, memory_protection::execute);

  bool needs_protection_change = !writable;
  if (needs_protection_change) {
    memory_protection desired = original_protection | memory_protection::write;
    if (!options.allow_wx && executable) {
      desired = remove_execute(desired);
    }
    auto status = space.set_protection(entry.address, patch_size, desired);
    if (!status.ok()) {
      return error_result<size_t>(status.code, "failed to change memory protection");
    }
  }

  auto write_status = space.write(entry.address, std::span<const uint8_t>(merged.value));
  if (!write_status.ok()) {
    if (needs_protection_change) {
      space.set_protection(entry.address, patch_size, original_protection);
    }
    return error_result<size_t>(write_status.code, "failed to write patch bytes");
  }

  if (options.verify) {
    auto verify = space.read(entry.address, patch_size);
    if (!verify.ok() || !std::equal(merged.value.begin(), merged.value.end(), verify.value.begin())) {
      if (options.rollback_on_failure) {
        space.write(entry.address, std::span<const uint8_t>(original_bytes.value));
      }
      if (needs_protection_change) {
        space.set_protection(entry.address, patch_size, original_protection);
      }
      return error_result<size_t>(error_code::verification_failed, "patch verification failed");
    }
  }

  if (options.flush_icache && executable) {
    space.flush_instruction_cache(entry.address, patch_size);
  }

  if (needs_protection_change) {
    space.set_protection(entry.address, patch_size, original_protection);
  }

  size_t bytes_written = count_written_bytes(entry.patch_mask);
  const std::vector<uint8_t>* hexdump_before = &original_bytes.value;
  const std::vector<uint8_t>* hexdump_after = &merged.value;
  uint64_t hexdump_base = entry.address;
  if (has_context) {
    hexdump_before = &context_before;
    hexdump_after = &context_after;
    hexdump_base = context_base;
  }

  pretty_logging::log_patch_apply(
      log, entry, bytes_written, region.value, *hexdump_before, *hexdump_after, hexdump_base
  );

  return ok_result(bytes_written);
}

} // namespace

result<apply_report> apply_plan(
    address_space& space, const std::vector<plan_entry>& plan, const apply_options& options
) {
  apply_report report;

  for (const auto& entry : plan) {
    auto applied = apply_entry(space, entry, options);
    if (!applied.ok()) {
      report.failed++;
      report.diagnostics.push_back(applied.status);
      if (entry.spec.required) {
        report.success = false;
        return result<apply_report>{report, applied.status};
      }
      continue;
    }

    report.applied++;
  }

  report.success = (report.failed == 0 && report.applied > 0);
  return ok_result(report);
}

} // namespace p1ll::engine
