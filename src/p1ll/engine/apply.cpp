#include "apply.hpp"
#include <algorithm>
#include <span>

namespace p1ll::engine {

namespace {

memory_protection remove_execute(memory_protection prot) {
  return static_cast<memory_protection>(static_cast<int>(prot) & ~static_cast<int>(memory_protection::execute));
}

result<std::vector<uint8_t>> merge_patch_bytes(
    const std::vector<uint8_t>& patch_bytes, const std::vector<uint8_t>& patch_mask, const std::vector<uint8_t>& original
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

  size_t bytes_written = 0;
  for (size_t i = 0; i < entry.patch_mask.size(); ++i) {
    if (entry.patch_mask[i]) {
      bytes_written++;
    }
  }

  return ok_result(bytes_written);
}

} // namespace

result<apply_report> apply_plan(address_space& space, const std::vector<plan_entry>& plan, const apply_options& options) {
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
