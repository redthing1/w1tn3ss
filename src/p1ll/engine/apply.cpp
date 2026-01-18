#include "apply.hpp"
#include "pretty_logging.hpp"
#include "utils/hex_utils.hpp"
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
  int log_level = static_cast<int>(redlog::get_level());
  bool verbose_enabled = log_level >= static_cast<int>(redlog::level::verbose);
  bool trace_enabled = log_level >= static_cast<int>(redlog::level::trace);
  size_t patch_size = entry.patch_bytes.size();
  if (patch_size == 0) {
    if (trace_enabled) {
      log.trc("skipping empty patch", redlog::field("address", utils::format_address(entry.address)));
    }
    return ok_result(static_cast<size_t>(0));
  }

  if (trace_enabled) {
    log.trc(
        "applying patch entry", redlog::field("address", utils::format_address(entry.address)),
        redlog::field("patch_size", patch_size), redlog::field("required", entry.spec.required)
    );
  }

  auto region = space.region_info(entry.address);
  if (!region.ok()) {
    return error_result<size_t>(region.status_info.code, "failed to resolve memory region");
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
    return error_result<size_t>(original_bytes.status_info.code, "failed to read original bytes");
  }

  auto merged = merge_patch_bytes(entry.patch_bytes, entry.patch_mask, original_bytes.value);
  if (!merged.ok()) {
    return error_result<size_t>(merged.status_info.code, merged.status_info.message);
  }

  std::vector<uint8_t> context_before;
  std::vector<uint8_t> context_after;
  uint64_t context_base = entry.address;
  bool has_context = false;
  if (verbose_enabled) {
    has_context = build_patch_context(
        space, entry.address, original_bytes.value, merged.value, context_before, context_after, context_base
    );
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
      auto restore = space.set_protection(entry.address, patch_size, original_protection);
      if (!restore.ok()) {
        log.wrn(
            "failed to restore original protection", redlog::field("address", utils::format_address(entry.address))
        );
      }
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
        auto restore = space.set_protection(entry.address, patch_size, original_protection);
        if (!restore.ok()) {
          log.wrn(
              "failed to restore original protection", redlog::field("address", utils::format_address(entry.address))
          );
        }
      }
      return error_result<size_t>(error_code::verification_failed, "patch verification failed");
    }
  }

  if (options.flush_icache && executable) {
    auto flush = space.flush_instruction_cache(entry.address, patch_size);
    if (!flush.ok()) {
      log.wrn("failed to flush instruction cache", redlog::field("address", utils::format_address(entry.address)));
    }
  }

  if (needs_protection_change) {
    auto restore = space.set_protection(entry.address, patch_size, original_protection);
    if (!restore.ok()) {
      log.wrn("failed to restore original protection", redlog::field("address", utils::format_address(entry.address)));
    }
  }

  size_t bytes_written = count_written_bytes(entry.patch_mask);
  if (verbose_enabled) {
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
  }

  log.inf(
      "patch applied", redlog::field("address", utils::format_address(entry.address)),
      redlog::field("bytes_written", bytes_written)
  );

  return ok_result(bytes_written);
}

} // namespace

result<apply_report> apply_plan(
    address_space& space, const std::vector<plan_entry>& plan, const apply_options& options
) {
  auto log = redlog::get_logger("p1ll.apply");
  apply_report report;

  log.inf("applying patch plan", redlog::field("entries", plan.size()));
  if (static_cast<int>(redlog::get_level()) >= static_cast<int>(redlog::level::trace)) {
    log.trc(
        "apply options", redlog::field("verify", options.verify), redlog::field("flush_icache", options.flush_icache),
        redlog::field("rollback_on_failure", options.rollback_on_failure), redlog::field("allow_wx", options.allow_wx)
    );
  }

  for (const auto& entry : plan) {
    auto applied = apply_entry(space, entry, options);
    if (!applied.ok()) {
      report.failed++;
      report.diagnostics.push_back(applied.status_info);
      if (entry.spec.required) {
        log.err(
            "required patch failed", redlog::field("address", utils::format_address(entry.address)),
            redlog::field("signature", entry.spec.signature.pattern), redlog::field("error", applied.status_info.message)
        );
        report.success = false;
        return result<apply_report>{report, applied.status_info};
      }
      log.wrn(
          "optional patch failed", redlog::field("address", utils::format_address(entry.address)),
          redlog::field("signature", entry.spec.signature.pattern), redlog::field("error", applied.status_info.message)
      );
      continue;
    }

    report.applied++;
  }

  report.success = (report.failed == 0 && report.applied > 0);
  log.inf(
      "patch plan complete", redlog::field("success", report.success), redlog::field("applied", report.applied),
      redlog::field("failed", report.failed)
  );
  return ok_result(report);
}

} // namespace p1ll::engine
