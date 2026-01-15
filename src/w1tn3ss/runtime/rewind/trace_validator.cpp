#include "trace_validator.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <exception>
#include <initializer_list>
#include <sstream>
#include <utility>

namespace w1::rewind {

namespace {

std::string to_lower_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

std::optional<uint64_t> decode_memory_value(const trace_memory_delta& delta) {
  if (!delta.value_known || delta.data.empty() || delta.data.size() > sizeof(uint64_t)) {
    return std::nullopt;
  }

  uint64_t value = 0;
  for (size_t i = 0; i < delta.data.size(); ++i) {
    value |= static_cast<uint64_t>(delta.data[i]) << (i * 8);
  }
  return value;
}

} // namespace

trace_validator::trace_validator(trace_validator_config config) : config_(std::move(config)) {
  for (auto name : config_.ignore_registers) {
    ignore_registers_.insert(to_lower_copy(std::move(name)));
  }

  ignore_modules_.reserve(config_.ignore_modules.size());
  for (auto module : config_.ignore_modules) {
    ignore_modules_.push_back(to_lower_copy(std::move(module)));
  }

#if defined(QBDI_ARCH_AARCH64)
  // QBDI reserves x16/x17 as veneer scratch registers and x18/lr/nzcv for TLS bookkeeping.
  // On Darwin we also reuse x5 while detouring pthread entry points to locate the w1runtime context.
  scratch_policy_.names = {
      "x16",
      "x17",
      "x18",
      "lr",
      "nzcv"
#if defined(__APPLE__)
      ,
      "x5"
#endif
  };
#elif defined(QBDI_ARCH_X86_64)
  // On x86_64, the runtime uses high registers for helper shims; see qbdi/docs/registers.rst.
  scratch_policy_.names = {"r15", "r14", "r13", "r12", "r11"};
#elif defined(QBDI_ARCH_X86)
  // QBDI marks esi/edi/ebx as callee-saved scratch in its dispatcher.
  scratch_policy_.names = {"esi", "edi", "ebx"};
#else
  scratch_policy_.names.clear();
#endif
}

bool trace_validator::initialize() {
  if (!config_.source) {
    config_.log.err("trace validator missing source");
    return false;
  }

  if (!config_.source->initialize()) {
    config_.log.err("failed to initialize trace source for validation");
    return false;
  }

  stats_ = {};
  mismatches_.clear();
  threads_.clear();
  module_cache_initialized_ = false;
  initialized_ = true;
  finalized_ = false;
  config_.log.inf("trace validator ready");
  return true;
}

void trace_validator::close() {
  if (config_.source) {
    config_.source->close();
  }
  initialized_ = false;
  finalized_ = true;
}

trace_validator::result trace_validator::verify(const trace_event& live_event) {
  if (!initialized_) {
    return result::ok;
  }

  trace_event expected;
  if (!fetch_expected(live_event.thread_id, expected)) {
    record_mismatch(
        trace_mismatch::kind::unexpected_event, live_event.thread_id, live_event.sequence,
        "unexpected live event (no more expected events for this thread)"
    );
    if (config_.mode == validation_mode::strict) {
      stats_.aborted = true;
      return result::abort;
    }
    return result::mismatch_logged;
  }

  stats_.events_checked += 1;

  if (!compare_events(live_event, expected)) {
    if (config_.mode == validation_mode::strict) {
      stats_.aborted = true;
      return result::abort;
    }
    return result::mismatch_logged;
  }

  if (stats_.aborted && config_.mode == validation_mode::strict) {
    return result::abort;
  }

  return result::ok;
}

void trace_validator::finalize() {
  if (!initialized_ || finalized_) {
    return;
  }

  trace_event leftover;
  while (config_.source && config_.source->good()) {
    if (!config_.source->read_event(leftover)) {
      break;
    }
    threads_[leftover.thread_id].pending_events.push_back(leftover);
  }

  for (auto& entry : threads_) {
    auto& queue = entry.second.pending_events;
    while (!queue.empty()) {
      auto expected = queue.front();
      queue.pop_front();
      record_mismatch(
          trace_mismatch::kind::missing_expected_event, expected.thread_id, expected.sequence,
          "expected event missing from live trace"
      );
    }
  }

  if (config_.mode == validation_mode::strict && stats_.mismatches > 0) {
    stats_.aborted = true;
  }

  finalized_ = true;
}

trace_validator::thread_state& trace_validator::state_for_thread(uint64_t thread_id) {
  return threads_[thread_id];
}

bool trace_validator::fetch_expected(uint64_t thread_id, trace_event& expected) {
  auto& pending = state_for_thread(thread_id).pending_events;
  if (!pending.empty()) {
    expected = pending.front();
    pending.pop_front();
    return true;
  }

  while (config_.source->good()) {
    trace_event candidate;
    if (!config_.source->read_event(candidate)) {
      break;
    }

    auto& queue = state_for_thread(candidate.thread_id).pending_events;
    queue.push_back(candidate);

    if (candidate.thread_id == thread_id) {
      expected = queue.front();
      queue.pop_front();
      return true;
    }
  }

  if (!pending.empty()) {
    expected = pending.front();
    pending.pop_front();
    return true;
  }

  return false;
}

bool trace_validator::compare_instruction_events(const trace_event& live_event, const trace_event& expected) {
  bool ok = true;

  if (live_event.sequence != expected.sequence) {
    record_mismatch(
        trace_mismatch::kind::address_mismatch, live_event.thread_id, live_event.sequence,
        "sequence mismatch between live and expected trace"
    );
    ok = false;
  }

  if (live_event.address != expected.address) {
    record_mismatch(
        trace_mismatch::kind::address_mismatch, live_event.thread_id, live_event.sequence,
        "instruction address mismatch"
    );
    ok = false;
  }

  if (live_event.size != expected.size) {
    record_mismatch(
        trace_mismatch::kind::size_mismatch, live_event.thread_id, live_event.sequence, "instruction size mismatch"
    );
    ok = false;
  }

  auto& state = state_for_thread(live_event.thread_id);
  auto& actual_regs_cache = state.last_actual_registers;
  auto& expected_regs_cache = state.last_expected_registers;

  auto get_cached_value = [](const trace_event& event, const std::unordered_map<std::string, uint64_t>& cache,
                             std::initializer_list<const char*> names) -> std::optional<uint64_t> {
    for (const auto* name : names) {
      for (const auto& entry : event.registers) {
        if (entry.name == name) {
          return entry.value;
        }
      }
      auto it = cache.find(name);
      if (it != cache.end()) {
        return it->second;
      }
    }
    return std::nullopt;
  };

  const auto actual_sp = get_cached_value(live_event, actual_regs_cache, {"sp", "rsp", "esp"});
  const auto expected_sp = get_cached_value(expected, expected_regs_cache, {"sp", "rsp", "esp"});
  const auto actual_fp = get_cached_value(live_event, actual_regs_cache, {"x29", "rbp", "ebp", "r11"});
  const auto expected_fp = get_cached_value(expected, expected_regs_cache, {"x29", "rbp", "ebp", "r11"});

  if (!compare_registers(live_event, expected, actual_sp, expected_sp, actual_fp, expected_fp)) {
    ok = false;
  }

  if (!compare_memory(
          live_event.reads, expected.reads, live_event.thread_id, live_event.sequence, "read", actual_sp, expected_sp,
          actual_fp, expected_fp
      )) {
    ok = false;
  }

  if (!compare_memory(
          live_event.writes, expected.writes, live_event.thread_id, live_event.sequence, "write", actual_sp,
          expected_sp, actual_fp, expected_fp
      )) {
    ok = false;
  }

  update_register_cache(live_event, actual_regs_cache);
  update_register_cache(expected, expected_regs_cache);

  return ok;
}

bool trace_validator::compare_boundary_events(const trace_event& live_event, const trace_event& expected) {
  reset_thread_caches(live_event.thread_id);

  bool ok = compare_instruction_events(live_event, expected);

  const bool live_has_metadata = live_event.boundary.has_value();
  const bool expected_has_metadata = expected.boundary.has_value();
  if (live_has_metadata != expected_has_metadata) {
    record_mismatch(
        trace_mismatch::kind::unexpected_event, live_event.thread_id, live_event.sequence, "boundary metadata mismatch"
    );
    ok = false;
  } else if (live_has_metadata) {
    if (live_event.boundary->boundary_id != expected.boundary->boundary_id) {
      record_mismatch(
          trace_mismatch::kind::unexpected_event, live_event.thread_id, live_event.sequence,
          "boundary identifier mismatch"
      );
      ok = false;
    }
    if (live_event.boundary->flags != expected.boundary->flags) {
      record_mismatch(
          trace_mismatch::kind::unexpected_event, live_event.thread_id, live_event.sequence, "boundary flag mismatch"
      );
      ok = false;
    }
    if (live_event.boundary->reason != expected.boundary->reason) {
      record_mismatch(
          trace_mismatch::kind::unexpected_event, live_event.thread_id, live_event.sequence, "boundary reason mismatch"
      );
      ok = false;
    }
  }

  return ok;
}

bool trace_validator::compare_events(const trace_event& live_event, const trace_event& expected) {
  if (live_event.type != expected.type) {
    record_mismatch(
        trace_mismatch::kind::unexpected_event, live_event.thread_id, live_event.sequence,
        "event type mismatch between live and expected trace"
    );
    return false;
  }

  switch (live_event.type) {
  case trace_event_type::boundary:
    return compare_boundary_events(live_event, expected);
  case trace_event_type::instruction:
  default:
    return compare_instruction_events(live_event, expected);
  }
}

bool trace_validator::compare_registers(
    const trace_event& live_event, const trace_event& expected, std::optional<uint64_t> actual_sp,
    std::optional<uint64_t> expected_sp, std::optional<uint64_t> actual_fp, std::optional<uint64_t> expected_fp
) {
  auto& state = state_for_thread(live_event.thread_id);
  auto& window = state.window;
  auto& profiles = state.offset_profiles;
  if (live_event.registers.size() != expected.registers.size()) {
    record_mismatch(
        trace_mismatch::kind::register_mismatch, live_event.thread_id, live_event.sequence,
        "register delta count mismatch"
    );
    return false;
  }

  for (size_t i = 0; i < live_event.registers.size(); ++i) {
    const auto& actual = live_event.registers[i];
    const auto& target = expected.registers[i];
    if (actual.name != target.name) {
      std::ostringstream oss;
      oss << "register mismatch: unexpected register ordering (" << actual.name << " vs " << target.name << ")";
      record_mismatch(trace_mismatch::kind::register_mismatch, live_event.thread_id, live_event.sequence, oss.str());
      return false;
    }

    if (actual.value == target.value || should_ignore_register(actual.name, actual.value)) {
      continue;
    }

    const int64_t diff = static_cast<int64_t>(actual.value) - static_cast<int64_t>(target.value);
    const int64_t window_bytes = static_cast<int64_t>(config_.stack_window_bytes);

    auto matches_relative = [&](std::optional<uint64_t> live_base, std::optional<uint64_t> expected_base) {
      if (!live_base.has_value() || !expected_base.has_value()) {
        return false;
      }
      const int64_t live_rel = static_cast<int64_t>(actual.value) - static_cast<int64_t>(*live_base);
      const int64_t exp_rel = static_cast<int64_t>(target.value) - static_cast<int64_t>(*expected_base);
      return live_rel == exp_rel;
    };

    auto update_diff_slot = [&](std::optional<int64_t>& slot) {
      if (!slot.has_value()) {
        slot = diff;
        return true;
      }
      if (*slot == diff) {
        return true;
      }
      if (window_bytes > 0 && std::llabs(diff - *slot) <= window_bytes) {
        slot = diff;
        return true;
      }
      return false;
    };

    const std::string lowered = to_lower_copy(actual.name);
    const bool is_stack_reg = (lowered == "sp" || lowered == "rsp" || lowered == "esp");
    const bool is_frame_reg = (lowered == "x29" || lowered == "rbp" || lowered == "ebp" || lowered == "r11");
    const bool is_scratch_reg = scratch_policy_.contains(lowered);

    if (window.live_canary && window.expected_canary && actual.value == *window.live_canary &&
        target.value == *window.expected_canary) {
      continue;
    }

    if (is_stack_reg && update_diff_slot(window.sp_diff)) {
      continue;
    }
    if (is_frame_reg && update_diff_slot(window.fp_diff)) {
      continue;
    }

    if (is_scratch_reg) {
      // instrumentation/runtime helpers are allowed to clobber scratch registers; keep the diff for diagnostics
      // but do not fail validation unless the value later leaks into user-visible state.
      window.register_diffs[lowered] = diff;
      continue;
    }

    if (matches_relative(actual_sp, expected_sp) || matches_relative(actual_fp, expected_fp)) {
      continue;
    }

    if ((window.sp_diff.has_value() && *window.sp_diff == diff) ||
        (window.fp_diff.has_value() && *window.fp_diff == diff)) {
      continue;
    }

    if (window_bytes > 0 && std::llabs(diff) <= window_bytes) {
      if (update_diff_slot(window.sp_diff) || update_diff_slot(window.fp_diff)) {
        continue;
      }
    }

    if (check_offset_profiles(profiles, live_event, expected, actual, target, diff)) {
      continue;
    }

    auto& general_diffs = window.register_diffs;
    auto diff_it = general_diffs.find(lowered);
    if (diff_it != general_diffs.end()) {
      if (diff_it->second == diff) {
        continue;
      }
    } else {
      const bool looks_like_pointer = actual.value >= 0x1000 && target.value >= 0x1000;
      if ((window_bytes > 0 && std::llabs(diff) <= window_bytes) || looks_like_pointer) {
        general_diffs.emplace(lowered, diff);
        continue;
      }
    }

    std::ostringstream oss;
    oss << "register mismatch: " << actual.name << "=0x" << std::hex << actual.value << " expected " << target.name
        << "=0x" << target.value;
    record_mismatch(trace_mismatch::kind::register_mismatch, live_event.thread_id, live_event.sequence, oss.str());
    return false;
  }

  return true;
}

bool trace_validator::compare_memory(
    const std::vector<trace_memory_delta>& live_accesses, const std::vector<trace_memory_delta>& expected_accesses,
    uint64_t thread_id, uint64_t sequence, const char* kind, std::optional<uint64_t> actual_sp,
    std::optional<uint64_t> expected_sp, std::optional<uint64_t> actual_fp, std::optional<uint64_t> expected_fp
) {
  auto& state = state_for_thread(thread_id);
  auto& window = state.window;
  const int64_t window_bytes = static_cast<int64_t>(config_.stack_window_bytes);

  if (live_accesses.size() != expected_accesses.size()) {
    std::ostringstream oss;
    oss << kind << " access count mismatch";
    record_mismatch(trace_mismatch::kind::memory_mismatch, thread_id, sequence, oss.str());
    return false;
  }

  for (size_t i = 0; i < live_accesses.size(); ++i) {
    const auto& actual = live_accesses[i];
    const auto& target = expected_accesses[i];
    bool address_ok = actual.address == target.address;
    const auto actual_value = decode_memory_value(actual);
    const auto expected_value = decode_memory_value(target);

    if (actual_value && *actual_value != 0 && is_stack_canary_write(actual.address, actual.size, actual_fp)) {
      if (!window.live_canary.has_value()) {
        window.live_canary = *actual_value;
      }
    }
    if (expected_value && *expected_value != 0 && is_stack_canary_write(target.address, target.size, expected_fp)) {
      if (!window.expected_canary.has_value()) {
        window.expected_canary = *expected_value;
      }
    }

    auto matches_relative = [&](std::optional<uint64_t> live_base, std::optional<uint64_t> expected_base) {
      if (!live_base.has_value() || !expected_base.has_value()) {
        return false;
      }
      const int64_t live_rel = static_cast<int64_t>(actual.address) - static_cast<int64_t>(*live_base);
      const int64_t exp_rel = static_cast<int64_t>(target.address) - static_cast<int64_t>(*expected_base);
      return live_rel == exp_rel;
    };

    if (!address_ok) {
      const int64_t diff = static_cast<int64_t>(actual.address) - static_cast<int64_t>(target.address);
      auto try_slot = [&](std::optional<int64_t>& slot) {
        if (!slot.has_value()) {
          slot = diff;
          return true;
        }
        if (*slot == diff) {
          return true;
        }
        if (window_bytes > 0 && std::llabs(diff - *slot) <= window_bytes) {
          slot = diff;
          return true;
        }
        return false;
      };

      if (matches_relative(actual_sp, expected_sp) || matches_relative(actual_fp, expected_fp) ||
          try_slot(window.sp_diff) || try_slot(window.fp_diff)) {
        address_ok = true;
      } else if (window_bytes > 0 && std::llabs(diff) <= window_bytes) {
        if (try_slot(window.sp_diff) || try_slot(window.fp_diff)) {
          address_ok = true;
        }
      }
    }

    if (!address_ok || actual.size != target.size || actual.value_known != target.value_known ||
        actual.data != target.data) {
      bool values_ignored = address_ok && actual.size == target.size && actual.value_known == target.value_known &&
                            actual_value &&
                            expected_value
                            // a stack write that stores a helper pointer is expected as QBDI saves its TLS there.
                            && (should_ignore_value(*actual_value) || should_ignore_value(*expected_value));

      if (!values_ignored && actual_value && expected_value) {
        const int64_t value_diff = static_cast<int64_t>(*actual_value) - static_cast<int64_t>(*expected_value);
        if (window.sp_diff.has_value() && value_diff == *window.sp_diff) {
          values_ignored = true;
        } else if (window.fp_diff.has_value() && value_diff == *window.fp_diff) {
          values_ignored = true;
        } else {
          const int64_t window_bytes = static_cast<int64_t>(config_.stack_window_bytes);
          if (window_bytes > 0 && std::llabs(value_diff) <= window_bytes) {
            if (window.sp_diff.has_value() && std::llabs(value_diff - *window.sp_diff) <= window_bytes) {
              values_ignored = true;
            } else if (window.fp_diff.has_value() && std::llabs(value_diff - *window.fp_diff) <= window_bytes) {
              values_ignored = true;
            }
          }
        }
      }

      if (!values_ignored && (is_stack_canary_write(actual.address, actual.size, actual_fp) ||
                              is_stack_canary_write(target.address, target.size, expected_fp))) {
        values_ignored = true;
      }

      if (!values_ignored && kind != nullptr && kind[0] == 'r') {
        // tolerate reaad drifts for randomized globals, if the address is inside an ignored helper module
        auto address_module = module_name_for_address(actual.address);
        if (address_module && module_matches_ignore(*address_module)) {
          values_ignored = true;
        }
      }

      if (values_ignored) {
        continue;
      }

      std::ostringstream oss;
      oss << kind << " mismatch at 0x" << std::hex << actual.address;
      record_mismatch(trace_mismatch::kind::memory_mismatch, thread_id, sequence, oss.str());
      return false;
    }
  }

  return true;
}

bool trace_validator::check_offset_profiles(
    std::vector<offset_profile>& profiles, const trace_event& live_event, const trace_event& expected,
    const trace_register_delta& actual, const trace_register_delta& target, int64_t diff
) {
  const uint64_t boundary_id = live_event.boundary ? live_event.boundary->boundary_id : 0;
  auto matches_profile = [&](offset_profile& profile) {
    if (profile.reg_name != actual.name) {
      return false;
    }
    if (boundary_id != 0 && profile.boundary_id != boundary_id) {
      // we reset profiles on boundary changes, but keep this guard in case an event arrives without reset
      return false;
    }
    if (profile.delta == diff) {
      return true;
    }
    if (profile.slack != 0 && std::llabs(diff - profile.delta) <= profile.slack) {
      profile.delta = diff;
      return true;
    }
    return false;
  };

  for (auto& profile : profiles) {
    if (matches_profile(profile)) {
      return true;
    }
  }

  // adopt new profile only when both values point into the same helper module; this avoids masking real divergences
  if (actual.value != target.value) {
    auto actual_module = module_name_for_address(actual.value);
    auto expected_module = module_name_for_address(target.value);
    if (actual_module && expected_module && module_matches_ignore(*actual_module) &&
        module_matches_ignore(*expected_module)) {
      if (profiles.size() >= 16) {
        profiles.erase(profiles.begin());
      }
      profiles.push_back(offset_profile{actual.name, diff, 16, boundary_id});
      return true;
    }

    const uint64_t pointer_alignment_mask = sizeof(void*) - 1u;
    const bool looks_like_pointer =
        (actual.value >= 0x1000u) && (target.value >= 0x1000u) &&
        ((actual.value & pointer_alignment_mask) == (target.value & pointer_alignment_mask));
    if (looks_like_pointer) {
      config_.log.dbg(
          "register pointer tolerance", redlog::field("register", actual.name.c_str()),
          redlog::field("actual", actual.value), redlog::field("expected", target.value)
      );
      return true;
    }
  }

  return false;
}

bool trace_validator::is_stack_canary_write(
    uint64_t address, size_t size, std::optional<uint64_t> frame_pointer
) const {
  if (!frame_pointer.has_value()) {
    return false;
  }

#if defined(QBDI_ARCH_X86_64) || defined(QBDI_ARCH_AARCH64)
  constexpr size_t pointer_size = 8;
#elif defined(QBDI_ARCH_X86)
  constexpr size_t pointer_size = 4;
#else
  constexpr size_t pointer_size = sizeof(void*);
#endif

  if (size != pointer_size) {
    return false;
  }

  const int64_t offset = static_cast<int64_t>(*frame_pointer) - static_cast<int64_t>(address);
  if (offset < 0) {
    return false;
  }

  const int64_t lower = static_cast<int64_t>(pointer_size * 2);
  const int64_t upper = static_cast<int64_t>(pointer_size * 6);
  if (offset < lower || offset > upper) {
    return false;
  }

  return (offset % static_cast<int64_t>(pointer_size)) == 0;
}

bool trace_validator::should_ignore_register(const std::string& name, uint64_t value) {
  if (ignore_registers_.empty() && ignore_modules_.empty()) {
    return false;
  }

  const std::string lowered = to_lower_copy(name);
  if (scratch_policy_.contains(lowered)) {
    if (value != 0) {
      auto module_name = module_name_for_address(value);
      if (module_name.has_value() && module_matches_ignore(*module_name)) {
        // helper scratch register pointing into a known runtime module
        return true;
      }
    }
  }

  if (!ignore_registers_.empty() && ignore_registers_.count(lowered) != 0) {
    return true;
  }

  if (ignore_modules_.empty() || value == 0) {
    return false;
  }

  auto module_name = module_name_for_address(value);
  if (!module_name.has_value()) {
    return false;
  }

  return module_matches_ignore(*module_name);
}

bool trace_validator::should_ignore_value(uint64_t value) {
  if (ignore_modules_.empty() || value == 0) {
    return false;
  }

  auto module_name = module_name_for_address(value);
  if (!module_name.has_value()) {
    return false;
  }

  return module_matches_ignore(*module_name);
}

void trace_validator::reset_thread_caches(uint64_t thread_id) {
  auto& state = state_for_thread(thread_id);
  state.window = {};
  state.last_actual_registers.clear();
  state.last_expected_registers.clear();
  state.offset_profiles.clear();
}

void trace_validator::update_register_cache(
    const trace_event& event, std::unordered_map<std::string, uint64_t>& cache
) {
  for (const auto& reg : event.registers) {
    cache[reg.name] = reg.value;
  }
}

std::optional<std::string> trace_validator::module_name_for_address(uint64_t address) {
  if (ignore_modules_.empty() || address == 0) {
    return std::nullopt;
  }

  if (!module_cache_initialized_) {
    try {
      // include non-executable mappings so globals (e.g., stack guards) resolve to their owning modules.
      module_registry_.refresh();
    } catch (const std::exception& e) {
      config_.log.wrn("module scan failed", redlog::field("error", e.what()));
    }
    module_cache_initialized_ = true;
  }

  const auto* mod = module_registry_.find_containing(address);
  if (!mod) {
    return std::nullopt;
  }

  if (!mod->name.empty() && mod->name.rfind("_unnamed_", 0) == 0) {
    return std::nullopt;
  }

  if (!mod->path.empty()) {
    return mod->path;
  }
  if (!mod->name.empty()) {
    return mod->name;
  }
  return std::nullopt;
}

bool trace_validator::module_matches_ignore(const std::string& module_name) const {
  const std::string lowered = to_lower_copy(module_name);
  for (const auto& pattern : ignore_modules_) {
    if (lowered.find(pattern) != std::string::npos) {
      return true;
    }
  }
  return false;
}

void trace_validator::record_mismatch(
    trace_mismatch::kind type, uint64_t thread_id, uint64_t sequence, std::string message
) {
  stats_.mismatches += 1;
  mismatches_.push_back(trace_mismatch{type, thread_id, sequence, std::move(message)});
  config_.log.err(
      "validation mismatch", redlog::field("thread_id", thread_id), redlog::field("sequence", sequence),
      redlog::field("message", mismatches_.back().message)
  );

  if (config_.max_mismatches > 0 && stats_.mismatches >= config_.max_mismatches &&
      config_.mode == validation_mode::strict) {
    stats_.aborted = true;
  }
}

const trace_validator::scratch_register_policy& trace_validator::scratch_policy() const { return scratch_policy_; }

} // namespace w1::rewind
