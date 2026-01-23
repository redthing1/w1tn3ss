#include "rewind_engine.hpp"

#include <algorithm>
#include <string_view>
#include <utility>

#include "w1base/arch_spec.hpp"

namespace w1rewind {
namespace {

constexpr uint64_t k_module_id_offset = 1;

std::string_view basename_view(std::string_view path) {
  const auto pos = path.find_last_of("/\\");
  if (pos == std::string_view::npos) {
    return path;
  }
  return path.substr(pos + 1);
}

} // namespace

using module_record = w1::rewind::module_record;
using module_load_record = w1::rewind::module_load_record;
using module_unload_record = w1::rewind::module_unload_record;

rewind_engine::rewind_engine(rewind_config config)
    : config_(std::move(config)), registry_(w1::core::instrumented_module_policy{config_.common.instrumentation}),
      log_(redlog::get_logger("w1rewind.engine")),
      instruction_flow_(config_.flow.mode == rewind_config::flow_options::flow_mode::instruction) {}

void rewind_engine::configure(w1::runtime::module_catalog& modules) {
  std::lock_guard<std::mutex> lock(mutex_);

  modules_ = &modules;
  if (configured_) {
    return;
  }

  registry_.configure(modules);
  trace_ready_.store(false, std::memory_order_release);
  trace_failed_.store(false, std::memory_order_release);
  register_schema_.clear();
  module_table_.clear();

  if (writer_) {
    writer_->close();
  }
  writer_.reset();
  builder_.reset();
  emitter_.reset();

  arch_spec_ = w1::arch::detect_host_arch_spec();
  metadata_cache_.emplace(arch_spec_);

  rebuild_module_state_locked(modules);

  w1::rewind::trace_file_writer_config writer_config;
  writer_config.path = config_.output_path;
  writer_config.log = redlog::get_logger("w1rewind.trace");
  writer_config.compression =
      config_.compress_trace ? w1::rewind::trace_compression::zstd : w1::rewind::trace_compression::none;
  writer_config.chunk_size = config_.chunk_size;

  writer_ = w1::rewind::make_trace_file_writer(writer_config);
  if (!writer_ || !writer_->open()) {
    trace_failed_.store(true, std::memory_order_release);
    log_.err("failed to open trace writer", redlog::field("path", writer_config.path));
    return;
  }

  w1::rewind::trace_builder_config builder_config;
  builder_config.sink = writer_;
  builder_config.log = writer_config.log;
  builder_config.options.record_instructions = instruction_flow_;
  builder_config.options.record_register_deltas = config_.registers.deltas;
  builder_config.options.record_memory_access = config_.memory.access != rewind_config::memory_access::none;
  builder_config.options.record_memory_values = config_.memory.values;
  builder_config.options.record_snapshots =
      config_.registers.snapshot_interval > 0 || config_.stack_snapshots.interval > 0;
  builder_config.options.record_stack_segments = config_.stack_snapshots.interval > 0;

  builder_ = std::make_unique<w1::rewind::trace_builder>(std::move(builder_config));
  emitter_ = std::make_unique<trace_emitter>(builder_.get(), config_, instruction_flow_);
  configured_ = true;
}

bool rewind_engine::ensure_trace_ready(w1::trace_context& ctx, const w1::util::register_state& regs) {
  if (trace_ready()) {
    return true;
  }
  if (trace_failed_.load(std::memory_order_acquire)) {
    return false;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  if (trace_ready_.load(std::memory_order_acquire)) {
    return true;
  }
  if (trace_failed_.load(std::memory_order_acquire)) {
    return false;
  }

  if (!start_trace_locked(ctx, regs)) {
    trace_failed_.store(true, std::memory_order_release);
    return false;
  }

  trace_ready_.store(true, std::memory_order_release);
  return true;
}

bool rewind_engine::start_trace_locked(w1::trace_context& ctx, const w1::util::register_state& regs) {
  if (!builder_ || !builder_->good()) {
    log_.err("trace builder not ready");
    return false;
  }

  if (arch_spec_.arch_family == w1::arch::family::unknown || arch_spec_.arch_mode == w1::arch::mode::unknown) {
    log_.err("unsupported host architecture");
    return false;
  }

  register_schema_.update(regs, arch_spec_);
  if (register_schema_.empty()) {
    log_.err("register specs missing");
    return false;
  }

  ctx.modules().refresh();
  rebuild_module_state_locked(ctx.modules());

  auto memory_map = collect_memory_map(module_table_);

  w1::rewind::target_info_record target{};
  target.os = detect_os_id();

  auto environment = build_target_environment(memory_map, module_table_, arch_spec_);

  if (!builder_->begin_trace(arch_spec_, target, environment, register_schema_.specs())) {
    log_.err("failed to begin trace", redlog::field("error", builder_->error()));
    return false;
  }

  if (!module_table_.empty()) {
    if (!builder_->set_module_table(module_table_)) {
      log_.err("failed to write module table", redlog::field("error", builder_->error()));
      return false;
    }
  }

  if (!memory_map.empty()) {
    if (!builder_->set_memory_map(std::move(memory_map))) {
      log_.err("failed to write memory map", redlog::field("error", builder_->error()));
      return false;
    }
  }

  return true;
}

void rewind_engine::rebuild_module_state_locked(const w1::runtime::module_catalog& modules) {
  module_table_.clear();
  auto list = modules.list_modules();
  module_table_.reserve(list.size());

  if (!metadata_cache_.has_value()) {
    metadata_cache_.emplace(arch_spec_);
  }

  for (const auto& module : list) {
    auto lookup = registry_.find(module.base_address);
    if (!lookup) {
      continue;
    }

    const uint64_t id = lookup->value + k_module_id_offset;
    module_table_.push_back(build_module_record(module, id, *metadata_cache_));
  }
}

std::optional<w1::runtime::module_info> rewind_engine::find_module_info(const w1::monitor::module_event& event) const {
  if (!modules_) {
    return std::nullopt;
  }

  const uint64_t base = reinterpret_cast<uint64_t>(event.base);
  auto list = modules_->list_modules();

  if (base != 0) {
    auto it = std::find_if(list.begin(), list.end(), [&](const w1::runtime::module_info& module) {
      return module.full_range.start <= base && base < module.full_range.end;
    });
    if (it != list.end()) {
      return *it;
    }
  }

  if (!event.path.empty()) {
    const std::string_view event_path = event.path;
    const std::string_view event_name = basename_view(event_path);
    auto it = std::find_if(list.begin(), list.end(), [&](const w1::runtime::module_info& module) {
      if (module.path == event_path || module.name == event_path) {
        return true;
      }
      if (!event_name.empty() && (module.name == event_name || basename_view(module.path) == event_name)) {
        return true;
      }
      return false;
    });
    if (it != list.end()) {
      return *it;
    }
  }

  return std::nullopt;
}

bool rewind_engine::handle_module_loaded_locked(const w1::runtime::module_info& module) {
  if (!metadata_cache_.has_value()) {
    metadata_cache_.emplace(arch_spec_);
  }

  auto lookup = registry_.find(module.base_address);
  if (!lookup) {
    return false;
  }

  const uint64_t id = lookup->value + k_module_id_offset;
  module_record record = build_module_record(module, id, *metadata_cache_);
  upsert_module_record(record);

  if (trace_ready_.load(std::memory_order_acquire) && builder_ && builder_->good()) {
    if (!builder_->emit_module_load(module_load_record{record})) {
      log_.err("failed to write module load", redlog::field("error", builder_->error()));
    } else if (!emit_memory_map_locked()) {
      log_.err("failed to update memory map", redlog::field("error", builder_->error()));
    }
  }

  return true;
}

void rewind_engine::handle_module_unloaded_locked(const w1::monitor::module_event& event) {
  const uint64_t base = reinterpret_cast<uint64_t>(event.base);
  auto removed = remove_module_record(0, base, event.path);
  if (!removed.has_value()) {
    return;
  }

  module_unload_record record{};
  record.module_id = removed->id;
  record.base = removed->base;
  record.size = removed->size;
  record.path = removed->path;

  if (trace_ready_.load(std::memory_order_acquire) && builder_ && builder_->good()) {
    if (!builder_->emit_module_unload(record)) {
      log_.err("failed to write module unload", redlog::field("error", builder_->error()));
    } else if (!emit_memory_map_locked()) {
      log_.err("failed to update memory map", redlog::field("error", builder_->error()));
    }
  }
}

void rewind_engine::upsert_module_record(module_record record) {
  auto it = std::find_if(module_table_.begin(), module_table_.end(), [&](const module_record& entry) {
    return entry.id == record.id;
  });
  if (it == module_table_.end()) {
    it = std::find_if(module_table_.begin(), module_table_.end(), [&](const module_record& entry) {
      return entry.base == record.base && entry.base != 0;
    });
  }
  if (it != module_table_.end()) {
    *it = std::move(record);
    return;
  }
  module_table_.push_back(std::move(record));
}

std::optional<module_record> rewind_engine::remove_module_record(
    uint64_t module_id, uint64_t base, const std::string& path
) {
  auto it = module_table_.end();
  if (module_id != 0) {
    it = std::find_if(module_table_.begin(), module_table_.end(), [&](const module_record& entry) {
      return entry.id == module_id;
    });
  }

  if (it == module_table_.end() && base != 0) {
    it = std::find_if(module_table_.begin(), module_table_.end(), [&](const module_record& entry) {
      return entry.base == base;
    });
  }

  if (it == module_table_.end() && !path.empty()) {
    it = std::find_if(module_table_.begin(), module_table_.end(), [&](const module_record& entry) {
      return entry.path == path;
    });
  }

  if (it == module_table_.end()) {
    return std::nullopt;
  }

  module_record removed = *it;
  module_table_.erase(it);
  return removed;
}

bool rewind_engine::emit_memory_map_locked() {
  if (!builder_ || !builder_->good()) {
    return false;
  }
  auto memory_map = collect_memory_map(module_table_);
  if (memory_map.empty()) {
    return true;
  }
  return builder_->set_memory_map(std::move(memory_map));
}

bool rewind_engine::begin_thread(uint64_t thread_id, const std::string& name) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!emitter_) {
    return false;
  }
  return emitter_->begin_thread(thread_id, name);
}

bool rewind_engine::emit_block(
    uint64_t thread_id, uint64_t address, uint32_t size, uint32_t flags, uint64_t& sequence_out
) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!emitter_) {
    return false;
  }
  return emitter_->emit_block(thread_id, address, size, flags, sequence_out);
}

void rewind_engine::flush_pending(std::optional<pending_instruction>& pending) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (emitter_) {
    emitter_->flush_pending(pending);
  }
}

bool rewind_engine::emit_snapshot(
    uint64_t thread_id, uint64_t sequence, uint64_t snapshot_id, std::span<const w1::rewind::register_delta> registers,
    std::span<const w1::rewind::stack_segment> stack_segments, std::string reason
) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!builder_ || !builder_->good()) {
    return false;
  }
  return builder_->emit_snapshot(thread_id, sequence, snapshot_id, registers, stack_segments, std::move(reason));
}

void rewind_engine::finalize_thread(
    uint64_t thread_id, const std::string& name, std::optional<pending_instruction>& pending
) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (emitter_) {
    emitter_->flush_pending(pending);
    emitter_->finalize_thread(thread_id, name);
  }
}

void rewind_engine::on_process_event(const w1::runtime::process_event& event) {
  if (trace_failed_.load(std::memory_order_acquire)) {
    return;
  }

  if (event.type != w1::runtime::process_event::kind::module_loaded &&
      event.type != w1::runtime::process_event::kind::module_unloaded) {
    return;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  auto info = find_module_info(event.module);

  if (event.type == w1::runtime::process_event::kind::module_loaded) {
    if (info.has_value()) {
      handle_module_loaded_locked(*info);
    } else {
      log_.wrn("module load event missing module info", redlog::field("path", event.module.path));
    }
  } else if (event.type == w1::runtime::process_event::kind::module_unloaded) {
    handle_module_unloaded_locked(event.module);
  }
}

bool rewind_engine::export_trace() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (builder_) {
    builder_->flush();
  }
  bool ok = writer_ && writer_->good();
  if (writer_) {
    writer_->close();
  }
  configured_ = false;
  trace_ready_.store(false, std::memory_order_release);
  return ok;
}

size_t rewind_engine::module_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return module_table_.size();
}

std::string rewind_engine::output_path() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return writer_ ? writer_->path() : std::string{};
}

} // namespace w1rewind
