#include "rewind_engine.hpp"

#include <algorithm>
#include <cctype>
#include <random>
#include <string>
#include <string_view>
#include <utility>

namespace w1rewind {
namespace {

std::string lower_ascii(std::string_view value) {
  std::string out(value);
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return out;
}

std::optional<uint16_t> find_mode_id(const w1::rewind::arch_descriptor_record& arch, std::string_view name) {
  std::string target = lower_ascii(name);
  for (const auto& mode : arch.modes) {
    if (lower_ascii(mode.name) == target) {
      return mode.mode_id;
    }
  }
  return std::nullopt;
}

uint16_t resolve_mode_id_for_arch(
    const w1::util::register_state* regs, const w1::rewind::arch_descriptor_record& arch
) {
  if (arch.modes.empty()) {
    return 0;
  }

  uint16_t default_mode = arch.modes.front().mode_id;
  if (!arch.arch_id.empty()) {
    if (auto arch_mode = find_mode_id(arch, arch.arch_id)) {
      default_mode = *arch_mode;
    }
  }
  auto arm_mode = find_mode_id(arch, "arm");
  auto thumb_mode = find_mode_id(arch, "thumb");

  bool thumb = false;
  std::string id = lower_ascii(arch.arch_id);
  if (id == "thumb") {
    thumb = true;
  }
  if (regs && thumb_mode.has_value()) {
    uint64_t cpsr = 0;
    if (regs->get_register("cpsr", cpsr)) {
      thumb = ((cpsr >> 5) & 1u) != 0;
    }
  }

  if (thumb && thumb_mode.has_value()) {
    return *thumb_mode;
  }
  if (arm_mode.has_value()) {
    return *arm_mode;
  }
  return default_mode;
}

std::array<uint8_t, 16> generate_trace_uuid() {
  std::array<uint8_t, 16> uuid{};
  std::random_device rd;
  for (auto& byte : uuid) {
    byte = static_cast<uint8_t>(rd());
  }
  bool all_zero = true;
  for (auto byte : uuid) {
    if (byte != 0) {
      all_zero = false;
      break;
    }
  }
  if (all_zero) {
    uuid[0] = 1;
  }
  return uuid;
}

} // namespace

rewind_engine::rewind_engine(rewind_config config)
    : config_(std::move(config)), log_(redlog::get_logger("w1rewind.engine")), image_pipeline_(log_),
      instruction_flow_(config_.flow.mode == rewind_config::flow_options::flow_mode::instruction) {}

uint16_t rewind_engine::resolve_mode_id(const w1::util::register_state* regs) const {
  return resolve_mode_id_for_arch(regs, arch_desc_);
}

void rewind_engine::set_register_schema(std::vector<w1::rewind::register_spec> specs) {
  std::lock_guard<std::mutex> lock(mutex_);
  register_schema_.set_specs(std::move(specs));
}

void rewind_engine::set_register_schema_provider(std::shared_ptr<register_schema_provider> provider) {
  std::lock_guard<std::mutex> lock(mutex_);
  register_schema_provider_ = std::move(provider);
}

void rewind_engine::set_arch_descriptor(w1::rewind::arch_descriptor_record arch) {
  std::lock_guard<std::mutex> lock(mutex_);
  arch_desc_ = std::move(arch);
  arch_configured_ = true;
}

void rewind_engine::set_environment_record(w1::rewind::environment_record env) {
  std::lock_guard<std::mutex> lock(mutex_);
  environment_record_ = std::move(env);
  environment_configured_ = true;
}

void rewind_engine::configure(std::shared_ptr<image_inventory_provider> provider) {
  std::lock_guard<std::mutex> lock(mutex_);

  if (!arch_configured_) {
    trace_failed_.store(true, std::memory_order_release);
    log_.err("arch descriptor not configured");
    return;
  }

  if (provider) {
    image_provider_ = std::move(provider);
  }

  if (configured_) {
    if (image_provider_) {
      image_provider_->reset(arch_desc_);
      image_pipeline_.snapshot(*image_provider_, 0);
    }
    return;
  }
  if (!image_provider_) {
    trace_failed_.store(true, std::memory_order_release);
    log_.err("image inventory provider not configured");
    return;
  }

  trace_ready_.store(false, std::memory_order_release);
  trace_failed_.store(false, std::memory_order_release);
  register_schema_.clear();
  image_pipeline_.reset();

  if (writer_) {
    writer_->close();
  }
  writer_.reset();
  builder_.reset();
  emitter_.reset();

  if (arch_desc_.arch_id.empty()) {
    arch_desc_.arch_id = "unknown";
  }

  image_provider_->reset(arch_desc_);
  image_pipeline_.snapshot(*image_provider_, 0);

  if (config_.image_blobs.enabled) {
    auto* blob_provider = dynamic_cast<image_blob_provider*>(image_provider_.get());
    if (!blob_provider) {
      trace_failed_.store(true, std::memory_order_release);
      log_.err("image blob provider not configured");
      return;
    }
  }

  w1::rewind::trace_file_writer_config writer_config;
  writer_config.path = config_.output_path;
  writer_config.log = redlog::get_logger("w1rewind.trace");
  writer_config.codec = config_.compress_trace ? w1::rewind::compression::zstd : w1::rewind::compression::none;
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

  builder_ = std::make_unique<w1::rewind::trace_builder>(std::move(builder_config));
  emitter_ = std::make_unique<trace_emitter>(builder_.get(), config_, instruction_flow_);
  configured_ = true;
}

bool rewind_engine::ensure_trace_ready(const w1::util::register_state& regs) {
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

  if (!start_trace_locked(regs)) {
    trace_failed_.store(true, std::memory_order_release);
    return false;
  }

  trace_ready_.store(true, std::memory_order_release);
  return true;
}

bool rewind_engine::start_trace_locked(const w1::util::register_state& regs) {
  if (!builder_ || !builder_->good()) {
    log_.err("trace builder not ready");
    return false;
  }

  bool want_registers = config_.registers.deltas || config_.registers.bytes ||
                        config_.registers.snapshot_interval > 0 || config_.stack_snapshots.interval > 0;
  bool need_schema =
      want_registers || config_.stack_window.mode != rewind_config::stack_window_options::window_mode::none;
  if (register_schema_.empty() && register_schema_provider_) {
    std::vector<w1::rewind::register_spec> specs;
    std::string error;
    if (!register_schema_provider_->build_register_schema(arch_desc_, specs, error)) {
      log_.err("register schema provider failed", redlog::field("error", error));
      return false;
    }
    register_schema_.set_specs(std::move(specs));
  }
  if (need_schema) {
    if (register_schema_.empty()) {
      log_.err("register schema missing");
      return false;
    }
    if (!register_schema_.has_sizing()) {
      log_.err("register schema missing size information");
      return false;
    }
    std::string error;
    if (!register_schema_.covers_registers(regs, error)) {
      log_.err("register schema does not cover captured registers", redlog::field("error", error));
      return false;
    }
    for (const auto& name : regs.get_register_names()) {
      const auto* spec = register_schema_.find_spec(name);
      if (!spec) {
        continue;
      }
      uint32_t byte_size = (spec->bit_size + 7u) / 8u;
      if (byte_size > sizeof(uint64_t)) {
        log_.err(
            "register schema contains registers wider than 64 bits", redlog::field("register", name),
            redlog::field("bit_size", spec->bit_size)
        );
        return false;
      }
    }
  }

  if (image_provider_) {
    image_pipeline_.snapshot(*image_provider_, 0);
  }

  w1::rewind::file_header header{};
  header.trace_uuid = generate_trace_uuid();
  header.default_chunk_size = config_.chunk_size;

  if (!builder_->begin_trace(header)) {
    log_.err("failed to begin trace", redlog::field("error", builder_->error()));
    return false;
  }

  if (!builder_->emit_arch_descriptor_checked(arch_desc_)) {
    log_.err("failed to write arch descriptor", redlog::field("error", builder_->error()));
    return false;
  }

  if (!environment_configured_) {
    log_.err("environment record not configured");
    return false;
  }
  if (!builder_->emit_environment_checked(environment_record_)) {
    log_.err("failed to write environment", redlog::field("error", builder_->error()));
    return false;
  }

  w1::rewind::address_space_record space{};
  space.space_id = 0;
  space.name = "default";
  space.address_bits = arch_desc_.address_bits;
  space.byte_order = arch_desc_.byte_order;
  if (!builder_->emit_address_space(space)) {
    log_.err("failed to write address space", redlog::field("error", builder_->error()));
    return false;
  }

  if (!register_schema_.empty()) {
    w1::rewind::register_file_record reg_file{};
    reg_file.regfile_id = 0;
    reg_file.name = "gpr";
    reg_file.registers = register_schema_.specs();
    if (!builder_->emit_register_file(reg_file)) {
      log_.err("failed to write register file", redlog::field("error", builder_->error()));
      return false;
    }
  }

  image_blob_request request{};
  request.exec_only = config_.image_blobs.exec_only;
  request.max_bytes = config_.image_blobs.max_bytes;
  image_blob_provider* blob_provider = nullptr;
  if (config_.image_blobs.enabled) {
    blob_provider = dynamic_cast<image_blob_provider*>(image_provider_.get());
  }
  if (!image_pipeline_.emit_snapshot(*builder_, config_.image_blobs.enabled, request, blob_provider)) {
    return false;
  }

  return true;
}

bool rewind_engine::begin_thread(uint64_t thread_id, const std::string& name) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!emitter_) {
    return false;
  }
  return emitter_->begin_thread(thread_id, name);
}

bool rewind_engine::emit_block(
    uint64_t thread_id, uint64_t address, uint32_t size, uint32_t space_id, uint16_t mode_id, uint64_t& sequence_out
) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!emitter_) {
    return false;
  }
  return emitter_->emit_block(thread_id, address, size, space_id, mode_id, sequence_out);
}

void rewind_engine::flush_pending(std::optional<pending_instruction>& pending) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (emitter_) {
    emitter_->flush_pending(pending);
  }
}

bool rewind_engine::emit_snapshot(
    uint64_t thread_id, uint64_t sequence, uint64_t snapshot_id, std::span<const w1::rewind::reg_write_entry> registers,
    std::span<const w1::rewind::memory_segment> memory_segments
) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!builder_ || !builder_->good()) {
    return false;
  }
  w1::rewind::snapshot_record record{};
  record.thread_id = thread_id;
  record.sequence = sequence;
  record.regfile_id = 0;
  record.registers.assign(registers.begin(), registers.end());
  record.memory_segments.assign(memory_segments.begin(), memory_segments.end());
  (void) snapshot_id;
  return builder_->emit_snapshot(record);
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

void rewind_engine::on_image_event(const image_inventory_event& event) {
  if (trace_failed_.load(std::memory_order_acquire)) {
    return;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  image_blob_request request{};
  request.exec_only = config_.image_blobs.exec_only;
  request.max_bytes = config_.image_blobs.max_bytes;
  image_blob_provider* blob_provider = nullptr;
  if (config_.image_blobs.enabled) {
    blob_provider = dynamic_cast<image_blob_provider*>(image_provider_.get());
  }
  image_pipeline_.apply_event(
      event, builder_.get(), trace_ready_.load(std::memory_order_acquire), config_.image_blobs.enabled, request,
      blob_provider
  );
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

size_t rewind_engine::image_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return image_pipeline_.image_count();
}

std::string rewind_engine::output_path() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return writer_ ? writer_->path() : std::string{};
}

} // namespace w1rewind
