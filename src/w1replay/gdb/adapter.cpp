#include "adapter.hpp"

#include "w1replay/modules/asmr_block_decoder.hpp"
#include "w1replay/modules/composite_image_provider.hpp"
#include "w1replay/memory/memory_view.hpp"
#include "target_xml.hpp"
#include "loaded_libraries_provider.hpp"
#include "w1replay/trace_loader/trace_loader.hpp"

namespace w1replay::gdb {

adapter::adapter(config config) : config_(std::move(config)) {}

adapter::~adapter() = default;

bool adapter::open() {
  error_.clear();
  context_ = w1::rewind::replay_context{};
  stream_.reset();
  index_.reset();
  checkpoint_.reset();
  session_.reset();
  layout_ = register_layout{};
  target_xml_.clear();
  arch_spec_ = gdbstub::arch_spec{};
  pc_reg_num_ = -1;
  target_endian_ = endian::little;
  trace_is_block_ = false;
  decoder_available_ = false;
  track_memory_ = false;
  has_stack_snapshot_ = false;
  breakpoints_ = breakpoint_store{};
  decoder_.reset();
  image_resolver_.reset();
  image_layout_provider_.reset();
  image_reader_.reset();
  image_metadata_provider_.reset();
  memory_view_.reset();
  loaded_libraries_provider_.reset();
  image_index_.reset();
  services_ = adapter_services{};
  thread_state_ = thread_state{};
  image_resolver_ = make_image_path_resolver(config_.image_mappings, config_.image_dirs);
  {
    std::string layout_error;
    image_layout_provider_ = make_layout_provider(config_.image_layout, layout_error);
    if (!layout_error.empty()) {
      error_ = layout_error;
      return false;
    }
  }

  if (!load_context()) {
    return false;
  }

  if (!open_session()) {
    return false;
  }

  image_index_ = std::make_unique<image_address_index>(context_, session_ ? session_->mappings() : nullptr);

  w1replay::composite_image_provider_config provider_config{};
  provider_config.context = &context_;
  provider_config.resolver = image_resolver_.get();
  provider_config.address_index = image_index_.get();
  provider_config.mapping_state = session_ ? session_->mappings() : nullptr;
  provider_config.layout_provider = image_layout_provider_;
  provider_config.address_reader = config_.image_reader;
  auto provider = std::make_shared<w1replay::composite_image_provider>(std::move(provider_config));
  image_reader_ = provider;
  image_metadata_provider_ = provider;

  memory_view_ =
      std::make_unique<w1replay::replay_memory_view>(&context_, session_->state(), image_reader_.get());
  if (decoder_ && memory_view_) {
    decoder_->set_memory_view(memory_view_.get());
  }

  if (!prime_position()) {
    return false;
  }
  if (!build_layout()) {
    return false;
  }
  if (!build_target_xml()) {
    return false;
  }
  if (!build_arch_spec()) {
    return false;
  }

  services_.session = session_ ? &*session_ : nullptr;
  services_.context = &context_;
  services_.mappings = session_ ? session_->mappings() : nullptr;
  services_.layout = &layout_;
  services_.arch_spec = &arch_spec_;
  services_.image_resolver = image_resolver_.get();
  services_.image_reader = image_reader_.get();
  services_.image_metadata = image_metadata_provider_.get();
  services_.image_index = image_index_.get();
  services_.memory = memory_view_.get();
  services_.breakpoints = &breakpoints_;
  services_.target_endian = target_endian_;
  services_.track_memory = track_memory_;
  services_.run_policy.trace_is_block = trace_is_block_;
  services_.run_policy.decoder_available = decoder_available_;
  services_.run_policy.prefer_instruction_steps = config_.prefer_instruction_steps;

  regs_component_ = std::make_unique<regs_component>(services_);
  mem_component_ = std::make_unique<mem_component>(services_);
  run_component_ = std::make_unique<run_component>(services_, thread_state_);
  breakpoints_component_ = std::make_unique<breakpoints_component>(services_);
  threads_component_ = std::make_unique<threads_component>(services_, thread_state_);
  host_info_component_ = std::make_unique<host_info_component>(services_);
  memory_layout_component_ = std::make_unique<memory_layout_component>(services_);
  loaded_libraries_component_.reset();
  libraries_component_ = std::make_unique<libraries_component>(services_);
  if (image_metadata_provider_ && image_resolver_) {
    loaded_libraries_provider_ =
        make_loaded_libraries_provider(context_, session_ ? session_->mappings() : nullptr, *image_metadata_provider_,
                                       *image_resolver_);
  }
  if (loaded_libraries_provider_ && !loaded_libraries_provider_->has_loaded_images()) {
    loaded_libraries_provider_.reset();
  }
  services_.loaded_libraries = loaded_libraries_provider_.get();
  if (loaded_libraries_provider_) {
    loaded_libraries_component_ = std::make_unique<loaded_libraries_component>(services_);
  }
  process_info_component_ = std::make_unique<process_info_component>(services_);
  auxv_component_ = std::make_unique<auxv_component>(services_);
  if (!auxv_component_->auxv_data()) {
    auxv_component_.reset();
  }
  offsets_component_ = std::make_unique<offsets_component>(services_);
  register_info_component_ = std::make_unique<register_info_component>(services_);

  return true;
}

gdbstub::target adapter::make_target() {
  if (loaded_libraries_component_) {
    if (auxv_component_) {
      return gdbstub::make_target(
          *regs_component_, *mem_component_, *run_component_, *breakpoints_component_, *threads_component_,
          *host_info_component_, *memory_layout_component_, *libraries_component_, *loaded_libraries_component_,
          *process_info_component_, *auxv_component_, *offsets_component_, *register_info_component_
      );
    }
    return gdbstub::make_target(
        *regs_component_, *mem_component_, *run_component_, *breakpoints_component_, *threads_component_,
        *host_info_component_, *memory_layout_component_, *libraries_component_, *loaded_libraries_component_,
        *process_info_component_, *offsets_component_, *register_info_component_
    );
  }
  if (auxv_component_) {
    return gdbstub::make_target(
        *regs_component_, *mem_component_, *run_component_, *breakpoints_component_, *threads_component_,
        *host_info_component_, *memory_layout_component_, *libraries_component_, *process_info_component_,
        *auxv_component_, *offsets_component_, *register_info_component_
    );
  }
  return gdbstub::make_target(
      *regs_component_, *mem_component_, *run_component_, *breakpoints_component_, *threads_component_,
      *host_info_component_, *memory_layout_component_, *libraries_component_, *process_info_component_,
      *offsets_component_, *register_info_component_
  );
}

const w1::rewind::replay_session& adapter::session() const { return *session_; }

w1::rewind::replay_session& adapter::session() { return *session_; }

bool adapter::load_context() {
  if (config_.trace_path.empty()) {
    error_ = "trace path required";
    return false;
  }

  w1replay::trace_loader::trace_load_options load_options{};
  load_options.trace_path = config_.trace_path;
  load_options.index_path = config_.index_path;
  load_options.checkpoint_path = config_.checkpoint_path;
  load_options.index_stride = config_.index_stride;
  load_options.auto_build_checkpoint = false;

  w1replay::trace_loader::trace_load_result load_result;
  if (!w1replay::trace_loader::load_trace(load_options, load_result)) {
    error_ = load_result.error;
    return false;
  }

  context_ = std::move(load_result.context);
  stream_ = std::move(load_result.stream);
  index_ = std::move(load_result.index);
  checkpoint_ = std::move(load_result.checkpoint);

  if (context_.threads.empty()) {
    error_ = "trace has no thread records";
    return false;
  }

  if (config_.thread_id != 0) {
    thread_state_.active_thread_id = config_.thread_id;
    bool found = false;
    for (const auto& info : context_.threads) {
      if (info.thread_id == thread_state_.active_thread_id) {
        found = true;
        break;
      }
    }
    if (!found) {
      error_ = "thread id not found";
      return false;
    }
  } else {
    thread_state_.active_thread_id = context_.threads.front().thread_id;
  }

  trace_is_block_ = context_.features.has_block_exec && !context_.blocks_by_id.empty();
  track_memory_ = context_.features.has_mem_access || context_.features.has_snapshots;
  has_stack_snapshot_ = context_.features.has_snapshots;
  if (context_.arch.has_value() && context_.arch->byte_order == w1::rewind::endian::big) {
    target_endian_ = endian::big;
  } else {
    target_endian_ = endian::little;
  }

  return true;
}

bool adapter::open_session() {
  if (asmr_decoder_available()) {
    decoder_ = std::make_unique<w1replay::asmr_block_decoder>();
  }
  decoder_available_ = decoder_ != nullptr;

  bool has_registers = context_.features.has_reg_writes;

  if (!stream_ || !index_) {
    error_ = "trace loader not ready";
    return false;
  }

  w1::rewind::replay_session_config config{};
  config.stream = stream_;
  config.index = index_;
  config.checkpoint = checkpoint_;
  config.context = context_;
  config.thread_id = thread_state_.active_thread_id;
  config.start_sequence = config_.start_sequence;
  config.track_registers = has_registers;
  config.track_memory = track_memory_;
  config.strict_instructions = true;
  if (decoder_) {
    config.block_decoder = decoder_.get();
  }

  session_.emplace(config);
  if (!session_->open()) {
    error_ = session_->error();
    return false;
  }

  return true;
}

bool adapter::prime_position() {
  if (!session_) {
    error_ = "session not ready";
    return false;
  }
  if (!session_->step_instruction()) {
    auto kind = session_->error_kind();
    if (kind == w1::rewind::replay_session::replay_error_kind::begin_of_trace ||
        kind == w1::rewind::replay_session::replay_error_kind::end_of_trace) {
      error_ = "trace has no flow records";
    } else {
      error_ = session_->error();
    }
    return false;
  }
  return true;
}

bool adapter::build_layout() {
  layout_ = build_register_layout(context_, context_.default_registers);
  if (layout_.architecture.empty() || layout_.registers.empty()) {
    error_ = "trace is missing gdb architecture or register file";
    return false;
  }
  if (layout_.pc_reg_num < 0) {
    error_ = "pc register missing";
    return false;
  }
  pc_reg_num_ = layout_.pc_reg_num;
  return true;
}

bool adapter::build_target_xml() {
  target_xml_ = ::w1replay::gdb::build_target_xml(layout_);
  if (target_xml_.empty()) {
    error_ = "failed to build target xml";
    return false;
  }
  return true;
}

bool adapter::build_arch_spec() {
  arch_spec_ = gdbstub::arch_spec{};
  arch_spec_.target_xml = target_xml_;
  if (!layout_.feature_name.empty()) {
    arch_spec_.xml_arch_name = layout_.feature_name;
  } else {
    arch_spec_.xml_arch_name = "org.w1tn3ss.rewind";
  }
  arch_spec_.osabi.clear();
  arch_spec_.reg_count = static_cast<int>(layout_.registers.size());
  arch_spec_.pc_reg_num = pc_reg_num_;
  uint16_t address_bits = 0;
  if (context_.arch.has_value()) {
    address_bits = context_.arch->address_bits != 0 ? context_.arch->address_bits : context_.arch->pointer_bits;
  }
  arch_spec_.address_bits = static_cast<int>(address_bits);
  arch_spec_.swap_register_endianness = false;
  return true;
}

} // namespace w1replay::gdb
