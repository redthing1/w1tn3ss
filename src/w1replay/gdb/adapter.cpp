#include "adapter.hpp"

#include "w1replay/asmr_block_decoder.hpp"
#include "target_xml.hpp"

namespace w1replay::gdb {

adapter::adapter(config config) : config_(std::move(config)) {}

adapter::~adapter() = default;

bool adapter::open() {
  error_.clear();
  state_.context = w1::rewind::replay_context{};
  state_.session.reset();
  state_.layout = register_layout{};
  state_.target_xml.clear();
  state_.arch_spec = gdbstub::arch_spec{};
  state_.pc_reg_num = -1;
  state_.active_thread_id = 0;
  state_.last_stop.reset();
  state_.prefer_instruction_steps = config_.prefer_instruction_steps;
  state_.trace_is_block = false;
  state_.decoder_available = false;
  state_.track_memory = false;
  state_.breakpoints.clear();
  state_.decoder.reset();
  state_.module_source_state = module_source{};
  state_.module_source_state.configure(config_.module_mappings, config_.module_dirs);
  if (config_.module_reader) {
    state_.module_source_state.set_address_reader(config_.module_reader);
  }

  if (!load_context()) {
    return false;
  }
  if (!open_session()) {
    return false;
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

  regs_component_ = std::make_unique<regs_component>(state_);
  mem_component_ = std::make_unique<mem_component>(state_);
  run_component_ = std::make_unique<run_component>(state_);
  breakpoints_component_ = std::make_unique<breakpoints_component>(state_);
  threads_component_ = std::make_unique<threads_component>(state_);
  memory_layout_component_ = std::make_unique<memory_layout_component>(state_);
  register_info_component_ = std::make_unique<register_info_component>(state_);

  return true;
}

gdbstub::target adapter::make_target() {
  return gdbstub::make_target(
      *regs_component_,
      *mem_component_,
      *run_component_,
      *breakpoints_component_,
      *threads_component_,
      *memory_layout_component_,
      *register_info_component_
  );
}

const w1::rewind::replay_session& adapter::session() const { return *state_.session; }

w1::rewind::replay_session& adapter::session() { return *state_.session; }

bool adapter::load_context() {
  if (config_.trace_path.empty()) {
    error_ = "trace path required";
    return false;
  }

  if (!w1::rewind::load_replay_context(config_.trace_path, state_.context, error_)) {
    return false;
  }
  if (!config_.module_mappings.empty() || !config_.module_dirs.empty()) {
    state_.module_source_state.apply_to_context(state_.context);
  }
  if (state_.context.threads.empty()) {
    error_ = "trace has no thread records";
    return false;
  }

  if (config_.thread_id != 0) {
    state_.active_thread_id = config_.thread_id;
    bool found = false;
    for (const auto& info : state_.context.threads) {
      if (info.thread_id == state_.active_thread_id) {
        found = true;
        break;
      }
    }
    if (!found) {
      error_ = "thread id not found";
      return false;
    }
  } else {
    state_.active_thread_id = state_.context.threads.front().thread_id;
  }

  auto features = state_.context.features();
  state_.trace_is_block = features.has_blocks;
  state_.track_memory = features.track_memory;

  return true;
}

bool adapter::open_session() {
  if (asmr_decoder_available()) {
    state_.decoder = std::make_unique<w1replay::asmr_block_decoder>();
    state_.decoder->set_code_source(&state_.module_source_state);
    state_.decoder_available = true;
  }

  bool has_registers = state_.context.features().has_registers;

  w1::rewind::replay_session_config config{};
  config.trace_path = config_.trace_path;
  config.index_path = config_.index_path;
  config.checkpoint_path = config_.checkpoint_path;
  config.thread_id = state_.active_thread_id;
  config.start_sequence = config_.start_sequence;
  config.track_registers = has_registers;
  config.track_memory = state_.track_memory;
  if (!config_.module_mappings.empty() || !config_.module_dirs.empty()) {
    auto* module_source = &state_.module_source_state;
    config.context_hook = [module_source](w1::rewind::replay_context& context) {
      module_source->apply_to_context(context);
    };
  }
  if (state_.decoder) {
    config.block_decoder = state_.decoder.get();
  }

  state_.session.emplace(config);
  if (!state_.session->open()) {
    error_ = state_.session->error();
    return false;
  }

  return true;
}

bool adapter::prime_position() {
  if (!state_.session) {
    error_ = "session not ready";
    return false;
  }
  if (!state_.session->step_instruction()) {
    auto kind = state_.session->error_kind();
    if (kind == w1::rewind::replay_session::replay_error_kind::begin_of_trace ||
        kind == w1::rewind::replay_session::replay_error_kind::end_of_trace) {
      error_ = "trace has no flow records";
    } else {
      error_ = state_.session->error();
    }
    return false;
  }
  return true;
}

bool adapter::build_layout() {
  if (!state_.context.target_info.has_value()) {
    error_ = "target metadata missing";
    return false;
  }
  state_.layout = build_register_layout(*state_.context.target_info, state_.context.register_specs);
  if (state_.layout.architecture.empty() || state_.layout.registers.empty()) {
    error_ = "unsupported trace architecture";
    return false;
  }
  if (state_.layout.pc_reg_num < 0) {
    error_ = "pc register missing";
    return false;
  }
  state_.pc_reg_num = state_.layout.pc_reg_num;
  return true;
}

bool adapter::build_target_xml() {
  state_.target_xml = ::w1replay::gdb::build_target_xml(state_.layout);
  if (state_.target_xml.empty()) {
    error_ = "failed to build target xml";
    return false;
  }
  return true;
}

bool adapter::build_arch_spec() {
  state_.arch_spec = gdbstub::arch_spec{};
  state_.arch_spec.target_xml = state_.target_xml;
  state_.arch_spec.xml_arch_name = "target.xml";
  state_.arch_spec.osabi.clear();
  state_.arch_spec.reg_count = static_cast<int>(state_.layout.registers.size());
  state_.arch_spec.pc_reg_num = state_.pc_reg_num;
  state_.arch_spec.address_bits = static_cast<int>(state_.context.target_info->pointer_bits);
  state_.arch_spec.swap_register_endianness = false;
  return true;
}

} // namespace w1replay::gdb
