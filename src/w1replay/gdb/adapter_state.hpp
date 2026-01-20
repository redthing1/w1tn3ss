#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>

#include "gdbstub/server/server.hpp"
#include "gdbstub/target/target.hpp"

#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/replay/replay_session.hpp"

#include "w1replay/module_source.hpp"
#include "layout.hpp"
#include "loaded_libraries_provider.hpp"
#include "run_policy.hpp"
#include "value_codec.hpp"

namespace w1replay {
class asmr_block_decoder;
}

namespace w1replay::gdb {

struct adapter_state {
  w1::rewind::replay_context context{};
  std::optional<w1::rewind::replay_session> session;
  register_layout layout{};
  std::string target_xml;
  gdbstub::arch_spec arch_spec{};
  int pc_reg_num = -1;
  uint64_t active_thread_id = 0;
  std::optional<gdbstub::stop_reason> last_stop;
  endian target_endian = endian::little;
  bool prefer_instruction_steps = false;
  bool trace_is_block = false;
  bool decoder_available = false;
  bool track_memory = false;
  bool has_stack_snapshot = false;
  std::unordered_set<uint64_t> breakpoints;
  std::unique_ptr<w1replay::asmr_block_decoder> decoder;
  module_source module_source_state;
  std::unique_ptr<loaded_libraries_provider> loaded_libraries_provider;

  run_policy make_run_policy() const {
    run_policy policy{};
    policy.trace_is_block = trace_is_block;
    policy.decoder_available = decoder_available;
    policy.prefer_instruction_steps = prefer_instruction_steps;
    return policy;
  }

  std::optional<uint64_t> current_pc() const {
    if (!session) {
      return std::nullopt;
    }
    return session->current_step().address;
  }
};

} // namespace w1replay::gdb
