#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "gdbstub/target.hpp"

#include "adapter_components.hpp"
#include "adapter_state.hpp"
#include "w1replay/module_source.hpp"

namespace w1replay::gdb {

class adapter {
public:
  struct config {
    std::string trace_path;
    std::string index_path;
    std::string checkpoint_path;
    uint64_t thread_id = 0;
    uint64_t start_sequence = 0;
    bool prefer_instruction_steps = false;
    std::vector<std::string> module_mappings;
    std::vector<std::string> module_dirs;
    module_address_reader module_reader;
  };

  explicit adapter(config config);
  ~adapter();

  bool open();
  const std::string& error() const { return error_; }

  gdbstub::target make_target();
  const gdbstub::arch_spec& arch_spec() const { return state_.arch_spec; }

  const w1::rewind::replay_session& session() const;
  w1::rewind::replay_session& session();

private:
  bool load_context();
  bool open_session();
  bool prime_position();
  bool build_layout();
  bool build_arch_spec();
  bool build_target_xml();

  config config_;
  adapter_state state_{};
  std::string error_;

  std::unique_ptr<regs_component> regs_component_;
  std::unique_ptr<mem_component> mem_component_;
  std::unique_ptr<run_component> run_component_;
  std::unique_ptr<breakpoints_component> breakpoints_component_;
  std::unique_ptr<threads_component> threads_component_;
  std::unique_ptr<memory_layout_component> memory_layout_component_;
  std::unique_ptr<register_info_component> register_info_component_;
};

} // namespace w1replay::gdb
