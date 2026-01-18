#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "w1rewind/format/trace_format.hpp"

namespace w1::rewind {

struct replay_thread_info {
  uint64_t thread_id = 0;
  std::string name;
  bool started = false;
  bool ended = false;
};

struct replay_context {
  trace_header header{};
  std::vector<std::string> register_names;
  std::vector<module_record> modules;
  std::unordered_map<uint64_t, module_record> modules_by_id;
  std::unordered_map<uint64_t, block_definition_record> blocks_by_id;
  std::vector<replay_thread_info> threads;
  std::optional<uint16_t> sp_reg_id;

  struct trace_features {
    bool has_registers = false;
    bool has_memory_access = false;
    bool has_memory_values = false;
    bool has_stack_snapshot = false;
    bool has_blocks = false;
    bool track_memory = false;
  };

  bool resolve_address(uint64_t module_id, uint64_t module_offset, uint64_t& address) const;
  bool has_blocks() const;
  bool has_registers() const;
  trace_features features() const;

  const module_record* find_module_for_address(uint64_t address, uint64_t size, uint64_t& module_offset) const;
};

bool load_replay_context(const std::string& trace_path, replay_context& out, std::string& error);

} // namespace w1::rewind
