#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "gdbstub/target/target.hpp"

#include "adapter_state.hpp"

namespace w1replay::gdb {

class regs_component {
public:
  explicit regs_component(adapter_state& state);

  size_t reg_size(int regno) const;
  gdbstub::target_status read_reg(int regno, std::span<std::byte> out);
  gdbstub::target_status write_reg(int regno, std::span<const std::byte> data);

private:
  adapter_state& state_;
};

class mem_component {
public:
  explicit mem_component(adapter_state& state);

  gdbstub::target_status read_mem(uint64_t addr, std::span<std::byte> out);
  gdbstub::target_status write_mem(uint64_t addr, std::span<const std::byte> data);

private:
  adapter_state& state_;
};

class run_component {
public:
  explicit run_component(adapter_state& state);

  gdbstub::run_capabilities capabilities() const;
  gdbstub::resume_result resume(const gdbstub::resume_request& request);

private:
  adapter_state& state_;
};

class breakpoints_component {
public:
  explicit breakpoints_component(adapter_state& state);

  gdbstub::target_status set_breakpoint(const gdbstub::breakpoint_request& request);
  gdbstub::target_status remove_breakpoint(const gdbstub::breakpoint_request& request);

private:
  adapter_state& state_;
};

class threads_component {
public:
  explicit threads_component(adapter_state& state);

  std::vector<uint64_t> thread_ids() const;
  uint64_t current_thread() const;
  gdbstub::target_status set_current_thread(uint64_t tid);
  std::optional<uint64_t> thread_pc(uint64_t tid) const;
  std::optional<std::string> thread_name(uint64_t tid) const;
  std::optional<gdbstub::stop_reason> thread_stop_reason(uint64_t tid) const;

private:
  adapter_state& state_;
};

class host_info_component {
public:
  explicit host_info_component(adapter_state& state);

  std::optional<gdbstub::host_info> get_host_info() const;

private:
  adapter_state& state_;
};

class memory_layout_component {
public:
  explicit memory_layout_component(adapter_state& state);

  std::vector<gdbstub::memory_region> memory_map() const;

private:
  adapter_state& state_;
};

class libraries_component {
public:
  explicit libraries_component(adapter_state& state);

  std::vector<gdbstub::library_entry> libraries() const;

private:
  adapter_state& state_;
};

class loaded_libraries_component {
public:
  explicit loaded_libraries_component(adapter_state& state);

  std::optional<std::string> loaded_libraries_json(const gdbstub::lldb::loaded_libraries_request& request);
  std::optional<std::vector<gdbstub::lldb::process_kv_pair>> process_info_extras() const;
  bool has_loaded_images() const;

private:
  adapter_state& state_;
};

class process_info_component {
public:
  explicit process_info_component(adapter_state& state);

  std::optional<gdbstub::process_info> get_process_info() const;

private:
  adapter_state& state_;
};

class offsets_component {
public:
  explicit offsets_component(adapter_state& state);

  std::optional<gdbstub::offsets_info> get_offsets_info() const;

private:
  adapter_state& state_;
};

class register_info_component {
public:
  explicit register_info_component(adapter_state& state);

  std::optional<gdbstub::register_info> get_register_info(int regno) const;

private:
  adapter_state& state_;
};

} // namespace w1replay::gdb
