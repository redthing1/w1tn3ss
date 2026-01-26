#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "gdbstub/target/target.hpp"

#include "adapter_services.hpp"
#include "thread_state.hpp"

namespace w1replay::gdb {

class regs_component {
public:
  explicit regs_component(const adapter_services& services);

  size_t reg_size(int regno) const;
  gdbstub::target_status read_reg(int regno, std::span<std::byte> out);
  gdbstub::target_status write_reg(int regno, std::span<const std::byte> data);

private:
  const adapter_services& services_;
};

class mem_component {
public:
  explicit mem_component(const adapter_services& services);

  gdbstub::target_status read_mem(uint64_t addr, std::span<std::byte> out);
  gdbstub::target_status write_mem(uint64_t addr, std::span<const std::byte> data);

private:
  const adapter_services& services_;
};

class run_component {
public:
  run_component(const adapter_services& services, thread_state& thread);

  gdbstub::run_capabilities capabilities() const;
  gdbstub::resume_result resume(const gdbstub::resume_request& request);

private:
  const adapter_services& services_;
  thread_state& thread_;
};

class breakpoints_component {
public:
  explicit breakpoints_component(const adapter_services& services);

  gdbstub::target_status set_breakpoint(const gdbstub::breakpoint_request& request);
  gdbstub::target_status remove_breakpoint(const gdbstub::breakpoint_request& request);

private:
  const adapter_services& services_;
};

class threads_component {
public:
  threads_component(const adapter_services& services, thread_state& thread);

  std::vector<uint64_t> thread_ids() const;
  uint64_t current_thread() const;
  gdbstub::target_status set_current_thread(uint64_t tid);
  std::optional<uint64_t> thread_pc(uint64_t tid) const;
  std::optional<std::string> thread_name(uint64_t tid) const;
  std::optional<gdbstub::stop_reason> thread_stop_reason(uint64_t tid) const;

private:
  const adapter_services& services_;
  thread_state& thread_;
};

class host_info_component {
public:
  explicit host_info_component(const adapter_services& services);

  std::optional<gdbstub::host_info> get_host_info() const;

private:
  const adapter_services& services_;
};

class memory_layout_component {
public:
  explicit memory_layout_component(const adapter_services& services);

  std::vector<gdbstub::memory_region> memory_map() const;

private:
  const adapter_services& services_;
};

class libraries_component {
public:
  explicit libraries_component(const adapter_services& services);

  std::vector<gdbstub::library_entry> libraries() const;
  std::optional<uint64_t> libraries_generation() const;

private:
  const adapter_services& services_;
};

class loaded_libraries_component {
public:
  explicit loaded_libraries_component(const adapter_services& services);

  std::optional<std::string> loaded_libraries_json(const gdbstub::lldb::loaded_libraries_request& request);
  std::optional<std::vector<gdbstub::lldb::process_kv_pair>> process_info_extras() const;
  bool has_loaded_images() const;

private:
  const adapter_services& services_;
};

class process_info_component {
public:
  explicit process_info_component(const adapter_services& services);

  std::optional<gdbstub::process_info> get_process_info() const;

private:
  const adapter_services& services_;
};

class auxv_component {
public:
  explicit auxv_component(const adapter_services& services);

  std::optional<std::vector<std::byte>> auxv_data() const;

private:
  std::optional<std::vector<std::byte>> build_auxv() const;

  const adapter_services& services_;
  mutable bool auxv_cached_ = false;
  mutable std::optional<std::vector<std::byte>> auxv_data_;
};

class offsets_component {
public:
  explicit offsets_component(const adapter_services& services);

  std::optional<gdbstub::offsets_info> get_offsets_info() const;

private:
  const adapter_services& services_;
};

class register_info_component {
public:
  explicit register_info_component(const adapter_services& services);

  std::optional<gdbstub::register_info> get_register_info(int regno) const;

private:
  const adapter_services& services_;
};

} // namespace w1replay::gdb
