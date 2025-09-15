// neat, modernized debugger api

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <chrono>
#include <optional>
#include <functional>
#include <memory>
#include <system_error>
#if __has_include(<expected>)
#include <expected>
#elif __has_include(<tl/expected.hpp>)
#include <tl/expected.hpp>
namespace std {
template <class T, class E> using expected = tl::expected<T, E>;
}
#else
#error "expected is required: provide C++23 <expected> or tl::expected.hpp"
#endif

namespace w1::debugger {

// strong types and enums

using pid_t = std::uint64_t;
using tid_t = std::uint64_t;
using addr_t = std::uint64_t;

enum class os_kind { windows, linux, macos };
enum class arch { x86_64, arm64 };
enum class endianness { little, big };

enum class detach_mode { continue_process, leave_suspended };
enum class step_kind { into, over, out, single };
enum class bp_kind { software, hardware };
enum class wp_kind { read, write, read_write, execute };

enum class reg_class { general, float_simd, debug, all };

enum class page_prot : std::uint32_t {
  none = 0,
  r = 1 << 0,
  w = 1 << 1,
  x = 1 << 2,
};
inline page_prot operator|(page_prot a, page_prot b) {
  return static_cast<page_prot>(static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b));
}

struct version {
  int major{}, minor{}, patch{};
};

// all backend-specific errors map into this category, with a nested origin
enum class dbg_errc {
  ok = 0,
  invalid_argument,
  not_supported,
  permission_denied,
  no_such_process,
  no_such_thread,
  timeout,
  unavailable,
  interrupted,
  already_exists,
  not_found,
  backend_error,
};
std::error_code make_error_code(dbg_errc) noexcept;

// capability and target info

struct capability_limits {
  std::uint32_t hw_breakpoints_per_thread{};
  std::uint32_t hw_watchpoints_per_thread{};
  bool supports_software_breakpoints{true};
  bool supports_watchpoints{false};
  bool supports_single_step{true};
  bool supports_step_over_out{true};
  bool supports_memory_protect{true};
  bool supports_fork_exec_events{true};
  bool supports_module_events{true};
};

struct target_info {
  os_kind os{};
  arch cpu{};
  endianness endian{endianness::little};
  pid_t pid{};
  version os_version{};
  version api_kernel_version{};
  capability_limits caps{};
};

// launch and attach options

struct launch_options {
  std::string path;
  std::vector<std::string> args;
  std::vector<std::string> env;
  std::optional<std::string> cwd;
  bool start_suspended{true};
  bool stop_at_entry{true};
  bool disable_aslr{false};
  bool follow_forks{false};
};

struct attach_options {
  pid_t pid{};
  bool noninvasive{false};
  bool stop_on_attach{true};
  bool follow_forks{false};
};

// memory and modules

struct memory_region {
  addr_t base{};
  std::size_t size{};
  page_prot prot{};
  bool shared{};
  std::string name;
  std::string backing;
};

struct module {
  std::string name;
  std::string path;
  addr_t base{};
  std::size_t size{};
};

// registers

struct reg_desc {
  std::string name;
  reg_class cls{reg_class::general};
  std::uint32_t bit_size{};
  std::uint32_t dwarf_regnum{0xFFFFFFFF};
  std::uint32_t native_regnum{0xFFFFFFFF};
};

struct register_file {
  // one contiguous blob; offsets & sizes match the vector<reg_desc> returned by describe_registers()
  std::vector<std::byte> data;

  std::expected<std::uint64_t, std::error_code> get_u64(std::size_t index) const;
  std::expected<void, std::error_code> set_u64(std::size_t index, std::uint64_t v);
};

// breakpoints and watchpoints

using breakpoint_id = std::uint64_t;
using watchpoint_id = std::uint64_t;

struct breakpoint_opts {
  bp_kind kind{bp_kind::software};
  bool one_shot{false};
  std::optional<std::uint32_t> ignore_count{};
  std::optional<std::string> condition_expr{};
};

struct watchpoint_opts {
  wp_kind kind{wp_kind::read_write};
  std::size_t byte_len{1};
  bool one_shot{false};
};

// events

enum class event_kind {
  process_started,
  process_exited,
  thread_started,
  thread_exited,
  module_loaded,
  module_unloaded,
  breakpoint_hit,
  watchpoint_hit,
  single_step,
  exception,
  output_string,
  forked,
  exec,
};

struct exit_info {
  int exit_code{};
};
struct bp_hit_info {
  breakpoint_id id{};
  addr_t address{};
};
struct wp_hit_info {
  watchpoint_id id{};
  addr_t address{};
};
struct exception_info {
  int platform_code{};
  std::uint64_t details1{};
  std::uint64_t details2{};
  std::string summary;
};

struct debug_event {
  event_kind kind{};
  pid_t pid{};
  tid_t tid{};
  std::optional<exit_info> exit;
  std::optional<bp_hit_info> bp;
  std::optional<wp_hit_info> wp;
  std::optional<exception_info> ex;
  std::optional<module> mod;
  std::optional<std::string> dbg_string;
};

// core session interface

class session {
public:
  // factory
  static std::expected<std::unique_ptr<session>, std::error_code> launch(const launch_options&);

  static std::expected<std::unique_ptr<session>, std::error_code> attach(const attach_options&);

  virtual ~session() = default;

  // introspection
  virtual const target_info& info() const = 0;
  virtual std::expected<std::vector<module>, std::error_code> modules() = 0;

  // threads
  virtual std::expected<std::vector<tid_t>, std::error_code> threads() = 0;
  virtual std::expected<void, std::error_code> suspend(tid_t) = 0;
  virtual std::expected<void, std::error_code> resume(tid_t) = 0;

  // run control
  virtual std::expected<void, std::error_code> detach(detach_mode = detach_mode::continue_process) = 0;
  virtual std::expected<void, std::error_code> terminate(int exit_code = 0) = 0;
  virtual std::expected<void, std::error_code> continue_all() = 0;
  virtual std::expected<void, std::error_code> step(tid_t, step_kind) = 0;

  // registers
  virtual std::expected<std::vector<reg_desc>, std::error_code> describe_registers(reg_class cls = reg_class::all) = 0;

  virtual std::expected<register_file, std::error_code> read_registers(tid_t, reg_class cls = reg_class::all) = 0;

  virtual std::expected<void, std::error_code> write_registers(
      tid_t, const register_file& rf, reg_class cls = reg_class::all
  ) = 0;

  // memory
  virtual std::expected<std::size_t, std::error_code> read_memory(addr_t addr, std::span<std::byte> out) = 0;

  virtual std::expected<std::size_t, std::error_code> write_memory(addr_t addr, std::span<const std::byte> in) = 0;

  virtual std::expected<std::vector<memory_region>, std::error_code> memory_map() = 0;

  virtual std::expected<addr_t, std::error_code> allocate(std::size_t size, page_prot prot) = 0;

  virtual std::expected<void, std::error_code> protect(addr_t addr, std::size_t size, page_prot prot) = 0;

  // breakpoints & watchpoints
  virtual std::expected<breakpoint_id, std::error_code> set_breakpoint(addr_t addr, const breakpoint_opts& = {}) = 0;

  virtual std::expected<void, std::error_code> remove_breakpoint(breakpoint_id) = 0;

  virtual std::expected<watchpoint_id, std::error_code> set_watchpoint(addr_t addr, const watchpoint_opts& = {}) = 0;

  virtual std::expected<void, std::error_code> remove_watchpoint(watchpoint_id) = 0;

  // events (sync & async)
  virtual std::expected<debug_event, std::error_code> wait_for_event(
      std::optional<std::chrono::milliseconds> timeout = {}
  ) = 0;

  using event_callback = std::function<void(const debug_event&)>;
  virtual std::expected<void, std::error_code> subscribe(event_callback cb) = 0;

  // non-copyable
  session(const session&) = delete;
  session& operator=(const session&) = delete;

protected:
  session() = default;
};

// utilities

struct process_info {
  pid_t pid{};
  std::string name;
  std::string path;
  arch cpu{};
};
std::expected<std::vector<process_info>, std::error_code> list_processes();

// quick capability probe (can this process debug at all?)
std::expected<bool, std::error_code> can_debug();

} // namespace w1::debugger

// make dbg_errc interoperable with std::error_code
namespace std {
template <> struct is_error_code_enum<w1::debugger::dbg_errc> : true_type {};
} // namespace std
