#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>
#include <optional>
#include <chrono>
#include <map>

namespace w1::debugger {

// architecture enumeration
enum class arch { x86, x86_64, arm64 };

// memory protection flags (can be OR'd together)
enum class memory_prot : uint32_t { none = 0, read = 1, write = 2, exec = 4 };

// process id wrapper
struct pid {
  int native;
  bool operator==(const pid& other) const { return native == other.native; }
};

// thread id wrapper
struct tid {
  uint64_t native;
  bool operator==(const tid& other) const { return native == other.native; }
};

// address wrapper
struct addr {
  uint64_t value;
  bool operator==(const addr& other) const { return value == other.value; }
};

// memory region information
struct memory_region {
  addr start;
  uint64_t size;
  memory_prot prot;
  std::string module_path; // empty if not file-backed
};

// x86 32-bit registers
struct x86_regs {
  uint32_t eax, ebx, ecx, edx;
  uint32_t esi, edi, ebp, esp;
  uint32_t eip;
  uint32_t eflags;
  // other regs?
};

// x86_64 registers
struct x64_regs {
  uint64_t rax, rbx, rcx, rdx;
  uint64_t rsi, rdi, rbp, rsp;
  uint64_t r8, r9, r10, r11;
  uint64_t r12, r13, r14, r15;
  uint64_t rip;
  uint64_t rflags;
  // other regs?
};

// arm64 registers
struct arm64_regs {
  uint64_t x[31];  // x0-x30
  uint64_t sp;     // stack pointer
  uint64_t pc;     // program counter
  uint64_t pstate; // processor state
                   // other regs?
};

// unified register context
using register_context = std::variant<x86_regs, x64_regs, arm64_regs>;

// event types
enum class event_type {
  breakpoint_hit,
  single_step,
  access_violation,
  thread_create,
  thread_exit,
  process_exit,
  library_load,
  library_unload,
  exception
};

// debug event
struct debug_event {
  event_type type;
  tid thread_id;
  addr address;     // fault/breakpoint address
  uint64_t code;    // os-specific code
  std::string info; // additional context
};

// process information for discovery
struct process_info {
  pid process_id;
  std::string name;
  std::string full_path;
  std::string command_line;
};

// capabilities query
struct capabilities {
  bool hardware_breakpoints = false;
  bool watchpoints = false;
  bool remote_allocation = false;
  bool thread_suspension = false;
  bool single_stepping = false;
};

// configuration
struct config {
  // target specification
  std::optional<pid> target_pid;
  std::optional<std::string> executable_path;
  std::vector<std::string> args;
  std::map<std::string, std::string> env_vars;

  // launch options
  bool start_suspended = true;
  bool disable_aslr = false;

  // behavior
  std::chrono::milliseconds timeout{5000};
  bool verbose = false;
};

} // namespace w1::debugger
