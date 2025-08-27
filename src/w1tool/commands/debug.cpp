#include "debug.hpp"
#include <w1debugger/w1debugger.hpp>
#include <redlog.hpp>
#include <iostream>
#include <sstream>
#include <iomanip>

namespace w1tool::commands {

// interactive debugger commands
class interactive_debugger {
private:
  std::unique_ptr<w1::debugger::session> session;
  redlog::logger log;
  bool running = true;

public:
  interactive_debugger(std::unique_ptr<w1::debugger::session> sess)
      : session(std::move(sess)), log(redlog::get_logger("w1tool.debug.interactive")) {}

  void run() {
    log.info("entering interactive mode, type 'help' for commands");

    while (running && session) {
      std::cout << "w1dbg> " << std::flush;

      std::string line;
      if (!std::getline(std::cin, line)) {
        break;
      }

      if (line.empty()) {
        continue;
      }

      // parse command
      std::istringstream iss(line);
      std::string cmd;
      iss >> cmd;

      if (cmd == "help" || cmd == "h") {
        print_help();
      } else if (cmd == "quit" || cmd == "q") {
        handle_quit();
      } else if (cmd == "continue" || cmd == "c") {
        handle_continue();
      } else if (cmd == "threads" || cmd == "t") {
        handle_threads();
      } else if (cmd == "regs" || cmd == "printregs") {
        handle_printregs(iss);
      } else if (cmd == "read" || cmd == "r") {
        handle_read(iss);
      } else if (cmd == "write" || cmd == "w") {
        handle_write(iss);
      } else if (cmd == "step" || cmd == "s") {
        handle_step(iss);
      } else if (cmd == "info") {
        handle_info();
      } else {
        std::cout << "unknown command: " << cmd << "\n";
        std::cout << "type 'help' for available commands\n";
      }
    }
  }

private:
  void print_help() {
    std::cout << "available commands:\n";
    std::cout << "  help, h              - show this help\n";
    std::cout << "  quit, q              - detach and quit\n";
    std::cout << "  continue, c          - continue execution\n";
    std::cout << "  threads, t           - list threads\n";
    std::cout << "  regs, printregs [tid] - print registers (optional thread id)\n";
    std::cout << "  read <addr> <size>   - read memory\n";
    std::cout << "  write <addr> <hex>   - write memory\n";
    std::cout << "  step [tid]           - single step (optional thread id)\n";
    std::cout << "  info                 - show process info\n";
  }

  void handle_quit() {
    log.info("detaching from process");
    auto result = session->detach();
    if (!result.success()) {
      log.err("failed to detach", redlog::field("error", result.error_message));
    }
    running = false;
  }

  void handle_continue() {
    auto result = session->continue_execution();
    if (result.success()) {
      log.info("continued execution");
    } else {
      log.err("failed to continue", redlog::field("error", result.error_message));
    }
  }

  void handle_threads() {
    std::vector<w1::debugger::tid> threads;
    auto result = session->get_threads(threads);
    if (!result.success()) {
      log.err("failed to get threads", redlog::field("error", result.error_message));
      return;
    }
    std::cout << "threads (" << threads.size() << "):\n";
    for (const auto& tid : threads) {
      std::cout << "  tid: 0x" << std::hex << tid.native << std::dec << "\n";
    }
  }

  void handle_printregs(std::istringstream& args) {
    // optional thread id
    uint64_t tid_value = 0;
    if (args >> std::hex >> tid_value) {
      // specific thread
    } else {
      // use first thread
      std::vector<w1::debugger::tid> threads;
      auto result = session->get_threads(threads);
      if (!result.success() || threads.empty()) {
        log.err("no threads available");
        return;
      }
      tid_value = threads[0].native;
    }

    w1::debugger::tid tid{tid_value};
    w1::debugger::register_context regs;
    auto result = session->get_registers(tid, regs);
    if (!result.success()) {
      log.err("failed to get registers", redlog::field("error", result.error_message));
      return;
    }

    // print based on variant type
    std::visit(
        [](const auto& regs) {
          using T = std::decay_t<decltype(regs)>;
          if constexpr (std::is_same_v<T, w1::debugger::arm64_regs>) {
            std::cout << "arm64 registers:\n";
            for (int i = 0; i < 31; i++) {
              std::cout << "  x" << i << ": 0x" << std::hex << std::setw(16) << std::setfill('0') << regs.x[i] << "\n";
            }
            std::cout << "  sp: 0x" << std::hex << std::setw(16) << std::setfill('0') << regs.sp << "\n";
            std::cout << "  pc: 0x" << std::hex << std::setw(16) << std::setfill('0') << regs.pc << "\n";
            std::cout << "  pstate: 0x" << std::hex << regs.pstate << std::dec << "\n";
          } else if constexpr (std::is_same_v<T, w1::debugger::x64_regs>) {
            std::cout << "x64 registers:\n";
            std::cout << "  rax: 0x" << std::hex << std::setw(16) << std::setfill('0') << regs.rax << "\n";
            std::cout << "  rbx: 0x" << std::hex << std::setw(16) << std::setfill('0') << regs.rbx << "\n";
            std::cout << "  rcx: 0x" << std::hex << std::setw(16) << std::setfill('0') << regs.rcx << "\n";
            std::cout << "  rdx: 0x" << std::hex << std::setw(16) << std::setfill('0') << regs.rdx << "\n";
            std::cout << "  rsi: 0x" << std::hex << std::setw(16) << std::setfill('0') << regs.rsi << "\n";
            std::cout << "  rdi: 0x" << std::hex << std::setw(16) << std::setfill('0') << regs.rdi << "\n";
            std::cout << "  rbp: 0x" << std::hex << std::setw(16) << std::setfill('0') << regs.rbp << "\n";
            std::cout << "  rsp: 0x" << std::hex << std::setw(16) << std::setfill('0') << regs.rsp << "\n";
            std::cout << "  rip: 0x" << std::hex << std::setw(16) << std::setfill('0') << regs.rip << "\n";
            std::cout << std::dec;
          }
        },
        regs
    );
  }

  void handle_read(std::istringstream& args) {
    uint64_t addr;
    size_t size;

    if (!(args >> std::hex >> addr >> std::dec >> size)) {
      std::cout << "usage: read <hex_addr> <size>\n";
      return;
    }

    std::vector<uint8_t> data;
    auto result = session->read_memory(w1::debugger::addr{addr}, size, data);
    if (!result.success()) {
      log.err("failed to read memory", redlog::field("error", result.error_message));
      return;
    }
    std::cout << "memory at 0x" << std::hex << addr << ":\n";

    // hex dump format
    for (size_t i = 0; i < data.size(); i += 16) {
      std::cout << "  " << std::hex << std::setw(8) << std::setfill('0') << (addr + i) << ": ";

      // hex bytes
      for (size_t j = 0; j < 16 && i + j < data.size(); j++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i + j]) << " ";
      }

      // padding
      for (size_t j = data.size() - i; j < 16; j++) {
        std::cout << "   ";
      }

      std::cout << " ";

      // ascii representation
      for (size_t j = 0; j < 16 && i + j < data.size(); j++) {
        char c = static_cast<char>(data[i + j]);
        std::cout << (std::isprint(c) ? c : '.');
      }

      std::cout << "\n";
    }
    std::cout << std::dec;
  }

  void handle_write(std::istringstream& args) {
    uint64_t addr;
    std::string hex_data;

    if (!(args >> std::hex >> addr >> hex_data)) {
      std::cout << "usage: write <hex_addr> <hex_bytes>\n";
      std::cout << "example: write 0x100000000 deadbeef\n";
      return;
    }

    // parse hex string to bytes
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex_data.length(); i += 2) {
      std::string byte_str = hex_data.substr(i, 2);
      uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
      bytes.push_back(byte);
    }

    auto result = session->write_memory(w1::debugger::addr{addr}, bytes);
    if (result.success()) {
      log.info("wrote memory", redlog::field("addr", addr), redlog::field("size", bytes.size()));
    } else {
      log.err("failed to write memory", redlog::field("error", result.error_message));
    }
  }

  void handle_step(std::istringstream& args) {
    // optional thread id
    uint64_t tid_value = 0;
    if (args >> std::hex >> tid_value) {
      // specific thread
    } else {
      // use first thread
      std::vector<w1::debugger::tid> threads;
      auto result = session->get_threads(threads);
      if (!result.success() || threads.empty()) {
        log.err("no threads available");
        return;
      }
      tid_value = threads[0].native;
    }

    w1::debugger::tid tid{tid_value};
    auto result = session->single_step(tid);
    if (result.success()) {
      log.info("single stepped thread", redlog::field("tid", tid_value));
    } else {
      log.err("failed to single step", redlog::field("error", result.error_message));
    }
  }

  void handle_info() {
    auto pid = session->get_pid();
    auto arch = session->get_arch();
    auto caps = session->get_capabilities();

    std::cout << "process info:\n";
    std::cout << "  pid: " << pid.native << "\n";
    std::cout << "  arch: ";
    switch (arch) {
    case w1::debugger::arch::x86:
      std::cout << "x86\n";
      break;
    case w1::debugger::arch::x86_64:
      std::cout << "x86_64\n";
      break;
    case w1::debugger::arch::arm64:
      std::cout << "arm64\n";
      break;
    }

    std::cout << "  capabilities:\n";
    std::cout << "    hardware breakpoints: " << (caps.hardware_breakpoints ? "yes" : "no") << "\n";
    std::cout << "    watchpoints: " << (caps.watchpoints ? "yes" : "no") << "\n";
    std::cout << "    remote allocation: " << (caps.remote_allocation ? "yes" : "no") << "\n";
    std::cout << "    thread suspension: " << (caps.thread_suspension ? "yes" : "no") << "\n";
    std::cout << "    single stepping: " << (caps.single_stepping ? "yes" : "no") << "\n";
  }
};

int debug(
    args::ValueFlag<int>& pid_flag, args::Flag& spawn_flag, args::Flag& interactive_flag, args::Flag& suspended_flag,
    args::PositionalList<std::string>& args_list
) {
  auto log = redlog::get_logger("w1tool.debug");

  // validate target specification
  int target_count = 0;
  if (spawn_flag) {
    target_count++;
  }
  if (pid_flag) {
    target_count++;
  }

  if (target_count != 1) {
    log.err("exactly one target required: specify --spawn or --pid");
    return 1;
  }

  // validate suspended flag usage
  if (suspended_flag && !spawn_flag) {
    log.err("--suspended can only be used with --spawn");
    return 1;
  }

  std::unique_ptr<w1::debugger::session> session;

  if (spawn_flag) {
    // launch target
    if (args_list.Get().empty()) {
      log.err("binary path required when using --spawn flag");
      return 1;
    }

    std::vector<std::string> all_args = args::get(args_list);
    std::string binary_path = all_args[0];

    // extract arguments after the binary
    std::vector<std::string> binary_args;
    if (all_args.size() > 1) {
      binary_args.assign(all_args.begin() + 1, all_args.end());
    }

    w1::debugger::config cfg;
    cfg.executable_path = binary_path;
    cfg.args = binary_args;
    cfg.start_suspended = suspended_flag;

    log.info(
        "launching target", redlog::field("binary", binary_path), redlog::field("args_count", binary_args.size()),
        redlog::field("suspended", suspended_flag ? "true" : "false")
    );

    w1::debugger::result result;
    session = w1::debugger::session::launch(binary_path, cfg, result);
    if (!result.success()) {
      log.err("failed to launch target", redlog::field("error", result.error_message));
      return 1;
    }
    log.info("launched successfully", redlog::field("pid", session->get_pid().native));

  } else if (pid_flag) {
    // attach to existing process
    int target_pid = args::get(pid_flag);

    w1::debugger::config cfg;
    log.info("attaching to process", redlog::field("pid", target_pid));

    w1::debugger::result result;
    session = w1::debugger::session::attach(w1::debugger::pid{target_pid}, cfg, result);
    if (!result.success()) {
      log.err("failed to attach", redlog::field("error", result.error_message));
      return 1;
    }
    log.info("attached successfully");
  }

  // run interactive mode if requested
  if (interactive_flag) {
    interactive_debugger debugger(std::move(session));
    debugger.run();
  } else {
    // non-interactive mode - just detach
    session->detach();
  }

  return 0;
}

} // namespace w1tool::commands
