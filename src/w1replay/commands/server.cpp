#include "server.hpp"

#include <iostream>
#include <memory>

#include <redlog.hpp>

#include "gdbstub/server.hpp"
#include "gdbstub/transport_tcp.hpp"

#include "gdb/adapter.hpp"

namespace w1replay::commands {

namespace {

constexpr const char* k_default_gdb_listen = "127.0.0.1:51234";

} // namespace

int server(const server_options& options) {
  auto log = redlog::get_logger("w1replay.server");

  if (options.trace_path.empty()) {
    log.err("trace path required");
    std::cerr << "error: --trace is required" << std::endl;
    return 1;
  }

  std::string listen_addr = options.gdb_listen.empty() ? k_default_gdb_listen : options.gdb_listen;

  gdb::adapter::config config;
  config.trace_path = options.trace_path;
  config.index_path = options.index_path;
  config.checkpoint_path = options.checkpoint_path;
  config.thread_id = options.thread_id;
  config.start_sequence = options.start_sequence;
  config.prefer_instruction_steps = options.instruction_steps;
  config.module_mappings = options.module_mappings;
  config.module_dirs = options.module_dirs;

  gdb::adapter adapter(std::move(config));
  if (!adapter.open()) {
    log.err("failed to open trace", redlog::field("error", adapter.error()));
    std::cerr << "error: " << adapter.error() << std::endl;
    return 1;
  }

  auto transport = std::make_unique<gdbstub::transport_tcp>();
  gdbstub::server server(adapter.make_target(), adapter.arch_spec(), std::move(transport));
  if (!server.listen(listen_addr)) {
    log.err("failed to listen", redlog::field("address", listen_addr));
    std::cerr << "error: failed to listen on " << listen_addr << std::endl;
    return 1;
  }

  log.info("listening", redlog::field("address", listen_addr));
  std::cout << "listening on " << listen_addr << std::endl;
  server.serve_forever();
  return 0;
}

} // namespace w1replay::commands
