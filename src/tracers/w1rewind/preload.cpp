#include <memory>

#include "QBDIPreload.h"
#include <redlog.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1base/windows_console.hpp>
#endif

#include "rewind_config.hpp"
#include "rewind_tracer.hpp"

#include "w1rewind/trace/trace_file_writer.hpp"
#include "w1instrument/tracer/vm_session.hpp"
#include "w1instrument/self_exclude.hpp"

namespace {

using rewind_instruction_session = w1::vm_session<w1rewind::rewind_instruction_tracer>;
using rewind_block_session = w1::vm_session<w1rewind::rewind_block_tracer>;

std::unique_ptr<rewind_instruction_session> g_instruction_session;
std::unique_ptr<rewind_block_session> g_block_session;
w1rewind::rewind_config g_config;

void configure_logging(int verbose) {
  if (verbose >= 5) {
    redlog::set_level(redlog::level::annoying);
  } else if (verbose >= 4) {
    redlog::set_level(redlog::level::pedantic);
  } else if (verbose >= 3) {
    redlog::set_level(redlog::level::debug);
  } else if (verbose >= 2) {
    redlog::set_level(redlog::level::trace);
  } else if (verbose >= 1) {
    redlog::set_level(redlog::level::verbose);
  } else {
    redlog::set_level(redlog::level::info);
  }
}

void shutdown_tracer() {
  auto log = redlog::get_logger("w1rewind.preload");

  if (g_instruction_session) {
    g_instruction_session->shutdown(false);
    g_instruction_session.reset();
  }
  if (g_block_session) {
    g_block_session->shutdown(false);
    g_block_session.reset();
  }
}

bool has_filter(
    const std::vector<w1rewind::rewind_config::memory_filter_kind>& filters,
    w1rewind::rewind_config::memory_filter_kind kind
) {
  for (const auto& entry : filters) {
    if (entry == kind) {
      return true;
    }
  }
  return false;
}

} // namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = redlog::get_logger("w1rewind.preload");
  log.inf("qbdipreload_on_run");

  std::string config_error;
  g_config = w1rewind::rewind_config::from_environment(config_error);
  configure_logging(g_config.verbose);
  if (!config_error.empty()) {
    log.err("invalid rewind config", redlog::field("error", config_error));
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  if (g_config.exclude_self) {
    w1::util::append_self_excludes(g_config.instrumentation, reinterpret_cast<const void*>(&qbdipreload_on_run));
  }

  w1::rewind::trace_file_writer_config writer_config;
  writer_config.path = g_config.output_path;
  writer_config.log = redlog::get_logger("w1rewind.trace");
  writer_config.compression =
      g_config.compress_trace ? w1::rewind::trace_compression::zstd : w1::rewind::trace_compression::none;
  writer_config.chunk_size = g_config.chunk_size;
  auto writer = w1::rewind::make_trace_file_writer(std::move(writer_config));
  if (!writer || !writer->open()) {
    log.err("failed to initialize trace writer");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  w1::vm_session_config session_config;
  session_config.instrumentation = g_config.instrumentation;
  session_config.thread_id = 1;
  session_config.thread_name = "main";

  bool instruction_flow = g_config.flow.mode == w1rewind::rewind_config::flow_options::mode::instruction;
  if (g_config.memory.access != w1rewind::rewind_config::memory_access::none && !g_config.memory.values) {
    log.wrn("memory values disabled; replayable memory state will be incomplete");
  }
  if (!g_config.memory.ranges.empty() &&
      !has_filter(g_config.memory.filters, w1rewind::rewind_config::memory_filter_kind::ranges)) {
    log.wrn("memory ranges configured but ranges filter not enabled");
  }

  if (instruction_flow) {
    g_instruction_session =
        std::make_unique<rewind_instruction_session>(session_config, vm, std::in_place, g_config, writer);
  } else {
    g_block_session = std::make_unique<rewind_block_session>(session_config, vm, std::in_place, g_config, writer);
  }

  log.inf(
      "starting rewind session", redlog::field("start", "0x%llx", static_cast<unsigned long long>(start)),
      redlog::field("stop", "0x%llx", static_cast<unsigned long long>(stop))
  );

  bool run_ok = false;
  if (instruction_flow && g_instruction_session) {
    run_ok = g_instruction_session->run(static_cast<uint64_t>(start), static_cast<uint64_t>(stop));
  } else if (g_block_session) {
    run_ok = g_block_session->run(static_cast<uint64_t>(start), static_cast<uint64_t>(stop));
  }

  if (!run_ok) {
    log.err("rewind session run failed");
    shutdown_tracer();
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
  auto log = redlog::get_logger("w1rewind.preload");
  log.inf("qbdipreload_on_exit", redlog::field("status", status));

  shutdown_tracer();
  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_start(void* main) {
  (void) main;
#if defined(_WIN32) || defined(WIN32)
  w1::common::allocate_windows_console();
#endif
  return QBDIPRELOAD_NOT_HANDLED;
}

QBDI_EXPORT int qbdipreload_on_premain(void*, void*) { return QBDIPRELOAD_NOT_HANDLED; }
QBDI_EXPORT int qbdipreload_on_main(int, char**) { return QBDIPRELOAD_NOT_HANDLED; }

} // extern "C"
