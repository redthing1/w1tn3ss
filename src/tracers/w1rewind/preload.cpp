#include <memory>

#include "QBDIPreload.h"
#include <redlog.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1common/windows_console.hpp>
#endif

#include "rewind_config.hpp"
#include "rewind_tracer.hpp"

#include "w1tn3ss/runtime/rewind/trace_writer.hpp"
#include "w1tn3ss/tracer/trace_session.hpp"
#include "w1tn3ss/util/self_exclude.hpp"

namespace {

using rewind_instruction_session = w1::trace_session<w1rewind::rewind_instruction_tracer>;
using rewind_block_session = w1::trace_session<w1rewind::rewind_block_tracer>;

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

} // namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = redlog::get_logger("w1rewind.preload");
  log.inf("qbdipreload_on_run");

  g_config = w1rewind::rewind_config::from_environment();
  configure_logging(g_config.verbose);

  if (g_config.exclude_self) {
    w1::util::append_self_excludes(g_config.instrumentation, reinterpret_cast<const void*>(&qbdipreload_on_run));
  }

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = g_config.output_path;
  writer_config.log = redlog::get_logger("w1rewind.trace");
  writer_config.compression =
      g_config.compress_trace ? w1::rewind::trace_compression::zstd : w1::rewind::trace_compression::none;
  writer_config.chunk_size = g_config.chunk_size;
  auto writer = w1::rewind::make_trace_writer(std::move(writer_config));
  if (!writer || !writer->open()) {
    log.err("failed to initialize trace writer");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  w1::trace_session_config session_config;
  session_config.instrumentation = g_config.instrumentation;
  session_config.thread_id = 1;
  session_config.thread_name = "main";

  bool instruction_flow = g_config.requires_instruction_flow();
  if (instruction_flow && !g_config.record_instructions) {
    log.wrn("instruction flow forced by state capture");
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
