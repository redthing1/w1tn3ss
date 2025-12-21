#include <memory>
#include <utility>
#include <type_traits>
#include <variant>

#include "QBDIPreload.h"
#include <redlog.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1common/windows_console.hpp>
#endif

#include "w1tn3ss/tracer/trace_session.hpp"
#include "w1tn3ss/util/self_exclude.hpp"

#include "coverage_config.hpp"
#include "coverage_tracer.hpp"

namespace {

using basic_tracer = w1cov::coverage_tracer<w1cov::coverage_mode::basic_block>;
using inst_tracer = w1cov::coverage_tracer<w1cov::coverage_mode::instruction>;
using basic_session = w1::trace_session<basic_tracer>;
using inst_session = w1::trace_session<inst_tracer>;
using session_variant = std::variant<std::monostate, std::unique_ptr<basic_session>, std::unique_ptr<inst_session>>;

session_variant g_session;
w1cov::coverage_config g_config;

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

bool run_session(uint64_t start, uint64_t stop) {
  bool ok = false;

  std::visit(
      [&](auto& entry) {
        using entry_t = std::decay_t<decltype(entry)>;
        if constexpr (std::is_same_v<entry_t, std::unique_ptr<basic_session>> ||
                      std::is_same_v<entry_t, std::unique_ptr<inst_session>>) {
          if (entry) {
            ok = entry->run(start, stop);
          }
        }
      },
      g_session
  );

  return ok;
}

void shutdown_session() {
  std::visit(
      [&](auto& entry) {
        using entry_t = std::decay_t<decltype(entry)>;
        if constexpr (std::is_same_v<entry_t, std::unique_ptr<basic_session>> ||
                      std::is_same_v<entry_t, std::unique_ptr<inst_session>>) {
          if (entry) {
            entry->shutdown(false);
            entry.reset();
          }
        }
      },
      g_session
  );

  g_session = std::monostate{};
}

} // namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = redlog::get_logger("w1cov.preload");

  g_config = w1cov::coverage_config::from_environment();
  configure_logging(g_config.verbose);
  if (g_config.exclude_self) {
    w1::util::append_self_excludes(g_config.instrumentation, reinterpret_cast<const void*>(&qbdipreload_on_run));
  }

  w1::trace_session_config session_config;
  session_config.instrumentation = g_config.instrumentation;
  session_config.thread_id = 1;
  session_config.thread_name = "main";

  if (g_config.inst_trace) {
    g_session = std::make_unique<inst_session>(session_config, vm, std::in_place, g_config);
  } else {
    g_session = std::make_unique<basic_session>(session_config, vm, std::in_place, g_config);
  }

  log.inf(
      "starting coverage session", redlog::field("start", "0x%llx", static_cast<unsigned long long>(start)),
      redlog::field("stop", "0x%llx", static_cast<unsigned long long>(stop)),
      redlog::field("inst_trace", g_config.inst_trace ? "true" : "false")
  );

  if (!run_session(static_cast<uint64_t>(start), static_cast<uint64_t>(stop))) {
    log.err("coverage session run failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
  auto log = redlog::get_logger("w1cov.preload");
  log.inf("qbdipreload_on_exit called", redlog::field("status", status));

  shutdown_session();

  log.inf("qbdipreload_on_exit completed");
  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_start(void* main) {
  (void) main;
#if defined(_WIN32) || defined(WIN32)
  w1::common::allocate_windows_console();
#endif
  return QBDIPRELOAD_NOT_HANDLED;
}

QBDI_EXPORT int qbdipreload_on_premain(void* gpr_ctx, void* fpu_ctx) {
  (void) gpr_ctx;
  (void) fpu_ctx;
  return QBDIPRELOAD_NOT_HANDLED;
}

QBDI_EXPORT int qbdipreload_on_main(int argc, char** argv) {
  (void) argc;
  (void) argv;
  return QBDIPRELOAD_NOT_HANDLED;
}

} // extern "C"
