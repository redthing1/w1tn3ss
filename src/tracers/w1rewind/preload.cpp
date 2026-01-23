#include <memory>
#include <stdexcept>

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
#include "w1instrument/logging.hpp"
#include "w1instrument/preload_driver.hpp"

namespace {

using rewind_instruction_session = w1::vm_session<w1rewind::rewind_instruction_tracer>;
using rewind_block_session = w1::vm_session<w1rewind::rewind_block_tracer>;

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

struct rewind_runtime {
  std::shared_ptr<w1::rewind::trace_file_writer> writer;
  std::unique_ptr<rewind_instruction_session> instruction_session;
  std::unique_ptr<rewind_block_session> block_session;
  bool instruction_flow = false;
};

struct rewind_preload_policy {
  using config_type = w1rewind::rewind_config;
  using runtime_type = rewind_runtime;

  static config_type load_config() {
    std::string config_error;
    auto config = config_type::from_environment(config_error);
    if (!config_error.empty()) {
      throw std::runtime_error(config_error);
    }
    return config;
  }

  static void configure_logging(const config_type& config) {
    w1::instrument::configure_redlog_verbosity(config.verbose, true);
  }

  static bool should_exclude_self(const config_type& config) { return config.exclude_self; }

  static void apply_self_excludes(config_type& config, const void* anchor) {
    w1::util::append_self_excludes(config.instrumentation, anchor);
  }

  static std::unique_ptr<runtime_type> create_runtime(const config_type& config, QBDI::VMInstanceRef vm) {
    auto runtime = std::make_unique<runtime_type>();

    auto log = redlog::get_logger("w1rewind.preload");

    w1::rewind::trace_file_writer_config writer_config;
    writer_config.path = config.output_path;
    writer_config.log = redlog::get_logger("w1rewind.trace");
    writer_config.compression =
        config.compress_trace ? w1::rewind::trace_compression::zstd : w1::rewind::trace_compression::none;
    writer_config.chunk_size = config.chunk_size;
    runtime->writer = w1::rewind::make_trace_file_writer(std::move(writer_config));
    if (!runtime->writer || !runtime->writer->open()) {
      log.err("failed to initialize trace writer");
      return nullptr;
    }

    w1::vm_session_config session_config;
    session_config.instrumentation = config.instrumentation;
    session_config.thread_id = 1;
    session_config.thread_name = "main";

    runtime->instruction_flow = config.flow.mode == w1rewind::rewind_config::flow_options::mode::instruction;

    if (config.memory.access != w1rewind::rewind_config::memory_access::none && !config.memory.values) {
      log.wrn("memory values disabled; replayable memory state will be incomplete");
    }
    if (!config.memory.ranges.empty() &&
        !has_filter(config.memory.filters, w1rewind::rewind_config::memory_filter_kind::ranges)) {
      log.wrn("memory ranges configured but ranges filter not enabled");
    }

    if (runtime->instruction_flow) {
      runtime->instruction_session =
          std::make_unique<rewind_instruction_session>(session_config, vm, std::in_place, config, runtime->writer);
    } else {
      runtime->block_session =
          std::make_unique<rewind_block_session>(session_config, vm, std::in_place, config, runtime->writer);
    }

    return runtime;
  }

  static bool run(runtime_type& runtime, QBDI::VMInstanceRef, QBDI::rword start, QBDI::rword stop) {
    auto log = redlog::get_logger("w1rewind.preload");
    log.inf("qbdipreload_on_run");

    if (runtime.instruction_flow) {
      log.inf("starting rewind session", redlog::field("start", "0x%llx", static_cast<unsigned long long>(start)),
              redlog::field("stop", "0x%llx", static_cast<unsigned long long>(stop)));
      if (runtime.instruction_session) {
        return runtime.instruction_session->run(static_cast<uint64_t>(start), static_cast<uint64_t>(stop));
      }
    } else {
      log.inf("starting rewind session", redlog::field("start", "0x%llx", static_cast<unsigned long long>(start)),
              redlog::field("stop", "0x%llx", static_cast<unsigned long long>(stop)));
      if (runtime.block_session) {
        return runtime.block_session->run(static_cast<uint64_t>(start), static_cast<uint64_t>(stop));
      }
    }

    return false;
  }

  static void shutdown(runtime_type& runtime, int status, const config_type&) {
    auto log = redlog::get_logger("w1rewind.preload");
    log.inf("qbdipreload_on_exit", redlog::field("status", status));

    if (runtime.instruction_session) {
      runtime.instruction_session->shutdown(false);
    }
    if (runtime.block_session) {
      runtime.block_session->shutdown(false);
    }

    if (runtime.writer) {
      runtime.writer->close();
    }
  }
};

using preload_state = w1::instrument::preload_state<rewind_preload_policy>;

preload_state g_state;

} // namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  try {
    if (!w1::instrument::preload_run(g_state, reinterpret_cast<const void*>(&qbdipreload_on_run), vm, start, stop)) {
      auto log = redlog::get_logger("w1rewind.preload");
      log.err("rewind session run failed");
      return QBDIPRELOAD_ERR_STARTUP_FAILED;
    }
  } catch (const std::exception& error) {
    auto log = redlog::get_logger("w1rewind.preload");
    log.err("invalid rewind config", redlog::field("error", error.what()));
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
  w1::instrument::preload_shutdown(g_state, status);
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
