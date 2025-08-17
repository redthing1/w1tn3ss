/**
 * Gadget Demo Tracer
 *
 * Demonstrates gadget execution from within QBDI callbacks.
 * This shows how to safely execute arbitrary code (gadgets) from
 * instrumentation callbacks without reentrancy issues.
 */

#include <QBDI.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <redlog.hpp>
#include "w1tn3ss/gadget/gadget_executor.hpp"
#include "w1tn3ss/util/register_access.hpp"
#include "w1tn3ss/util/env_config.hpp"
#include "QBDIPreload.h"

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

// global state
static QBDI::VM* g_vm = nullptr;
static std::unique_ptr<w1tn3ss::gadget::gadget_executor> g_executor;
static bool g_demo_completed = false;

// demo gadget functions
extern "C" {
int demo_add(int a, int b) { return a + b; }

int demo_multiply(int a, int b) { return a * b; }

size_t demo_strlen(const char* str) {
  if (!str) {
    return 0;
  }
  size_t len = 0;
  while (str[len]) {
    len++;
  }
  return len;
}

void demo_print(const char* msg) { fprintf(stderr, "[gadget] %s\n", msg); }
}

// hardcoded offsets from hook_test_target (from nm output)
// these would normally be resolved dynamically via symbol resolution
static const QBDI::rword OFFSET_get_process_id = 0xa34;
static const QBDI::rword OFFSET_compute_hash = 0xa10;
static const QBDI::rword OFFSET_contains_pattern = 0x9e0;
static const QBDI::rword OFFSET_get_string_length = 0x9d4;
static const QBDI::rword OFFSET_is_valid_pointer = 0xa38;

// get base address of main executable
static QBDI::rword get_main_base() {
#ifdef _WIN32
  auto maps = QBDI::getRemoteProcessMaps(_getpid());
#else
  auto maps = QBDI::getRemoteProcessMaps(getpid());
#endif

  // look for the main executable (usually has the lowest address and contains "hook_test_target")
  QBDI::rword lowest_exec = 0;
  for (const auto& map : maps) {
    if (map.permission & QBDI::PF_EXEC) {
      if (lowest_exec == 0 || map.range.start() < lowest_exec) {
        lowest_exec = map.range.start();
      }
      // if name contains our target binary, prefer that
      if (map.name.find("hook_test_target") != std::string::npos) {
        return map.range.start();
      }
    }
  }
  return lowest_exec;
}

// instruction callback that demonstrates gadget execution
static QBDI::VMAction instruction_callback(
    QBDI::VMInstanceRef vm, QBDI::GPRState* gprState, QBDI::FPRState* fprState, void* data
) {
  static uint64_t inst_count = 0;
  static QBDI::rword main_base = 0;
  inst_count++;

  // get main base address once
  if (main_base == 0) {
    main_base = get_main_base();
  }

  // demonstrate gadget execution after a reasonable number of instructions
  static constexpr uint64_t DEMO_TRIGGER_COUNT = 100;
  if (inst_count == DEMO_TRIGGER_COUNT && !g_demo_completed && g_executor && main_base) {
    g_demo_completed = true;

    auto log = redlog::get_logger("gadgetdemo");
    log.info("=== demonstrating gadget execution from VM callback ===");
    log.dbg("main executable base", redlog::field("base", "0x%llx", main_base));

    try {
      // call get_process_id from target - this is really interesting!
      QBDI::rword get_pid_addr = main_base + OFFSET_get_process_id;
      int pid = g_executor->gadget_call<int>(get_pid_addr, {});
      log.info(
          "target gadget", redlog::field("get_process_id()", "%d", pid), redlog::field("addr", "0x%llx", get_pid_addr)
      );

      // call compute_hash from target
      const char* data = "test data for hash";
      QBDI::rword compute_hash_addr = main_base + OFFSET_compute_hash;
      unsigned int hash =
          g_executor->gadget_call<unsigned int>(compute_hash_addr, {reinterpret_cast<QBDI::rword>(data), strlen(data)});
      log.info("target gadget", redlog::field("compute_hash", "0x%08x", hash), redlog::field("data", data));

      // call contains_pattern from target
      const char* haystack = "the quick brown fox";
      const char* needle = "brown";
      QBDI::rword contains_pattern_addr = main_base + OFFSET_contains_pattern;
      int found = g_executor->gadget_call<int>(
          contains_pattern_addr, {reinterpret_cast<QBDI::rword>(haystack), reinterpret_cast<QBDI::rword>(needle)}
      );
      log.info(
          "target gadget", redlog::field("contains_pattern", found ? "found" : "not found"),
          redlog::field("needle", needle), redlog::field("haystack", haystack)
      );

      // also demonstrate our simple demo gadgets
      int sum = g_executor->gadget_call<int>(reinterpret_cast<QBDI::rword>(demo_add), {42, 58});
      log.info("demo gadget", redlog::field("add(42, 58)", "%d", sum));

      log.info("=== gadget execution complete ===");
    } catch (const std::exception& e) {
      log.error("gadget execution failed", redlog::field("error", e.what()));
    }
  }

  return QBDI::VMAction::CONTINUE;
}

// qbdi preload callbacks
extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_start(void* main_addr) {
  auto log = redlog::get_logger("gadgetdemo");
  log.info("gadgetdemo tracer loaded", redlog::field("main", "%p", main_addr));
  return QBDIPRELOAD_NOT_HANDLED;
}

QBDI_EXPORT int qbdipreload_on_premain(void* gprCtx, void* fpuCtx) { return QBDIPRELOAD_NOT_HANDLED; }

QBDI_EXPORT int qbdipreload_on_main(int argc, char** argv) { return QBDIPRELOAD_NOT_HANDLED; }

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vminstance, QBDI::rword start, QBDI::rword stop) {
  auto log = redlog::get_logger("gadgetdemo");

  // get config
  w1::util::env_config config_loader("GADGETDEMO_");
  int verbose = config_loader.get<int>("VERBOSE", 0);

  // set log level based on debug level
  if (verbose >= 4) {
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

  log.inf("gadgetdemo configuration", redlog::field("verbose", verbose));

  if (!vminstance) {
    log.error("VM instance is NULL");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  // save VM instance
  g_vm = static_cast<QBDI::VM*>(vminstance);

  try {
    // create gadget executor
    g_executor = std::make_unique<w1tn3ss::gadget::gadget_executor>(g_vm);
    log.info("gadget executor initialized");

    // add instruction callback
    g_vm->addCodeCB(QBDI::PREINST, instruction_callback, nullptr);

    // demonstrate immediate gadget execution
    log.info("testing gadget execution from on_run callback...");
    int result = g_executor->gadget_call<int>(reinterpret_cast<QBDI::rword>(demo_add), {100, 200});
    log.info("immediate test", redlog::field("add(100, 200)", "%d", result));

    // run the VM
    log.info("starting instrumented execution");
    g_vm->run(start, stop);

  } catch (const std::exception& e) {
    log.error("initialization failed", redlog::field("error", e.what()));
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
  auto log = redlog::get_logger("gadgetdemo");
  log.info("gadgetdemo tracer exiting", redlog::field("status", "%d", status));
  g_executor.reset();
  return QBDIPRELOAD_NOT_HANDLED;
}

} // extern "C"