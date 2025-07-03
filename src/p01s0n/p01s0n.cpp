#include "p01s0n.hpp"

#include <cstdlib>
#include <iostream>
#include <filesystem>

#include <redlog/redlog.hpp>
#include "p1ll/p1ll.hpp"
#include "p1ll/core/context.hpp"

#ifdef WITNESS_SCRIPT_ENABLED
#include "p1ll/scripting/lua_api.hpp"
#endif

namespace p01s0n {

int p01s0n_run() {
  // check for verbosity setting first
  const char* verbose_env = std::getenv("POISON_VERBOSE");
  if (verbose_env && strlen(verbose_env) > 0) {
    int verbose_level = std::atoi(verbose_env);
    if (verbose_level >= 1) {
      redlog::set_level(redlog::level::trace);
    }
    if (verbose_level >= 2) {
      redlog::set_level(redlog::level::debug);
    }
    if (verbose_level >= 3) {
      redlog::set_level(redlog::level::pedantic);
    }
  }

  auto log = redlog::get_logger("p01s0n");

  log.inf("p01s0n dynamic patcher starting");

  // check for P1LL_CURE environment variable
  const char* cure_script_path = std::getenv("P1LL_CURE");
  if (!cure_script_path || strlen(cure_script_path) == 0) {
    log.warn("P1LL_CURE environment variable not set - no cure script to apply");
    return 0; // not an error, just nothing to do
  }

  std::string script_path(cure_script_path);
  log.inf("found cure script", redlog::field("path", script_path));

  // validate script file exists
  if (!std::filesystem::exists(script_path)) {
    log.err("cure script file does not exist", redlog::field("path", script_path));
    return 1;
  }

#ifdef WITNESS_SCRIPT_ENABLED
  try {
    // create dynamic context for in-memory patching
    auto context = p1ll::core::p1ll_context::create_dynamic();
    p1ll::core::set_current_context(std::move(context));

    log.inf("executing dynamic cure script", redlog::field("script", script_path));

    // execute the cure script in dynamic mode
    p1ll::scripting::lua_api lua_engine;
    auto result = lua_engine.execute_cure_script(script_path);

    // clean up context
    p1ll::core::clear_current_context();

    if (result.success) {
      log.inf(
          "dynamic cure completed successfully", redlog::field("patches_applied", result.patches_applied),
          redlog::field("patches_failed", result.patches_failed)
      );

      if (result.patches_applied > 0) {
        std::cout << "p01s0n: applied " << result.patches_applied << " patches successfully" << std::endl;
      }

      return 0;
    } else {
      log.err(
          "dynamic cure failed", redlog::field("patches_applied", result.patches_applied),
          redlog::field("patches_failed", result.patches_failed),
          redlog::field("error_count", result.error_messages.size())
      );

      for (const auto& error : result.error_messages) {
        log.err("cure error", redlog::field("message", error));
        std::cerr << "p01s0n error: " << error << std::endl;
      }

      return 1;
    }

  } catch (const std::exception& e) {
    log.err("exception during dynamic cure", redlog::field("what", e.what()));
    std::cerr << "p01s0n exception: " << e.what() << std::endl;
    return 1;
  }
#else
  log.err("p01s0n compiled without scripting support (WITNESS_SCRIPT_ENABLED not defined)");
  std::cerr << "p01s0n: compiled without scripting support" << std::endl;
  return 1;
#endif
}

} // namespace p01s0n

// platform-specific library initializers
#ifdef _WIN32
// windows dll entry point
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
  switch (ul_reason_for_call) {
  case DLL_PROCESS_ATTACH:
    // run p01s0n when dll is loaded
    p01s0n::p01s0n_run();
    break;
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH:
    break;
  }
  return TRUE;
}

#else
// unix (darwin/linux) constructor attribute
__attribute__((constructor)) static void p01s0n_init() {
  // run p01s0n when shared library is loaded
  p01s0n::p01s0n_run();
}

#endif