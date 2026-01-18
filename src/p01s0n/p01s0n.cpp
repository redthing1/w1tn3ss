#include "p01s0n.hpp"
#include "p01s0n_config.hpp"

#include <cstdlib>
#include <iostream>
#include <filesystem>
#include <fstream>

#include <redlog.hpp>
#include "p1ll/p1ll.hpp"
#include "p1ll/scripting/script_engine_factory.hpp"

namespace p01s0n {

int p01s0n_run() {
  p01s0n_config config = p01s0n_config::discover();

  if (config.verbose >= 4) {
    redlog::set_level(redlog::level::pedantic);
  } else if (config.verbose >= 3) {
    redlog::set_level(redlog::level::debug);
  } else if (config.verbose >= 2) {
    redlog::set_level(redlog::level::trace);
  } else if (config.verbose >= 1) {
    redlog::set_level(redlog::level::verbose);
  } else {
    redlog::set_level(redlog::level::info);
  }

  auto log = redlog::get_logger("p01s0n");

  log.inf("p01s0n dynamic patcher starting", redlog::field("config_source", config.source_string()));

  if (config.script_path.empty()) {
    log.warn("no cure script configured");
    return 0;
  }

  log.inf("found cure script", redlog::field("path", config.script_path));

  if (!std::filesystem::exists(config.script_path)) {
    log.err("script file does not exist", redlog::field("path", config.script_path));
    return 1;
  }

  try {
    auto session = p1ll::engine::session::for_process();

    log.inf("executing dynamic cure script", redlog::field("script", config.script_path));

    std::ifstream file(config.script_path);
    if (!file.is_open()) {
      log.err("failed to open script file", redlog::field("path", config.script_path));
      return 1;
    }

    std::string script_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    auto script_engine = p1ll::scripting::ScriptEngineFactory::create();
    if (!script_engine) {
      log.err("failed to create script engine");
      return 1;
    }

    auto result = script_engine->execute_script(session, script_content);

    if (result.ok() && result.value.success) {
      log.inf(
          "dynamic cure completed successfully", redlog::field("patches_applied", result.value.applied),
          redlog::field("patches_failed", result.value.failed)
      );
      return 0;
    } else {
      log.err(
          "dynamic cure failed", redlog::field("patches_applied", result.value.applied),
          redlog::field("patches_failed", result.value.failed),
          redlog::field("error_count", result.value.diagnostics.size())
      );

      for (const auto& error : result.value.diagnostics) {
        log.err("cure error", redlog::field("message", error.message));
      }
      if (!result.ok() && !result.status_info.message.empty()) {
        log.err("cure error", redlog::field("message", result.status_info.message));
      }
      return 1;
    }

  } catch (const std::exception& e) {
    log.err("exception during dynamic cure", redlog::field("what", e.what()));
    return 1;
  }
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
