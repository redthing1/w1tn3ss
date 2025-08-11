#include "p01s0n.hpp"
#include "p01s0n_config.hpp"

#include <cstdlib>
#include <iostream>
#include <filesystem>
#include <fstream>

#include <redlog.hpp>
#include "p1ll/core/context.hpp"

#include "p1ll/scripting/script_engine_factory.hpp"

namespace p01s0n {

int p01s0n_run() {
  // get config from environment
  p01s0n_config config = p01s0n_config::from_environment();

  // set log level based on verbose setting
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

  log.inf("p01s0n dynamic patcher starting");

  // check for POISON_CURE environment variable
  const char* cure_script_path = std::getenv("POISON_CURE");
  if (!cure_script_path || strlen(cure_script_path) == 0) {
    log.warn("POISON_CURE environment variable not set, no cure script to apply");
    return 0; // not an error, just nothing to do
  }

  std::string script_path(cure_script_path);
  log.inf("found cure script", redlog::field("path", script_path));

  // validate script file exists
  if (!std::filesystem::exists(script_path)) {
    log.err("cure script file does not exist", redlog::field("path", script_path));
    return 1;
  }

  try {
    // create dynamic context for in-memory patching
    auto context = p1ll::context::create_dynamic();

    log.inf("executing dynamic cure script", redlog::field("script", script_path));

    // read script content from file
    std::ifstream file(script_path);
    if (!file.is_open()) {
      log.err("failed to open script file", redlog::field("path", script_path));
      return 1;
    }

    std::string script_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    // execute the cure script in dynamic mode
    auto script_engine = p1ll::scripting::ScriptEngineFactory::create();
    if (!script_engine) {
      log.err("failed to create script engine");
      return 1;
    }
    auto result = script_engine->execute_script(*context, script_content);

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