#include <cstdint>
#include <iostream>
#include <string>

#include "runtime/coverage_runtime.hpp"
#include "w1formats/drcov.hpp"

#include "w1cov_demo_lib.hpp"

int main() {
  using w1::test_helpers::demo_library;
  using w1::test_helpers::load_demo_library;
  using w1::test_helpers::run_demo_thread;
  using w1::test_helpers::unload_demo_library;

  w1cov::coverage_config config;
  config.output_file = "test_w1cov_multithread.drcov";
  config.common.instrumentation.include_modules = {"w1cov_demo_lib"};

  using process_runtime = w1cov::coverage_process_runtime<w1cov::coverage_mode::basic_block>;
  process_runtime runtime(config);

  auto main_session = runtime.session().attach_current_thread("main");
  if (!main_session) {
    std::cerr << "failed to attach main session\n";
    return 1;
  }

  demo_library lib{};
  if (!load_demo_library(lib)) {
    std::cerr << "failed to load demo library\n";
    return 1;
  }

  runtime.refresh_modules();

  uint64_t result = 0;
  if (!main_session->call(reinterpret_cast<uint64_t>(lib.add), {1, 2}, &result)) {
    std::cerr << "failed to trace demo add\n";
    return 1;
  }
  if (!main_session->call(reinterpret_cast<uint64_t>(lib.branch), {42}, &result)) {
    std::cerr << "failed to trace demo branch\n";
    return 1;
  }

  if (!run_demo_thread(lib.thread_proc, 25)) {
    std::cerr << "failed to run demo thread\n";
    return 1;
  }

  main_session.reset();
  runtime.stop();
  unload_demo_library(lib);

  if (!runtime.export_output()) {
    std::cerr << "coverage export produced no output\n";
    return 1;
  }

  auto data = drcov::read(config.output_file);
  if (data.basic_blocks.empty()) {
    std::cerr << "no basic blocks recorded\n";
    return 1;
  }

  bool has_module = false;
  for (const auto& module : data.modules) {
    if (module.path.find("w1cov_demo_lib") != std::string::npos) {
      has_module = true;
      break;
    }
  }
  if (!has_module) {
    std::cerr << "demo module missing from drcov output\n";
    return 1;
  }

  std::cout << "w1cov multithread demo completed\n";
  return 0;
}
