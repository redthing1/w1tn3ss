#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#include "tracers/w1cov/coverage_engine.hpp"
#include "tracers/w1cov/coverage_recorder.hpp"
#include "w1formats/drcov.hpp"
#include "w1instrument/process_instrumentor.hpp"
#include "w1runtime/process_observer.hpp"

#include "w1cov_demo_lib.hpp"

int main() {
  using tracer_t = w1cov::coverage_recorder<w1cov::coverage_mode::basic_block>;
  using w1::test_helpers::demo_library;
  using w1::test_helpers::load_demo_library;
  using w1::test_helpers::unload_demo_library;

  std::cout << "\n=== testing w1cov module filtering ===\n";

  w1cov::coverage_config config;
  config.output_file = "test_w1cov_module_filtering.drcov";
  config.instrumentation.include_modules = {"w1cov_demo_lib"};

  w1::runtime::process_observer monitor;
  monitor.modules().refresh();

  auto engine = std::make_shared<w1cov::coverage_engine>(config);
  engine->configure(monitor.modules());

  w1::instrument::process_instrumentor<tracer_t>::config process_config{};
  process_config.instrumentation = config.instrumentation;
  process_config.attach_new_threads = false;
  process_config.refresh_on_module_events = true;
  process_config.owns_observer = true;

  w1::instrument::process_instrumentor<tracer_t> process(
      monitor, process_config, [engine](const w1::runtime::thread_info&) { return tracer_t(engine); }
  );
  process.start();

  auto main_session = process.attach_current_thread("main");
  if (!main_session) {
    std::cerr << "failed to attach main session\n";
    return 1;
  }

  demo_library lib{};
  if (!load_demo_library(lib)) {
    std::cerr << "failed to load demo library\n";
    return 1;
  }

  for (int i = 0; i < 5; ++i) {
    monitor.poll_once();
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }

  uint64_t result = 0;
  if (!main_session->call(reinterpret_cast<uint64_t>(lib.add), {4, 7}, &result)) {
    std::cerr << "failed to trace demo add\n";
    return 1;
  }
  if (!main_session->call(reinterpret_cast<uint64_t>(lib.branch), {9}, &result)) {
    std::cerr << "failed to trace demo branch\n";
    return 1;
  }

  main_session.reset();
  process.stop();
  unload_demo_library(lib);

  if (!engine->export_coverage()) {
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

  if (engine->module_count() == 0 || engine->coverage_unit_count() == 0) {
    std::cerr << "engine did not record filtered module coverage\n";
    return 1;
  }

  std::cout << "w1cov module filtering test completed\n";
  return 0;
}
