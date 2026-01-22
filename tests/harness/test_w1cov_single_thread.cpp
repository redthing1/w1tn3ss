#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "tracers/w1cov/engine/coverage_engine.hpp"
#include "tracers/w1cov/instrument/coverage_recorder.hpp"
#include "w1base/thread_utils.hpp"
#include "w1formats/drcov.hpp"
#include "w1instrument/tracer/vm_session.hpp"
#include "w1runtime/module_catalog.hpp"

extern "C" uint64_t test_coverage_control_flow(uint64_t value);

int main() {
  std::cout << "\n=== testing w1cov single-thread ===\n";

  w1cov::coverage_config config;
  config.output_file = "test_w1cov_single_thread.drcov";
  config.instrumentation.include_modules = {"test_w1cov_single_thread"};

  w1::runtime::module_catalog modules;
  modules.refresh();

  auto engine = std::make_shared<w1cov::coverage_engine>(config);
  engine->configure(modules);

  w1::vm_session_config session_config;
  session_config.instrumentation = config.instrumentation;
  session_config.thread_id = w1::util::current_thread_id();
  session_config.thread_name = "main";
  session_config.shared_modules = &modules;

  w1::vm_session<w1cov::coverage_recorder<w1cov::coverage_mode::basic_block>> session(
      session_config, w1cov::coverage_recorder<w1cov::coverage_mode::basic_block>(engine)
  );

  if (!session.initialize()) {
    std::cout << "failed to initialize w1cov tracer\n";
    return 1;
  }

  uint64_t result1 = 0;
  uint64_t result2 = 0;
  uint64_t result3 = 0;
  uint64_t result4 = 0;

  if (!session.call(reinterpret_cast<uint64_t>(test_coverage_control_flow), {5}, &result1)) {
    std::cout << "failed to trace function (value < 10)\n";
    return 1;
  }
  if (!session.call(reinterpret_cast<uint64_t>(test_coverage_control_flow), {15}, &result2)) {
    std::cout << "failed to trace function (10 <= value < 20)\n";
    return 1;
  }
  if (!session.call(reinterpret_cast<uint64_t>(test_coverage_control_flow), {30}, &result3)) {
    std::cout << "failed to trace function (20 <= value < 50)\n";
    return 1;
  }
  if (!session.call(reinterpret_cast<uint64_t>(test_coverage_control_flow), {100}, &result4)) {
    std::cout << "failed to trace function (value >= 50)\n";
    return 1;
  }

  session.shutdown();

  if (engine->coverage_unit_count() == 0 || engine->total_hits() == 0) {
    std::cout << "coverage engine reported no activity\n";
    return 1;
  }

  if (!engine->export_coverage()) {
    std::cout << "coverage export produced no output\n";
    return 1;
  }

  auto data = drcov::read(config.output_file);
  if (data.basic_blocks.empty()) {
    std::cout << "no basic blocks recorded\n";
    return 1;
  }
  if (!data.has_hitcounts()) {
    std::cout << "missing hitcounts in drcov output\n";
    return 1;
  }

  bool has_module = false;
  for (const auto& module : data.modules) {
    if (module.path.find("test_w1cov_single_thread") != std::string::npos) {
      has_module = true;
      break;
    }
  }
  if (!has_module) {
    std::cout << "self module missing from drcov output\n";
    return 1;
  }

  std::cout << "w1cov single-thread test completed\n";
  std::cout << "function results: " << result1 << ", " << result2 << ", " << result3 << ", " << result4 << "\n";
  std::cout << "unique blocks: " << engine->coverage_unit_count() << "\n";
  std::cout << "total hits: " << engine->total_hits() << "\n";
  std::cout << "coverage output: " << config.output_file << "\n";

  return 0;
}
