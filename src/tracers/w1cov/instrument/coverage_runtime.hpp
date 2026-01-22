#pragma once

#include <memory>
#include <string>

#include <QBDI.h>

#include "w1instrument/process_instrumentor.hpp"
#include "w1runtime/process_observer.hpp"

#include "config/coverage_config.hpp"
#include "engine/coverage_engine.hpp"
#include "instrument/coverage_recorder.hpp"

namespace w1cov {

class coverage_runtime {
public:
  explicit coverage_runtime(coverage_config config);

  bool run_main(QBDI::VM* vm, uint64_t start, uint64_t stop, std::string name = "main");
  void stop();
  bool export_coverage();

  coverage_engine& engine() const { return *engine_; }

private:
  using block_recorder = coverage_recorder<coverage_mode::basic_block>;
  using inst_recorder = coverage_recorder<coverage_mode::instruction>;
  using block_instrumentor = w1::instrument::process_instrumentor<block_recorder>;
  using inst_instrumentor = w1::instrument::process_instrumentor<inst_recorder>;

  void reset_instrumentors();

  w1::runtime::process_observer observer_{};
  std::shared_ptr<coverage_engine> engine_{};
  coverage_config config_{};
  std::unique_ptr<block_instrumentor> block_instrumentor_{};
  std::unique_ptr<inst_instrumentor> inst_instrumentor_{};
};

} // namespace w1cov
