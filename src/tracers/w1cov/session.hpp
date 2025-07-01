#pragma once

#include "coverage_tracer.hpp"
#include "coverage_config.hpp"
#include <w1tn3ss/engine/tracer_engine.hpp>
#include <QBDI.h>
#include <memory>
#include <vector>

namespace w1cov {

class session {
public:
  session();
  explicit session(const coverage_config& config);
  ~session();

  bool initialize();
  void shutdown();
  bool is_initialized() const;

  void set_output_file(const std::string& filepath);
  void add_target_module_pattern(const std::string& pattern);

  bool trace_function(void* func_ptr, const std::vector<uint64_t>& args = {}, uint64_t* result = nullptr);

  size_t get_basic_block_count() const;
  uint64_t get_total_hits() const;

  coverage_config& get_config();

private:
  coverage_config config_;
  std::unique_ptr<coverage_tracer> tracer_;
  std::unique_ptr<w1::tracer_engine<coverage_tracer>> engine_;
  bool initialized_;
};

} // namespace w1cov