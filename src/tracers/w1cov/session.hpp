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

  void add_target_module_pattern(const std::string& pattern);

  bool trace_function(void* func_ptr, const std::vector<uint64_t>& args = {}, uint64_t* result = nullptr);

  size_t get_coverage_unit_count() const;
  size_t get_module_count() const;
  uint64_t get_total_hits() const;
  void print_statistics() const;

  bool export_coverage(const std::string& output_path) const;
  void clear_coverage();

  coverage_config& get_config();

private:
  coverage_config config_;
  std::unique_ptr<coverage_tracer> tracer_;
  std::unique_ptr<w1::tracer_engine<coverage_tracer>> engine_;
  bool initialized_;
};

} // namespace w1cov