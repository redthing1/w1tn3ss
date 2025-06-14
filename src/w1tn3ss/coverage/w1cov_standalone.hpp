#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace w1::coverage {

/**
 * W1TN3SS Coverage Tracer using standalone QBDI approach
 *
 * This implementation uses the proven working QBDI standalone VM pattern
 * instead of the problematic QBDIPreload approach. Based on the successful
 * fibonacci example pattern.
 */
class w1cov_standalone {
public:
  w1cov_standalone();
  ~w1cov_standalone();

  // Core initialization
  bool initialize();

  // Function instrumentation (like addInstrumentedModuleFromAddr)
  bool instrument_function(void* func_ptr, const std::string& name = "");

  // Call instrumented function with coverage (like vm.call())
  bool call_instrumented_function(void* func_ptr, const std::vector<uint64_t>& args = {}, uint64_t* result = nullptr);

  // Run entire binary with instrumentation (like vm.run())
  bool run_instrumented_binary(
      const std::string& binary_path, const std::vector<std::string>& args = {}, int* exit_code = nullptr
  );

  // Coverage data access
  size_t get_coverage_count() const;
  bool export_coverage(const std::string& output_file);
  void print_stats() const;

  // Non-copyable
  w1cov_standalone(const w1cov_standalone&) = delete;
  w1cov_standalone& operator=(const w1cov_standalone&) = delete;

  // Forward declaration for callback access
  class impl;

private:
  std::unique_ptr<impl> pimpl;
};

} // namespace w1::coverage