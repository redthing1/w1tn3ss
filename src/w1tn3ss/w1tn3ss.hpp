#pragma once

#include <memory>
#include <redlog/redlog.hpp>

// Windows DLL export/import declarations
#ifdef _WIN32
#ifdef W1TN3SS_EXPORTS
#define W1TN3SS_API __declspec(dllexport)
#elif defined(W1TN3SS_IMPORTS)
#define W1TN3SS_API __declspec(dllimport)
#else
#define W1TN3SS_API
#endif
#else
#define W1TN3SS_API
#endif

// forward declarations
namespace w1::coverage {
class coverage_tracer;
}

namespace w1 {

enum class analysis_mode {
  inspection, // static binary inspection
  coverage,   // dynamic coverage tracing
  profiling,  // performance profiling
  debugging   // dynamic debugging support
};

class W1TN3SS_API w1tn3ss {
public:
  w1tn3ss();
  ~w1tn3ss();

  // lifecycle management
  bool initialize(analysis_mode mode = analysis_mode::inspection);
  void shutdown();
  bool is_initialized() const { return initialized_; }

  // mode management
  analysis_mode get_mode() const { return mode_; }
  bool set_mode(analysis_mode mode);


  // inspection-specific interface
  bool analyze_binary(const std::string& binary_path);

  // statistics and reporting
  void print_statistics() const;

private:
  redlog::logger log_;
  analysis_mode mode_;
  bool initialized_;


  // initialization helpers
  bool initialize_coverage_mode();
  bool initialize_inspection_mode();
  void cleanup_mode_components();

  // environment detection
  analysis_mode detect_mode_from_environment() const;
};

} // namespace w1