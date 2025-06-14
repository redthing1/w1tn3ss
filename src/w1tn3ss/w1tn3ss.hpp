#pragma once

#include <redlog/redlog.hpp>
#include <memory>

// forward declarations
namespace w1::coverage {
    class w1cov_tracer;
}

namespace w1 {

enum class analysis_mode {
    inspection,    // static binary inspection
    coverage,      // dynamic coverage tracing
    profiling,     // performance profiling
    debugging      // dynamic debugging support
};

class w1tn3ss {
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
    
    // coverage-specific interface
    bool start_coverage_tracing();
    bool stop_coverage_tracing();
    bool is_coverage_active() const;
    void export_coverage_data(const std::string& output_file = "");
    
    // inspection-specific interface
    bool analyze_binary(const std::string& binary_path);
    
    // statistics and reporting
    void print_statistics() const;

private:
    redlog::logger log_;
    analysis_mode mode_;
    bool initialized_;
    
    // mode-specific components
    std::unique_ptr<coverage::w1cov_tracer> coverage_tracer_;
    
    // initialization helpers
    bool initialize_coverage_mode();
    bool initialize_inspection_mode();
    void cleanup_mode_components();
    
    // environment detection
    analysis_mode detect_mode_from_environment() const;
};

} // namespace w1