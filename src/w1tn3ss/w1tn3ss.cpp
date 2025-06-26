#include "w1tn3ss.hpp"
#include <cstdlib>
#include <cstring>

namespace w1 {

w1tn3ss::w1tn3ss() : log_(redlog::get_logger("w1tn3ss")), mode_(analysis_mode::inspection), initialized_(false) {
  log_.debug("w1tn3ss analysis engine created");
}

w1tn3ss::~w1tn3ss() {
  if (initialized_) {
    shutdown();
  }
  log_.debug("w1tn3ss analysis engine destroyed");
}

bool w1tn3ss::initialize(analysis_mode mode) {
  if (initialized_) {
    log_.warn("engine already initialized");
    return true;
  }

  // detect mode from environment if not explicitly set
  if (mode == analysis_mode::inspection) {
    analysis_mode detected_mode = detect_mode_from_environment();
    if (detected_mode != analysis_mode::inspection) {
      mode = detected_mode;
      log_.info("detected analysis mode from environment", redlog::field("mode", static_cast<int>(mode)));
    }
  }

  mode_ = mode;

  log_.info("initializing w1tn3ss analysis engine", redlog::field("mode", static_cast<int>(mode_)));

  bool success = false;

  switch (mode_) {
  case analysis_mode::coverage:
    success = initialize_coverage_mode();
    break;

  case analysis_mode::inspection:
    success = initialize_inspection_mode();
    break;

  case analysis_mode::profiling:
  case analysis_mode::debugging:
    log_.warn("mode not yet implemented", redlog::field("mode", static_cast<int>(mode_)));
    success = false;
    break;
  }

  if (success) {
    initialized_ = true;
    log_.info("w1tn3ss engine initialized successfully", redlog::field("mode", static_cast<int>(mode_)));
  } else {
    log_.error("w1tn3ss engine initialization failed");
    cleanup_mode_components();
  }

  return success;
}

void w1tn3ss::shutdown() {
  if (!initialized_) {
    return;
  }

  log_.info("shutting down w1tn3ss analysis engine");

  // stop any active operations

  // cleanup mode-specific components
  cleanup_mode_components();

  initialized_ = false;
  log_.info("w1tn3ss engine shutdown complete");
}

bool w1tn3ss::set_mode(analysis_mode mode) {
  if (initialized_ && mode_ != mode) {
    log_.warn("cannot change mode while engine is initialized");
    return false;
  }

  mode_ = mode;
  return true;
}


bool w1tn3ss::analyze_binary(const std::string& binary_path) {
  if (mode_ != analysis_mode::inspection) {
    log_.error("engine not in inspection mode");
    return false;
  }

  log_.info("analyzing binary", redlog::field("path", binary_path));

  // future: implement binary analysis logic
  log_.warn("binary analysis not yet implemented");

  return false;
}

void w1tn3ss::print_statistics() const {
  log_.info(
      "w1tn3ss statistics", redlog::field("mode", static_cast<int>(mode_)), redlog::field("initialized", initialized_)
  );
}

bool w1tn3ss::initialize_coverage_mode() {
  log_.debug("initializing coverage mode");

  // Coverage mode is handled by specific implementations (QBDIPreload, standalone)
  // This class doesn't manage coverage tracers directly anymore
  
  log_.debug("coverage mode initialized successfully");
  return true;
}

bool w1tn3ss::initialize_inspection_mode() {
  log_.debug("initializing inspection mode");

  // future: initialize static analysis components
  log_.debug("inspection mode initialized successfully");

  return true;
}

void w1tn3ss::cleanup_mode_components() {
  log_.debug("cleaning up mode-specific components");

  // future: cleanup other mode components
}

analysis_mode w1tn3ss::detect_mode_from_environment() const {
  // check for w1cov coverage mode
  const char* w1cov_enabled = std::getenv("W1COV_ENABLED");
  if (w1cov_enabled && std::strcmp(w1cov_enabled, "1") == 0) {
    return analysis_mode::coverage;
  }

  // future: check for other mode environment variables

  return analysis_mode::inspection; // default
}

} // namespace w1