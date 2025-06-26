/**
 * w1cov QBDIPreload Coverage Tracer
 *
 * Coverage collection using QBDI for launch-time instrumentation.
 * Exports DrCov format for analysis tools.
 *
 * Environment variables:
 * - W1COV_ENABLED: Set to "1" to enable coverage collection
 * - W1COV_OUTPUT_FILE: Output file path (default: w1cov.drcov)
 * - W1COV_DEBUG: Set to "1" for verbose debug output
 */

#include "coverage_tracer.hpp"
#include "../../framework/callback_registrar.hpp"
#include "w1cov_constants.hpp"

#include <memory>
#include <atomic>

#include "QBDIPreload.h"
#include <QBDI.h>

namespace {

// === Simple QBDIPreload wrapper for coverage tracer ===
// This avoids the problematic global state pattern

class qbdipreload_coverage_wrapper {
public:
    qbdipreload_coverage_wrapper() = default;
    ~qbdipreload_coverage_wrapper() = default;

    bool initialize() {
        // Check if coverage is enabled
        if (!w1::coverage::is_coverage_enabled()) {
            w1::cov::log("w1cov not enabled");
            return false;
        }

        try {
            // Create tracer from environment
            tracer_ = w1::coverage::create_coverage_tracer_from_env();
            
            if (!tracer_) {
                w1::cov::log("Failed to create coverage tracer");
                return false;
            }

            // Initialize tracer
            if (!tracer_->initialize()) {
                w1::cov::log("Failed to initialize coverage tracer");
                tracer_.reset();
                return false;
            }

            // Create callback registrar
            registrar_ = std::make_unique<w1::framework::callback_registrar<w1::coverage::coverage_tracer>>("w1cov");

            enabled_ = true;
            w1::cov::log("w1cov coverage tracer initialized successfully");
            return true;

        } catch (const std::exception& e) {
            w1::cov::log("Failed to initialize coverage tracer: %s", e.what());
            return false;
        }
    }

    bool register_callbacks(QBDI::VM* vm) {
        if (!tracer_ || !registrar_) {
            w1::cov::log("Coverage tracer not initialized");
            return false;
        }

        // Register callbacks using framework
        return registrar_->register_callbacks(vm, tracer_.get());
    }

    void export_coverage() {
        if (!tracer_) {
            return;
        }

        try {
            // Export using tracer's configured output file
            tracer_->export_data(tracer_->get_config().output_file);
        } catch (const std::exception& e) {
            w1::cov::log("Failed to export coverage: %s", e.what());
        }
    }

    void cleanup() {
        if (tracer_) {
            tracer_->shutdown();
            tracer_.reset();
        }
        
        if (registrar_) {
            registrar_.reset();
        }
        
        enabled_ = false;
    }

    bool is_enabled() const { return enabled_; }
    bool is_debug_mode() const { 
        return tracer_ ? tracer_->get_config().debug_mode : false; 
    }
    
    w1::coverage::coverage_tracer* get_tracer() const { return tracer_.get(); }

private:
    std::unique_ptr<w1::coverage::coverage_tracer> tracer_;
    std::unique_ptr<w1::framework::callback_registrar<w1::coverage::coverage_tracer>> registrar_;
    bool enabled_ = false;
};

// Single static instance - much cleaner than global state
qbdipreload_coverage_wrapper* get_coverage_wrapper() {
    static qbdipreload_coverage_wrapper instance;
    return &instance;
}

} // anonymous namespace

extern "C" {

QBDIPRELOAD_INIT;

int qbdipreload_on_start(void* main) {
    // Always print something to verify library is loaded
    w1::cov::log("qbdipreload_on_start called");
    
    // Early initialization check
    if (!w1::coverage::is_coverage_enabled()) {
        w1::cov::log("w1cov not enabled, exiting");
        return QBDIPRELOAD_NOT_HANDLED;
    }

    w1::cov::log("w1cov enabled, continuing");
    return QBDIPRELOAD_NOT_HANDLED;
}

int qbdipreload_on_premain(void* gprCtx, void* fpuCtx) { 
    return QBDIPRELOAD_NOT_HANDLED; 
}

int qbdipreload_on_main(int argc, char** argv) {
    if (!w1::coverage::is_coverage_enabled()) {
        return QBDIPRELOAD_NOT_HANDLED;
    }

    // Initialize coverage tracer
    auto* wrapper = get_coverage_wrapper();
    if (!wrapper->initialize()) {
        w1::cov::log("Failed to initialize coverage tracer");
        return QBDIPRELOAD_NOT_HANDLED;
    }

    return QBDIPRELOAD_NOT_HANDLED;
}

int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
    auto* wrapper = get_coverage_wrapper();
    
    if (!wrapper->is_enabled()) {
        vm->run(start, stop);
        return QBDIPRELOAD_NO_ERROR;
    }

    if (wrapper->is_debug_mode()) {
        w1::cov::log("qbdipreload_on_run: start=0x%llx, stop=0x%llx", start, stop);
    }

    // Register callbacks using framework
    QBDI::VM* qbdi_vm = static_cast<QBDI::VM*>(vm);
    if (!wrapper->register_callbacks(qbdi_vm)) {
        w1::cov::log("Failed to register coverage callbacks");
        vm->run(start, stop);
        return QBDIPRELOAD_NO_ERROR;
    }

    if (wrapper->is_debug_mode()) {
        w1::cov::log("Coverage callbacks registered, starting instrumentation");
    }

    // Run with instrumentation
    vm->run(start, stop);

    if (wrapper->is_debug_mode()) {
        w1::cov::log("Instrumentation completed");
    }

    return QBDIPRELOAD_NO_ERROR;
}

int qbdipreload_on_exit(int status) {
    auto* wrapper = get_coverage_wrapper();
    
    if (!wrapper->is_enabled()) {
        return QBDIPRELOAD_NO_ERROR;
    }

    if (wrapper->is_debug_mode()) {
        w1::cov::log("qbdipreload_on_exit: exporting coverage data");
    }

    // Export coverage using framework
    wrapper->export_coverage();

    if (wrapper->is_debug_mode()) {
        w1::cov::log("w1cov coverage collection completed");
    }

    // Cleanup
    wrapper->cleanup();

    return QBDIPRELOAD_NO_ERROR;
}

} // extern "C"