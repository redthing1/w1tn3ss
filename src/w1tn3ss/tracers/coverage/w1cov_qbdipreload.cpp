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
            return false;
        }

        try {
            // Create tracer from environment
            tracer_ = w1::coverage::create_coverage_tracer_from_env();
            
            if (!tracer_) {
                return false;
            }

            // Initialize tracer
            if (!tracer_->initialize()) {
                tracer_.reset();
                return false;
            }

            // Create callback registrar
            registrar_ = std::make_unique<w1::framework::callback_registrar<w1::coverage::coverage_tracer>>("w1cov");

            enabled_ = true;
            return true;

        } catch (const std::exception& e) {
            return false;
        }
    }

    bool register_callbacks(QBDI::VM* vm) {
        if (!tracer_ || !registrar_) {
            return false;
        }

        // Register callbacks using framework
        return registrar_->register_callbacks(vm, tracer_.get());
    }

    void export_coverage() {
        // Export is now handled by tracer.shutdown()
        // This method is kept for compatibility but does nothing
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
    // Early initialization check
    if (!w1::coverage::is_coverage_enabled()) {
        return QBDIPRELOAD_NOT_HANDLED;
    }

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

    // Register callbacks using framework
    QBDI::VM* qbdi_vm = static_cast<QBDI::VM*>(vm);
    if (!wrapper->register_callbacks(qbdi_vm)) {
        vm->run(start, stop);
        return QBDIPRELOAD_NO_ERROR;
    }

    // Run with instrumentation
    vm->run(start, stop);

    return QBDIPRELOAD_NO_ERROR;
}

int qbdipreload_on_exit(int status) {
    auto* wrapper = get_coverage_wrapper();
    
    if (!wrapper->is_enabled()) {
        return QBDIPRELOAD_NO_ERROR;
    }

    // Cleanup (tracer.shutdown() will handle export)
    wrapper->cleanup();

    return QBDIPRELOAD_NO_ERROR;
}

} // extern "C"