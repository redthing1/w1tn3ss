/**
 * Gadget Demo Tracer
 * 
 * Demonstrates gadget execution from within QBDI callbacks.
 * This shows how to safely execute arbitrary code (gadgets) from 
 * instrumentation callbacks without reentrancy issues.
 */

#include <QBDI.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <redlog.hpp>
#include "w1tn3ss/gadget/gadget_executor.hpp"
#include "w1tn3ss/util/register_access.hpp"
#include "w1tn3ss/util/env_config.hpp"
#include "QBDIPreload.h"

// global state
static QBDI::VM* g_vm = nullptr;
static std::unique_ptr<w1tn3ss::gadget::gadget_executor> g_executor;
static bool g_demo_completed = false;

// demo gadget functions
extern "C" {
    int demo_add(int a, int b) {
        return a + b;
    }
    
    int demo_multiply(int a, int b) {
        return a * b;
    }
    
    size_t demo_strlen(const char* str) {
        if (!str) return 0;
        size_t len = 0;
        while (str[len]) len++;
        return len;
    }
    
    void demo_print(const char* msg) {
        fprintf(stderr, "[gadget] %s\n", msg);
    }
}

// instruction callback that demonstrates gadget execution
static QBDI::VMAction instruction_callback(QBDI::VMInstanceRef vm, QBDI::GPRState* gprState, 
                                         QBDI::FPRState* fprState, void* data) {
    static uint64_t inst_count = 0;
    inst_count++;
    
    // demonstrate gadget execution after 100 instructions
    if (inst_count == 100 && !g_demo_completed && g_executor) {
        g_demo_completed = true;
        
        auto log = redlog::get_logger("gadgetdemo");
        log.info("=== demonstrating gadget execution from VM callback ===");
        
        try {
            // arithmetic gadgets
            int sum = g_executor->call<int>(
                reinterpret_cast<QBDI::rword>(demo_add), {42, 58});
            log.info("arithmetic gadget", redlog::field("add(42, 58)", "%d", sum));
            
            int product = g_executor->call<int>(
                reinterpret_cast<QBDI::rword>(demo_multiply), {7, 9});
            log.info("arithmetic gadget", redlog::field("multiply(7, 9)", "%d", product));
            
            // string gadget
            const char* test_str = "hello from gadget!";
            size_t len = g_executor->call<size_t>(
                reinterpret_cast<QBDI::rword>(demo_strlen), 
                {reinterpret_cast<QBDI::rword>(test_str)});
            log.info("string gadget", 
                    redlog::field("strlen", "%zu", len),
                    redlog::field("expected", "%zu", strlen(test_str)));
            
            // void gadget
            g_executor->call<void>(
                reinterpret_cast<QBDI::rword>(demo_print),
                {reinterpret_cast<QBDI::rword>("gadget execution successful!")});
            
            log.info("=== gadget execution complete ===");
        } catch (const std::exception& e) {
            log.error("gadget execution failed", redlog::field("error", e.what()));
        }
    }
    
    return QBDI::VMAction::CONTINUE;
}

// qbdi preload callbacks
extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_start(void* main_addr) {
    auto log = redlog::get_logger("gadgetdemo");
    log.info("gadgetdemo tracer loaded", redlog::field("main", "%p", main_addr));
    return QBDIPRELOAD_NOT_HANDLED;
}

QBDI_EXPORT int qbdipreload_on_premain(void* gprCtx, void* fpuCtx) {
    return QBDIPRELOAD_NOT_HANDLED;
}

QBDI_EXPORT int qbdipreload_on_main(int argc, char** argv) {
    return QBDIPRELOAD_NOT_HANDLED;
}

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vminstance, QBDI::rword start,
                                   QBDI::rword stop) {
    auto log = redlog::get_logger("gadgetdemo");
    
    // get config
    w1::util::env_config config_loader("GADGETDEMO_");
    int verbose = config_loader.get<int>("VERBOSE", 0);
    
    // set log level based on debug level
    if (verbose >= 4) {
        redlog::set_level(redlog::level::pedantic);
    } else if (verbose >= 3) {
        redlog::set_level(redlog::level::debug);
    } else if (verbose >= 2) {
        redlog::set_level(redlog::level::trace);
    } else if (verbose >= 1) {
        redlog::set_level(redlog::level::verbose);
    } else {
        redlog::set_level(redlog::level::info);
    }
    
    log.inf("gadgetdemo configuration", redlog::field("verbose", verbose));
    
    if (!vminstance) {
        log.error("VM instance is NULL");
        return QBDIPRELOAD_ERR_STARTUP_FAILED;
    }
    
    // save VM instance
    g_vm = static_cast<QBDI::VM*>(vminstance);
    
    try {
        // create gadget executor
        g_executor = std::make_unique<w1tn3ss::gadget::gadget_executor>(g_vm);
        log.info("gadget executor initialized");
        
        // add instruction callback
        g_vm->addCodeCB(QBDI::PREINST, instruction_callback, nullptr);
        
        // demonstrate immediate gadget execution
        log.info("testing gadget execution from on_run callback...");
        int result = g_executor->call<int>(
            reinterpret_cast<QBDI::rword>(demo_add), {100, 200});
        log.info("immediate test", redlog::field("add(100, 200)", "%d", result));
        
        // run the VM
        log.info("starting instrumented execution");
        g_vm->run(start, stop);
        
    } catch (const std::exception& e) {
        log.error("initialization failed", redlog::field("error", e.what()));
        return QBDIPRELOAD_ERR_STARTUP_FAILED;
    }
    
    return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
    auto log = redlog::get_logger("gadgetdemo");
    log.info("gadgetdemo tracer exiting", redlog::field("status", "%d", status));
    g_executor.reset();
    return QBDIPRELOAD_NOT_HANDLED;
}

} // extern "C"