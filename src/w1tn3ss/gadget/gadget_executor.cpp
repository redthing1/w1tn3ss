#include "w1tn3ss/gadget/gadget_executor.hpp"
#include "w1tn3ss/util/register_access.hpp"
#include <w1common/ext/tinyformat.hpp>
#include <cstring>

namespace w1tn3ss {
namespace gadget {

gadget_executor::gadget_executor(QBDI::VM* parent_vm) 
    : parent_vm_(parent_vm) {
    // cache parent vm configuration
    auto config = parent_vm_->getOptions();
    options_ = config;
    
    // get cpu model from parent
    const QBDI::GPRState* parent_gpr = parent_vm_->getGPRState();
    
    // TODO: properly extract cpu model and mattrs from parent vm
    // for now use defaults based on architecture
#if defined(QBDI_ARCH_X86_64)
    cpu_model_ = "generic";
#elif defined(QBDI_ARCH_AARCH64)
    cpu_model_ = "generic";
#else
    cpu_model_ = "generic";
#endif
    
    auto log = redlog::get_logger("gadget_executor");
    log.dbg("initialized gadget executor", 
            redlog::field("parent_vm", "%p", parent_vm),
            redlog::field("options", "0x%x", options_),
            redlog::field("cpu_model", cpu_model_.c_str()));
}

std::unique_ptr<QBDI::VM> gadget_executor::create_sub_vm() {
    // create new vm with same configuration as parent
    auto sub_vm = std::make_unique<QBDI::VM>(cpu_model_, mattrs_, options_);
    
    auto log = redlog::get_logger("gadget_executor");
    log.dbg("created sub-vm",
            redlog::field("sub_vm", "%p", sub_vm.get()),
            redlog::field("parent_vm", "%p", parent_vm_));
    
    // copy instrumented ranges from parent
    copy_instrumented_ranges(sub_vm.get());
    
    return sub_vm;
}

void gadget_executor::copy_instrumented_ranges(QBDI::VM* sub_vm) {
    // don't instrument anything by default - let the caller decide
    // what to instrument based on the gadget address
    auto log = redlog::get_logger("gadget_executor");
    log.trace("sub-vm created without default instrumentation");
}

gadget_result gadget_executor::call_with_state(QBDI::rword gadget_addr, 
                                               const std::vector<QBDI::rword>& args) {
    gadget_result result;
    result.success = false;
    
    try {
        // create a separate vm instance to execute the gadget
        // this is necessary because qbdi doesn't support reentrancy - 
        // we can't call vm methods from within a vm callback
        auto sub_vm = create_sub_vm();
        
        // copy cpu state from parent vm so the gadget sees the same context
        result.gpr = *parent_vm_->getGPRState();
        result.fpr = *parent_vm_->getFPRState();
        
        // allocate a separate stack for the gadget execution
        // this prevents stack corruption between parent and gadget
        uint8_t* stack = nullptr;
        QBDI::allocateVirtualStack(&result.gpr, 0x10000, &stack);
        
        auto log = redlog::get_logger("gadget_executor");
        log.dbg("stack allocated for sub-vm",
                redlog::field("stack", "%p", stack),
                redlog::field("size", "0x10000"),
                redlog::field("sub_sp", "0x%llx", w1::registers::get_sp(&result.gpr)),
                redlog::field("parent_sp", "0x%llx", w1::registers::get_sp(parent_vm_->getGPRState())));
        
        // Set the initial state in the sub-VM
        sub_vm->setGPRState(&result.gpr);
        sub_vm->setFPRState(&result.fpr);
        
        // prepare arguments for vm.call()
        std::vector<QBDI::rword> call_args = args;
        
        log.dbg("preparing gadget call", 
                redlog::field("addr", "0x%llx", gadget_addr),
                redlog::field("args", "%zu", args.size()),
                redlog::field("sp", "0x%llx", w1::registers::get_sp(&result.gpr)));
        
        // Add instrumentation for the gadget code
        // Use addInstrumentedModuleFromAddr to ensure recursive calls are covered
        bool module_added = sub_vm->addInstrumentedModuleFromAddr(gadget_addr);
        if (!module_added) {
            // Fallback to range-based instrumentation if module detection fails
            QBDI::rword range_start = gadget_addr & ~0xFFF;  // align to page
            QBDI::rword range_size = 0x10000;  // 64KB should be enough for most functions
            sub_vm->addInstrumentedRange(range_start, range_start + range_size);
            log.dbg("add instrumented range (fallback)", 
                    redlog::field("start", "0x%llx", range_start),
                    redlog::field("size", "0x%llx", range_size));
        } else {
            log.dbg("add instrumented module", redlog::field("addr", "0x%llx", gadget_addr));
        }
        
        // Set up arguments in registers according to platform calling convention
        // This simulates how a normal function call would pass arguments
        if (!args.empty()) {
            log.dbg("setting up arguments in registers", redlog::field("count", "%zu", args.size()));
#if defined(QBDI_ARCH_X86_64)
            // system v amd64 abi: rdi, rsi, rdx, rcx, r8, r9
            if (args.size() > 0) { result.gpr.rdi = args[0]; log.dbg("arg0", redlog::field("rdi", "0x%llx", args[0])); }
            if (args.size() > 1) { result.gpr.rsi = args[1]; log.dbg("arg1", redlog::field("rsi", "0x%llx", args[1])); }
            if (args.size() > 2) { result.gpr.rdx = args[2]; log.dbg("arg2", redlog::field("rdx", "0x%llx", args[2])); }
            if (args.size() > 3) { result.gpr.rcx = args[3]; log.dbg("arg3", redlog::field("rcx", "0x%llx", args[3])); }
            if (args.size() > 4) { result.gpr.r8 = args[4]; log.dbg("arg4", redlog::field("r8", "0x%llx", args[4])); }
            if (args.size() > 5) { result.gpr.r9 = args[5]; log.dbg("arg5", redlog::field("r9", "0x%llx", args[5])); }
#elif defined(QBDI_ARCH_AARCH64)
            // aarch64: x0-x7
            if (args.size() > 0) { result.gpr.x0 = args[0]; log.dbg("arg0", redlog::field("x0", "0x%llx", args[0])); }
            if (args.size() > 1) { result.gpr.x1 = args[1]; log.dbg("arg1", redlog::field("x1", "0x%llx", args[1])); }
            if (args.size() > 2) { result.gpr.x2 = args[2]; log.dbg("arg2", redlog::field("x2", "0x%llx", args[2])); }
            if (args.size() > 3) { result.gpr.x3 = args[3]; log.dbg("arg3", redlog::field("x3", "0x%llx", args[3])); }
            if (args.size() > 4) { result.gpr.x4 = args[4]; log.dbg("arg4", redlog::field("x4", "0x%llx", args[4])); }
            if (args.size() > 5) { result.gpr.x5 = args[5]; log.dbg("arg5", redlog::field("x5", "0x%llx", args[5])); }
            if (args.size() > 6) { result.gpr.x6 = args[6]; log.dbg("arg6", redlog::field("x6", "0x%llx", args[6])); }
            if (args.size() > 7) { result.gpr.x7 = args[7]; log.dbg("arg7", redlog::field("x7", "0x%llx", args[7])); }
#endif
            sub_vm->setGPRState(&result.gpr);
        }
        
        // use vm.call() which handles function call semantics properly
        // (sets up return address, manages stack frame, etc.)
        log.dbg("executing gadget via vm.call");
        bool call_success = sub_vm->call(nullptr, gadget_addr, call_args);
        log.dbg("gadget execution completed", redlog::field("success", call_success));
        
        if (!call_success) {
            result.error = "vm run failed";
            log.error("gadget call failed", redlog::field("addr", "0x%llx", gadget_addr));
            QBDI::alignedFree(stack);
            return result;
        }
        
        // extract final state
        result.gpr = *sub_vm->getGPRState();
        result.fpr = *sub_vm->getFPRState();
        
        // extract return value from appropriate register
#if defined(QBDI_ARCH_X86_64)
        result.return_value = result.gpr.rax;
#elif defined(QBDI_ARCH_AARCH64)
        result.return_value = result.gpr.x0;
#endif
        
        result.success = true;
        
        log.dbg("gadget call succeeded", redlog::field("return", "0x%llx", result.return_value));
        
        // clean up stack
        QBDI::alignedFree(stack);
        log.dbg("stack freed");
        
    } catch (const std::exception& e) {
        result.error = std::string("exception: ") + e.what();
        auto log = redlog::get_logger("gadget_executor");
        log.error("gadget execution exception", redlog::field("error", e.what()));
    }
    
    return result;
}

gadget_result gadget_executor::execute_raw(QBDI::rword start_addr,
                                          QBDI::GPRState* custom_gpr,
                                          QBDI::FPRState* custom_fpr,
                                          QBDI::rword stop_addr) {
    gadget_result result;
    result.success = false;
    
    try {
        // create sub-vm
        auto sub_vm = create_sub_vm();
        
        // use custom state or copy from parent
        if (custom_gpr) {
            result.gpr = *custom_gpr;
        } else {
            result.gpr = *parent_vm_->getGPRState();
        }
        
        if (custom_fpr) {
            result.fpr = *custom_fpr;
        } else {
            result.fpr = *parent_vm_->getFPRState();
        }
        
        // allocate a stack if not already present
        uint8_t* stack = nullptr;
        bool allocated_stack = false;
        if (w1::registers::get_sp(&result.gpr) == 0) {
            QBDI::allocateVirtualStack(&result.gpr, 0x10000, &stack);
            allocated_stack = true;
        }
        
        // set state in sub-vm
        sub_vm->setGPRState(&result.gpr);
        sub_vm->setFPRState(&result.fpr);
        
        // Add instrumentation for the gadget
        QBDI::rword range_start = start_addr & ~0xFFF;
        QBDI::rword range_size = 0x10000;
        sub_vm->addInstrumentedRange(range_start, range_start + range_size);
        
        // run the gadget
        auto log = redlog::get_logger("gadget_executor");
        
        // If stop_addr is 0, use a reasonable default
        if (stop_addr == 0) {
            stop_addr = start_addr + 0x1000;  // 4KB range
        }
        
        log.dbg("executing raw gadget",
                redlog::field("start", "0x%llx", start_addr),
                redlog::field("stop", "0x%llx", stop_addr));
        bool run_success = sub_vm->run(start_addr, stop_addr);
        
        if (!run_success) {
            result.error = "vm run failed";
            log.error("raw gadget execution failed", redlog::field("addr", "0x%llx", start_addr));
            if (allocated_stack) {
                QBDI::alignedFree(stack);
            }
            return result;
        }
        
        // extract final state
        result.gpr = *sub_vm->getGPRState();
        result.fpr = *sub_vm->getFPRState();
        result.success = true;
        
        // clean up stack if we allocated it
        if (allocated_stack) {
            QBDI::alignedFree(stack);
        }
        
        // for raw execution, return value is final rax/x0
#if defined(QBDI_ARCH_X86_64) || defined(QBDI_ARCH_X86)
        result.return_value = result.gpr.rax;
#elif defined(QBDI_ARCH_AARCH64)
        result.return_value = result.gpr.x0;
#elif defined(QBDI_ARCH_ARM)
        result.return_value = result.gpr.r0;
#endif
        
        log.dbg("raw gadget execution succeeded");
        
    } catch (const std::exception& e) {
        result.error = std::string("exception: ") + e.what();
        auto log = redlog::get_logger("gadget_executor");
        log.error("raw gadget execution exception", redlog::field("error", e.what()));
    }
    
    return result;
}

gadget_result gadget_executor::execute_chain(const std::vector<QBDI::rword>& gadget_addrs,
                                            QBDI::GPRState* initial_state,
                                            const std::vector<QBDI::rword>& stop_addrs) {
    gadget_result result;
    result.success = false;
    
    if (gadget_addrs.empty()) {
        result.error = "empty gadget chain";
        return result;
    }
    
    // start with initial state or parent state
    if (initial_state) {
        result.gpr = *initial_state;
    } else {
        result.gpr = *parent_vm_->getGPRState();
    }
    result.fpr = *parent_vm_->getFPRState();
    
    // execute each gadget in sequence
    for (size_t i = 0; i < gadget_addrs.size(); i++) {
        QBDI::rword gadget_addr = gadget_addrs[i];
        QBDI::rword stop_addr = (i < stop_addrs.size()) ? stop_addrs[i] : 0;
        
        auto log = redlog::get_logger("gadget_executor");
        log.dbg("executing gadget in chain",
                redlog::field("index", "%zu", i+1),
                redlog::field("total", "%zu", gadget_addrs.size()),
                redlog::field("addr", "0x%llx", gadget_addr));
        
        // execute gadget with current state
        auto gadget_result = execute_raw(gadget_addr, &result.gpr, &result.fpr, stop_addr);
        
        if (!gadget_result.success) {
            result.error = tinyformat::format("gadget %d failed: %s", i, gadget_result.error);
            return result;
        }
        
        // use output state as input for next gadget
        result.gpr = gadget_result.gpr;
        result.fpr = gadget_result.fpr;
    }
    
    result.success = true;
    auto log = redlog::get_logger("gadget_executor");
    log.info("gadget chain execution completed successfully");
    
    return result;
}

} // namespace gadget
} // namespace w1tn3ss