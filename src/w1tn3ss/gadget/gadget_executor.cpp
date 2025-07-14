#include "w1tn3ss/gadget/gadget_executor.hpp"
#include "w1tn3ss/util/register_access.hpp"
#include "w1tn3ss/abi/calling_convention_factory.hpp"
#include <w1common/ext/tinyformat.hpp>
#include <cstring>
#include <cstdlib>

namespace w1tn3ss {
namespace gadget {

gadget_executor::gadget_executor(QBDI::VM* parent_vm) 
    : parent_vm_(parent_vm) {
        
    // create calling convention for platform
    calling_convention_ = w1::abi::create_default_calling_convention();
    
    auto log = redlog::get_logger("gadget_executor");
    log.dbg("initialized gadget executor", 
            redlog::field("parent_vm", "%p", parent_vm),
            redlog::field("calling_convention", calling_convention_->get_name().c_str()));
}

std::unique_ptr<QBDI::VM> gadget_executor::create_sub_vm() {
    // create new vm with same configuration as parent
    auto sub_vm = std::make_unique<QBDI::VM>();
    
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
                                               const std::vector<QBDI::rword>& args,
                                               size_t stack_size) {
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
        QBDI::allocateVirtualStack(&result.gpr, stack_size, &stack);
        
        // RAII wrapper to ensure stack cleanup
        struct StackDeleter {
            uint8_t* stack;
            ~StackDeleter() { if (stack) QBDI::alignedFree(stack); }
        } stack_deleter{stack};
        
        auto log = redlog::get_logger("gadget_executor");
        log.dbg("stack allocated for sub-vm",
                redlog::field("stack", "%p", stack),
                redlog::field("size", "0x%zx", stack_size),
                redlog::field("sub_sp", "0x%llx", w1::registers::get_sp(&result.gpr)),
                redlog::field("parent_sp", "0x%llx", w1::registers::get_sp(parent_vm_->getGPRState())));
        
        // Set the initial state in the sub-VM
        sub_vm->setGPRState(&result.gpr);
        sub_vm->setFPRState(&result.fpr);
        
        log.dbg("preparing gadget call", 
                redlog::field("addr", "0x%llx", gadget_addr),
                redlog::field("args", "%zu", args.size()),
                redlog::field("sp", "0x%llx", w1::registers::get_sp(&result.gpr)));
        
        // Add instrumentation for the gadget code
        // Use addInstrumentedModuleFromAddr to ensure recursive calls are covered
        bool module_added = sub_vm->addInstrumentedModuleFromAddr(gadget_addr);
        if (!module_added) {
            // Fallback to range-based instrumentation if module detection fails
            static constexpr QBDI::rword PAGE_MASK = 0xFFF;
            static constexpr QBDI::rword DEFAULT_RANGE_SIZE = 0x10000;  // 64KB
            QBDI::rword range_start = gadget_addr & ~PAGE_MASK;  // align to page
            QBDI::rword range_size = DEFAULT_RANGE_SIZE;
            sub_vm->addInstrumentedRange(range_start, range_start + range_size);
            log.dbg("add instrumented range (fallback)", 
                    redlog::field("start", "0x%llx", range_start),
                    redlog::field("size", "0x%llx", range_size));
        } else {
            log.dbg("add instrumented module", redlog::field("addr", "0x%llx", gadget_addr));
        }
        
        // use vm.call() which handles function call semantics properly
        // (sets up arguments, return address, manages stack frame, etc.)
        log.dbg("executing gadget via vm.call");
        bool call_success = sub_vm->call(nullptr, gadget_addr, args);
        log.dbg("gadget execution completed", redlog::field("success", call_success));
        
        if (!call_success) {
            result.error = "vm call failed";
            log.error("gadget call failed", redlog::field("addr", "0x%llx", gadget_addr));
            return result;
        }
        
        // extract final state
        result.gpr = *sub_vm->getGPRState();
        result.fpr = *sub_vm->getFPRState();
        
        // extract return value using calling convention
        result.return_value = calling_convention_->get_integer_return(&result.gpr);
        
        result.success = true;
        
        log.dbg("gadget call succeeded", redlog::field("return", "0x%llx", result.return_value));
        
        // stack cleanup handled by RAII wrapper
        
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
        
        // Add debug callback if requested via environment variable
        static bool debug_enabled = (getenv("W1_GADGET_DEBUG") != nullptr);
        if (debug_enabled) {
            sub_vm->addCodeCB(QBDI::PREINST, [](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, 
                                                QBDI::FPRState* fpr, void* data) -> QBDI::VMAction {
                const QBDI::InstAnalysis* inst = vm->getInstAnalysis();
                if (inst && inst->disassembly) {
                    printf("[GADGET DEBUG] 0x%llx: %s\n", 
                           (unsigned long long)inst->address, inst->disassembly);
                }
                return QBDI::VMAction::CONTINUE;
            }, nullptr);
        }
        
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
        
        // set state in sub-vm FIRST
        sub_vm->setGPRState(&result.gpr);
        sub_vm->setFPRState(&result.fpr);
        
        // THEN allocate a stack - this updates the sub-VM's stack pointer
        uint8_t* stack = nullptr;
        QBDI::allocateVirtualStack(sub_vm->getGPRState(), 0x10000, &stack);
        
        // Get the updated state with proper stack
        result.gpr = *sub_vm->getGPRState();
        result.fpr = *sub_vm->getFPRState();
        
        // Add instrumentation for the gadget
        static constexpr QBDI::rword PAGE_MASK = 0xFFF;
        static constexpr QBDI::rword DEFAULT_RANGE_SIZE = 0x10000;  // 64KB
        QBDI::rword range_start = start_addr & ~PAGE_MASK;
        QBDI::rword range_size = DEFAULT_RANGE_SIZE;
        sub_vm->addInstrumentedRange(range_start, range_start + range_size);
        
        // run the gadget
        auto log = redlog::get_logger("gadget_executor");
        
        // If stop_addr is 0, use a reasonable default
        if (stop_addr == 0) {
            static constexpr QBDI::rword DEFAULT_STOP_RANGE = 0x1000;  // 4KB
            stop_addr = start_addr + DEFAULT_STOP_RANGE;
        }
        
        log.dbg("executing raw gadget",
                redlog::field("start", "0x%llx", start_addr),
                redlog::field("stop", "0x%llx", stop_addr));
        bool run_success = sub_vm->run(start_addr, stop_addr);
        
        if (!run_success) {
            result.error = "vm run failed";
            log.error("raw gadget execution failed", redlog::field("addr", "0x%llx", start_addr));
            QBDI::alignedFree(stack);
            return result;
        }
        
        // extract final state
        result.gpr = *sub_vm->getGPRState();
        result.fpr = *sub_vm->getFPRState();
        result.success = true;
        
        // clean up stack
        QBDI::alignedFree(stack);
        
        // Raw execution doesn't interpret return values - user gets raw CPU state
        result.return_value = 0;  // Not applicable for raw execution
        
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