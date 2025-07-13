#ifndef W1TN3SS_GADGET_EXECUTOR_HPP
#define W1TN3SS_GADGET_EXECUTOR_HPP

#include <QBDI.h>
#include <memory>
#include <vector>
#include <string>
#include <type_traits>
#include <redlog.hpp>
#include "w1tn3ss/abi/calling_convention_base.hpp"

namespace w1tn3ss {
namespace gadget {

/**
 * @brief Result of a gadget execution
 * 
 * Contains the success status, return value, final CPU state,
 * and any error messages from the execution.
 */
struct gadget_result {
    QBDI::GPRState gpr;             ///< Final general purpose register state
    QBDI::FPRState fpr;             ///< Final floating point register state  
    bool success;                   ///< Whether execution completed successfully
    std::string error;              ///< Error message if execution failed
    QBDI::rword return_value;       ///< Return value from the gadget (rax/x0)
};

/**
 * @brief Executes code gadgets within QBDI VM contexts
 * 
 * This class provides the ability to execute arbitrary code (gadgets) from within
 * QBDI VM callbacks, working around QBDI's non-reentrant VM limitation.
 * 
 * ## Background: The Stack Switching Problem
 * 
 * QBDI VMs are not reentrant - the same VM instance cannot be run recursively.
 * Additionally, when using vm.call(), QBDI performs stack switching via the
 * qbdi_asmStackSwitch assembly routine. This creates a problem when trying to
 * execute gadgets from within VM callbacks:
 * 
 * 1. Parent VM switches stacks (stack A → stack B) when calling the target
 * 2. Callback fires and creates a sub-VM to execute a gadget
 * 3. If sub-VM uses vm.call(), it also switches stacks (stack B → stack C)
 * 4. Sub-VM returns (stack C → stack B)
 * 5. Parent VM callback returns
 * 6. Parent VM tries to restore stack (stack B → stack A)
 * 7. **BUS ERROR** - stack pointer corruption due to nested stack switches
 * 
 * The qbdi_asmStackSwitch routine saves/restores frame pointers (x29/rbp) and
 * link registers (x30/rip), but nested calls corrupt these saved values.
 * 
 * ## Solution: Using vm.run() Instead of vm.call()
 * 
 * This implementation uses vm.run() which executes code without stack switching.
 * To make gadgets behave like function calls:
 * 
 * 1. Set up arguments in registers according to calling convention
 * 2. Add instrumentation to detect RET instructions
 * 3. Run the gadget with vm.run() until it returns
 * 4. Extract return value from the appropriate register
 * 
 * This approach avoids the nested stack switching problem entirely.
 * 
 * ## Usage Example
 * 
 * ```cpp
 * // In a QBDI callback:
 * w1tn3ss::gadget::gadget_executor executor(parent_vm);
 * 
 * // Call a function gadget
 * int result = executor.call<int>(gadget_addr, {arg1, arg2});
 * 
 * // Execute raw gadget with custom state
 * auto result = executor.execute_raw(gadget_addr, custom_gpr, custom_fpr);
 * ```
 */
class gadget_executor {
private:
    // cached parent vm configuration
    QBDI::VM* parent_vm_;
    std::string cpu_model_;
    std::vector<std::string> mattrs_;
    QBDI::Options options_;
    w1::abi::calling_convention_ptr calling_convention_;
    
    // create sub-vm with parent's configuration and instrumented ranges
    std::unique_ptr<QBDI::VM> create_sub_vm();
    
    // copy instrumented ranges from parent to sub-vm
    void copy_instrumented_ranges(QBDI::VM* sub_vm);
    
public:
    explicit gadget_executor(QBDI::VM* parent_vm);
    ~gadget_executor() = default;
    
    // execute gadget using qbdi's vm->call() for clean function calls
    // returns just the return value for convenience
    template<typename RetType = QBDI::rword>
    RetType call(QBDI::rword gadget_addr, const std::vector<QBDI::rword>& args = {});
    
    // execute gadget and return full state (for when you need more than return value)
    gadget_result call_with_state(QBDI::rword gadget_addr, const std::vector<QBDI::rword>& args = {});
    
    // execute raw gadget with custom state (for rop chains, weird jumps)
    gadget_result execute_raw(QBDI::rword start_addr, 
                             QBDI::GPRState* custom_gpr = nullptr,
                             QBDI::FPRState* custom_fpr = nullptr,
                             QBDI::rword stop_addr = 0);
    
    // execute gadget chain (multiple gadgets in sequence)
    gadget_result execute_chain(const std::vector<QBDI::rword>& gadget_addrs,
                               QBDI::GPRState* initial_state = nullptr,
                               const std::vector<QBDI::rword>& stop_addrs = {});
};

// template implementation
template<typename RetType>
RetType gadget_executor::call(QBDI::rword gadget_addr, const std::vector<QBDI::rword>& args) {
    auto result = call_with_state(gadget_addr, args);
    if (!result.success) {
        auto log = redlog::get_logger("gadget_executor");
        log.error("gadget call failed", redlog::field("error", result.error.c_str()));
        if constexpr (std::is_same_v<RetType, void>) {
            return;
        } else {
            return RetType{};
        }
    }
    return static_cast<RetType>(result.return_value);
}

} // namespace gadget
} // namespace w1tn3ss

#endif // W1TN3SS_GADGET_EXECUTOR_HPP