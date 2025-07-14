#include "w1tn3ss/gadget/gadget_executor.hpp"
#include "w1tn3ss/util/register_access.hpp"
#include "w1tn3ss/abi/calling_convention_factory.hpp"
#include <cstring>
#include <cstdlib>

namespace w1tn3ss {
namespace gadget {

gadget_executor::gadget_executor(QBDI::VM* parent_vm, const config& cfg) : parent_vm_(parent_vm), config_(cfg) {
  calling_convention_ = w1::abi::create_default_calling_convention();
  
  auto log = redlog::get_logger("gadget_executor");
  log.dbg("initialized", redlog::field("parent_vm", "%p", parent_vm), redlog::field("debug", config_.debug));
}

std::unique_ptr<QBDI::VM> gadget_executor::create_sub_vm() {
  auto sub_vm = std::make_unique<QBDI::VM>();
  
  auto log = redlog::get_logger("gadget_executor");
  log.dbg("created sub-vm", redlog::field("sub_vm", "%p", sub_vm.get()), redlog::field("parent_vm", "%p", parent_vm_));
  
  setup_debug_callback(sub_vm.get());
  return sub_vm;
}

void gadget_executor::setup_debug_callback(QBDI::VM* vm) {
  if (!config_.debug) {
    return;
  }
  
  vm->addCodeCB(QBDI::PREINST,
    [](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) -> QBDI::VMAction {
      const QBDI::InstAnalysis* inst = vm->getInstAnalysis();
      if (inst && inst->disassembly) {
        printf("[gadget debug] 0x%llx: %s\n", (unsigned long long) inst->address, inst->disassembly);
      }
      return QBDI::VMAction::CONTINUE;
    },
    nullptr
  );
  
  auto log = redlog::get_logger("gadget_executor");
  log.dbg("enabled debug callback for sub-vm");
}

gadget_result gadget_executor::gadget_run(
    QBDI::rword start_addr, QBDI::rword stop_addr, QBDI::GPRState* initial_gpr, QBDI::FPRState* initial_fpr
) {
  gadget_result result;
  result.success = false;
  
  try {
    auto sub_vm = create_sub_vm();
    
    // use custom state or copy from parent
    if (initial_gpr) {
      result.gpr = *initial_gpr;
    } else {
      result.gpr = *parent_vm_->getGPRState();
    }
    
    if (initial_fpr) {
      result.fpr = *initial_fpr;
    } else {
      result.fpr = *parent_vm_->getFPRState();
    }
    
    // set state in sub-vm first
    sub_vm->setGPRState(&result.gpr);
    sub_vm->setFPRState(&result.fpr);
    
    // then allocate a stack - this updates the sub-vm's stack pointer
    uint8_t* stack = nullptr;
    QBDI::allocateVirtualStack(sub_vm->getGPRState(), config_.default_stack_size, &stack);
    
    // get the updated state with proper stack
    result.gpr = *sub_vm->getGPRState();
    result.fpr = *sub_vm->getFPRState();
    
    auto log = redlog::get_logger("gadget_executor");
    log.dbg("executing raw gadget", 
            redlog::field("start", "0x%llx", start_addr), 
            redlog::field("stop", "0x%llx", stop_addr));
    
    // add instrumentation for the gadget range
    static constexpr QBDI::rword PAGE_MASK = 0xFFF;
    static constexpr QBDI::rword DEFAULT_RANGE_SIZE = 0x10000; // 64kb
    QBDI::rword range_start = start_addr & ~PAGE_MASK;
    QBDI::rword range_size = DEFAULT_RANGE_SIZE;
    sub_vm->addInstrumentedRange(range_start, range_start + range_size);
    
    // run the gadget
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
    
    log.dbg("raw gadget execution succeeded");
    
  } catch (const std::exception& e) {
    result.error = std::string("exception: ") + e.what();
    auto log = redlog::get_logger("gadget_executor");
    log.error("raw gadget execution exception", redlog::field("error", e.what()));
  }
  
  return result;
}

gadget_result gadget_executor::run_with_vm(QBDI::VM* vm, QBDI::rword start_addr, QBDI::rword stop_addr) {
  gadget_result result;
  result.success = false;
  
  try {
    auto log = redlog::get_logger("gadget_executor");
    log.dbg("running with custom vm", 
            redlog::field("vm", "%p", vm), 
            redlog::field("start", "0x%llx", start_addr),
            redlog::field("stop", "0x%llx", stop_addr));
    
    // run the vm
    bool run_success = vm->run(start_addr, stop_addr);
    
    if (!run_success) {
      result.error = "vm run failed";
      log.error("custom vm run failed", redlog::field("addr", "0x%llx", start_addr));
      return result;
    }
    
    // extract final state
    result.gpr = *vm->getGPRState();
    result.fpr = *vm->getFPRState();
    result.success = true;
    
    log.dbg("custom vm execution succeeded");
    
  } catch (const std::exception& e) {
    result.error = std::string("exception: ") + e.what();
    auto log = redlog::get_logger("gadget_executor");
    log.error("custom vm execution exception", redlog::field("error", e.what()));
  }
  
  return result;
}

} // namespace gadget
} // namespace w1tn3ss