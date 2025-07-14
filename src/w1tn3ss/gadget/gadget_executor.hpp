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

// result from raw gadget execution (no calling convention interpretation)
struct gadget_result {
  bool success;
  std::string error;
  QBDI::GPRState gpr;
  QBDI::FPRState fpr;
};

// execute gadgets from within qbdi callbacks without reentrancy issues
// two modes: gadget_call (function semantics) and gadget_run (raw execution)
class gadget_executor {
public:
  struct config {
    bool debug = false;
    size_t default_stack_size = 0x10000;
  };

  explicit gadget_executor(QBDI::VM* parent_vm, const config& cfg = {});
  ~gadget_executor() = default;

  // call function with arguments and return value
  template <typename RetType = QBDI::rword>
  RetType gadget_call(QBDI::rword addr, const std::vector<QBDI::rword>& args = {});

  // raw execution between two addresses
  gadget_result gadget_run(
      QBDI::rword start_addr, QBDI::rword stop_addr, QBDI::GPRState* initial_gpr = nullptr,
      QBDI::FPRState* initial_fpr = nullptr
  );

  // create sub-vm for custom configuration
  std::unique_ptr<QBDI::VM> create_sub_vm();

  // run with custom-configured sub-vm
  gadget_result run_with_vm(QBDI::VM* vm, QBDI::rword start_addr, QBDI::rword stop_addr);

private:
  QBDI::VM* parent_vm_;
  config config_;
  w1::abi::calling_convention_ptr calling_convention_;

  void setup_debug_callback(QBDI::VM* vm);
};

template <typename RetType>
RetType gadget_executor::gadget_call(QBDI::rword addr, const std::vector<QBDI::rword>& args) {
  try {
    auto sub_vm = create_sub_vm();

    // copy parent state and allocate stack
    QBDI::GPRState gpr = *parent_vm_->getGPRState();
    QBDI::FPRState fpr = *parent_vm_->getFPRState();

    sub_vm->setGPRState(&gpr);
    sub_vm->setFPRState(&fpr);

    uint8_t* stack = nullptr;
    QBDI::allocateVirtualStack(sub_vm->getGPRState(), config_.default_stack_size, &stack);

    auto log = redlog::get_logger("gadget_executor");
    log.dbg("calling gadget", redlog::field("addr", "0x%llx", addr));

    bool success = sub_vm->call(nullptr, addr, args);

    if (!success) {
      QBDI::alignedFree(stack);
      log.error("gadget call failed");
      if constexpr (std::is_same_v<RetType, void>) {
        return;
      } else {
        return RetType{};
      }
    }

    QBDI::rword result = calling_convention_->get_integer_return(sub_vm->getGPRState());
    QBDI::alignedFree(stack);

    log.dbg("gadget call succeeded");

    if constexpr (std::is_same_v<RetType, void>) {
      return;
    } else {
      return static_cast<RetType>(result);
    }

  } catch (const std::exception& e) {
    auto log = redlog::get_logger("gadget_executor");
    log.error("gadget call exception", redlog::field("error", e.what()));
    if constexpr (std::is_same_v<RetType, void>) {
      return;
    } else {
      return RetType{};
    }
  }
}

} // namespace gadget
} // namespace w1tn3ss

#endif // W1TN3SS_GADGET_EXECUTOR_HPP