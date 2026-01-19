#include "w1gadget/gadget_executor.hpp"

#include <cstdio>
#include <string>

#include "w1base/interval.hpp"

namespace {

// Guard to avoid truncating disassembly at the end of an instrumented range.
constexpr size_t k_range_guard_bytes = 16;

} // namespace

namespace w1::gadget {

gadget_executor::gadget_executor(QBDI::VM* parent_vm, config cfg) : parent_vm_(parent_vm), config_(cfg) {
  auto log = redlog::get_logger("w1.gadget.executor");
  log.dbg("initialized", redlog::field("parent_vm", "%p", parent_vm_), redlog::field("debug", config_.debug));
}

gadget_executor::stack_guard::~stack_guard() {
  if (stack) {
    QBDI::alignedFree(stack);
  }
}

bool gadget_executor::stack_guard::allocate(QBDI::GPRState* gpr, size_t stack_size) {
  if (!gpr || stack_size == 0) {
    return false;
  }

  return QBDI::allocateVirtualStack(gpr, static_cast<uint32_t>(stack_size), &stack);
}

std::unique_ptr<QBDI::VM> gadget_executor::create_sub_vm() {
  auto sub_vm = std::make_unique<QBDI::VM>();

  if (parent_vm_) {
    sub_vm->setOptions(parent_vm_->getOptions());
  }

  auto log = redlog::get_logger("w1.gadget.executor");
  log.dbg("created sub-vm", redlog::field("sub_vm", "%p", sub_vm.get()), redlog::field("parent_vm", "%p", parent_vm_));

  setup_debug_callback(sub_vm.get());
  return sub_vm;
}

void gadget_executor::setup_debug_callback(QBDI::VM* vm) {
  if (!config_.debug || !vm) {
    return;
  }

  vm->addCodeCB(
      QBDI::PREINST,
      [](QBDI::VMInstanceRef vm_ref, QBDI::GPRState*, QBDI::FPRState*, void*) -> QBDI::VMAction {
        const QBDI::InstAnalysis* inst = vm_ref->getInstAnalysis();
        if (inst && inst->disassembly) {
          std::printf("[gadget debug] 0x%llx: %s\n", static_cast<unsigned long long>(inst->address), inst->disassembly);
        }
        return QBDI::VMAction::CONTINUE;
      },
      nullptr
  );

  auto log = redlog::get_logger("w1.gadget.executor");
  log.dbg("enabled debug callback for sub-vm");
}

instrumentation_scope gadget_executor::resolve_scope(
    instrumentation_scope requested, instrumentation_scope fallback
) const {
  return requested == instrumentation_scope::inherit ? fallback : requested;
}

size_t gadget_executor::resolve_stack_size(size_t requested) const {
  return requested == 0 ? config_.stack_size : requested;
}

size_t gadget_executor::resolve_range_size(size_t requested, size_t fallback) const {
  return requested == 0 ? fallback : requested;
}

size_t gadget_executor::resolve_max_instructions(size_t requested) const {
  return requested == 0 ? config_.max_instructions : requested;
}

bool gadget_executor::prepare_vm_state(
    QBDI::VM* vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, size_t stack_size, stack_guard& stack
) {
  if (!vm || !gpr || !fpr || !parent_vm_) {
    return false;
  }

  *gpr = *parent_vm_->getGPRState();
  *fpr = *parent_vm_->getFPRState();

  if (!stack.allocate(gpr, stack_size)) {
    return false;
  }

  vm->setGPRState(gpr);
  vm->setFPRState(fpr);
  return true;
}

bool gadget_executor::configure_instrumentation(
    QBDI::VM* vm, instrumentation_scope scope, QBDI::rword start_addr, QBDI::rword stop_addr, size_t range_size,
    std::string* error
) {
  if (!vm) {
    if (error) {
      *error = "vm is null";
    }
    return false;
  }

  switch (scope) {
  case instrumentation_scope::range: {
    uint64_t range_end = 0;
    if (stop_addr > start_addr) {
      range_end = static_cast<uint64_t>(stop_addr);
      if (!w1::util::compute_end(range_end, k_range_guard_bytes, &range_end)) {
        if (error) {
          *error = "range size overflow";
        }
        return false;
      }
    } else if (!w1::util::compute_end(static_cast<uint64_t>(start_addr), range_size, &range_end)) {
      if (error) {
        *error = "range size overflow";
      }
      return false;
    }

    if (range_end <= start_addr) {
      if (error) {
        *error = "invalid instrumentation range";
      }
      return false;
    }

    vm->addInstrumentedRange(start_addr, static_cast<QBDI::rword>(range_end));
    return true;
  }
  case instrumentation_scope::module: {
    if (!vm->addInstrumentedModuleFromAddr(start_addr)) {
      if (error) {
        *error = "failed to instrument module from address";
      }
      return false;
    }
    return true;
  }
  case instrumentation_scope::all_executable: {
    if (!vm->instrumentAllExecutableMaps()) {
      if (error) {
        *error = "failed to instrument executable maps";
      }
      return false;
    }
    return true;
  }
  case instrumentation_scope::inherit:
    break;
  }

  if (error) {
    *error = "invalid instrumentation scope";
  }
  return false;
}

bool gadget_executor::install_stop_callback(QBDI::VM* vm, stop_state& state) {
  if (!vm) {
    return false;
  }

  uint32_t id = vm->addCodeCB(
      QBDI::PREINST,
      [](QBDI::VMInstanceRef, QBDI::GPRState* gpr, QBDI::FPRState*, void* data) -> QBDI::VMAction {
        auto* stop = static_cast<stop_state*>(data);
        stop->instruction_count += 1;
        stop->stop_pc = QBDI_GPR_GET(gpr, QBDI::REG_PC);

        if (stop->max_instructions != 0 && stop->instruction_count >= stop->max_instructions) {
          return QBDI::VMAction::STOP;
        }

        if (stop->stop_addr != 0 && stop->stop_pc >= stop->stop_addr) {
          return QBDI::VMAction::STOP;
        }

        return QBDI::VMAction::CONTINUE;
      },
      &state
  );

  return id != QBDI::INVALID_EVENTID;
}

bool gadget_executor::execute_call(
    QBDI::rword addr, std::span<const QBDI::rword> args, const call_options& options, QBDI::rword* result,
    std::string* error
) {
  if (!parent_vm_) {
    if (error) {
      *error = "parent vm is null";
    }
    return false;
  }

  auto sub_vm = create_sub_vm();
  if (!sub_vm) {
    if (error) {
      *error = "failed to create sub-vm";
    }
    return false;
  }

  QBDI::GPRState gpr{};
  QBDI::FPRState fpr{};
  stack_guard stack;
  size_t stack_size = resolve_stack_size(options.stack_size);
  if (!prepare_vm_state(sub_vm.get(), &gpr, &fpr, stack_size, stack)) {
    if (error) {
      *error = "failed to prepare vm state";
    }
    return false;
  }

  instrumentation_scope scope = resolve_scope(options.scope, config_.call_scope);
  size_t range_size = resolve_range_size(options.range_size, config_.call_range_size);
  if (!configure_instrumentation(sub_vm.get(), scope, addr, 0, range_size, error)) {
    return false;
  }

  stop_state stop{};
  stop.max_instructions = resolve_max_instructions(options.max_instructions);
  if (stop.max_instructions != 0 && !install_stop_callback(sub_vm.get(), stop)) {
    if (error) {
      *error = "failed to install stop callback";
    }
    return false;
  }

  QBDI::rword return_value = 0;
  bool call_success = sub_vm->callA(&return_value, addr, static_cast<uint32_t>(args.size()), args.data());
  if (!call_success) {
    if (error) {
      *error = "vm call failed";
    }
    return false;
  }

  if (result) {
    *result = return_value;
  }

  return true;
}

gadget_result gadget_executor::gadget_run(QBDI::rword start_addr, QBDI::rword stop_addr, run_options options) {
  gadget_result result;

  if (!parent_vm_) {
    result.error = "parent vm is null";
    return result;
  }

  if (stop_addr <= start_addr) {
    result.error = "stop address must be greater than start address";
    return result;
  }

  auto sub_vm = create_sub_vm();
  if (!sub_vm) {
    result.error = "failed to create sub-vm";
    return result;
  }

  QBDI::GPRState gpr{};
  QBDI::FPRState fpr{};
  stack_guard stack;
  size_t stack_size = resolve_stack_size(options.stack_size);
  if (!prepare_vm_state(sub_vm.get(), &gpr, &fpr, stack_size, stack)) {
    result.error = "failed to prepare vm state";
    return result;
  }

  instrumentation_scope scope = resolve_scope(options.scope, config_.run_scope);
  size_t range_size = resolve_range_size(options.range_size, config_.run_range_size);
  if (!configure_instrumentation(sub_vm.get(), scope, start_addr, stop_addr, range_size, &result.error)) {
    return result;
  }

  stop_state stop{};
  stop.stop_addr = stop_addr;
  stop.max_instructions = resolve_max_instructions(options.max_instructions);
  if (!install_stop_callback(sub_vm.get(), stop)) {
    result.error = "failed to install stop callback";
    return result;
  }

  auto log = redlog::get_logger("w1.gadget.executor");
  log.dbg(
      "executing raw gadget", redlog::field("start", "0x%llx", start_addr), redlog::field("stop", "0x%llx", stop_addr)
  );

  bool run_success = sub_vm->run(start_addr, stop_addr);
  if (!run_success) {
    result.error = "vm run failed";
    log.err("raw gadget execution failed", redlog::field("addr", "0x%llx", start_addr));
    return result;
  }

  result.gpr = *sub_vm->getGPRState();
  result.fpr = *sub_vm->getFPRState();
  result.instruction_count = stop.instruction_count;
  result.stop_address = stop.stop_pc;
  result.success = true;

  log.dbg("raw gadget execution succeeded", redlog::field("instructions", stop.instruction_count));
  return result;
}

gadget_result gadget_executor::run_with_vm(QBDI::VM* vm, QBDI::rword start_addr, QBDI::rword stop_addr) {
  gadget_result result;

  if (!vm) {
    result.error = "vm is null";
    return result;
  }

  if (stop_addr <= start_addr) {
    result.error = "stop address must be greater than start address";
    return result;
  }

  stop_state stop{};
  stop.stop_addr = stop_addr;
  stop.max_instructions = config_.max_instructions;
  if (!install_stop_callback(vm, stop)) {
    result.error = "failed to install stop callback";
    return result;
  }

  try {
    auto log = redlog::get_logger("w1.gadget.executor");
    log.dbg(
        "running with custom vm", redlog::field("vm", "%p", vm), redlog::field("start", "0x%llx", start_addr),
        redlog::field("stop", "0x%llx", stop_addr)
    );

    bool run_success = vm->run(start_addr, stop_addr);
    if (!run_success) {
      result.error = "vm run failed";
      log.err("custom vm run failed", redlog::field("addr", "0x%llx", start_addr));
      return result;
    }

    result.gpr = *vm->getGPRState();
    result.fpr = *vm->getFPRState();
    result.instruction_count = stop.instruction_count;
    result.stop_address = stop.stop_pc;
    result.success = true;

    log.dbg("custom vm execution succeeded");
  } catch (const std::exception& e) {
    result.error = std::string("exception: ") + e.what();
    auto log = redlog::get_logger("w1.gadget.executor");
    log.err("custom vm execution exception", redlog::field("error", e.what()));
  }

  return result;
}

} // namespace w1::gadget
