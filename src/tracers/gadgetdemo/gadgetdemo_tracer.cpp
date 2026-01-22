#include "gadgetdemo_tracer.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <utility>

#include "w1runtime/module_catalog.hpp"

namespace gadgetdemo {

namespace {

constexpr QBDI::rword offset_get_process_id = 0xa34;
constexpr QBDI::rword offset_compute_hash = 0xa10;
constexpr QBDI::rword offset_contains_pattern = 0x9e0;
constexpr QBDI::rword offset_get_string_length = 0x9d4;
constexpr QBDI::rword offset_is_valid_pointer = 0xa38;

} // namespace

extern "C" {

int demo_add(int a, int b) { return a + b; }

int demo_multiply(int a, int b) { return a * b; }

size_t demo_strlen(const char* str) {
  if (!str) {
    return 0;
  }
  size_t len = 0;
  while (str[len]) {
    len++;
  }
  return len;
}

void demo_print(const char* msg) {
  if (!msg) {
    return;
  }
  std::fprintf(stderr, "[gadget] %s\n", msg);
}

} // extern "C"

gadgetdemo_tracer::gadgetdemo_tracer(gadgetdemo_config config) : config_(std::move(config)) {
  log_.inf(
      "gadgetdemo tracer created", redlog::field("trigger", config_.trigger_count),
      redlog::field("immediate", config_.run_immediate ? "true" : "false"),
      redlog::field("debug_gadgets", config_.debug_gadgets ? "true" : "false")
  );
}

QBDI::VMAction gadgetdemo_tracer::on_vm_start(
    w1::trace_context& ctx, const w1::sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  (void) event;
  (void) state;
  (void) gpr;
  (void) fpr;

  ensure_executor(vm);
  resolve_main_base(ctx.modules());

  if (config_.run_immediate && !immediate_done_) {
    run_immediate_test();
    immediate_done_ = true;
  }

  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction gadgetdemo_tracer::on_instruction_pre(
    w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) ctx;
  (void) event;
  (void) vm;
  (void) gpr;
  (void) fpr;

  instruction_count_ += 1;
  if (!demo_completed_ && instruction_count_ == config_.trigger_count) {
    run_demo();
    demo_completed_ = true;
  }

  return QBDI::VMAction::CONTINUE;
}

void gadgetdemo_tracer::ensure_executor(QBDI::VMInstanceRef vm) {
  if (executor_) {
    return;
  }

  auto* qbdi_vm = static_cast<QBDI::VM*>(vm);
  if (!qbdi_vm) {
    log_.err("vm instance is null");
    return;
  }

  w1::gadget::gadget_executor::config cfg{};
  cfg.debug = config_.debug_gadgets;
  executor_ = std::make_unique<w1::gadget::gadget_executor>(qbdi_vm, cfg);
}

void gadgetdemo_tracer::resolve_main_base(const w1::runtime::module_catalog& modules) {
  if (main_base_ != 0) {
    return;
  }

  auto list = modules.list_modules();
  uint64_t lowest_exec = 0;

  for (const auto& module : list) {
    if (module.exec_ranges.empty()) {
      continue;
    }

    if (module.name.find("hook_test_target") != std::string::npos ||
        module.path.find("hook_test_target") != std::string::npos) {
      main_base_ = module.base_address;
      break;
    }

    if (lowest_exec == 0 || module.base_address < lowest_exec) {
      lowest_exec = module.base_address;
    }
  }

  if (main_base_ == 0) {
    main_base_ = lowest_exec;
  }

  if (main_base_ == 0) {
    log_.err("failed to resolve main base");
  } else {
    log_.inf("resolved main base", redlog::field("base", "0x%llx", main_base_));
  }
}

void gadgetdemo_tracer::run_immediate_test() {
  if (!executor_) {
    log_.err("gadget executor unavailable for immediate test");
    return;
  }

  int result = executor_->gadget_call<int>(reinterpret_cast<QBDI::rword>(demo_add), {100, 200});
  log_.inf("immediate test", redlog::field("add(100, 200)", "%d", result));
}

void gadgetdemo_tracer::run_demo() {
  if (!executor_) {
    log_.err("gadget executor unavailable");
    return;
  }

  if (main_base_ == 0) {
    log_.err("main base is unknown; skipping gadget demo");
    return;
  }

  log_.inf("demonstrating gadget execution from callback");

  QBDI::rword get_pid_addr = main_base_ + offset_get_process_id;
  int pid = executor_->gadget_call<int>(get_pid_addr, {});
  log_.inf(
      "target gadget", redlog::field("get_process_id()", "%d", pid), redlog::field("addr", "0x%llx", get_pid_addr)
  );

  const char* data = "test data for hash";
  QBDI::rword compute_hash_addr = main_base_ + offset_compute_hash;
  unsigned int hash =
      executor_->gadget_call<unsigned int>(compute_hash_addr, {reinterpret_cast<QBDI::rword>(data), std::strlen(data)});
  log_.inf("target gadget", redlog::field("compute_hash", "0x%08x", hash), redlog::field("data", data));

  const char* haystack = "the quick brown fox";
  const char* needle = "brown";
  QBDI::rword contains_pattern_addr = main_base_ + offset_contains_pattern;
  int found = executor_->gadget_call<int>(
      contains_pattern_addr, {reinterpret_cast<QBDI::rword>(haystack), reinterpret_cast<QBDI::rword>(needle)}
  );
  log_.inf(
      "target gadget", redlog::field("contains_pattern", found ? "found" : "not found"),
      redlog::field("needle", needle), redlog::field("haystack", haystack)
  );

  QBDI::rword strlen_addr = main_base_ + offset_get_string_length;
  size_t len = executor_->gadget_call<size_t>(strlen_addr, {reinterpret_cast<QBDI::rword>(haystack)});
  log_.inf("target gadget", redlog::field("get_string_length", "%zu", len), redlog::field("data", haystack));

  QBDI::rword is_valid_addr = main_base_ + offset_is_valid_pointer;
  int valid = executor_->gadget_call<int>(is_valid_addr, {reinterpret_cast<QBDI::rword>(haystack)});
  log_.inf("target gadget", redlog::field("is_valid_pointer", "%d", valid));

  int sum = executor_->gadget_call<int>(reinterpret_cast<QBDI::rword>(demo_add), {42, 58});
  log_.inf("demo gadget", redlog::field("add(42, 58)", "%d", sum));

  int product = executor_->gadget_call<int>(reinterpret_cast<QBDI::rword>(demo_multiply), {7, 6});
  log_.inf("demo gadget", redlog::field("multiply(7, 6)", "%d", product));

  size_t local_len = executor_->gadget_call<size_t>(
      reinterpret_cast<QBDI::rword>(demo_strlen), {reinterpret_cast<QBDI::rword>(needle)}
  );
  log_.inf("demo gadget", redlog::field("strlen(needle)", "%zu", local_len));

  executor_->gadget_call<void>(
      reinterpret_cast<QBDI::rword>(demo_print), {reinterpret_cast<QBDI::rword>("demo complete")}
  );

  log_.inf("gadget execution complete");
}

} // namespace gadgetdemo
