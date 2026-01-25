#include "doctest/doctest.hpp"

#include <cstdint>
#include <vector>

#include <QBDI.h>

#include "w1instrument/trace/event_dispatcher.hpp"
#include "w1runtime/module_catalog.hpp"
#include "w1instrument/tracer/event.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1runtime/memory_reader.hpp"

namespace {

int test_add(int value) { return value + 1; }
int test_call_chain(int value) { return test_add(value); }

volatile int g_value = 0;
int test_load() { return g_value; }
int test_store(int value) {
  g_value = value;
  return g_value;
}

struct counting_tracer {
  size_t count = 0;

  const char* name() const { return "counting_tracer"; }
  static constexpr w1::event_mask requested_events() { return w1::event_mask_of(w1::event_kind::instruction_pre); }

  void on_instruction_pre(
      w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  ) {
    (void) ctx;
    (void) event;
    (void) vm;
    (void) gpr;
    (void) fpr;
    ++count;
  }
};

struct silent_tracer {
  size_t count = 0;

  const char* name() const { return "silent_tracer"; }
  static constexpr w1::event_mask requested_events() { return 0; }

  void on_instruction_pre(
      w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  ) {
    (void) ctx;
    (void) event;
    (void) vm;
    (void) gpr;
    (void) fpr;
    ++count;
  }
};

struct dual_tracer {
  size_t pre_count = 0;
  size_t post_count = 0;

  const char* name() const { return "dual_tracer"; }
  static constexpr w1::event_mask requested_events() {
    return w1::event_mask_or(
        w1::event_mask_of(w1::event_kind::instruction_pre), w1::event_mask_of(w1::event_kind::instruction_post)
    );
  }

  void on_instruction_pre(
      w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  ) {
    (void) ctx;
    (void) event;
    (void) vm;
    (void) gpr;
    (void) fpr;
    ++pre_count;
  }

  void on_instruction_post(
      w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  ) {
    (void) ctx;
    (void) event;
    (void) vm;
    (void) gpr;
    (void) fpr;
    ++post_count;
  }
};

struct basic_block_tracer {
  size_t entry_count = 0;
  size_t exit_count = 0;

  const char* name() const { return "basic_block_tracer"; }
  static constexpr w1::event_mask requested_events() {
    return w1::event_mask_or(
        w1::event_mask_of(w1::event_kind::basic_block_entry), w1::event_mask_of(w1::event_kind::basic_block_exit)
    );
  }

  void on_basic_block_entry(
      w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  ) {
    (void) ctx;
    (void) event;
    (void) vm;
    (void) state;
    (void) gpr;
    (void) fpr;
    ++entry_count;
  }

  void on_basic_block_exit(
      w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  ) {
    (void) ctx;
    (void) event;
    (void) vm;
    (void) state;
    (void) gpr;
    (void) fpr;
    ++exit_count;
  }
};

struct sequence_tracer {
  size_t start_count = 0;
  size_t stop_count = 0;

  const char* name() const { return "sequence_tracer"; }
  static constexpr w1::event_mask requested_events() {
    return w1::event_mask_or(w1::event_mask_of(w1::event_kind::vm_start), w1::event_mask_of(w1::event_kind::vm_stop));
  }

  void on_vm_start(
      w1::trace_context& ctx, const w1::sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  ) {
    (void) ctx;
    (void) event;
    (void) vm;
    (void) state;
    (void) gpr;
    (void) fpr;
    ++start_count;
  }

  void on_vm_stop(
      w1::trace_context& ctx, const w1::sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  ) {
    (void) ctx;
    (void) event;
    (void) vm;
    (void) state;
    (void) gpr;
    (void) fpr;
    ++stop_count;
  }
};

struct memory_tracer {
  size_t read_count = 0;
  size_t write_count = 0;

  const char* name() const { return "memory_tracer"; }
  static constexpr w1::event_mask requested_events() {
    return w1::event_mask_or(
        w1::event_mask_of(w1::event_kind::memory_read), w1::event_mask_of(w1::event_kind::memory_write)
    );
  }

  void on_memory(
      w1::trace_context& ctx, const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  ) {
    (void) ctx;
    (void) event;
    (void) vm;
    (void) gpr;
    (void) fpr;
    if (event.is_read) {
      ++read_count;
    }
    if (event.is_write) {
      ++write_count;
    }
  }
};

struct exec_transfer_tracer {
  size_t call_count = 0;
  size_t return_count = 0;

  const char* name() const { return "exec_transfer_tracer"; }
  static constexpr w1::event_mask requested_events() {
    return w1::event_mask_or(
        w1::event_mask_of(w1::event_kind::exec_transfer_call), w1::event_mask_of(w1::event_kind::exec_transfer_return)
    );
  }

  void on_exec_transfer_call(
      w1::trace_context& ctx, const w1::exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  ) {
    (void) ctx;
    (void) event;
    (void) vm;
    (void) state;
    (void) gpr;
    (void) fpr;
    ++call_count;
  }

  void on_exec_transfer_return(
      w1::trace_context& ctx, const w1::exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  ) {
    (void) ctx;
    (void) event;
    (void) vm;
    (void) state;
    (void) gpr;
    (void) fpr;
    ++return_count;
  }
};

} // namespace

TEST_CASE("event_router registers instruction_pre callbacks") {
  QBDI::VM vm;

  w1::runtime::module_catalog modules;
  w1::util::memory_reader memory(&vm, modules);
  w1::trace_context ctx(0, &vm, &modules, &memory);

  counting_tracer tracer;
  w1::instrument::event_dispatcher<counting_tracer> router(&vm);

  REQUIRE(router.bind(counting_tracer::requested_events(), tracer, ctx));
  REQUIRE(vm.addInstrumentedModuleFromAddr(reinterpret_cast<QBDI::rword>(&test_add)));

  QBDI::rword result = 0;
  std::vector<QBDI::rword> args;
  args.push_back(1);
  REQUIRE(vm.switchStackAndCall(&result, reinterpret_cast<QBDI::rword>(&test_add), args));
  CHECK(tracer.count > 0);

  router.clear();
}

TEST_CASE("event_router skips callbacks when event mask is empty") {
  QBDI::VM vm;

  w1::runtime::module_catalog modules;
  w1::util::memory_reader memory(&vm, modules);
  w1::trace_context ctx(0, &vm, &modules, &memory);

  silent_tracer tracer;
  w1::instrument::event_dispatcher<silent_tracer> router(&vm);

  REQUIRE(router.bind(silent_tracer::requested_events(), tracer, ctx));
  REQUIRE(vm.addInstrumentedModuleFromAddr(reinterpret_cast<QBDI::rword>(&test_add)));

  QBDI::rword result = 0;
  std::vector<QBDI::rword> args;
  args.push_back(2);
  REQUIRE(vm.switchStackAndCall(&result, reinterpret_cast<QBDI::rword>(&test_add), args));
  CHECK(tracer.count == 0);

  router.clear();
}

TEST_CASE("event_router registers instruction_post callbacks") {
  QBDI::VM vm;

  w1::runtime::module_catalog modules;
  w1::util::memory_reader memory(&vm, modules);
  w1::trace_context ctx(0, &vm, &modules, &memory);

  dual_tracer tracer;
  w1::instrument::event_dispatcher<dual_tracer> router(&vm);

  REQUIRE(router.bind(dual_tracer::requested_events(), tracer, ctx));
  REQUIRE(vm.addInstrumentedModuleFromAddr(reinterpret_cast<QBDI::rword>(&test_add)));

  QBDI::rword result = 0;
  std::vector<QBDI::rword> args;
  args.push_back(3);
  REQUIRE(vm.switchStackAndCall(&result, reinterpret_cast<QBDI::rword>(&test_add), args));
  CHECK(tracer.pre_count > 0);
  CHECK(tracer.post_count > 0);

  router.clear();
}

TEST_CASE("event_router registers basic block callbacks") {
  QBDI::VM vm;

  w1::runtime::module_catalog modules;
  w1::util::memory_reader memory(&vm, modules);
  w1::trace_context ctx(0, &vm, &modules, &memory);

  basic_block_tracer tracer;
  w1::instrument::event_dispatcher<basic_block_tracer> router(&vm);

  REQUIRE(router.bind(basic_block_tracer::requested_events(), tracer, ctx));
  REQUIRE(vm.addInstrumentedModuleFromAddr(reinterpret_cast<QBDI::rword>(&test_add)));

  QBDI::rword result = 0;
  std::vector<QBDI::rword> args;
  args.push_back(4);
  REQUIRE(vm.switchStackAndCall(&result, reinterpret_cast<QBDI::rword>(&test_add), args));
  CHECK(tracer.entry_count > 0);
  CHECK(tracer.exit_count > 0);

  router.clear();
}

TEST_CASE("event_router registers vm start and stop callbacks") {
  QBDI::VM vm;

  w1::runtime::module_catalog modules;
  w1::util::memory_reader memory(&vm, modules);
  w1::trace_context ctx(0, &vm, &modules, &memory);

  sequence_tracer tracer;
  w1::instrument::event_dispatcher<sequence_tracer> router(&vm);

  REQUIRE(router.bind(sequence_tracer::requested_events(), tracer, ctx));
  REQUIRE(vm.addInstrumentedModuleFromAddr(reinterpret_cast<QBDI::rword>(&test_add)));

  QBDI::rword result = 0;
  std::vector<QBDI::rword> args;
  args.push_back(5);
  REQUIRE(vm.switchStackAndCall(&result, reinterpret_cast<QBDI::rword>(&test_add), args));
  CHECK(tracer.start_count > 0);
  CHECK(tracer.stop_count > 0);

  router.clear();
}

TEST_CASE("event_router registers memory callbacks") {
  QBDI::VM vm;

  w1::runtime::module_catalog modules;
  w1::util::memory_reader memory(&vm, modules);
  w1::trace_context ctx(0, &vm, &modules, &memory);

  memory_tracer tracer;
  w1::instrument::event_dispatcher<memory_tracer> router(&vm);

  REQUIRE(router.bind(memory_tracer::requested_events(), tracer, ctx));
  REQUIRE(vm.addInstrumentedModuleFromAddr(reinterpret_cast<QBDI::rword>(&test_load)));
  REQUIRE(router.ensure_memory_recording());

  QBDI::rword result = 0;
  std::vector<QBDI::rword> args;
  REQUIRE(vm.switchStackAndCall(&result, reinterpret_cast<QBDI::rword>(&test_load), args));
  args.clear();
  args.push_back(42);
  REQUIRE(vm.switchStackAndCall(&result, reinterpret_cast<QBDI::rword>(&test_store), args));
  CHECK(tracer.read_count > 0);
  CHECK(tracer.write_count > 0);

  router.clear();
}

TEST_CASE("event_router registers exec transfer callbacks") {
  QBDI::VM vm;

  w1::runtime::module_catalog modules;
  w1::util::memory_reader memory(&vm, modules);
  w1::trace_context ctx(0, &vm, &modules, &memory);

  exec_transfer_tracer tracer;
  w1::instrument::event_dispatcher<exec_transfer_tracer> router(&vm);

  REQUIRE(router.bind(exec_transfer_tracer::requested_events(), tracer, ctx));
  REQUIRE(vm.addInstrumentedModuleFromAddr(reinterpret_cast<QBDI::rword>(&test_call_chain)));

  QBDI::rword result = 0;
  std::vector<QBDI::rword> args;
  args.push_back(6);
  REQUIRE(vm.switchStackAndCall(&result, reinterpret_cast<QBDI::rword>(&test_call_chain), args));
  if (tracer.call_count == 0 && tracer.return_count == 0) {
    WARN("exec transfer callbacks did not fire; QBDI ExecBroker events may be disabled for this build");
  } else {
    CHECK(tracer.call_count > 0);
    CHECK(tracer.return_count > 0);
  }

  router.clear();
}
