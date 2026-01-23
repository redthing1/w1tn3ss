#include "doctest/doctest.hpp"

#include <cstdint>
#include <vector>

#include "w1instrument/trace/thread_session.hpp"

namespace {

int thread_session_add(int value) { return value + 1; }

struct simple_tracer {
  size_t count = 0;

  const char* name() const { return "simple_tracer"; }
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

} // namespace

TEST_CASE("thread_session runs a minimal tracer") {
  w1::instrument::thread_session_config config;
  config.thread_id = 1;
  config.thread_name = "unit_main";

  w1::instrument::thread_session<simple_tracer> session(config, simple_tracer{});

  if (!session.instrument()) {
    WARN("vm_session could not instrument modules; module scanning may be blocked");
    return;
  }

  std::vector<uint64_t> args;
  args.push_back(1);
  uint64_t result = 0;

  REQUIRE(session.call(reinterpret_cast<uint64_t>(&thread_session_add), args, &result));
  CHECK(result == 2);
  CHECK(session.tracer().count > 0);

  session.shutdown();
}
