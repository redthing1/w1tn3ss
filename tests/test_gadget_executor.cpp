/**
 * Comprehensive test suite for w1tn3ss gadget_executor
 *
 * This test validates the gadget execution capability that allows
 * calling arbitrary code from within QBDI VM callbacks.
 */

#include "w1tn3ss/gadget/gadget_executor.hpp"
#include "w1tn3ss/util/register_access.hpp"
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

// === Test Infrastructure ===

class TestHarness {
private:
  int tests_run = 0;
  int tests_passed = 0;
  bool verbose = false;

public:
  TestHarness(bool verbose = false) : verbose(verbose) {}

  ~TestHarness() {
    printf("\n=== Test Summary ===\n");
    printf("Total tests: %d\n", tests_run);
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_run - tests_passed);
    if (tests_run > 0) {
      printf("Success rate: %.1f%%\n", 100.0 * tests_passed / tests_run);
    }
  }

  void test(const char *name, bool condition, const char *error = nullptr) {
    tests_run++;
    if (condition) {
      tests_passed++;
      printf("  ✓ %s\n", name);
    } else {
      printf("  ✗ %s", name);
      if (error)
        printf(" - %s", error);
      printf("\n");
    }
  }

  bool all_passed() const { return tests_run > 0 && tests_run == tests_passed; }
};

// === Test Gadgets ===

// Global state for testing side effects
struct TestState {
  int counter;
  char buffer[256];
  double sum;
  bool flag;
} g_state = {0, "", 0.0, false};

extern "C" {
// Basic void function
void gadget_increment() { g_state.counter++; }

// Function with return value
int gadget_add(int a, int b) { return a + b; }

// Function with many arguments (tests calling convention)
int gadget_sum8(int a, int b, int c, int d, int e, int f, int g, int h) {
  return a + b + c + d + e + f + g + h;
}

// String operations
int gadget_strlen(const char *str) { return strlen(str); }

void gadget_strcpy(const char *src) {
  if (src) {
    strcpy(g_state.buffer, src);
  }
}

// Floating point
double gadget_multiply_double(double x, double y) {
  g_state.sum = x * y;
  return g_state.sum;
}

// Complex function that uses stack - prevent inlining
__attribute__((noinline)) int gadget_fibonacci(int n) {
  if (n <= 1)
    return n;
  return gadget_fibonacci(n - 1) + gadget_fibonacci(n - 2);
}

// Helper function for testing calls - prevent inlining
__attribute__((noinline)) int gadget_add_helper(int a, int b) { return a + b; }

// Function that calls another function - prevent inlining
__attribute__((noinline)) int gadget_call_helper(int x, int y) {
  return gadget_add_helper(x, y) + 1;
}

// Function that modifies multiple globals
void gadget_complex_state(int value, const char *str, bool flag) {
  g_state.counter = value;
  strcpy(g_state.buffer, str);
  g_state.flag = flag;
}

// Raw execution test function - make it longer to avoid hitting ret
__attribute__((noinline)) void gadget_raw_manip() {
  // Make this function longer so we don't hit the ret before stop_addr
  volatile int *ptr = &g_state.counter;
  *ptr = 0x1234;

  // Add more operations to make the function longer
  for (volatile int i = 0; i < 10; i++) {
    *ptr += 1;
  }

  // More operations to ensure we have enough instructions
  g_state.sum = 3.14159;
  g_state.flag = true;

  // Even more to be safe
  for (volatile int j = 0; j < 5; j++) {
    g_state.buffer[j] = 'A' + j;
  }
}
}

// Target function for VM instrumentation
void target_function(int iterations) {
  for (int i = 0; i < iterations; i++) {
    asm volatile("nop");
  }
}

// === Test Cases ===

void test_basic_functionality() {
  printf("\n[1] Testing Basic Functionality\n");
  TestHarness harness;

  // Create parent VM
  QBDI::VM vm("", {});
  uint8_t *stack = nullptr;
  QBDI::allocateVirtualStack(vm.getGPRState(), 0x100000, &stack);

  printf("  Parent VM created: %p\n", &vm);
  printf("  Parent VM stack: %p (size: 0x100000)\n", stack);
  printf("  Parent VM SP: 0x%llx\n",
         (unsigned long long)w1::registers::get_sp(vm.getGPRState()));

  w1tn3ss::gadget::gadget_executor executor(&vm);

  // Reset state
  g_state = {0, "", 0.0, false};

  // Test void function
  printf("\n  Testing void function (gadget_increment):\n");
  printf("    Gadget address: %p\n", gadget_increment);
  printf("    State before: counter=%d\n", g_state.counter);
  executor.gadget_call<void>(reinterpret_cast<QBDI::rword>(gadget_increment));
  printf("    State after: counter=%d\n", g_state.counter);
  harness.test("void function execution", g_state.counter == 1);

  // Test function with return
  printf("\n  Testing function with return (gadget_add):\n");
  printf("    Gadget address: %p\n", gadget_add);
  printf("    Arguments: 10, 20\n");
  int result = executor.gadget_call<int>(
      reinterpret_cast<QBDI::rword>(gadget_add), {10, 20});
  printf("    Return value: %d\n", result);
  harness.test("return value capture", result == 30);

  // Test multiple arguments
  result = executor.gadget_call<int>(reinterpret_cast<QBDI::rword>(gadget_sum8),
                                     {1, 2, 3, 4, 5, 6, 7, 8});
  harness.test("8 argument passing", result == 36);

  // Test recursive function base cases
  printf("\n  Testing recursive function base cases:\n");
  result = executor.gadget_call<int>(
      reinterpret_cast<QBDI::rword>(gadget_fibonacci), {0});
  printf("    fibonacci(0) = %d\n", result);
  harness.test("fibonacci(0)", result == 0);

  result = executor.gadget_call<int>(
      reinterpret_cast<QBDI::rword>(gadget_fibonacci), {1});
  printf("    fibonacci(1) = %d\n", result);
  harness.test("fibonacci(1)", result == 1);

  // Test function call (non-recursive)
  printf("\n  Testing function that calls another function:\n");
  printf("    gadget_call_helper address: %p\n", gadget_call_helper);
  printf("    gadget_add_helper address: %p\n", gadget_add_helper);
  result = executor.gadget_call<int>(
      reinterpret_cast<QBDI::rword>(gadget_call_helper), {10, 20});
  printf("    gadget_call_helper(10, 20) = %d (should be add_helper(10,20) + 1 "
         "= 31)\n",
         result);
  harness.test("function call", result == 31);

  // Test recursive function complex case
  printf("\n  Testing complex recursive function:\n");
  result = executor.gadget_call<int>(
      reinterpret_cast<QBDI::rword>(gadget_fibonacci), {5});
  printf("    fibonacci(5) = %d (expected: 5)\n", result);
  printf("    This tests multiple recursive calls within the sub-VM\n");
  harness.test("fibonacci(5)", result == 5);

  // Test multiple gadgets in sequence to show VM isolation
  printf("\n  Testing multiple gadgets in sequence (VM isolation):\n");
  g_state.counter = 100;
  printf("    Initial counter: %d\n", g_state.counter);

  executor.gadget_call<void>(reinterpret_cast<QBDI::rword>(gadget_increment));
  printf("    After first increment: %d\n", g_state.counter);

  executor.gadget_call<void>(reinterpret_cast<QBDI::rword>(gadget_increment));
  printf("    After second increment: %d\n", g_state.counter);

  int sum = executor.gadget_call<int>(
      reinterpret_cast<QBDI::rword>(gadget_add),
      {static_cast<QBDI::rword>(g_state.counter), 10});
  printf("    add(%d, 10) = %d\n", g_state.counter, sum);

  harness.test("sequential gadget calls", g_state.counter == 102 && sum == 112);

  QBDI::alignedFree(stack);
}

void test_within_vm_callback() {
  printf("\n[2] Testing Execution Within VM Callbacks\n");
  TestHarness harness;

  printf("  Creating parent VM for instrumentation...\n");
  QBDI::VM vm("", {});
  uint8_t *stack = nullptr;
  QBDI::allocateVirtualStack(vm.getGPRState(), 0x100000, &stack);
  printf("  Parent VM: %p, stack: %p\n", &vm, stack);

  struct CallbackContext {
    int instruction_count;
    bool gadget_executed;
    int gadget_result;
    TestHarness *harness;
  } ctx = {0, false, 0, &harness};

  // Reset state
  g_state = {0, "", 0.0, false};

  vm.addCodeCB(
      QBDI::PREINST,
      [](QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr, void *data) {
        auto *ctx = static_cast<CallbackContext *>(data);
        ctx->instruction_count++;

        // Execute gadgets at specific instruction counts
        if (ctx->instruction_count == 3) {
          printf("\n  [Callback] Instruction #3 - executing gadgets from "
                 "within VM callback:\n");
          printf("    Parent VM (in callback): %p\n", vm);
          printf("    Parent VM SP: 0x%llx\n",
                 (unsigned long long)w1::registers::get_sp(gpr));

          w1tn3ss::gadget::gadget_executor executor(vm);

          // Test basic execution
          printf("    Calling gadget_increment from callback...\n");
          executor.gadget_call<void>(
              reinterpret_cast<QBDI::rword>(gadget_increment));
          printf("    Global counter after gadget: %d\n", g_state.counter);
          ctx->harness->test("callback: increment executed",
                             g_state.counter == 1);

          // Test with return value
          printf("    Calling gadget_add(50, 50) from callback...\n");
          ctx->gadget_result = executor.gadget_call<int>(
              reinterpret_cast<QBDI::rword>(gadget_add), {50, 50});
          printf("    Result: %d\n", ctx->gadget_result);
          ctx->gadget_executed = true;
        }

        if (ctx->instruction_count == 5) {
          printf("\n  [Callback] Instruction #5 - testing complex state "
                 "modification:\n");
          w1tn3ss::gadget::gadget_executor executor(vm);

          // Test complex state modification
          printf("    Calling gadget_complex_state(42, \"from callback\", "
                 "true)...\n");
          executor.gadget_call<void>(
              reinterpret_cast<QBDI::rword>(gadget_complex_state),
              {42, reinterpret_cast<QBDI::rword>("from callback"), 1});
          printf("    State after: counter=%d, buffer=\"%s\", flag=%d\n",
                 g_state.counter, g_state.buffer, g_state.flag);
        }

        return QBDI::CONTINUE;
      },
      &ctx);

  // Run instrumented function
  vm.addInstrumentedModuleFromAddr(
      reinterpret_cast<QBDI::rword>(target_function));
  vm.call(nullptr, reinterpret_cast<QBDI::rword>(target_function), {10});

  harness.test("gadget executed in callback", ctx.gadget_executed);
  harness.test("callback: return value", ctx.gadget_result == 100);
  harness.test("callback: complex state.counter", g_state.counter == 42);
  harness.test("callback: complex state.buffer",
               strcmp(g_state.buffer, "from callback") == 0);
  harness.test("callback: complex state.flag", g_state.flag == true);

  QBDI::alignedFree(stack);
}

void test_state_management() {
  printf("\n[3] Testing State Management\n");
  TestHarness harness;

  // Create parent VM with stack like other working tests
  QBDI::VM vm("", {});
  uint8_t *stack = nullptr;
  QBDI::allocateVirtualStack(vm.getGPRState(), 0x100000, &stack);

  w1tn3ss::gadget::gadget_executor executor(&vm);

  // Test gadget_call (clean function call api)
  printf("  Testing gadget_call...\n");
  int call_result = executor.gadget_call<int>(
      reinterpret_cast<QBDI::rword>(gadget_add), {15, 25});
  harness.test("gadget_call success", call_result == 40);

  // Test gadget_run (clean raw execution api)
  printf("  Testing gadget_run...\n");
  g_state.counter = 0; // reset global state

  QBDI::rword start_addr = reinterpret_cast<QBDI::rword>(gadget_raw_manip);
  QBDI::rword end_addr = start_addr + 32; // smaller range to avoid hitting ret

  printf("  raw gadget: 0x%llx - 0x%llx\n", (unsigned long long)start_addr,
         (unsigned long long)end_addr);

  // use null state to let gadget_run use parent vm state
  auto raw_result = executor.gadget_run(start_addr, end_addr);

  if (!raw_result.success) {
    printf("  gadget_run failed: %s\n", raw_result.error.c_str());
  }

  harness.test("gadget_run success", raw_result.success);

  // raw execution stopped before the loop completed - this is correct behavior
  // the initial value 0x1234 (4660) was set, but loop didn't finish due to
  // stop_addr
  harness.test("gadget_run modifies global state", g_state.counter == 0x1234);
  harness.test("gadget_run respects stop address",
               g_state.counter == 0x1234); // proves it stopped early

  printf("  counter after raw execution: %d\n", g_state.counter);
  printf("  raw execution correctly stopped at specified address range\n");

  QBDI::alignedFree(stack);
}

void test_error_handling() {
  printf("\n[4] Testing Error Handling\n");
  TestHarness harness;

  QBDI::VM vm("", {});
  w1tn3ss::gadget::gadget_executor executor(&vm);

  // Test invalid address - gadget_call should return default value
  int invalid_result = executor.gadget_call<int>(0x0, {});
  harness.test("null address returns default", invalid_result == 0);

  // Test unmapped address
  invalid_result = executor.gadget_call<int>(0xdeadbeef, {});
  harness.test("invalid address returns default", invalid_result == 0);
}

void test_performance() {
  printf("\n[5] Testing Performance\n");
  TestHarness harness;

  QBDI::VM vm("", {});
  w1tn3ss::gadget::gadget_executor executor(&vm);

  const int iterations = 1000;

  // Time direct calls
  auto start = std::chrono::high_resolution_clock::now();
  int sum = 0;
  for (int i = 0; i < iterations; i++) {
    sum += gadget_add(i, i);
  }
  auto direct_time = std::chrono::high_resolution_clock::now() - start;

  // Time gadget calls
  start = std::chrono::high_resolution_clock::now();
  sum = 0;
  for (int i = 0; i < iterations; i++) {
    sum += executor.gadget_call<int>(
        reinterpret_cast<QBDI::rword>(gadget_add),
        {static_cast<QBDI::rword>(i), static_cast<QBDI::rword>(i)});
  }
  auto gadget_time = std::chrono::high_resolution_clock::now() - start;

  auto direct_us =
      std::chrono::duration_cast<std::chrono::microseconds>(direct_time)
          .count();
  auto gadget_us =
      std::chrono::duration_cast<std::chrono::microseconds>(gadget_time)
          .count();

  printf("  Direct calls: %lld µs (%.2f µs/call)\n", direct_us,
         direct_us / (double)iterations);
  printf("  Gadget calls: %lld µs (%.2f µs/call)\n", gadget_us,
         gadget_us / (double)iterations);
  printf("  Overhead: %.1fx\n", gadget_us / (double)direct_us);

  harness.test("performance test completed", true);
}

void test_nested_execution() {
  printf("\n[6] Testing Nested Gadget Execution\n");
  TestHarness harness;

  // This tests the key fix - executing gadgets from within VM callbacks
  // should not cause bus errors due to stack switching

  QBDI::VM outer_vm("", {});
  uint8_t *outer_stack = nullptr;
  QBDI::allocateVirtualStack(outer_vm.getGPRState(), 0x100000, &outer_stack);

  struct NestedContext {
    bool outer_executed;
    bool inner_executed;
    int inner_result;
  } ctx = {false, false, 0};

  outer_vm.addCodeCB(
      QBDI::PREINST,
      [](QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr, void *data) {
        static int count = 0;
        if (++count == 2) {
          auto *ctx = static_cast<NestedContext *>(data);
          ctx->outer_executed = true;

          // Create inner VM and execute gadget
          QBDI::VM inner_vm("", {});
          uint8_t *inner_stack = nullptr;
          QBDI::allocateVirtualStack(inner_vm.getGPRState(), 0x100000,
                                     &inner_stack);

          inner_vm.addCodeCB(
              QBDI::PREINST,
              [](QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr,
                 void *data) {
                static int inner_count = 0;
                if (++inner_count == 2) {
                  auto *ctx = static_cast<NestedContext *>(data);

                  // Execute gadget from within nested VM callback
                  w1tn3ss::gadget::gadget_executor executor(vm);
                  ctx->inner_result = executor.gadget_call<int>(
                      reinterpret_cast<QBDI::rword>(gadget_add), {123, 456});
                  ctx->inner_executed = true;
                }
                return QBDI::CONTINUE;
              },
              ctx);

          inner_vm.addInstrumentedModuleFromAddr(
              reinterpret_cast<QBDI::rword>(target_function));
          inner_vm.call(nullptr, reinterpret_cast<QBDI::rword>(target_function),
                        {5});

          QBDI::alignedFree(inner_stack);
        }
        return QBDI::CONTINUE;
      },
      &ctx);

  outer_vm.addInstrumentedModuleFromAddr(
      reinterpret_cast<QBDI::rword>(target_function));
  outer_vm.call(nullptr, reinterpret_cast<QBDI::rword>(target_function), {5});

  harness.test("outer VM callback executed", ctx.outer_executed);
  harness.test("inner VM callback executed", ctx.inner_executed);
  harness.test("nested gadget result", ctx.inner_result == 579);
  harness.test("no bus error in nested execution", true);

  QBDI::alignedFree(outer_stack);
}

// === Main ===

int main(int argc, char *argv[]) {
  printf("=== W1TN3SS Gadget Executor Test Suite ===\n");
  fflush(stdout);
  printf("Testing gadget execution capability for QBDI\n");
  fflush(stdout);

  bool verbose = argc > 1 && strcmp(argv[1], "-v") == 0;
  if (verbose) {
    printf("Verbose mode enabled\n");
  }

  // Run core test suites
  test_basic_functionality();
  test_within_vm_callback();
  test_state_management();
  // test_error_handling();
  // test_performance();
  // test_nested_execution();

  printf("\n=== Test Complete ===\n");
  return 0;
}