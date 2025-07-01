#include "../../src/tracers/w1cov/session.hpp"
#include <cstdint>
#include <iostream>

// Simple test function to instrument
extern "C" uint64_t fibonacci(uint64_t n) {
  if (n <= 1) {
    return n;
  }
  return fibonacci(n - 1) + fibonacci(n - 2);
}

extern "C" uint64_t simple_math(uint64_t a, uint64_t b) {
  if (a > b) {
    return a * 2;
  } else {
    return b * 3;
  }
}

int main() {
  std::cout << "Testing w1cov standalone implementation...\n";

  w1cov::session session;
  session.add_target_module_pattern("test_standalone_coverage");

  if (!session.initialize()) {
    std::cout << "Failed to initialize tracer\n";
    return 1;
  }

  // Trace function multiple times to see basic block coverage and hitcounts
  uint64_t result1, result2;
  if (!session.trace_function((void *)simple_math, {10, 5}, &result1)) {
    std::cout << "Failed to trace function (first call)\n";
    return 1;
  }

  if (!session.trace_function((void *)simple_math, {3, 8}, &result2)) {
    std::cout << "Failed to trace function (second call)\n";
    return 1;
  }

  std::cout << "Function results: " << result1 << ", " << result2 << "\n";
  std::cout << "Unique blocks: " << session.get_basic_block_count() << "\n";
  std::cout << "Total hits: " << session.get_total_hits() << "\n";

  std::cout << "Standalone coverage test completed\n";
  return 0;
}