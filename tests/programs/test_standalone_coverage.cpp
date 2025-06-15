#include "../../src/w1tn3ss/coverage/w1cov_standalone.hpp"
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

  w1::coverage::w1cov_standalone tracer;

  if (!tracer.initialize()) {
    std::cout << "Failed to initialize tracer\n";
    return 1;
  }

  // Test function instrumentation
  if (!tracer.instrument_function((void *)simple_math, "simple_math")) {
    std::cout << "Failed to instrument simple_math\n";
    return 1;
  }

  // Call instrumented function multiple times to see basic block coverage
  uint64_t result1, result2;
  if (!tracer.call_instrumented_function((void *)simple_math, {10, 5},
                                         &result1)) {
    std::cout << "Failed to call instrumented function (first call)\n";
    return 1;
  }

  if (!tracer.call_instrumented_function((void *)simple_math, {3, 8},
                                         &result2)) {
    std::cout << "Failed to call instrumented function (second call)\n";
    return 1;
  }

  std::cout << "Function results: " << result1 << ", " << result2 << "\n";
  std::cout << "Coverage count: " << tracer.get_coverage_count() << "\n";

  tracer.print_stats();

  if (!tracer.export_coverage("test_standalone_coverage.drcov")) {
    std::cout << "Failed to export coverage\n";
    return 1;
  }

  std::cout << "Standalone coverage test completed\n";
  return 0;
}