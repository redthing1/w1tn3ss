/**
 * W1COV Standalone Coverage Example
 * 
 * Demonstrates how to use the w1cov standalone library for programmatic
 * coverage collection. This approach gives you full control over what 
 * functions to instrument and when to collect coverage.
 */

#include "../src/w1tn3ss/coverage/w1cov_standalone.hpp"
#include <iostream>
#include <vector>
#include <cstdint>

// Example functions to instrument
extern "C" {
    uint64_t fibonacci(uint64_t n) {
        if (n <= 1) {
            return n;
        }
        return fibonacci(n - 1) + fibonacci(n - 2);
    }
    
    uint64_t factorial(uint64_t n) {
        if (n <= 1) {
            return 1;
        }
        return n * factorial(n - 1);
    }
    
    uint64_t math_operations(uint64_t a, uint64_t b) {
        if (a > b) {
            return a * 2 + b;  // Branch 1
        } else if (a == b) {
            return a + b;      // Branch 2  
        } else {
            return b * 3 - a;  // Branch 3
        }
    }
}

int main() {
    std::cout << "=== W1COV Standalone Coverage Example ===\n\n";
    
    // Step 1: Initialize the coverage tracer
    w1::coverage::w1cov_standalone tracer;
    
    if (!tracer.initialize()) {
        std::cerr << "Failed to initialize coverage tracer\n";
        return 1;
    }
    std::cout << "Coverage tracer initialized\n";
    
    // Step 2: Trace functions and collect coverage
    std::cout << "\n--- Collecting Coverage ---\n";
    
    uint64_t result;
    
    // Test fibonacci with different inputs to hit different code paths
    if (tracer.trace_function((void*)fibonacci, {5}, &result)) {
        std::cout << "fibonacci(5) = " << result << "\n";
    }
    
    if (tracer.trace_function((void*)fibonacci, {1}, &result)) {
        std::cout << "fibonacci(1) = " << result << "\n";
    }
    
    // Call fibonacci(5) again to demonstrate hitcount tracking
    if (tracer.trace_function((void*)fibonacci, {5}, &result)) {
        std::cout << "fibonacci(5) = " << result << " (second call)\n";
    }
    
    // Test factorial
    if (tracer.trace_function((void*)factorial, {4}, &result)) {
        std::cout << "factorial(4) = " << result << "\n";
    }
    
    // Test math_operations with different branches
    if (tracer.trace_function((void*)math_operations, {10, 5}, &result)) {
        std::cout << "math_operations(10, 5) = " << result << " (branch 1)\n";
    }
    
    if (tracer.trace_function((void*)math_operations, {3, 3}, &result)) {
        std::cout << "math_operations(3, 3) = " << result << " (branch 2)\n";
    }
    
    if (tracer.trace_function((void*)math_operations, {2, 8}, &result)) {
        std::cout << "math_operations(2, 8) = " << result << " (branch 3)\n";
    }
    
    // Step 3: Analyze coverage results
    std::cout << "\n--- Coverage Results ---\n";
    
    std::cout << "Unique basic blocks: " << tracer.get_unique_blocks() << "\n";
    std::cout << "Total hits: " << tracer.get_total_hits() << "\n";
    
    tracer.print_summary();
    
    // Step 4: Export coverage data
    std::cout << "\n--- Exporting Coverage ---\n";
    
    if (tracer.export_drcov("example_coverage.drcov")) {
        std::cout << "Coverage data exported to example_coverage.drcov\n";
        std::cout << "   You can analyze this file with:\n";
        std::cout << "   ./w1tool read-drcov --file example_coverage.drcov\n";
        std::cout << "   or import it into Lighthouse/IDA Pro/Binary Ninja\n";
    } else {
        std::cerr << "Failed to export coverage data\n";
        return 1;
    }
    
    std::cout << "\nCoverage collection completed successfully!\n";
    std::cout << "Notice: Hitcounts show how many times each basic block was executed.\n";
    
    return 0;
}