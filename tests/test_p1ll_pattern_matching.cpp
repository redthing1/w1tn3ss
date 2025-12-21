#include "p1ll/core/signature.hpp"
#include "p1ll/engine/pattern_matcher.hpp"
#include "p1ll/utils/hex_utils.hpp"
#include <cassert>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <vector>

using namespace p1ll;
using namespace p1ll::engine;
using namespace p1ll::utils;

// Test result tracking
struct TestResult {
  int passed = 0;
  int failed = 0;

  void pass(const std::string& test_name) {
    std::cout << "[PASS] " << test_name << std::endl;
    passed++;
  }

  void fail(const std::string& test_name, const std::string& reason) {
    std::cout << "[FAIL] " << test_name << " - " << reason << std::endl;
    failed++;
  }

  void summary() {
    std::cout << "\n=== TEST SUMMARY ===" << std::endl;
    std::cout << "Passed: " << passed << std::endl;
    std::cout << "Failed: " << failed << std::endl;
    std::cout << "Total:  " << (passed + failed) << std::endl;
    std::cout << "===================" << std::endl;
  }
};

TestResult results;

// Test data for wildcard pattern matching
void test_wildcard_pattern_matching() {
  std::cout << "\n=== Testing Wildcard Pattern Matching ===" << std::endl;

  // Test case 1: The specific failing pattern from the issue
  {
    std::string pattern = "488b5158 488d4c24?? ffd2 ?? 84db 74?? b001 eb??";

    // Create test data that matches this pattern
    uint8_t test_data[] = {
        0x48, 0x8b, 0x51, 0x58, // 488b5158
        0x48, 0x8d, 0x4c, 0x24, // 488d4c24
        0x28,                   // ?? (wildcard)
        0xff, 0xd2,             // ffd2
        0x90,                   // ?? (wildcard)
        0x84, 0xdb,             // 84db
        0x74, 0x04,             // 74?? (wildcard)
        0xb0, 0x01,             // b001
        0xeb, 0x1d              // eb?? (wildcard)
    };

    auto compiled_sig_opt = compile_signature(pattern);
    if (!compiled_sig_opt) {
      results.fail("Wildcard pattern matching - basic case", "failed to compile signature");
      return;
    }
    auto sig = *compiled_sig_opt;
    pattern_matcher matcher(sig);

    auto matches = matcher.search(test_data, sizeof(test_data));
    if (matches.size() == 1 && matches[0] == 0) {
      results.pass("Wildcard pattern matching - basic case");
    } else {
      results.fail(
          "Wildcard pattern matching - basic case",
          "Expected 1 match at offset 0, got " + std::to_string(matches.size()) + " matches"
      );
    }
  }

  // Test case 2: Pattern with different wildcard values
  {
    std::string pattern = "488b5158 488d4c24?? ffd2 ?? 84db 74?? b001 eb??";

    uint8_t test_data[] = {
        0x48, 0x8b, 0x51, 0x58, // 488b5158
        0x48, 0x8d, 0x4c, 0x24, // 488d4c24
        0xFF,                   // ?? (different wildcard value)
        0xff, 0xd2,             // ffd2
        0x00,                   // ?? (different wildcard value)
        0x84, 0xdb,             // 84db
        0x74, 0x99,             // 74?? (different wildcard value)
        0xb0, 0x01,             // b001
        0xeb, 0xAB              // eb?? (different wildcard value)
    };

    auto compiled_sig_opt = compile_signature(pattern);
    if (!compiled_sig_opt) {
      results.fail("Wildcard pattern matching - different wildcard values", "failed to compile signature");
      return;
    }
    auto sig = *compiled_sig_opt;
    pattern_matcher matcher(sig);

    auto matches = matcher.search(test_data, sizeof(test_data));
    if (matches.size() == 1 && matches[0] == 0) {
      results.pass("Wildcard pattern matching - different wildcard values");
    } else {
      results.fail(
          "Wildcard pattern matching - different wildcard values",
          "Expected 1 match at offset 0, got " + std::to_string(matches.size()) + " matches"
      );
    }
  }

  // Test case 3: Pattern should NOT match when exact bytes are wrong
  {
    std::string pattern = "488b5158 488d4c24?? ffd2 ?? 84db 74?? b001 eb??";

    uint8_t test_data[] = {
        0x48, 0x8b, 0x51, 0x58, // 488b5158
        0x48, 0x8d, 0x4c, 0x24, // 488d4c24
        0x28,                   // ?? (wildcard)
        0xff, 0xd2,             // ffd2
        0x90,                   // ?? (wildcard)
        0x84, 0xdb,             // 84db
        0x75, 0x04,             // 75?? (WRONG: should be 74)
        0xb0, 0x01,             // b001
        0xeb, 0x1d              // eb?? (wildcard)
    };

    auto compiled_sig_opt = compile_signature(pattern);
    if (!compiled_sig_opt) {
      results.fail("compile_signature failed", "failed to compile signature");
      return;
    }
    auto sig = *compiled_sig_opt;
    pattern_matcher matcher(sig);

    auto matches = matcher.search(test_data, sizeof(test_data));
    if (matches.size() == 0) {
      results.pass("Wildcard pattern matching - negative case");
    } else {
      results.fail(
          "Wildcard pattern matching - negative case",
          "Expected 0 matches, got " + std::to_string(matches.size()) + " matches"
      );
    }
  }

  // Test case 4: Pattern at different offset
  {
    std::string pattern = "488b5158 488d4c24?? ffd2 ?? 84db 74?? b001 eb??";

    std::vector<uint8_t> buffer(100, 0x00);
    uint8_t test_data[] = {
        0x48, 0x8b, 0x51, 0x58, // 488b5158
        0x48, 0x8d, 0x4c, 0x24, // 488d4c24
        0x28,                   // ?? (wildcard)
        0xff, 0xd2,             // ffd2
        0x90,                   // ?? (wildcard)
        0x84, 0xdb,             // 84db
        0x74, 0x04,             // 74?? (wildcard)
        0xb0, 0x01,             // b001
        0xeb, 0x1d              // eb?? (wildcard)
    };

    std::memcpy(buffer.data() + 50, test_data, sizeof(test_data));

    auto compiled_sig_opt = compile_signature(pattern);
    if (!compiled_sig_opt) {
      results.fail("compile_signature failed", "failed to compile signature");
      return;
    }
    auto sig = *compiled_sig_opt;
    pattern_matcher matcher(sig);

    auto matches = matcher.search(buffer.data(), buffer.size());
    if (matches.size() == 1 && matches[0] == 50) {
      results.pass("Wildcard pattern matching - different offset");
    } else {
      results.fail(
          "Wildcard pattern matching - different offset",
          "Expected 1 match at offset 50, got " + std::to_string(matches.size()) + " matches"
      );
    }
  }
}

void test_exact_pattern_matching() {
  std::cout << "\n=== Testing Exact Pattern Matching ===" << std::endl;

  // Test case 1: Simple exact pattern
  {
    std::string pattern = "488b5158 488d4c24";
    uint8_t test_data[] = {0x48, 0x8b, 0x51, 0x58, 0x48, 0x8d, 0x4c, 0x24};

    auto compiled_sig_opt = compile_signature(pattern);
    if (!compiled_sig_opt) {
      results.fail("compile_signature failed", "failed to compile signature");
      return;
    }
    auto sig = *compiled_sig_opt;
    pattern_matcher matcher(sig);

    auto matches = matcher.search(test_data, sizeof(test_data));
    if (matches.size() == 1 && matches[0] == 0) {
      results.pass("Exact pattern matching - basic case");
    } else {
      results.fail(
          "Exact pattern matching - basic case",
          "Expected 1 match at offset 0, got " + std::to_string(matches.size()) + " matches"
      );
    }
  }

  // Test case 2: Pattern not found
  {
    std::string pattern = "488b5158 488d4c24";
    uint8_t test_data[] = {0x48, 0x8b, 0x51, 0x58, 0x48, 0x8d, 0x4c, 0x25}; // Last byte wrong

    auto compiled_sig_opt = compile_signature(pattern);
    if (!compiled_sig_opt) {
      results.fail("compile_signature failed", "failed to compile signature");
      return;
    }
    auto sig = *compiled_sig_opt;
    pattern_matcher matcher(sig);

    auto matches = matcher.search(test_data, sizeof(test_data));
    if (matches.size() == 0) {
      results.pass("Exact pattern matching - negative case");
    } else {
      results.fail(
          "Exact pattern matching - negative case",
          "Expected 0 matches, got " + std::to_string(matches.size()) + " matches"
      );
    }
  }
}

void test_edge_cases() {
  std::cout << "\n=== Testing Edge Cases ===" << std::endl;

  // Test case 1: Single byte pattern
  {
    std::string pattern = "48";
    uint8_t test_data[] = {0x48};

    auto compiled_sig_opt = compile_signature(pattern);
    if (!compiled_sig_opt) {
      results.fail("compile_signature failed", "failed to compile signature");
      return;
    }
    auto sig = *compiled_sig_opt;
    pattern_matcher matcher(sig);

    auto matches = matcher.search(test_data, sizeof(test_data));
    if (matches.size() == 1 && matches[0] == 0) {
      results.pass("Edge case - single byte pattern");
    } else {
      results.fail(
          "Edge case - single byte pattern",
          "Expected 1 match at offset 0, got " + std::to_string(matches.size()) + " matches"
      );
    }
  }

  // Test case 2: Single wildcard pattern
  {
    std::string pattern = "??";
    uint8_t test_data[] = {0x48};

    auto compiled_sig_opt = compile_signature(pattern);
    if (!compiled_sig_opt) {
      results.fail("compile_signature failed", "failed to compile signature");
      return;
    }
    auto sig = *compiled_sig_opt;
    pattern_matcher matcher(sig);

    auto matches = matcher.search(test_data, sizeof(test_data));
    if (matches.size() == 1 && matches[0] == 0) {
      results.pass("Edge case - single wildcard pattern");
    } else {
      results.fail(
          "Edge case - single wildcard pattern",
          "Expected 1 match at offset 0, got " + std::to_string(matches.size()) + " matches"
      );
    }
  }

  // Test case 3: All wildcards pattern
  {
    std::string pattern = "?? ?? ??";
    uint8_t test_data[] = {0x48, 0x8b, 0x51};

    auto compiled_sig_opt = compile_signature(pattern);
    if (!compiled_sig_opt) {
      results.fail("compile_signature failed", "failed to compile signature");
      return;
    }
    auto sig = *compiled_sig_opt;
    pattern_matcher matcher(sig);

    auto matches = matcher.search(test_data, sizeof(test_data));
    if (matches.size() == 1 && matches[0] == 0) {
      results.pass("Edge case - all wildcards pattern");
    } else {
      results.fail(
          "Edge case - all wildcards pattern",
          "Expected 1 match at offset 0, got " + std::to_string(matches.size()) + " matches"
      );
    }
  }

  // Test case 4: Empty data
  {
    std::string pattern = "48";
    uint8_t* test_data = nullptr;

    auto compiled_sig_opt = compile_signature(pattern);
    if (!compiled_sig_opt) {
      results.fail("compile_signature failed", "failed to compile signature");
      return;
    }
    auto sig = *compiled_sig_opt;
    pattern_matcher matcher(sig);

    auto matches = matcher.search(test_data, 0);
    if (matches.size() == 0) {
      results.pass("Edge case - empty data");
    } else {
      results.fail("Edge case - empty data", "Expected 0 matches, got " + std::to_string(matches.size()) + " matches");
    }
  }
}

void test_performance_patterns() {
  std::cout << "\n=== Testing Performance Patterns ===" << std::endl;

  // Test case 1: Pattern with many wildcards (should still work but be slow)
  {
    std::string pattern = "?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b";

    std::vector<uint8_t> test_data(1000, 0x00);
    // Place the pattern at offset 500
    test_data[500 + 10] = 0x48;
    test_data[500 + 11] = 0x8b;

    auto compiled_sig_opt = compile_signature(pattern);
    if (!compiled_sig_opt) {
      results.fail("compile_signature failed", "failed to compile signature");
      return;
    }
    auto sig = *compiled_sig_opt;
    pattern_matcher matcher(sig);

    auto matches = matcher.search(test_data.data(), test_data.size());
    if (matches.size() >= 1) {
      bool found_at_500 = false;
      for (auto match : matches) {
        if (match == 500) {
          found_at_500 = true;
          break;
        }
      }
      if (found_at_500) {
        results.pass("Performance pattern - many wildcards");
      } else {
        results.fail("Performance pattern - many wildcards", "Expected match at offset 500, but not found");
      }
    } else {
      results.fail(
          "Performance pattern - many wildcards",
          "Expected at least 1 match, got " + std::to_string(matches.size()) + " matches"
      );
    }
  }
}

void test_hex_utils() {
  std::cout << "\n=== Testing Hex Utils ===" << std::endl;

  // Test case 1: Valid hex pattern
  {
    std::string pattern = "48 8b ?? ff d2";
    if (is_valid_hex_pattern(pattern)) {
      results.pass("Hex utils - valid pattern");
    } else {
      results.fail("Hex utils - valid pattern", "Pattern should be valid");
    }
  }

  // Test case 2: Invalid hex pattern
  {
    std::string pattern = "48 8b ? ff d2"; // Single ? instead of ??
    if (!is_valid_hex_pattern(pattern)) {
      results.pass("Hex utils - invalid pattern");
    } else {
      results.fail("Hex utils - invalid pattern", "Pattern should be invalid");
    }
  }

  // Test case 3: Normalize hex pattern
  {
    std::string pattern = "48 8B ?? FF d2";
    std::string normalized = normalize_hex_pattern(pattern);
    if (normalized == "488b??ffd2") {
      results.pass("Hex utils - normalize pattern");
    } else {
      results.fail("Hex utils - normalize pattern", "Expected '488b??ffd2', got '" + normalized + "'");
    }
  }
}

int main() {
  std::cout << "=== P1LL Pattern Matching Unit Tests ===" << std::endl;

  test_hex_utils();
  test_exact_pattern_matching();
  test_wildcard_pattern_matching();
  test_edge_cases();
  test_performance_patterns();

  results.summary();

  return results.failed > 0 ? 1 : 0;
}
