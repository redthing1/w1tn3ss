#include <iostream>
#include <vector>
#include <cassert>
#include <p1ll.hpp>

int main() {
  std::cout << "=== p1ll core standalone test ===" << std::endl;

  try {
    // test capabilities
    std::cout << "scripting support: " << (p1ll::has_scripting_support() ? "yes" : "no") << std::endl;

    // test context creation and properties
    auto static_ctx = p1ll::context::create_static();
    assert(static_ctx->is_static());
    assert(!static_ctx->is_dynamic());
    std::cout << "✓ static context created and verified" << std::endl;

    auto dynamic_ctx = p1ll::context::create_dynamic();
    assert(dynamic_ctx->is_dynamic());
    assert(!dynamic_ctx->is_static());
    std::cout << "✓ dynamic context created and verified" << std::endl;

    // test platform key parsing and matching
    auto darwin_arm = p1ll::platform_key::parse("darwin:arm64");
    auto linux_x64 = p1ll::platform_key::parse("linux:x64");
    auto wildcard = p1ll::platform_key::parse("*:*");

    assert(darwin_arm.os == "darwin" && darwin_arm.arch == "arm64");
    assert(linux_x64.os == "linux" && linux_x64.arch == "x64");
    assert(wildcard.os == "*" && wildcard.arch == "*");
    assert(darwin_arm != linux_x64);
    std::cout << "✓ platform key parsing and comparison" << std::endl;

    // test hex utilities with various patterns
    std::vector<uint8_t> prologue = {0x48, 0x89, 0xe5}; // mov rbp, rsp
    std::vector<uint8_t> nops = {0x90, 0x90, 0x90, 0x90};
    std::vector<uint8_t> mixed = {0xff, 0xd0, 0x85, 0xc0, 0x74, 0x05}; // call rax; test eax, eax; jz +5

    auto prologue_hex = p1ll::utils::format_bytes(prologue);
    auto nops_hex = p1ll::utils::format_bytes(nops);
    auto mixed_hex = p1ll::utils::format_bytes(mixed);

    assert(!prologue_hex.empty());
    assert(!nops_hex.empty());
    assert(!mixed_hex.empty());
    std::cout << "✓ hex formatting: " << prologue_hex << ", " << nops_hex << ", " << mixed_hex << std::endl;

    // test address formatting
    auto addr1 = p1ll::utils::format_address(0x7fff12345678);
    auto addr2 = p1ll::utils::format_address(0x1000);
    assert(!addr1.empty() && !addr2.empty());
    std::cout << "✓ address formatting: " << addr1 << ", " << addr2 << std::endl;

    // test signature pattern compilation with various patterns
    std::vector<std::string> test_patterns = {
        "48 89 e5",          // simple pattern
        "48 89 e5 ?? 90",    // pattern with wildcard
        "ff d0 ?? ?? 74 ??", // multiple wildcards
        "90 90 90 90"        // nop sled
    };

    for (const auto& pattern : test_patterns) {
      auto compiled = p1ll::compile_signature(pattern);
      assert(compiled.has_value());
      assert(!compiled->empty());
      assert(compiled->pattern.size() == compiled->mask.size());
      std::cout << "✓ compiled pattern '" << pattern << "' -> " << compiled->size() << " bytes" << std::endl;
    }

    // test invalid pattern handling
    std::vector<std::string> invalid_patterns = {
        "zz 90", // invalid hex
        "4",     // incomplete byte
        "",      // empty pattern
    };

    for (const auto& pattern : invalid_patterns) {
      auto compiled = p1ll::compile_signature(pattern);
      if (compiled.has_value()) {
        std::cout << "✗ pattern '" << pattern << "' should have been invalid but compiled" << std::endl;
        return 1;
      }
    }
    std::cout << "✓ invalid pattern rejection" << std::endl;

    // test signature validation
    assert(p1ll::validate_signature_pattern("48 89 e5"));
    assert(p1ll::validate_signature_pattern("ff d0 ?? 74"));
    assert(!p1ll::validate_signature_pattern("zz 90"));
    assert(!p1ll::validate_signature_pattern(""));
    std::cout << "✓ signature pattern validation" << std::endl;

    // test patch compilation
    auto patch = p1ll::compile_patch("90 90 eb 00");
    assert(patch.has_value());
    assert(patch->size() == 4);
    std::cout << "✓ patch pattern compilation" << std::endl;

    // test memory scanner creation
    p1ll::engine::memory_scanner scanner;
    std::cout << "✓ memory scanner instantiated" << std::endl;

    // test hex digit utilities
    assert(p1ll::utils::is_hex_digit('0'));
    assert(p1ll::utils::is_hex_digit('9'));
    assert(p1ll::utils::is_hex_digit('a'));
    assert(p1ll::utils::is_hex_digit('F'));
    assert(!p1ll::utils::is_hex_digit('g'));
    assert(!p1ll::utils::is_hex_digit(' '));
    std::cout << "✓ hex digit validation" << std::endl;

    // test hex parsing
    assert(p1ll::utils::parse_hex_digit('0') == 0);
    assert(p1ll::utils::parse_hex_digit('9') == 9);
    assert(p1ll::utils::parse_hex_digit('a') == 10);
    assert(p1ll::utils::parse_hex_digit('F') == 15);
    std::cout << "✓ hex digit parsing" << std::endl;

    std::cout << "=== all p1ll core tests passed! ===" << std::endl;
    return 0;

  } catch (const std::exception& e) {
    std::cout << "✗ exception: " << e.what() << std::endl;
    return 1;
  } catch (...) {
    std::cout << "✗ unknown exception" << std::endl;
    return 1;
  }
}