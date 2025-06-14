#include "linux_elf_wrapper.hpp"
#include <iomanip>
#include <iostream>
#include <unistd.h>

using namespace w1::inject::linux_elf;

void test_memory_maps(pid_t pid) {
  std::cout << "=== Testing Memory Maps (C++ API) ===" << std::endl;

  elf_resolver resolver(pid);
  auto maps = resolver.get_memory_maps();

  std::cout << "Found " << maps.size() << " memory mappings:" << std::endl;

  size_t count = 0;
  for (const auto& map : maps) {
    std::cout << "  " << std::hex << map.start_addr << "-" << map.end_addr << std::dec << " "
              << (map.permissions ? map.permissions : "????") << " " << (map.path ? map.path : "[anonymous]")
              << std::endl;

    if (++count >= 10) {
      std::cout << "  ... and " << (maps.size() - count) << " more" << std::endl;
      break;
    }
  }
}

void test_symbol_resolution(pid_t pid) {
  std::cout << "=== Testing Symbol Resolution (C++ API) ===" << std::endl;

  elf_resolver resolver(pid);

  // test common symbols
  const std::vector<std::pair<std::string, std::string>> test_symbols = {
      {"libc.so", "printf"}, {"libc.so", "malloc"}, {"libc.so", "free"}, {"libc.so", "strlen"}, {"ld-linux", "main"}
      // might not exist
  };

  for (const auto& [lib, symbol] : test_symbols) {
    auto addr = resolver.find_symbol(lib, symbol);
    if (addr) {
      std::cout << "  " << symbol << " in " << lib << ": " << std::hex << *addr << std::dec << std::endl;
    } else {
      std::cout << "  " << symbol << " in " << lib << ": NOT FOUND" << std::endl;
    }
  }
}

void test_symbol_enumeration(pid_t pid) {
  std::cout << "=== Testing Symbol Enumeration (C++ API) ===" << std::endl;

  elf_resolver resolver(pid);
  auto symbols = resolver.get_symbols("libc.so");

  std::cout << "Found " << symbols.size() << " symbols in libc.so:" << std::endl;

  size_t count = 0;
  for (const auto& symbol : symbols) {
    if (symbol.name && strlen(symbol.name) > 0) {
      std::cout << "  " << symbol.name << ": " << std::hex << symbol.address << std::dec << " (size: " << symbol.size
                << ")" << std::endl;

      if (++count >= 15) {
        std::cout << "  ... and " << (symbols.size() - count) << " more" << std::endl;
        break;
      }
    }
  }
}

void test_module_enumeration(pid_t pid) {
  std::cout << "=== Testing Module Enumeration (C++ API) ===" << std::endl;

  elf_resolver resolver(pid);
  auto modules = resolver.get_modules();

  std::cout << "Found " << modules.size() << " loaded modules:" << std::endl;

  size_t count = 0;
  for (const auto& module : modules) {
    std::cout << "  " << (module.path ? module.path : "<unknown>") << ": base=" << std::hex << module.base_addr
              << std::dec << " symbols=" << module.symbol_count << std::endl;

    if (++count >= 10) {
      std::cout << "  ... and " << (modules.size() - count) << " more" << std::endl;
      break;
    }
  }
}

void test_convenience_functions(pid_t pid) {
  std::cout << "=== Testing Convenience Functions ===" << std::endl;

  // test standalone functions
  auto malloc_addr = find_symbol(pid, "libc.so", "malloc");
  if (malloc_addr) {
    std::cout << "  malloc (standalone): " << std::hex << *malloc_addr << std::dec << std::endl;
  }

  auto libc_base = find_library_base(pid, "libc.so");
  if (libc_base) {
    std::cout << "  libc.so base (standalone): " << std::hex << *libc_base << std::dec << std::endl;
  }

  // test file checks
  std::vector<std::string> test_files = {
      "/bin/ls", "/lib/x86_64-linux-gnu/libc.so.6",
      "/etc/passwd" // not an ELF
  };

  for (const auto& file : test_files) {
    bool is_elf = is_elf_file(file);
    std::cout << "  " << file << ": " << (is_elf ? "ELF" : "not ELF") << std::endl;
  }
}

void test_architecture_detection(pid_t pid) {
  std::cout << "=== Testing Architecture Detection ===" << std::endl;

  elf_resolver resolver(pid);
  auto arch = resolver.is_64bit();

  if (arch) {
    std::cout << "  Process " << pid << " architecture: " << (*arch ? "64-bit" : "32-bit") << std::endl;
  } else {
    std::cout << "  Could not determine architecture for process " << pid << std::endl;
  }
}

void test_address_resolution(pid_t pid) {
  std::cout << "=== Testing Address Resolution ===" << std::endl;

  elf_resolver resolver(pid);

  // first find a symbol address
  auto malloc_addr = resolver.find_symbol("libc.so", "malloc");
  if (malloc_addr) {
    std::cout << "  malloc address: " << std::hex << *malloc_addr << std::dec << std::endl;

    // now try to resolve it back
    auto symbol = resolver.resolve_address(*malloc_addr);
    if (symbol) {
      std::cout << "  resolved back to: " << (symbol->name ? symbol->name : "<unnamed>") << " at " << std::hex
                << symbol->address << std::dec << std::endl;
    } else {
      std::cout << "  could not resolve address back to symbol" << std::endl;
    }
  }
}

int main(int argc, char* argv[]) {
  pid_t test_pid = getpid(); // test on ourselves by default

  if (argc > 1) {
    test_pid = std::atoi(argv[1]);
    if (test_pid <= 0) {
      std::cerr << "Invalid PID: " << argv[1] << std::endl;
      return 1;
    }
  }

  std::cout << "Linux ELF Backend C++ Wrapper Test" << std::endl;
  std::cout << "Testing on PID: " << test_pid << std::endl << std::endl;

  try {
    test_memory_maps(test_pid);
    std::cout << std::endl;

    test_architecture_detection(test_pid);
    std::cout << std::endl;

    test_symbol_resolution(test_pid);
    std::cout << std::endl;

    test_symbol_enumeration(test_pid);
    std::cout << std::endl;

    test_module_enumeration(test_pid);
    std::cout << std::endl;

    test_convenience_functions(test_pid);
    std::cout << std::endl;

    test_address_resolution(test_pid);
    std::cout << std::endl;

    std::cout << "All tests completed successfully!" << std::endl;

  } catch (const std::exception& e) {
    std::cerr << "Test failed with exception: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}