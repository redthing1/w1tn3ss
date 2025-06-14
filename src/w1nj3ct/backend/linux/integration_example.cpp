#include "../../error.hpp"
#include "../../w1nj3ct.hpp"
#include "linux_elf_wrapper.hpp"

#include <iostream>
#include <string>
#include <vector>

using namespace w1::inject;

// example of integrating Linux ELF backend with w1nj3ct injection
class enhanced_linux_injector {
public:
  explicit enhanced_linux_injector(pid_t pid) : pid_(pid), resolver_(pid) {}

  // inject library and resolve symbols
  struct injection_result {
    bool success;
    std::string error_message;
    std::vector<std::pair<std::string, void*>> resolved_symbols;
  };

  injection_result inject_with_symbol_resolution(
      const std::string& library_path, const std::vector<std::string>& symbols_to_resolve = {}
  ) {
    injection_result result;

    // step 1: perform injection using standard w1nj3ct
    config cfg;
    cfg.pid = pid_;
    cfg.library_path = library_path;

    auto inject_result = inject_runtime(cfg);
    if (!inject_result.success) {
      result.success = false;
      result.error_message = inject_result.error_message;
      return result;
    }

    // step 2: resolve requested symbols using ELF backend
    std::string lib_name = extract_library_name(library_path);

    for (const auto& symbol : symbols_to_resolve) {
      auto addr = resolver_.find_symbol(lib_name, symbol);
      if (addr) {
        result.resolved_symbols.emplace_back(symbol, *addr);
      } else {
        // symbol not found, but don't fail the entire operation
        result.resolved_symbols.emplace_back(symbol, nullptr);
      }
    }

    result.success = true;
    return result;
  }

  // analyze target process before injection
  struct process_analysis {
    bool is_64bit;
    size_t loaded_modules_count;
    std::vector<std::string> loaded_libraries;
    bool has_debug_symbols;
    std::string libc_version;
  };

  process_analysis analyze_target() {
    process_analysis analysis;

    // architecture detection
    auto arch = resolver_.is_64bit();
    analysis.is_64bit = arch.value_or(true); // assume 64-bit by default

    // enumerate loaded modules
    auto modules = resolver_.get_modules();
    analysis.loaded_modules_count = modules.size();

    for (const auto& module : modules) {
      if (module.path) {
        std::string path = module.path;
        std::string name = extract_library_name(path);
        analysis.loaded_libraries.push_back(name);

        // check for debug symbols
        if (module.symbol_count > 0 && !analysis.has_debug_symbols) {
          analysis.has_debug_symbols = true;
        }

        // detect libc version
        if (path.find("libc.so") != std::string::npos) {
          analysis.libc_version = extract_version_from_path(path);
        }
      }
    }

    return analysis;
  }

  // find injection points (exported functions that could be hooked)
  std::vector<std::pair<std::string, void*>> find_injection_points(const std::string& target_library = "libc.so") {
    std::vector<std::pair<std::string, void*>> injection_points;

    auto symbols = resolver_.get_symbols(target_library);

    // look for commonly hookable functions
    std::vector<std::string> hookable_functions = {"malloc", "free",    "calloc",         "realloc",
                                                   "open",   "close",   "read",           "write",
                                                   "printf", "fprintf", "sprintf",        "dlopen",
                                                   "dlsym",  "dlclose", "pthread_create", "pthread_join"};

    for (const auto& symbol : symbols) {
      if (symbol.name && symbol.type == STT_FUNC) {
        std::string name = symbol.name;

        // check if it's a hookable function
        for (const auto& func : hookable_functions) {
          if (name == func) {
            injection_points.emplace_back(name, symbol.address);
            break;
          }
        }
      }
    }

    return injection_points;
  }

  // verify injection compatibility
  struct compatibility_check {
    bool compatible;
    std::vector<std::string> warnings;
    std::vector<std::string> blocking_issues;
  };

  compatibility_check check_injection_compatibility(const std::string& library_path) {
    compatibility_check check;
    check.compatible = true;

    // check if library is ELF
    if (!linux_elf::is_elf_file(library_path)) {
      check.compatible = false;
      check.blocking_issues.push_back("Library is not a valid ELF file");
      return check;
    }

    // check architecture compatibility
    auto target_arch = resolver_.is_64bit();
    if (target_arch) {
      // TODO: check library architecture matches target
      // for now, just add a warning
      check.warnings.push_back("Architecture compatibility not fully verified");
    }

    // check for common dependency issues
    auto modules = resolver_.get_modules();
    bool has_libc = false;
    bool has_libdl = false;

    for (const auto& module : modules) {
      if (module.path) {
        std::string path = module.path;
        if (path.find("libc.so") != std::string::npos) {
          has_libc = true;
        }
        if (path.find("libdl.so") != std::string::npos) {
          has_libdl = true;
        }
      }
    }

    if (!has_libc) {
      check.warnings.push_back("libc not detected - injection may fail");
    }
    if (!has_libdl) {
      check.warnings.push_back("libdl not detected - dynamic loading may not work");
    }

    return check;
  }

private:
  std::string extract_library_name(const std::string& path) {
    size_t pos = path.find_last_of('/');
    if (pos != std::string::npos) {
      return path.substr(pos + 1);
    }
    return path;
  }

  std::string extract_version_from_path(const std::string& path) {
    // simple version extraction from path like /lib/libc.so.6
    size_t pos = path.find_last_of('.');
    if (pos != std::string::npos && pos + 1 < path.length()) {
      return path.substr(pos + 1);
    }
    return "unknown";
  }

  pid_t pid_;
  linux_elf::elf_resolver resolver_;
};

// demonstration of the enhanced injector
void demonstrate_enhanced_injection() {
  std::cout << "=== Enhanced Linux Injection Demo ===" << std::endl;

  pid_t target_pid = getpid(); // inject into ourselves for demo
  enhanced_linux_injector injector(target_pid);

  // analyze target process
  std::cout << "Analyzing target process..." << std::endl;
  auto analysis = injector.analyze_target();

  std::cout << "Target process analysis:" << std::endl;
  std::cout << "  Architecture: " << (analysis.is_64bit ? "64-bit" : "32-bit") << std::endl;
  std::cout << "  Loaded modules: " << analysis.loaded_modules_count << std::endl;
  std::cout << "  Has debug symbols: " << (analysis.has_debug_symbols ? "yes" : "no") << std::endl;
  std::cout << "  libc version: " << analysis.libc_version << std::endl;

  std::cout << "  Loaded libraries:" << std::endl;
  for (size_t i = 0; i < analysis.loaded_libraries.size() && i < 10; ++i) {
    std::cout << "    " << analysis.loaded_libraries[i] << std::endl;
  }
  if (analysis.loaded_libraries.size() > 10) {
    std::cout << "    ... and " << (analysis.loaded_libraries.size() - 10) << " more" << std::endl;
  }

  // find potential injection points
  std::cout << "\nFinding injection points..." << std::endl;
  auto injection_points = injector.find_injection_points();

  std::cout << "Found " << injection_points.size() << " potential injection points:" << std::endl;
  for (const auto& [name, addr] : injection_points) {
    std::cout << "  " << name << ": " << std::hex << addr << std::dec << std::endl;
  }

  // check compatibility (with a hypothetical library)
  std::string test_library = "/usr/lib/x86_64-linux-gnu/libssl.so";
  std::cout << "\nChecking injection compatibility for " << test_library << "..." << std::endl;

  auto compat = injector.check_injection_compatibility(test_library);
  std::cout << "Compatibility: " << (compat.compatible ? "OK" : "FAILED") << std::endl;

  if (!compat.warnings.empty()) {
    std::cout << "Warnings:" << std::endl;
    for (const auto& warning : compat.warnings) {
      std::cout << "  - " << warning << std::endl;
    }
  }

  if (!compat.blocking_issues.empty()) {
    std::cout << "Blocking issues:" << std::endl;
    for (const auto& issue : compat.blocking_issues) {
      std::cout << "  - " << issue << std::endl;
    }
  }

  std::cout << "\nDemo completed!" << std::endl;
}

int main() {
  std::cout << "Linux ELF Backend Integration Example" << std::endl;
  std::cout << "=====================================" << std::endl << std::endl;

  try {
    demonstrate_enhanced_injection();
  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}