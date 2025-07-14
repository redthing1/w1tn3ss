#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#ifdef _WIN32
#include <w1common/windows_clean.hpp>
#else
#include <unistd.h>
#endif

#include <redlog.hpp>

#include "../../src/tracers/w1cov/session.hpp"
#include "../../src/tracers/w1xfer/session.hpp"
#ifdef WITNESS_SCRIPT_ENABLED
#include "../../src/tracers/w1script/session.hpp"
#endif

// test function for w1cov - demonstrates control flow coverage
extern "C" uint64_t test_coverage_control_flow(uint64_t value) {
  uint64_t result = 0;

  // multiple branches
  if (value < 10) {
    result = value * 2;
  } else if (value < 20) {
    result = value * 3;
    if (value % 2 == 0) {
      result += 5;
    } else {
      result -= 3;
    }
  } else if (value < 50) {
    // loop with early exit
    for (int i = 0; i < 10; i++) {
      result += i;
      if (result > 100) {
        break;
      }
    }
  } else {
    // switch statement
    switch (value % 4) {
    case 0:
      result = value / 2;
      break;
    case 1:
      result = value * value;
      break;
    case 2:
      result = value + 100;
      break;
    default:
      result = value - 50;
      break;
    }
  }

  // nested conditions
  if (result > 0) {
    if (result % 2 == 0) {
      result = result / 2;
    } else {
      result = result * 3 + 1;
    }
  }

  return result;
}

// test function for w1xfer - demonstrates library calls and transfers
extern "C" void *test_xfer_library_calls(void *arg) {
  size_t size = reinterpret_cast<size_t>(arg);

  // allocate memory
  void *buffer = malloc(size);
  if (!buffer) {
    printf("malloc failed for size %zu\n", size);
    return nullptr;
  }

  // initialize memory
  memset(buffer, 0x42, size);

  // format a string
  char message[256];
  sprintf(message, "allocated and initialized %zu bytes at %p", size, buffer);

  // print the message
  printf("%s\n", message);

  // try to open a non-existent file (will fail gracefully)
  FILE *fp = fopen("/tmp/nonexistent_test_file_12345.txt", "r");
  if (fp) {
    printf("unexpectedly opened file\n");
    fclose(fp);
  } else {
    printf("expected file open failure\n");
  }

  // clean up
  free(buffer);

  return reinterpret_cast<void *>(size);
}

// test w1cov tracer
int test_w1cov(int verbose_level = 0) {
  std::cout << "\n=== testing w1cov tracer ===\n";

  w1cov::session session;
  session.add_target_module_pattern("test_standalone_tracers");

  if (!session.initialize()) {
    std::cout << "failed to initialize w1cov tracer\n";
    return 1;
  }

  // trace function multiple times with different paths to demonstrate coverage
  uint64_t result1, result2, result3, result4;

  // test different branches
  if (!session.trace_function((void *)test_coverage_control_flow, {5},
                              &result1)) {
    std::cout << "failed to trace function (value < 10)\n";
    return 1;
  }

  if (!session.trace_function((void *)test_coverage_control_flow, {15},
                              &result2)) {
    std::cout << "failed to trace function (10 <= value < 20)\n";
    return 1;
  }

  if (!session.trace_function((void *)test_coverage_control_flow, {30},
                              &result3)) {
    std::cout << "failed to trace function (20 <= value < 50)\n";
    return 1;
  }

  if (!session.trace_function((void *)test_coverage_control_flow, {100},
                              &result4)) {
    std::cout << "failed to trace function (value >= 50)\n";
    return 1;
  }

  std::cout << "function results: " << result1 << ", " << result2 << ", "
            << result3 << ", " << result4 << "\n";
  std::cout << "unique blocks: " << session.get_coverage_unit_count() << "\n";
  std::cout << "total hits: " << session.get_total_hits() << "\n";

  session.print_statistics();

  if (session.export_coverage("test_w1cov.drcov")) {
    std::cout << "coverage exported successfully\n";
  }

  std::cout << "w1cov test completed\n";
  return 0;
}

// test w1xfer tracer
int test_w1xfer(int verbose_level = 0) {
  std::cout << "\n=== testing w1xfer tracer ===\n";

  w1xfer::transfer_config config;
  config.output_file = "test_w1xfer.jsonl";

  // enable all features for comprehensive tracing
  config.log_registers = true;
  config.log_stack_info = true;
  config.log_call_targets = true;
  config.analyze_apis = true;
  config.verbose = verbose_level;

  w1xfer::session session(config);
  session.add_target_module_pattern("test_standalone_tracers");

  if (!session.initialize()) {
    std::cout << "failed to initialize w1xfer tracer\n";
    return 1;
  }

  // trace a function that makes library calls
  uint64_t result;
  if (!session.trace_function((void *)test_xfer_library_calls, {1024},
                              &result)) {
    std::cout << "failed to trace function\n";
    return 1;
  }

  const auto &stats = session.get_stats();
  std::cout << "transfer statistics:\n";
  std::cout << "  total calls: " << stats.total_calls << "\n";
  std::cout << "  total returns: " << stats.total_returns << "\n";
  std::cout << "  unique call targets: " << stats.unique_call_targets << "\n";
  std::cout << "  unique return sources: " << stats.unique_return_sources
            << "\n";
  std::cout << "  max call depth: " << stats.max_call_depth << "\n";

  std::cout << "w1xfer test completed (output in " << config.output_file
            << ")\n";
  return 0;
}

#ifdef WITNESS_SCRIPT_ENABLED
// minimal lua script embedded as string - instruction tracer
static const char *minimal_script = R"lua(
-- instruction tracer with disassembly
-- logs every instruction with address and assembly code

local instruction_count = 0
local max_instructions = 50  -- limit output for demo

local tracer = {}
tracer.callbacks = { "instruction_preinst" }

function tracer.on_instruction_preinst(vm, gpr, fpr)
    instruction_count = instruction_count + 1
    
    -- only log first N instructions to avoid spam
    if instruction_count <= max_instructions then
        -- get program counter and disassembly
        local pc = w1.get_reg_pc and w1.get_reg_pc(gpr) or 0
        local disasm = w1.get_disassembly(vm)
        
        -- log instruction with address and disassembly
        w1.log_info(w1.format_address(pc) .. ": " .. disasm)
    end

    -- at truncation point say we're truncating
    if instruction_count == max_instructions then
        w1.log_info("... silencing further instruction logs ...")
    end
    
    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    w1.log_info("traced " .. instruction_count .. " instructions total")
end

return tracer
)lua";

// test function for w1script - demonstrates scripted tracing
extern "C" int test_script_fibonacci(int n) {
  if (n <= 1)
    return n;
  return test_script_fibonacci(n - 1) + test_script_fibonacci(n - 2);
}

// test w1script tracer
int test_w1script(int verbose_level = 0) {
  std::cout << "\n=== testing w1script tracer ===\n";

  // write script to temporary file
  std::string script_path;
#ifdef _WIN32
  char temp_path[MAX_PATH];
  GetTempPathA(MAX_PATH, temp_path);
  script_path = std::string(temp_path) + "test_minimal_script.lua";
#else
  script_path = "/tmp/test_minimal_script.lua";
#endif
  std::ofstream script_file(script_path);
  script_file << minimal_script;
  script_file.close();

  w1::tracers::script::config config;
  config.script_path = script_path.c_str();
  config.verbose = (verbose_level > 0);

  w1::tracers::script::session session(config);
  session.add_target_module_pattern("test_standalone_tracers");

  if (!session.initialize()) {
    std::cout << "failed to initialize w1script tracer\n";
    return 1;
  }

  // trace a recursive function to generate some basic blocks
  uint64_t result;
  if (!session.trace_function((void *)test_script_fibonacci, {10}, &result)) {
    std::cout << "failed to trace function\n";
    return 1;
  }

  std::cout << "fibonacci(10) = " << result << "\n";

  // cleanup temp script
  std::remove(script_path.c_str());

  std::cout << "w1script test completed\n";
  return 0;
}
#endif // WITNESS_SCRIPT_ENABLED

void print_usage(const char *program_name) {
  std::cout << "usage: " << program_name << " [-v...] <tracer>\n";
  std::cout << "\navailable tracers:\n";
  std::cout << "  w1cov    - coverage tracer\n";
  std::cout << "  w1xfer   - transfer/call tracer\n";
#ifdef WITNESS_SCRIPT_ENABLED
  std::cout << "  w1script - scripted tracer\n";
#endif
  std::cout << "  all      - test all tracers\n";
  std::cout << "\noptions:\n";
  std::cout
      << "  -v      verbose output (can be repeated for more verbosity)\n";
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    print_usage(argv[0]);
    return 1;
  }

  // parse arguments
  int verbose = 0;
  std::string tracer_name;

  for (int i = 1; i < argc; i++) {
    if (argv[i][0] == '-') {
      // count verbose flags
      for (const char *p = argv[i]; *p; p++) {
        if (*p == 'v') {
          verbose++;
        }
      }
    } else {
      // first non-option argument is the tracer name
      if (tracer_name.empty()) {
        tracer_name = argv[i];
      }
    }
  }

  if (tracer_name.empty()) {
    print_usage(argv[0]);
    return 1;
  }

  // set log level based on verbose count
  if (verbose >= 4) {
    redlog::set_level(redlog::level::pedantic);
  } else if (verbose >= 3) {
    redlog::set_level(redlog::level::debug);
  } else if (verbose >= 2) {
    redlog::set_level(redlog::level::trace);
  } else if (verbose >= 1) {
    redlog::set_level(redlog::level::verbose);
  } else {
    redlog::set_level(redlog::level::info);
  }

  if (tracer_name == "w1cov") {
    return test_w1cov(verbose);
  } else if (tracer_name == "w1xfer") {
    return test_w1xfer(verbose);
#ifdef WITNESS_SCRIPT_ENABLED
  } else if (tracer_name == "w1script") {
    return test_w1script(verbose);
#endif
  } else if (tracer_name == "all") {
    int result = 0;
    result |= test_w1cov(verbose);
    result |= test_w1xfer(verbose);
#ifdef WITNESS_SCRIPT_ENABLED
    result |= test_w1script(verbose);
#endif
    return result;
  } else {
    std::cout << "unknown tracer: " << tracer_name << "\n";
    print_usage(argv[0]);
    return 1;
  }
}