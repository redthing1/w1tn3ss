#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#ifdef _WIN32
#include <w1base/windows_clean.hpp>
#else
#include <unistd.h>
#endif

#include <redlog.hpp>
#include "w1base/cli/verbosity.hpp"

#include "tracers/w1xfer/session.hpp"
#include "w1instrument/tracer/vm_session.hpp"
#ifdef WITNESS_SCRIPT_ENABLED
#include "tracers/w1script/session.hpp"
#endif

// test function for w1xfer - demonstrates library calls and transfers
extern "C" void* test_xfer_library_calls(void* arg) {
  size_t size = reinterpret_cast<size_t>(arg);

  // allocate memory
  void* buffer = malloc(size);
  if (!buffer) {
    printf("malloc failed for size %zu\n", size);
    return nullptr;
  }

  // initialize memory
  memset(buffer, 0x42, size);

  // format a string
  char message[256];
  snprintf(message, sizeof(message), "allocated and initialized %zu bytes at %p", size, buffer);

  // print the message
  printf("%s\n", message);

  // try to open a non-existent file (will fail gracefully)
  FILE* fp = fopen("/tmp/nonexistent_test_file_12345.txt", "r");
  if (fp) {
    printf("unexpectedly opened file\n");
    fclose(fp);
  } else {
    printf("expected file open failure\n");
  }

  // clean up
  free(buffer);

  return reinterpret_cast<void*>(size);
}


// test w1xfer tracer
int test_w1xfer(int verbose_level = 0) {
  std::cout << "\n=== testing w1xfer tracer ===\n";

  w1xfer::transfer_config config;
  config.output.path = "test_w1xfer.jsonl";

  // enable all features for comprehensive tracing
  config.capture.registers = true;
  config.capture.stack = true;
  config.enrich.modules = true;
  config.enrich.symbols = true;
  config.enrich.analyze_apis = true;
  config.verbose = verbose_level;

  config.instrumentation.include_modules = {"test_standalone_tracers"};

  w1::vm_session_config session_config;
  session_config.instrumentation = config.instrumentation;
  session_config.thread_id = 1;
  session_config.thread_name = "main";

  w1xfer::session session(session_config, std::in_place, config);

  if (!session.initialize()) {
    std::cout << "failed to initialize w1xfer tracer\n";
    return 1;
  }

  // trace a function that makes library calls
  uint64_t result;
  if (!session.call(reinterpret_cast<uint64_t>(test_xfer_library_calls), {1024}, &result)) {
    std::cout << "failed to trace function\n";
    return 1;
  }

  session.shutdown();

  const auto& stats = session.tracer().get_stats();
  std::cout << "transfer statistics:\n";
  std::cout << "  total calls: " << stats.total_calls << "\n";
  std::cout << "  total returns: " << stats.total_returns << "\n";
  std::cout << "  unique call targets: " << stats.unique_call_targets << "\n";
  std::cout << "  unique return sources: " << stats.unique_return_sources << "\n";
  std::cout << "  max call depth: " << stats.max_call_depth << "\n";

  std::cout << "w1xfer test completed (output in " << config.output.path << ")\n";
  return 0;
}

#ifdef WITNESS_SCRIPT_ENABLED
// minimal lua script embedded as string - instruction tracer
static const char* minimal_script = R"lua(
-- instruction tracer with disassembly
-- logs every instruction with address and assembly code

local instruction_count = 0
local max_instructions = 50  -- limit output for demo

local tracer = {}

local function on_instruction(vm, gpr, fpr)
    instruction_count = instruction_count + 1
    
    -- only log first N instructions to avoid spam
    if instruction_count <= max_instructions then
        local pc = w1.reg.pc(gpr) or 0
        local disasm = w1.inst.disasm(vm) or "<unknown>"

        w1.log.info(w1.util.format_address(pc) .. ": " .. disasm)
    end

    -- at truncation point say we're truncating
    if instruction_count == max_instructions then
        w1.log.info("... silencing further instruction logs ...")
    end
    
    return w1.enum.vm_action.CONTINUE
end

function tracer.init()
    w1.on(w1.event.INSTRUCTION_PRE, on_instruction)
end

function tracer.shutdown()
    w1.log.info("traced " .. instruction_count .. " instructions total")
end

return tracer
)lua";

// test function for w1script - demonstrates scripted tracing
extern "C" int test_script_fibonacci(int n) {
  if (n <= 1) {
    return n;
  }
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

  w1::tracers::script::script_config config;
  config.script_path = script_path;
  config.verbose = verbose_level;

  w1::vm_session_config session_config;
  session_config.instrumentation.include_modules = {"test_standalone_tracers"};
  session_config.thread_id = 1;
  session_config.thread_name = "main";

  w1::tracers::script::script_session session(session_config, std::in_place, config);

  if (!session.initialize()) {
    std::cout << "failed to initialize w1script tracer\n";
    return 1;
  }

  // trace a recursive function to generate some basic blocks
  uint64_t result;
  if (!session.call(reinterpret_cast<uint64_t>(test_script_fibonacci), {10}, &result)) {
    std::cout << "failed to trace function\n";
    return 1;
  }

  std::cout << "fibonacci(10) = " << result << "\n";

  session.shutdown();

  // cleanup temp script
  std::remove(script_path.c_str());

  std::cout << "w1script test completed\n";
  return 0;
}
#endif // WITNESS_SCRIPT_ENABLED

void print_usage(const char* program_name) {
  std::cout << "usage: " << program_name << " [-v...] <tracer>\n";
  std::cout << "\navailable tracers:\n";
  std::cout << "  w1xfer   - transfer/call tracer\n";
#ifdef WITNESS_SCRIPT_ENABLED
  std::cout << "  w1script - scripted tracer\n";
#endif
  std::cout << "  all      - test all tracers\n";
  std::cout << "\noptions:\n";
  std::cout << "  -v      verbose output (can be repeated for more verbosity)\n";
}

int main(int argc, char* argv[]) {
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
      for (const char* p = argv[i]; *p; p++) {
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

  w1::cli::apply_verbosity(verbose);

  if (tracer_name == "w1xfer") {
    return test_w1xfer(verbose);
#ifdef WITNESS_SCRIPT_ENABLED
  } else if (tracer_name == "w1script") {
    return test_w1script(verbose);
#endif
  } else if (tracer_name == "all") {
    int result = 0;
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
