#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "w1base/cli/verbosity.hpp"
#include "tracers/w1script/session.hpp"

namespace {

int parse_verbosity(int argc, char* argv[]) {
  int verbose = 0;
  for (int i = 1; i < argc; ++i) {
    if (argv[i][0] != '-') {
      continue;
    }
    for (const char* p = argv[i]; *p; ++p) {
      if (*p == 'v') {
        ++verbose;
      }
    }
  }
  return verbose;
}

} // namespace

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

int main(int argc, char* argv[]) {
  const int verbose = parse_verbosity(argc, argv);
  w1::cli::apply_verbosity(verbose);

  const std::string script_path = "test_minimal_script.lua";
  std::ofstream script_file(script_path);
  script_file << minimal_script;
  script_file.close();

  w1::tracers::script::script_config config;
  config.script_path = script_path;
  config.verbose = verbose;

  w1::vm_session_config session_config;
  session_config.instrumentation.include_modules = {"test_w1script"};
  session_config.thread_id = 1;
  session_config.thread_name = "main";

  w1::tracers::script::script_session session(session_config, std::in_place, config);

  if (!session.initialize()) {
    std::cerr << "failed to initialize w1script tracer\n";
    std::remove(script_path.c_str());
    return 1;
  }

  uint64_t result = 0;
  if (!session.call(reinterpret_cast<uint64_t>(test_script_fibonacci), {10}, &result)) {
    std::cerr << "failed to trace function\n";
    session.shutdown();
    std::remove(script_path.c_str());
    return 1;
  }

  session.shutdown();
  std::remove(script_path.c_str());

  std::cout << "w1script test completed (fibonacci(10) = " << result << ")\n";
  return 0;
}
