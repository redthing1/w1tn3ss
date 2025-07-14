#include "commands/cure.hpp"
#include "commands/patch.hpp"
#include "commands/poison.hpp"
#include <w1common/ext/args.hpp>
#include <redlog.hpp>
#include <string>

// global executable path for library discovery (like w1tool)
namespace {
std::string g_executable_path;
}

// following w1tool patterns exactly
namespace cli {
args::Group arguments("arguments");
args::HelpFlag help_flag(arguments, "help", "help", {'h', "help"});
args::CounterFlag verbosity_flag(arguments, "verbosity", "verbosity level", {'v'});

void apply_verbosity() {
  auto verbosity_count = args::get(verbosity_flag);

  // map verbosity levels like w1tool: info → verbose → trace → debug → pedantic
  redlog::level log_level = redlog::level::info; // default

  switch (verbosity_count) {
  case 0:
    log_level = redlog::level::info;
    break; // default
  case 1:
    log_level = redlog::level::verbose;
    break; // -v: verbose
  case 2:
    log_level = redlog::level::trace;
    break; // -vv: trace
  case 3:
    log_level = redlog::level::debug;
    break; // -vvv: debug
  default:
    log_level = redlog::level::pedantic;
    break; // -vvvv+: pedantic
  }

  redlog::set_level(log_level);
}
} // namespace cli

// command functions following w1tool pattern
int cmd_cure(
    args::ValueFlag<std::string>& script_flag, args::ValueFlag<std::string>& input_flag,
    args::ValueFlag<std::string>& output_flag, args::ValueFlag<std::string>& platform_flag
) {
  auto log = redlog::get_logger("p1llx.cure");
  cli::apply_verbosity();

  // validate required arguments
  if (!script_flag) {
    log.err("cure script required");
    std::cerr << "error: cure script (-c/--cure) is required" << std::endl;
    return 1;
  }

  if (!input_flag) {
    log.err("input file required");
    std::cerr << "error: input file (-i/--input) is required" << std::endl;
    return 1;
  }

  // default output to input if not specified
  std::string output_file = output_flag ? *output_flag : *input_flag;

  // get platform override if specified
  std::string platform_override = platform_flag ? *platform_flag : "";

  return p1llx::commands::cure(*script_flag, *input_flag, output_file, platform_override);
}

int cmd_patch(
    args::ValueFlag<std::string>& address_flag, args::ValueFlag<std::string>& replace_flag,
    args::ValueFlag<std::string>& input_flag, args::ValueFlag<std::string>& output_flag
) {
  auto log = redlog::get_logger("p1llx.patch");
  cli::apply_verbosity();

  // validate required arguments
  if (!address_flag || !replace_flag || !input_flag) {
    log.err("address, replace data, and input file required");
    std::cerr << "error: address (--address), replace data (--replace), and input file (-i/--input) are required"
              << std::endl;
    return 1;
  }

  // default output to input if not specified
  std::string output_file = output_flag ? *output_flag : *input_flag;

  return p1llx::commands::patch(*address_flag, *replace_flag, *input_flag, output_file);
}

int cmd_poison(
    args::ValueFlag<std::string>& script_flag, args::Flag& spawn_flag, args::ValueFlag<int>& pid_flag,
    args::ValueFlag<std::string>& process_name_flag, args::Flag& suspended_flag,
    args::PositionalList<std::string>& args_list
) {
  auto log = redlog::get_logger("p1llx.poison");
  cli::apply_verbosity();

  // validate required arguments
  if (!script_flag) {
    log.err("cure script required");
    std::cerr << "error: cure script (-c/--cure) is required" << std::endl;
    return 1;
  }

  // validate target specification
  int target_count = 0;
  if (spawn_flag) {
    target_count++;
  }
  if (pid_flag) {
    target_count++;
  }
  if (process_name_flag) {
    target_count++;
  }

  if (target_count != 1) {
    log.err("exactly one target required: specify -s/--spawn, --pid, or --process-name");
    std::cerr << "error: exactly one target required: specify -s/--spawn, --pid, or --process-name" << std::endl;
    return 1;
  }

  // validate suspended flag usage
  if (suspended_flag && !spawn_flag) {
    log.err("--suspended can only be used with -s/--spawn");
    std::cerr << "error: --suspended can only be used with -s/--spawn" << std::endl;
    return 1;
  }

  int verbosity_level = args::get(cli::verbosity_flag);

  // determine target method and call appropriate poison function
  if (spawn_flag) {
    // spawn injection with positional arguments
    if (args_list.Get().empty()) {
      log.err("binary path required when using -s/--spawn flag");
      std::cerr << "error: binary path required when using -s/--spawn flag" << std::endl;
      return 1;
    }

    std::vector<std::string> all_args = args::get(args_list);
    std::string binary_path = all_args[0];

    // extract arguments after the binary (everything after first arg)
    std::vector<std::string> binary_args;
    if (all_args.size() > 1) {
      binary_args.assign(all_args.begin() + 1, all_args.end());
    }

    return p1llx::commands::poison_spawn(
        *script_flag, binary_path, binary_args, suspended_flag, g_executable_path, verbosity_level
    );

  } else if (pid_flag) {
    // runtime injection by pid
    return p1llx::commands::poison_pid(*script_flag, args::get(pid_flag), g_executable_path, verbosity_level);

  } else if (process_name_flag) {
    // runtime injection by process name
    return p1llx::commands::poison_process_name(
        *script_flag, args::get(process_name_flag), g_executable_path, verbosity_level
    );

  } else {
    log.err("target required: specify -s/--spawn, --pid, or --process-name");
    std::cerr << "error: target required: specify -s/--spawn, --pid, or --process-name" << std::endl;
    return 1;
  }
}

int main(int argc, char* argv[]) {
  // store executable path for library auto-discovery (like w1tool)
  g_executable_path = argv[0];

  // argument parser following w1tool style
  args::ArgumentParser parser("p1llx - static binary patcher");
  parser.helpParams.showTerminator = false;

  // global flags
  parser.Add(cli::arguments);

  // cure command
  args::Command cure_cmd(parser, "cure", "apply auto-cure lua script to file");
  args::ValueFlag<std::string> cure_script_flag(cure_cmd, "script", "lua cure script path", {'c', "cure"});
  args::ValueFlag<std::string> cure_input_flag(cure_cmd, "input", "input file path", {'i', "input"});
  args::ValueFlag<std::string> cure_output_flag(
      cure_cmd, "output", "output file path (default: overwrite input)", {'o', "output"}
  );
  args::ValueFlag<std::string> cure_platform_flag(
      cure_cmd, "platform", "platform override (e.g., linux:x64, darwin:arm64)", {'p', "platform"}
  );

  // patch command
  args::Command patch_cmd(parser, "patch", "manual hex patching");
  args::ValueFlag<std::string> patch_address_flag(patch_cmd, "address", "address to patch (hex)", {"address"});
  args::ValueFlag<std::string> patch_replace_flag(patch_cmd, "replace", "replacement hex bytes", {"replace"});
  args::ValueFlag<std::string> patch_input_flag(patch_cmd, "input", "input file path", {'i', "input"});
  args::ValueFlag<std::string> patch_output_flag(
      patch_cmd, "output", "output file path (default: overwrite input)", {'o', "output"}
  );

  // poison command
  args::Command poison_cmd(parser, "poison", "inject p01s0n for dynamic patching");
  args::ValueFlag<std::string> poison_script_flag(poison_cmd, "script", "lua cure script path", {'c', "cure"});
  args::Flag poison_spawn_flag(poison_cmd, "spawn", "spawn target binary with p01s0n injection", {'s', "spawn"});
  args::ValueFlag<int> poison_pid_flag(poison_cmd, "pid", "inject into existing process by pid", {'p', "pid"});
  args::ValueFlag<std::string> poison_process_name_flag(
      poison_cmd, "process-name", "inject into existing process by name", {'n', "process-name"}
  );
  args::Flag poison_suspended_flag(poison_cmd, "suspended", "start target in suspended mode", {"suspended"});
  args::PositionalList<std::string> poison_args_list(
      poison_cmd, "args", "target binary and arguments (use -- to separate)"
  );

  try {
    parser.ParseCLI(argc, argv);

    if (cure_cmd) {
      return cmd_cure(cure_script_flag, cure_input_flag, cure_output_flag, cure_platform_flag);
    } else if (patch_cmd) {
      return cmd_patch(patch_address_flag, patch_replace_flag, patch_input_flag, patch_output_flag);
    } else if (poison_cmd) {
      return cmd_poison(
          poison_script_flag, poison_spawn_flag, poison_pid_flag, poison_process_name_flag, poison_suspended_flag,
          poison_args_list
      );
    } else {
      std::cerr << "error: no command specified" << std::endl;
      std::cerr << parser;
      return 1;
    }

  } catch (const args::Help&) {
    std::cout << parser;
    return 0;
  } catch (const args::ParseError& e) {
    std::cerr << e.what() << std::endl;
    std::cerr << parser;
    return 1;
  } catch (const args::ValidationError& e) {
    std::cerr << e.what() << std::endl;
    std::cerr << parser;
    return 1;
  }

  return 0;
}