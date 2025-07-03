#include "commands/cure.hpp"
#include "commands/patch.hpp"
#include "commands/poison.hpp"
#include <common/ext/args.hpp>
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
    log_level = redlog::level::info;
    break; // -v: verbose
  case 2:
    log_level = redlog::level::debug;
    break; // -vv: trace
  case 3:
    log_level = redlog::level::debug;
    break; // -vvv: debug
  default:
    log_level = redlog::level::debug;
    break; // -vvvv+: pedantic
  }

  redlog::set_level(log_level);
}
} // namespace cli

// command functions following w1tool pattern
int cmd_cure(
    args::ValueFlag<std::string>& script_flag, args::ValueFlag<std::string>& input_flag,
    args::ValueFlag<std::string>& output_flag
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

  return p1llx::commands::cure(*script_flag, *input_flag, output_file);
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
    args::ValueFlag<std::string>& script_flag, args::ValueFlag<std::string>& binary_flag, args::Flag& suspended_flag,
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

  if (!binary_flag) {
    log.err("target binary required");
    std::cerr << "error: target binary (-b/--binary) is required" << std::endl;
    return 1;
  }

  // extract binary arguments from positional list
  std::vector<std::string> binary_args;
  if (args_list) {
    binary_args = args::get(args_list);
  }

  int verbosity_level = args::get(cli::verbosity_flag);
  return p1llx::commands::poison(
      *script_flag, *binary_flag, binary_args, suspended_flag, g_executable_path, verbosity_level
  );
}

int main(int argc, char* argv[]) {
  // store executable path for library auto-discovery (like w1tool)
  g_executable_path = argv[0];

  // argument parser following w1tool style
  args::ArgumentParser parser("p1llx - static binary patcher");
  parser.helpParams.showTerminator = false;
  parser.helpParams.helpindent = 2;
  parser.helpParams.width = 120;

  // global flags
  parser.Add(cli::arguments);

  // cure command
  args::Command cure_cmd(parser, "cure", "apply auto-cure lua script to file");
  args::ValueFlag<std::string> cure_script_flag(cure_cmd, "script", "lua cure script path", {'c', "cure"});
  args::ValueFlag<std::string> cure_input_flag(cure_cmd, "input", "input file path", {'i', "input"});
  args::ValueFlag<std::string> cure_output_flag(
      cure_cmd, "output", "output file path (default: overwrite input)", {'o', "output"}
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
  args::ValueFlag<std::string> poison_binary_flag(poison_cmd, "binary", "target binary path", {'b', "binary"});
  args::Flag poison_suspended_flag(poison_cmd, "suspended", "start target in suspended mode", {"suspended"});
  args::PositionalList<std::string> poison_args_list(poison_cmd, "args", "arguments to pass to target binary");

  try {
    parser.ParseCLI(argc, argv);

    if (cure_cmd) {
      return cmd_cure(cure_script_flag, cure_input_flag, cure_output_flag);
    } else if (patch_cmd) {
      return cmd_patch(patch_address_flag, patch_replace_flag, patch_input_flag, patch_output_flag);
    } else if (poison_cmd) {
      return cmd_poison(poison_script_flag, poison_binary_flag, poison_suspended_flag, poison_args_list);
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