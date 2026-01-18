#ifdef P1LL_HAS_ASMR
#include "commands/asm.hpp"
#include "commands/disasm.hpp"
#endif
#include "commands/cure.hpp"
#include "commands/patch.hpp"
#include "commands/poison.hpp"
#include "commands/sig.hpp"
#include <cstdint>
#include <w1base/ext/args.hpp>
#include <redlog.hpp>
#include <w1base/cli/verbosity.hpp>
#include <string>

// global executable path for library discovery (like w1tool)
namespace {
std::string g_executable_path;

#ifdef P1LL_HAS_ASMR
bool parse_address_value(const std::string& value, uint64_t& out) {
  try {
    size_t idx = 0;
    unsigned long long parsed = std::stoull(value, &idx, 0);
    if (idx != value.size()) {
      return false;
    }
    out = static_cast<uint64_t>(parsed);
    return true;
  } catch (const std::exception&) {
    return false;
  }
}
#endif
} // namespace

// following w1tool patterns exactly
namespace cli {
args::Group arguments("arguments");
args::HelpFlag help_flag(arguments, "help", "help", {'h', "help"});
args::CounterFlag verbosity_flag(arguments, "verbosity", "verbosity level", {'v'});

void apply_verbosity() {
  w1::cli::apply_verbosity(args::get(verbosity_flag));
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
    args::ValueFlag<std::string>& sig_flag, args::ValueFlag<std::string>& address_flag,
    args::ValueFlag<std::string>& offset_flag, args::ValueFlag<std::string>& replace_flag,
    args::ValueFlag<std::string>& input_flag, args::ValueFlag<std::string>& output_flag,
    args::ValueFlag<std::string>& platform_flag
) {
  auto log = redlog::get_logger("p1llx.patch");
  cli::apply_verbosity();

  // validate required arguments
  if (!replace_flag || !input_flag) {
    log.err("replace data and input file required");
    std::cerr << "error: replace data (--replace) and input file (-i/--input) are required" << std::endl;
    return 1;
  }

  bool has_sig = sig_flag;
  bool has_address = address_flag;
  if (has_sig == has_address) {
    log.err("either signature or address required");
    std::cerr << "error: specify exactly one of --sig or --address" << std::endl;
    return 1;
  }

  // default output to input if not specified
  std::string output_file = output_flag ? *output_flag : *input_flag;

  if (has_sig) {
    std::string offset_value = offset_flag ? *offset_flag : "";
    std::string platform_override = platform_flag ? *platform_flag : "";
    return p1llx::commands::patch_signature(
        *sig_flag, offset_value, *replace_flag, *input_flag, output_file, platform_override
    );
  }

  return p1llx::commands::patch(*address_flag, *replace_flag, *input_flag, output_file);
}

int cmd_sig(
    args::Positional<std::string>& pattern_flag, args::ValueFlag<std::string>& input_flag, args::Flag& single_flag
) {
  auto log = redlog::get_logger("p1llx.sig");
  cli::apply_verbosity();

  if (!pattern_flag) {
    log.err("signature pattern required");
    std::cerr << "error: signature pattern is required" << std::endl;
    return 1;
  }

  if (!input_flag) {
    log.err("input file required");
    std::cerr << "error: input file (-i/--input) is required" << std::endl;
    return 1;
  }

  p1llx::commands::sig_request request;
  request.pattern = args::get(pattern_flag);
  request.input_file = args::get(input_flag);
  request.single = single_flag;

  return p1llx::commands::sig_command(request);
}

#ifdef P1LL_HAS_ASMR
int cmd_asm(
    args::Positional<std::string>& assembly_flag, args::ValueFlag<std::string>& platform_flag,
    args::ValueFlag<std::string>& address_flag
) {
  auto log = redlog::get_logger("p1llx.asm");
  cli::apply_verbosity();

  if (!assembly_flag) {
    log.err("assembly text required");
    std::cerr << "error: assembly text is required" << std::endl;
    return 1;
  }

  p1llx::commands::asm_request request;
  request.text = args::get(assembly_flag);
  if (platform_flag) {
    request.platform = args::get(platform_flag);
  }
  if (address_flag) {
    uint64_t parsed = 0;
    if (!parse_address_value(args::get(address_flag), parsed)) {
      std::cerr << "error: invalid address value" << std::endl;
      return 1;
    }
    request.address = parsed;
    request.has_address = true;
  }

  return p1llx::commands::asm_command(request);
}

int cmd_disasm(
    args::Positional<std::string>& bytes_flag, args::ValueFlag<std::string>& platform_flag,
    args::ValueFlag<std::string>& address_flag
) {
  auto log = redlog::get_logger("p1llx.disasm");
  cli::apply_verbosity();

  if (!bytes_flag) {
    log.err("hex bytes required");
    std::cerr << "error: hex bytes are required" << std::endl;
    return 1;
  }

  p1llx::commands::disasm_request request;
  request.bytes = args::get(bytes_flag);
  if (platform_flag) {
    request.platform = args::get(platform_flag);
  }
  if (address_flag) {
    uint64_t parsed = 0;
    if (!parse_address_value(args::get(address_flag), parsed)) {
      std::cerr << "error: invalid address value" << std::endl;
      return 1;
    }
    request.address = parsed;
    request.has_address = true;
  }

  return p1llx::commands::disasm_command(request);
}
#endif

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
  args::Command patch_cmd(parser, "patch", "signature or address patching");
  args::ValueFlag<std::string> patch_sig_flag(patch_cmd, "signature", "signature hex pattern", {"sig"});
  args::ValueFlag<std::string> patch_address_flag(patch_cmd, "address", "address to patch (hex)", {"address"});
  args::ValueFlag<std::string> patch_offset_flag(
      patch_cmd, "offset", "offset from signature match (hex or decimal)", {"offset"}
  );
  args::ValueFlag<std::string> patch_replace_flag(patch_cmd, "replace", "replacement hex bytes", {"replace"});
  args::ValueFlag<std::string> patch_input_flag(patch_cmd, "input", "input file path", {'i', "input"});
  args::ValueFlag<std::string> patch_output_flag(
      patch_cmd, "output", "output file path (default: overwrite input)", {'o', "output"}
  );
  args::ValueFlag<std::string> patch_platform_flag(
      patch_cmd, "platform", "platform override (e.g., linux:x64, darwin:arm64)", {'p', "platform"}
  );

  // sig command
  args::Command sig_cmd(parser, "sig", "search for a signature in a file");
  args::Positional<std::string> sig_pattern_flag(sig_cmd, "pattern", "signature hex pattern");
  args::ValueFlag<std::string> sig_input_flag(sig_cmd, "input", "input file path", {'i', "input"});
  args::Flag sig_single_flag(sig_cmd, "single", "require exactly one match", {"single"});

#ifdef P1LL_HAS_ASMR
  // asm/disasm commands
  args::Command asm_cmd(parser, "asm", "assemble instruction text");
  args::Positional<std::string> asm_text_flag(asm_cmd, "assembly", "assembly string");
  args::ValueFlag<std::string> asm_platform_flag(
      asm_cmd, "platform", "platform override (e.g., linux:x64)", {"platform"}
  );
  args::ValueFlag<std::string> asm_address_flag(asm_cmd, "address", "base address (hex or decimal)", {"address"});

  args::Command disasm_cmd(parser, "disasm", "disassemble hex bytes");
  args::Positional<std::string> disasm_bytes_flag(disasm_cmd, "bytes", "hex bytes");
  args::ValueFlag<std::string> disasm_platform_flag(
      disasm_cmd, "platform", "platform override (e.g., linux:x64)", {"platform"}
  );
  args::ValueFlag<std::string> disasm_address_flag(disasm_cmd, "address", "base address (hex or decimal)", {"address"});
#endif

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
      return cmd_patch(
          patch_sig_flag, patch_address_flag, patch_offset_flag, patch_replace_flag, patch_input_flag,
          patch_output_flag, patch_platform_flag
      );
    } else if (sig_cmd) {
      return cmd_sig(sig_pattern_flag, sig_input_flag, sig_single_flag);
#ifdef P1LL_HAS_ASMR
    } else if (asm_cmd) {
      return cmd_asm(asm_text_flag, asm_platform_flag, asm_address_flag);
    } else if (disasm_cmd) {
      return cmd_disasm(disasm_bytes_flag, disasm_platform_flag, disasm_address_flag);
#endif
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
