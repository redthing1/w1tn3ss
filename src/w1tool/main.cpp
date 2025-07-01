#include <cstdlib>
#include <iostream>
#include <string>

#include <redlog/redlog.hpp>
#include "ext/args.hpp"

#include "commands/cover.hpp"
#include "commands/inject.hpp"
#include "commands/inspect.hpp"
#include "commands/read_drcov.hpp"

namespace cli {
args::Group arguments("arguments");
args::HelpFlag help_flag(arguments, "help", "help", {'h', "help"});
args::CounterFlag verbosity_flag(arguments, "verbosity", "verbosity level", {'v'});

void apply_verbosity() {
  // apply verbosity
  int verbosity = args::get(verbosity_flag);
  redlog::set_level(redlog::level::info);
  if (verbosity == 1) {
    redlog::set_level(redlog::level::verbose);
  } else if (verbosity == 2) {
    redlog::set_level(redlog::level::trace);
  } else if (verbosity == 3) {
    redlog::set_level(redlog::level::debug);
  } else if (verbosity >= 4) {
    redlog::set_level(redlog::level::pedantic);
  }
}
} // namespace cli

namespace {
auto log_main = redlog::get_logger("w1tool");
std::string g_executable_path;
} // namespace

void cmd_inject(args::Subparser& parser) {
  cli::apply_verbosity();

  args::ValueFlag<std::string> library(parser, "path", "path to injection library", {'L', "library"});
  args::Flag spawn(parser, "spawn", "spawn new process for injection", {'s', "spawn"});
  args::ValueFlag<std::string> name(parser, "name", "target process name", {'n', "name"});
  args::ValueFlag<int> pid(parser, "pid", "target process id", {'p', "pid"});
  args::Flag suspended(parser, "suspended", "start process in suspended state (only with --spawn)", {"suspended"});
  args::PositionalList<std::string> args(parser, "args", "binary -- arguments");
  parser.Parse();

  w1tool::commands::inject(library, spawn, name, pid, suspended, args);
}

void cmd_inspect(args::Subparser& parser) {
  cli::apply_verbosity();

  args::ValueFlag<std::string> binary(parser, "path", "path to binary file", {'b', "binary"});
  parser.Parse();

  w1tool::commands::inspect(binary);
}

void cmd_cover(args::Subparser& parser) {
  cli::apply_verbosity();

  args::ValueFlag<std::string> library(parser, "path", "path to w1cov library", {'L', "w1cov-library"});
  args::Flag spawn(parser, "spawn", "spawn new process for tracing", {'s', "spawn"});
  args::ValueFlag<int> pid(parser, "pid", "process ID to attach to", {'p', "pid"});
  args::ValueFlag<std::string> name(parser, "name", "process name to attach to", {'n', "name"});
  args::ValueFlag<std::string> output(parser, "path", "output file path", {'o', "output"});
  args::Flag exclude_system(parser, "exclude-system", "exclude system libraries", {"exclude-system"});
  args::Flag track_hitcounts(parser, "track-hitcounts", "track hit counts in coverage data", {"track-hitcounts"});
  args::ValueFlag<std::string> module_filter(
      parser, "modules", "comma-separated list of modules to filter", {'m', "module-filter"}
  );
  args::ValueFlag<int> debug_level(parser, "level", "debug level override", {"debug"});
  args::ValueFlag<std::string> format(parser, "format", "output format (drcov, text)", {"format"});
  args::Flag suspended(parser, "suspended", "start process in suspended state (only with --spawn)", {"suspended"});
  args::PositionalList<std::string> args(parser, "args", "binary -- arguments");
  parser.Parse();

  w1tool::commands::cover(
      library, spawn, pid, name, output, exclude_system, track_hitcounts, module_filter, debug_level, format, suspended,
      args, g_executable_path
  );
}

void cmd_read_drcov(args::Subparser& parser) {
  cli::apply_verbosity();

  args::ValueFlag<std::string> file(parser, "path", "path to DrCov file", {'f', "file"});
  args::Flag summary(parser, "summary", "show summary only", {'s', "summary"});
  args::Flag detailed(parser, "detailed", "show detailed basic block listing", {'d', "detailed"});
  args::ValueFlag<std::string> module(parser, "module", "filter by module name (substring match)", {'m', "module"});
  parser.Parse();

  w1tool::commands::read_drcov(file, summary, detailed, module);
}

int main(int argc, char* argv[]) {
  // store executable path for library auto-discovery
  g_executable_path = argv[0];

  args::ArgumentParser parser(
      "w1tool - cross-platform dynamic binary analysis tool", "inject libraries, trace coverage, and analyze binaries"
  );
  parser.helpParams.showTerminator = false;
  parser.SetArgumentSeparations(false, false, true, true);
  parser.LongSeparator(" ");

  args::GlobalOptions globals(parser, cli::arguments);
  args::Group commands(parser, "commands");

  args::Command inject_cmd(commands, "inject", "inject library into target process", &cmd_inject);
  args::Command inspect_cmd(commands, "inspect", "inspect binary file", &cmd_inspect);
  args::Command cover_cmd(commands, "cover", "perform coverage tracing with configurable options", &cmd_cover);
  args::Command read_drcov_cmd(commands, "read-drcov", "analyze DrCov coverage files", &cmd_read_drcov);

  try {
    parser.ParseCLI(argc, argv);
  } catch (args::Help) {
    std::cout << parser;
    return 0;
  } catch (args::ParseError& e) {
    std::cerr << e.what() << std::endl;
    std::cerr << parser;
    return 1;
  }

  return 0;
}