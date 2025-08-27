#include <cstdlib>
#include <iostream>
#include <string>

#include <redlog.hpp>
#include "ext/args.hpp"

#include "commands/cover.hpp"
#include "commands/debug.hpp"
#include "commands/dump.hpp"
#include "commands/inject.hpp"
#include "commands/insert_library.hpp"
#include "commands/inspect.hpp"
#include "commands/read_drcov.hpp"
#include "commands/read_dump.hpp"
#include "commands/tracer.hpp"

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
  args::Flag spawn(parser, "spawn", "spawn new process for injection (uses preload)", {'s', "spawn"});
  args::ValueFlag<int> pid(parser, "pid", "target process id (uses runtime injection)", {'p', "pid"});
  args::ValueFlag<std::string> process_name(
      parser, "process", "target process name (uses runtime injection)", {"process-name"}
  );
  args::Flag suspended(parser, "suspended", "start process in suspended state (only with --spawn)", {"suspended"});
  args::Flag no_aslr(parser, "no-aslr", "disable ASLR when launching process (only with --spawn)", {"no-aslr"});
  args::PositionalList<std::string> args(parser, "args", "binary -- arguments");
  parser.Parse();

  w1tool::commands::inject(library, spawn, pid, process_name, suspended, no_aslr, args);
}

void cmd_insert_library(args::Subparser& parser) {
  cli::apply_verbosity();

  args::Positional<std::string> dylib_path(parser, "dylib_path", "path to library to insert");
  args::Positional<std::string> binary_path(parser, "binary_path", "path to target binary");
  args::Positional<std::string> output_path(parser, "output_path", "path to output binary (optional)");
  args::Flag inplace(parser, "inplace", "modify binary in-place", {"inplace"});
  args::Flag weak(parser, "weak", "insert as weak import", {"weak"});
  args::Flag overwrite(parser, "overwrite", "overwrite existing output file", {"overwrite"});
  args::Flag strip_codesig(parser, "strip-codesig", "automatically strip code signature", {"strip-codesig"});
  args::Flag all_yes(parser, "all-yes", "answer yes to all prompts", {"all-yes"});
  args::Flag show_platforms(parser, "show-platforms", "show platform support information", {"show-platforms"});
  parser.Parse();

  w1tool::commands::insert_library(
      dylib_path, binary_path, output_path, inplace, weak, overwrite, strip_codesig, all_yes, show_platforms
  );
}

void cmd_inspect(args::Subparser& parser) {
  cli::apply_verbosity();

  args::ValueFlag<std::string> binary(parser, "path", "path to binary file", {'b', "binary"});
  args::Flag detailed(parser, "detailed", "show detailed analysis", {'d', "detailed"});
  args::Flag sections(parser, "sections", "show section/segment information", {"sections"});
  args::Flag symbols(parser, "symbols", "show symbol table information", {"symbols"});
  args::Flag imports(parser, "imports", "show import/export information", {"imports"});
  args::Flag security(parser, "security", "show security features analysis", {"security"});
  args::Flag json(parser, "json", "output results in JSON format", {'j', "json"});
  args::ValueFlag<std::string> format(parser, "format", "force format (elf/pe/macho)", {"format"});
  parser.Parse();

  w1tool::commands::inspect(binary, detailed, sections, symbols, imports, security, json, format);
}

void cmd_cover(args::Subparser& parser) {
  cli::apply_verbosity();

  args::ValueFlag<std::string> library(parser, "path", "path to w1cov library", {'L', "w1cov-library"});
  args::Flag spawn(parser, "spawn", "spawn new process for tracing", {'s', "spawn"});
  args::ValueFlag<int> pid(parser, "pid", "process ID to attach to", {'p', "pid"});
  args::ValueFlag<std::string> name(parser, "name", "process name to attach to", {'n', "name"});
  args::ValueFlag<std::string> output(parser, "path", "output file path", {'o', "output"});
  args::Flag include_system(parser, "include-system", "include system libraries", {"include-system"});
  args::Flag inst_trace(parser, "inst-trace", "enable instruction-level tracing (default: basic block)", {"inst"});
  args::ValueFlag<std::string> module_filter(
      parser, "modules", "comma-separated list of modules to filter", {'m', "module-filter"}
  );
  args::ValueFlag<int> debug_level(parser, "level", "debug level override", {"debug"});
  args::ValueFlag<std::string> format(parser, "format", "output format (drcov, text)", {"format"});
  args::Flag suspended(parser, "suspended", "start process in suspended state (only with --spawn)", {"suspended"});
  args::Flag no_aslr(parser, "no-aslr", "disable ASLR when launching process (only with --spawn)", {"no-aslr"});
  args::PositionalList<std::string> args(parser, "args", "binary -- arguments");
  parser.Parse();

  w1tool::commands::cover(
      library, spawn, pid, name, output, include_system, inst_trace, module_filter, debug_level, format, suspended,
      no_aslr, args, g_executable_path
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

void cmd_dump(args::Subparser& parser) {
  cli::apply_verbosity();

  args::ValueFlag<std::string> library(parser, "path", "path to w1dump library", {'L', "w1dump-library"});
  args::Flag spawn(parser, "spawn", "spawn new process for dumping", {'s', "spawn"});
  args::ValueFlag<int> pid(parser, "pid", "process ID to attach to", {'p', "pid"});
  args::ValueFlag<std::string> name(parser, "name", "process name to attach to", {'n', "name"});
  args::ValueFlag<std::string> output(parser, "path", "output file path", {'o', "output"});
  args::Flag memory(parser, "memory", "dump memory content", {"memory"});
  args::ValueFlagList<std::string> filter(
      parser, "filter", "filter regions (format: type[:module1,module2])", {'f', "filter"}
  );
  args::ValueFlag<std::string> max_region_size(
      parser, "size", "max region size to dump (e.g. 10M, 1G)", {"max-region-size"}
  );
  args::ValueFlag<int> debug_level(parser, "level", "debug level override", {"debug"});
  args::Flag suspended(parser, "suspended", "start process in suspended state (only with --spawn)", {"suspended"});
  args::Flag no_aslr(parser, "no-aslr", "disable ASLR when launching process (only with --spawn)", {"no-aslr"});
  args::PositionalList<std::string> args(parser, "args", "binary -- arguments");
  parser.Parse();

  w1tool::commands::dump(
      library, spawn, pid, name, output, memory, filter, max_region_size, debug_level, suspended, no_aslr, args,
      g_executable_path
  );
}

void cmd_read_dump(args::Subparser& parser) {
  cli::apply_verbosity();

  args::ValueFlag<std::string> file(parser, "path", "path to dump file", {'f', "file"});
  args::Flag detailed(parser, "detailed", "show detailed module and region listings", {'d', "detailed"});
  args::ValueFlag<std::string> module(parser, "module", "filter by module name (substring match)", {'m', "module"});
  parser.Parse();

  w1tool::commands::read_dump(file, detailed, module);
}

void cmd_tracer(args::Subparser& parser) {
  cli::apply_verbosity();

  args::ValueFlag<std::string> library(parser, "path", "path to tracer library", {'L', "library"});
  args::ValueFlag<std::string> name(parser, "name", "tracer name (w1cov, w1mem, mintrace, etc.)", {'n', "name"});
  args::Flag spawn(parser, "spawn", "spawn new process for tracing", {'s', "spawn"});
  args::ValueFlag<int> pid(parser, "pid", "process ID to attach to", {'p', "pid"});
  args::ValueFlag<std::string> process_name(parser, "process", "process name to attach to", {"process-name"});
  args::ValueFlag<std::string> output(parser, "path", "output file path", {'o', "output"});
  args::ValueFlagList<std::string> config(parser, "config", "configuration key=value pairs", {'c', "config"});
  args::ValueFlag<int> debug_level(parser, "level", "debug level override", {"debug"});
  args::Flag list_tracers(parser, "list", "list available tracers", {"list-tracers"});
  args::Flag suspended(parser, "suspended", "start process in suspended state (only with --spawn)", {"suspended"});
  args::Flag no_aslr(parser, "no-aslr", "disable ASLR when launching process (only with --spawn)", {"no-aslr"});
  args::PositionalList<std::string> args(parser, "args", "binary -- arguments");
  parser.Parse();

  w1tool::commands::tracer(
      library, name, spawn, pid, process_name, output, config, debug_level, list_tracers, suspended, no_aslr, args,
      g_executable_path
  );
}

void cmd_debug(args::Subparser& parser) {
  cli::apply_verbosity();

  args::ValueFlag<int> pid(parser, "pid", "process ID to attach to", {'p', "pid"});
  args::Flag spawn(parser, "spawn", "spawn new process for debugging", {'s', "spawn"});
  args::Flag interactive(parser, "interactive", "interactive debugging mode", {'i', "interactive"});
  args::Flag suspended(parser, "suspended", "start process in suspended state (only with --spawn)", {"suspended"});
  args::PositionalList<std::string> args(parser, "args", "binary -- arguments");
  parser.Parse();

  w1tool::commands::debug(pid, spawn, interactive, suspended, args);
}

int main(int argc, char* argv[]) {
  // store executable path for library auto-discovery
  g_executable_path = argv[0];

  args::ArgumentParser parser(
      "w1tool - cross-platform dynamic binary analysis tool", "inject libraries, trace coverage, and analyze binaries"
  );
  parser.helpParams.showTerminator = false;

  args::GlobalOptions globals(parser, cli::arguments);
  args::Group commands(parser, "commands");

  args::Command inject_cmd(commands, "inject", "inject library into target process", &cmd_inject);
  args::Command insert_library_cmd(
      commands, "insert-library", "insert library import into binary file", &cmd_insert_library
  );
  args::Command inspect_cmd(commands, "inspect", "comprehensive binary analysis using LIEF", &cmd_inspect);
  args::Command cover_cmd(commands, "cover", "perform coverage tracing with configurable options", &cmd_cover);
  args::Command read_drcov_cmd(commands, "read-drcov", "analyze DrCov coverage files", &cmd_read_drcov);
  args::Command dump_cmd(commands, "dump", "dump process state to file", &cmd_dump);
  args::Command read_dump_cmd(commands, "read-dump", "analyze process dump files", &cmd_read_dump);
  args::Command tracer_cmd(commands, "tracer", "run arbitrary tracer with flexible configuration", &cmd_tracer);
  args::Command debug_cmd(commands, "debug", "interactive debugger for process control", &cmd_debug);

  try {
    parser.ParseCLI(argc, argv);
  } catch (args::Help) {
    std::cout << parser;
  } catch (args::Error& e) {
    std::cerr << e.what() << std::endl << parser;
    return 1;
  }

  return 0;
}