#include "commands/cover.hpp"
#include "commands/inject.hpp"
#include "commands/inspect.hpp"
#include "commands/read_drcov.hpp"
#include "ext/args.hpp"
#include <cstdlib>
#include <iostream>
#include <redlog/redlog.hpp>
#include <string>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

int main(int argc, char* argv[]) {
  auto log = redlog::get_logger("w1tool");

  // configure default logging level (warn for quiet operation)
  redlog::set_level(redlog::level::warn);

  log.debug("w1tool starting");

  args::ArgumentParser parser("w1tool - cross-platform dynamic binary analysis tool");
  parser.helpParams.proglineShowFlags = true;
  parser.helpParams.showTerminator = false;

  // global options group
  args::Group global_options("global options");
  args::HelpFlag help(global_options, "help", "show help", {'h', "help"});
  args::CounterFlag verbose(global_options, "verbose", "increase verbosity", {'v', "verbose"});
  args::Flag quiet(global_options, "quiet", "disable colored output", {'q', "quiet"});

  args::GlobalOptions globals(parser, global_options);
  args::Group commands(parser, "commands");

  // inject subcommand
  args::Command inject(commands, "inject", "inject library into target process");
  args::ValueFlag<std::string> inject_library(inject, "path", "path to injection library", {'L', "library"});
  args::ValueFlag<std::string> inject_name(inject, "name", "target process name", {'n', "name"});
  args::ValueFlag<int> inject_pid(inject, "pid", "target process id", {'p', "pid"});
  args::ValueFlag<std::string> inject_binary(inject, "path", "binary to launch with injection", {'b', "binary"});

  // inspect subcommand
  args::Command inspect(commands, "inspect", "inspect binary file");
  args::ValueFlag<std::string> inspect_binary(inspect, "path", "path to binary file", {'b', "binary"});

  // cover subcommand
  args::Command cover(commands, "cover", "perform coverage tracing with configurable options");
  args::ValueFlag<std::string> cover_binary(cover, "path", "binary to trace", {'b', "binary"});
  args::ValueFlag<int> cover_pid(cover, "pid", "process ID to attach to", {'p', "pid"});
  args::ValueFlag<std::string> cover_name(cover, "name", "process name to attach to", {'n', "name"});
  args::ValueFlag<std::string> cover_output(cover, "path", "output file path", {'o', "output"});
  args::Flag cover_exclude_system(cover, "exclude-system", "exclude system libraries", {"exclude-system"});
  args::Flag cover_debug(cover, "debug", "enable debug output", {"debug"});
  args::ValueFlag<std::string> cover_format(cover, "format", "output format (drcov, text)", {"format"});

  // read-drcov subcommand
  args::Command read_drcov(commands, "read-drcov", "analyze DrCov coverage files");
  args::ValueFlag<std::string> read_drcov_file(read_drcov, "path", "path to DrCov file", {'f', "file"});
  args::Flag read_drcov_summary(read_drcov, "summary", "show summary only", {'s', "summary"});
  args::Flag read_drcov_detailed(read_drcov, "detailed", "show detailed basic block listing", {'d', "detailed"});
  args::ValueFlag<std::string> read_drcov_module(
      read_drcov, "module", "filter by module name (substring match)", {'m', "module"}
  );

  try {
    parser.ParseCLI(argc, argv);

    // apply logging configuration - verbose flags take precedence over log-level
    if (verbose) {
      int verbosity = args::get(verbose);
      redlog::set_level(redlog::level::info);

      if (verbosity == 1) {
        redlog::set_level(redlog::level::verbose);
      } else if (verbosity == 2) {
        redlog::set_level(redlog::level::trace);
      } else if (verbosity >= 3) {
        redlog::set_level(redlog::level::debug);
      }

      log.debug(
          "verbosity level set", redlog::field("count", verbosity),
          redlog::field("level", redlog::level_name(redlog::get_level()))
      );
    }

    // Detect terminal capabilities for cross-platform color support
    bool is_terminal = false;
#ifdef _WIN32
    is_terminal = _isatty(_fileno(stdout));
#else
    is_terminal = isatty(STDOUT_FILENO);
#endif

    if (quiet || !is_terminal) {
      redlog::set_theme(redlog::themes::plain);
    }

    if (inject) {
      return w1tool::commands::inject(inject_library, inject_name, inject_pid, inject_binary);
    } else if (inspect) {
      return w1tool::commands::inspect(inspect_binary);
    } else if (cover) {
      return w1tool::commands::cover(
          cover_binary, cover_pid, cover_name, cover_output, cover_exclude_system, cover_debug, cover_format
      );
    } else if (read_drcov) {
      return w1tool::commands::read_drcov(read_drcov_file, read_drcov_summary, read_drcov_detailed, read_drcov_module);
    } else {
      // show help by default when no command specified
      std::cout << parser;
      return 0;
    }
  } catch (const args::Help&) {
    std::cout << parser;
    return 0;
  } catch (const args::ParseError& e) {
    log.error("command line parse error", redlog::field("error", e.what()));
    std::cout << parser;
    return 1;
  } catch (const std::exception& e) {
    log.error("unexpected error", redlog::field("error", e.what()));
    return 1;
  }

  return 0;
}