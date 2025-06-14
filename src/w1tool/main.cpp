#include "commands/drcov.hpp"
#include "commands/inject.hpp"
#include "commands/inspect.hpp"
#include "ext/args.hpp"
#include <cstdlib>
#include <iostream>
#include <redlog/redlog.hpp>
#include <string>

int main(int argc, char* argv[]) {
  auto log = redlog::get_logger("w1tool");

  // configure default logging level (warn for quiet operation)
  redlog::set_level(redlog::level::warn);

  log.debug("w1tool starting");

  args::ArgumentParser parser("w1tool - cross-platform dynamic binary analysis tool");
  parser.helpParams.proglineShowFlags = true;

  args::Group commands(parser, "commands");

  // inject subcommand
  args::Command inject(commands, "inject", "inject library into target process");
  args::ValueFlag<std::string> inject_library(inject, "path", "path to injection library", {'L', "library"});
  args::ValueFlag<std::string> inject_name(inject, "name", "target process name", {'n', "name"});
  args::ValueFlag<int> inject_pid(inject, "pid", "target process id", {'p', "pid"});
  args::ValueFlag<std::string> inject_binary(inject, "path", "binary to launch with injection", {'b', "binary"});
  args::ValueFlag<std::string> inject_tool(inject, "tool", "specify analysis tool (e.g., w1cov)", {'t', "tool"});

  // inspect subcommand
  args::Command inspect(commands, "inspect", "inspect binary file");
  args::ValueFlag<std::string> inspect_binary(inspect, "path", "path to binary file", {'b', "binary"});

  // drcov subcommand
  args::Command drcov(commands, "drcov", "analyze DrCov coverage files");
  args::ValueFlag<std::string> drcov_file(drcov, "path", "path to DrCov file", {'f', "file"});
  args::Flag drcov_summary(drcov, "summary", "show summary only", {'s', "summary"});
  args::Flag drcov_detailed(drcov, "detailed", "show detailed basic block listing", {'d', "detailed"});
  args::ValueFlag<std::string> drcov_module(
      drcov, "module", "filter by module name (substring match)", {'m', "module"}
  );

  // global logging options
  args::ValueFlag<std::string> log_level(
      parser, "level", "log level (critical,error,warn,info,verbose,trace,debug)", {"log-level"}
  );
  args::CounterFlag verbose(
      parser, "verbose", "increase verbosity: -v=info, -vv=verbose, -vvv=trace, -vvvv=debug", {'v', "verbose"}
  );
  args::Flag quiet(parser, "quiet", "disable colored output", {'q', "quiet"});

  args::HelpFlag help(parser, "help", "show help", {'h', "help"});

  try {
    parser.ParseCLI(argc, argv);

    // apply logging configuration - verbose flags take precedence over log-level
    if (verbose) {
      int verbosity = args::get(verbose);
      if (verbosity == 1) {
        redlog::set_level(redlog::level::info);
      } else if (verbosity == 2) {
        redlog::set_level(redlog::level::verbose);
      } else if (verbosity == 3) {
        redlog::set_level(redlog::level::trace);
      } else if (verbosity >= 4) {
        redlog::set_level(redlog::level::debug);
      }

      log.debug(
          "verbosity level set", redlog::field("count", verbosity),
          redlog::field("level", redlog::level_name(redlog::get_level()))
      );
    } else if (log_level) {
      std::string level_str = args::get(log_level);
      if (level_str == "critical") {
        redlog::set_level(redlog::level::critical);
      } else if (level_str == "error") {
        redlog::set_level(redlog::level::error);
      } else if (level_str == "warn") {
        redlog::set_level(redlog::level::warn);
      } else if (level_str == "info") {
        redlog::set_level(redlog::level::info);
      } else if (level_str == "verbose") {
        redlog::set_level(redlog::level::verbose);
      } else if (level_str == "trace") {
        redlog::set_level(redlog::level::trace);
      } else if (level_str == "debug") {
        redlog::set_level(redlog::level::debug);
      } else {
        log.warn("unknown log level, using default", redlog::field("level", level_str));
      }
    }

    if (quiet) {
      redlog::set_theme(redlog::themes::plain);
    }

    if (inject) {
      return w1tool::commands::inject(inject_library, inject_name, inject_pid, inject_binary, inject_tool);
    } else if (inspect) {
      return w1tool::commands::inspect(inspect_binary);
    } else if (drcov) {
      return w1tool::commands::drcov(drcov_file, drcov_summary, drcov_detailed, drcov_module);
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