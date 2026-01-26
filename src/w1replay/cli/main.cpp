#include <exception>
#include <iostream>
#include <string>

#include <redlog.hpp>
#include "w1base/ext/args.hpp"

#include "w1base/cli/verbosity.hpp"

#include "w1replay/cli/commands/checkpoint.hpp"
#include "w1replay/cli/commands/inspect.hpp"
#include "w1replay/cli/commands/server.hpp"
#include "w1replay/cli/commands/summary.hpp"
#include "w1replay/cli/commands/threads.hpp"

namespace cli {
args::Group arguments("arguments");
args::HelpFlag help_flag(arguments, "help", "help", {'h', "help"});
args::CounterFlag verbosity_flag(arguments, "verbosity", "verbosity level", {'v'});

void apply_verbosity() { w1::cli::apply_verbosity(args::get(verbosity_flag)); }
} // namespace cli

namespace {
auto log_main = redlog::get_logger("w1replay");
int g_exit_code = 0;
} // namespace

void cmd_inspect(args::Subparser& parser) {
  cli::apply_verbosity();

  args::ValueFlag<std::string> trace_flag(parser, "path", "path to trace file", {'t', "trace"});
  args::ValueFlag<std::string> index_flag(parser, "path", "path to index file", {'i', "index"});
  args::ValueFlag<uint32_t> index_stride_flag(
      parser, "count", "index anchor stride (flow records)", {"index-stride"}
  );
  args::ValueFlag<uint64_t> thread_flag(parser, "thread", "thread id", {'T', "thread"});
  args::ValueFlag<uint64_t> start_flag(parser, "sequence", "start sequence", {'s', "start"});
  args::ValueFlag<uint32_t> count_flag(parser, "count", "number of steps", {'n', "count"});
  args::ValueFlag<uint32_t> history_flag(parser, "size", "history size", {"history"});
  args::Flag reverse_flag(parser, "reverse", "step backward", {"reverse"});
  args::Flag inst_flag(parser, "inst", "step instructions (decode block traces)", {"inst"});
  args::Flag regs_flag(parser, "regs", "show register state", {"regs"});
  args::Flag json_flag(parser, "json", "emit JSON output", {"json"});
  args::ValueFlag<std::string> mem_flag(
      parser, "range", "show memory bytes at addr:size or space:addr:size (example: 0x1000:32)", {"mem"}
  );
  args::ValueFlag<std::string> mem_space_flag(
      parser, "space", "address space name or id for --mem (example: code or 1)", {"space"}
  );
  args::ValueFlagList<std::string> image_flag(parser, "mapping", "image mapping name=path (repeatable)", {"image"});
  args::ValueFlagList<std::string> image_dir_flag(
      parser, "dir", "image search directory (repeatable)", {"image-dir"}
  );
  args::ValueFlag<std::string> image_layout_flag(
      parser, "mode", "image layout source (trace|lief)", {"image-layout"}
  );
  args::ValueFlag<std::string> checkpoint_flag(parser, "path", "path to replay checkpoint file", {"checkpoint"});
  parser.Parse();

  if (!trace_flag) {
    log_main.err("trace path required");
    std::cerr << "error: --trace is required" << std::endl;
    g_exit_code = 1;
    return;
  }
  if (!thread_flag) {
    log_main.err("thread id required");
    std::cerr << "error: --thread is required" << std::endl;
    g_exit_code = 1;
    return;
  }

  w1replay::commands::inspect_options options;
  options.trace_path = *trace_flag;
  options.index_path = index_flag ? *index_flag : "";
  options.index_stride = index_stride_flag ? *index_stride_flag : 0;
  options.thread_id = *thread_flag;
  options.start_sequence = start_flag ? *start_flag : 0;
  options.count = count_flag ? *count_flag : 10;
  options.history_size = history_flag ? *history_flag : 1024;
  options.reverse = reverse_flag;
  options.instruction_steps = inst_flag;
  options.show_registers = regs_flag;
  options.memory_range = mem_flag ? *mem_flag : "";
  options.memory_space = mem_space_flag ? *mem_space_flag : "";
  options.checkpoint_path = checkpoint_flag ? *checkpoint_flag : "";
  options.json_output = json_flag;
  if (image_flag) {
    options.image_mappings = args::get(image_flag);
  }
  if (image_dir_flag) {
    options.image_dirs = args::get(image_dir_flag);
  }
  if (image_layout_flag) {
    auto parsed = w1replay::parse_image_layout_mode(*image_layout_flag);
    if (!parsed.has_value()) {
      log_main.err("invalid image layout mode", redlog::field("value", *image_layout_flag));
      std::cerr << "error: invalid --image-layout (use trace or lief)" << std::endl;
      g_exit_code = 1;
      return;
    }
    options.image_layout = *parsed;
  }

  g_exit_code = w1replay::commands::inspect(options);
}

void cmd_threads(args::Subparser& parser) {
  cli::apply_verbosity();

  args::ValueFlag<std::string> trace_flag(parser, "path", "path to trace file", {'t', "trace"});
  parser.Parse();

  if (!trace_flag) {
    log_main.err("trace path required");
    std::cerr << "error: --trace is required" << std::endl;
    g_exit_code = 1;
    return;
  }

  w1replay::commands::threads_options options;
  options.trace_path = *trace_flag;

  g_exit_code = w1replay::commands::threads(options);
}

void cmd_summary(args::Subparser& parser) {
  cli::apply_verbosity();

  args::ValueFlag<std::string> trace_flag(parser, "path", "path to trace file", {'t', "trace"});
  args::ValueFlag<std::string> index_flag(parser, "path", "path to index file", {'i', "index"});
  args::ValueFlag<std::string> checkpoint_flag(parser, "path", "path to replay checkpoint file", {"checkpoint"});
  args::Flag full_flag(parser, "full", "scan full trace details", {'f', "full"});
  parser.Parse();

  if (!trace_flag) {
    log_main.err("trace path required");
    std::cerr << "error: --trace is required" << std::endl;
    g_exit_code = 1;
    return;
  }

  w1replay::commands::summary_options options;
  options.trace_path = *trace_flag;
  options.index_path = index_flag ? *index_flag : "";
  options.checkpoint_path = checkpoint_flag ? *checkpoint_flag : "";
  options.full = full_flag;

  g_exit_code = w1replay::commands::summary(options);
}

void cmd_checkpoint(args::Subparser& parser) {
  cli::apply_verbosity();

  args::ValueFlag<std::string> trace_flag(parser, "path", "path to trace file", {'t', "trace"});
  args::ValueFlag<std::string> output_flag(parser, "path", "output checkpoint path", {'o', "output"});
  args::ValueFlag<uint32_t> stride_flag(parser, "count", "checkpoint stride (flow records)", {"stride"});
  args::ValueFlag<uint64_t> thread_flag(parser, "thread", "thread id (default: all)", {'T', "thread"});
  args::Flag mem_flag(parser, "memory", "include memory bytes in checkpoints", {"mem"});
  parser.Parse();

  if (!trace_flag) {
    log_main.err("trace path required");
    std::cerr << "error: --trace is required" << std::endl;
    g_exit_code = 1;
    return;
  }

  w1replay::commands::checkpoint_options options;
  options.trace_path = *trace_flag;
  options.output_path = output_flag ? *output_flag : "";
  options.stride = stride_flag ? *stride_flag : 50000;
  options.thread_id = thread_flag ? *thread_flag : 0;
  options.include_memory = mem_flag;

  g_exit_code = w1replay::commands::checkpoint(options);
}

void cmd_server(args::Subparser& parser) {
  cli::apply_verbosity();

  args::ValueFlag<std::string> trace_flag(parser, "path", "path to trace file", {'t', "trace"});
  args::ValueFlag<std::string> index_flag(parser, "path", "path to index file", {'i', "index"});
  args::ValueFlag<std::string> checkpoint_flag(parser, "path", "path to replay checkpoint file", {"checkpoint"});
  args::ValueFlag<std::string> gdb_flag(parser, "addr", "gdb listen address", {"gdb"});
  args::ValueFlag<uint64_t> thread_flag(parser, "thread", "thread id", {'T', "thread"});
  args::ValueFlag<uint64_t> start_flag(parser, "sequence", "start sequence", {'s', "start"});
  args::Flag inst_flag(parser, "inst", "prefer instruction steps when possible", {"inst"});
  args::ValueFlagList<std::string> image_flag(parser, "mapping", "image mapping name=path (repeatable)", {"image"});
  args::ValueFlagList<std::string> image_dir_flag(
      parser, "dir", "image search directory (repeatable)", {"image-dir"}
  );
  args::ValueFlag<std::string> image_layout_flag(
      parser, "mode", "image layout source (trace|lief)", {"image-layout"}
  );
  parser.Parse();

  if (!trace_flag) {
    log_main.err("trace path required");
    std::cerr << "error: --trace is required" << std::endl;
    g_exit_code = 1;
    return;
  }

  w1replay::commands::server_options options;
  options.trace_path = *trace_flag;
  options.index_path = index_flag ? *index_flag : "";
  options.checkpoint_path = checkpoint_flag ? *checkpoint_flag : "";
  options.gdb_listen = gdb_flag ? *gdb_flag : "";
  options.thread_id = thread_flag ? *thread_flag : 0;
  options.start_sequence = start_flag ? *start_flag : 0;
  options.instruction_steps = inst_flag;
  if (image_flag) {
    options.image_mappings = args::get(image_flag);
  }
  if (image_dir_flag) {
    options.image_dirs = args::get(image_dir_flag);
  }
  if (image_layout_flag) {
    auto parsed = w1replay::parse_image_layout_mode(*image_layout_flag);
    if (!parsed.has_value()) {
      log_main.err("invalid image layout mode", redlog::field("value", *image_layout_flag));
      std::cerr << "error: invalid --image-layout (use trace or lief)" << std::endl;
      g_exit_code = 1;
      return;
    }
    options.image_layout = *parsed;
  }

  g_exit_code = w1replay::commands::server(options);
}

int main(int argc, char* argv[]) {
  args::ArgumentParser parser("w1replay - rewind trace explorer", "inspect and replay rewind traces");
  parser.helpParams.showTerminator = false;

  args::GlobalOptions globals(parser, cli::arguments);
  args::Group commands(parser, "commands");

  args::Command inspect_cmd(commands, "inspect", "inspect a rewind trace", &cmd_inspect);
  args::Command threads_cmd(commands, "threads", "list threads in a rewind trace", &cmd_threads);
  args::Command summary_cmd(commands, "summary", "summarize a rewind trace", &cmd_summary);
  args::Command checkpoint_cmd(commands, "checkpoint", "build a replay checkpoint file", &cmd_checkpoint);
  args::Command server_cmd(commands, "server", "run gdbstub server for a rewind trace", &cmd_server);

  try {
    parser.ParseCLI(argc, argv);
  } catch (args::Help) {
    std::cout << parser;
    return 0;
  } catch (args::Error& e) {
    std::cerr << e.what() << std::endl << parser;
    return 1;
  }

  return g_exit_code;
}
