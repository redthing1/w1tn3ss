#include "inspect.hpp"

#include <filesystem>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>

#include <redlog.hpp>

#include "w1tn3ss/runtime/rewind/replay_cursor.hpp"
#include "w1tn3ss/runtime/rewind/trace_index.hpp"

namespace w1replay::commands {

namespace {

std::string format_address(uint64_t address) {
  std::ostringstream out;
  out << "0x" << std::hex << address;
  return out.str();
}

std::string format_byte(std::optional<uint8_t> byte) {
  if (!byte.has_value()) {
    return "??";
  }
  std::ostringstream out;
  out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*byte);
  return out.str();
}

struct memory_query {
  uint64_t address = 0;
  size_t size = 0;
};

std::optional<memory_query> parse_memory_query(const std::string& input, std::string& error) {
  if (input.empty()) {
    return std::nullopt;
  }
  auto sep = input.find(':');
  if (sep == std::string::npos) {
    error = "invalid --mem format (expected addr:size)";
    return std::nullopt;
  }
  auto addr_text = input.substr(0, sep);
  auto size_text = input.substr(sep + 1);
  if (addr_text.empty() || size_text.empty()) {
    error = "invalid --mem format (expected addr:size)";
    return std::nullopt;
  }
  try {
    uint64_t address = std::stoull(addr_text, nullptr, 0);
    uint64_t size = std::stoull(size_text, nullptr, 0);
    if (size == 0) {
      error = "--mem size must be > 0";
      return std::nullopt;
    }
    return memory_query{address, static_cast<size_t>(size)};
  } catch (const std::exception&) {
    error = "invalid --mem format (expected addr:size)";
    return std::nullopt;
  }
}

} // namespace

int inspect(const inspect_options& options) {
  auto log = redlog::get_logger("w1replay.inspect");

  if (options.trace_path.empty()) {
    log.err("trace path required");
    std::cerr << "error: --trace is required" << std::endl;
    return 1;
  }
  if (options.thread_id == 0) {
    log.err("thread id required");
    std::cerr << "error: --thread is required" << std::endl;
    return 1;
  }

  std::string index_path = options.index_path;
  if (index_path.empty()) {
    index_path = w1::rewind::default_trace_index_path(options.trace_path);
    if (!std::filesystem::exists(index_path)) {
      log.inf("building trace index", redlog::field("index", index_path));
      w1::rewind::trace_index_options index_options;
      w1::rewind::trace_index built;
      if (!w1::rewind::build_trace_index(
              options.trace_path, index_path, index_options, &built, log
          )) {
        std::cerr << "error: failed to build trace index" << std::endl;
        return 1;
      }
    }
  }

  std::string mem_error;
  auto mem_query = parse_memory_query(options.memory_range, mem_error);
  if (!mem_error.empty()) {
    log.err("invalid memory range", redlog::field("error", mem_error));
    std::cerr << "error: " << mem_error << std::endl;
    return 1;
  }

  w1::rewind::replay_cursor_config config{};
  config.trace_path = options.trace_path;
  config.index_path = index_path;
  config.history_size = options.history_size;
  config.track_registers = options.show_registers;
  config.track_memory = mem_query.has_value();

  w1::rewind::replay_cursor cursor(config);
  if (!cursor.open()) {
    log.err("failed to open trace", redlog::field("error", cursor.error()));
    std::cerr << "error: " << cursor.error() << std::endl;
    return 1;
  }

  if (!cursor.seek(options.thread_id, options.start_sequence)) {
    log.err("failed to seek", redlog::field("error", cursor.error()));
    std::cerr << "error: " << cursor.error() << std::endl;
    return 1;
  }

  auto print_step = [&](const w1::rewind::flow_step& step) {
    std::cout << "seq=" << step.sequence << " addr=" << format_address(step.address)
              << " module=" << step.module_id << " kind=" << (step.is_block ? "block" : "instruction")
              << std::endl;

    if (options.show_registers) {
      const auto* state = cursor.state();
      const auto& names = cursor.register_names();
      if (!state || names.empty()) {
        std::cout << "  regs: unavailable" << std::endl;
      } else {
        bool wrote_any = false;
        std::ostringstream out;
        out << "  regs:";
        const auto& regs = state->registers();
        for (size_t i = 0; i < names.size() && i < regs.size(); ++i) {
          if (!regs[i].has_value()) {
            continue;
          }
          out << " " << names[i] << "=" << format_address(*regs[i]);
          wrote_any = true;
        }
        if (!wrote_any) {
          out << " unknown";
        }
        std::cout << out.str() << std::endl;
      }
    }

    if (mem_query.has_value()) {
      const auto* state = cursor.state();
      if (!state) {
        std::cout << "  mem: unavailable" << std::endl;
      } else {
        auto bytes = state->read_memory(mem_query->address, mem_query->size);
        std::ostringstream out;
        out << "  mem[" << format_address(mem_query->address) << ":" << mem_query->size << "]:";
        for (const auto& byte : bytes) {
          out << " " << format_byte(byte);
        }
        std::cout << out.str() << std::endl;
      }
    }
  };

  if (options.count == 0) {
    return 0;
  }

  w1::rewind::flow_step step{};
  if (options.reverse) {
    if (!cursor.step_forward(step)) {
      log.err("failed to read step", redlog::field("error", cursor.error()));
      std::cerr << "error: " << cursor.error() << std::endl;
      return 1;
    }
    print_step(step);
    for (uint32_t i = 1; i < options.count; ++i) {
      if (!cursor.step_backward(step)) {
        log.err("failed to step backward", redlog::field("error", cursor.error()));
        std::cerr << "error: " << cursor.error() << std::endl;
        return 1;
      }
      print_step(step);
    }
    return 0;
  }

  for (uint32_t i = 0; i < options.count; ++i) {
    if (!cursor.step_forward(step)) {
      log.err("failed to read step", redlog::field("error", cursor.error()));
      std::cerr << "error: " << cursor.error() << std::endl;
      return 1;
    }
    print_step(step);
  }

  return 0;
}

} // namespace w1replay::commands
