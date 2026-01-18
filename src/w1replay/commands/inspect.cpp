#include "inspect.hpp"

#include <filesystem>
#include <iomanip>
#include <iostream>
#include <optional>
#include <span>
#include <sstream>

#include <redlog.hpp>

#include "asmr_block_decoder.hpp"
#include "module_source.hpp"
#include "w1rewind/replay/replay_session.hpp"

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

std::string format_bytes(std::span<const std::byte> bytes) {
  std::ostringstream out;
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i > 0) {
      out << " ";
    }
    out << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(std::to_integer<uint8_t>(bytes[i]));
  }
  return out.str();
}

const w1::rewind::module_record* find_module_for_address(
    const std::vector<w1::rewind::module_record>& modules,
    uint64_t address,
    uint64_t size,
    uint64_t& module_offset
) {
  if (size == 0) {
    return nullptr;
  }

  for (const auto& module : modules) {
    if (address < module.base) {
      continue;
    }
    uint64_t offset = address - module.base;
    if (module.size < size) {
      continue;
    }
    if (offset > module.size - size) {
      continue;
    }
    module_offset = offset;
    return &module;
  }
  return nullptr;
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

  std::string mem_error;
  auto mem_query = parse_memory_query(options.memory_range, mem_error);
  if (!mem_error.empty()) {
    log.err("invalid memory range", redlog::field("error", mem_error));
    std::cerr << "error: " << mem_error << std::endl;
    return 1;
  }

  module_source source;
  source.configure(options.module_mappings, options.module_dirs);

  w1::rewind::replay_session_config config{};
  config.trace_path = options.trace_path;
  config.index_path = options.index_path;
  config.history_size = options.history_size;
  config.track_registers = options.show_registers;
  config.track_memory = mem_query.has_value();
  config.thread_id = options.thread_id;
  config.start_sequence = options.start_sequence;
  config.checkpoint_path = options.checkpoint_path;
  if (!options.module_mappings.empty() || !options.module_dirs.empty()) {
    auto* module_source_ptr = &source;
    config.context_hook = [module_source_ptr](w1::rewind::replay_context& context) {
      module_source_ptr->apply_to_context(context);
    };
  }

  std::optional<asmr_block_decoder> decoder;
  if (options.instruction_steps) {
    if (asmr_decoder_available()) {
      decoder.emplace();
      decoder->set_code_source(&source);
      config.block_decoder = &*decoder;
    }
  }

  w1::rewind::replay_session session(config);
  if (!session.open()) {
    log.err("failed to open trace", redlog::field("error", session.error()));
    std::cerr << "error: " << session.error() << std::endl;
    return 1;
  }

  auto print_step = [&](const w1::rewind::flow_step& step) {
    uint64_t module_offset = 0;
    std::string module_label = "?";
    if (auto* module = find_module_for_address(session.modules(), step.address, step.size, module_offset)) {
      if (!module->path.empty()) {
        module_label = std::filesystem::path(module->path).filename().string();
      } else {
        module_label = format_address(module->base);
      }
      if (module_offset != 0) {
        std::ostringstream with_offset;
        with_offset << module_label << "+0x" << std::hex << module_offset;
        module_label = with_offset.str();
      }
    }

    std::cout << "seq=" << step.sequence << " addr=" << format_address(step.address)
              << " module=" << module_label << " kind=" << (step.is_block ? "block" : "instruction") << std::endl;

    if (options.show_registers) {
      const auto& names = session.register_names();
      const auto& specs = session.register_specs();
      auto regs = session.read_registers();
      if (names.empty()) {
        std::cout << "  regs: unavailable" << std::endl;
      } else {
        bool wrote_any = false;
        std::ostringstream out;
        out << "  regs:";
        for (size_t i = 0; i < names.size() && i < specs.size(); ++i) {
          const auto& spec = specs[i];
          if (spec.value_kind == w1::rewind::register_value_kind::bytes) {
            size_t size = (spec.bits + 7u) / 8u;
            std::vector<std::byte> buffer(size);
            bool known = false;
            if (!session.read_register_bytes(static_cast<uint16_t>(i), buffer, known) || !known) {
              continue;
            }
            out << " " << names[i] << "=" << format_bytes(buffer);
            wrote_any = true;
            continue;
          }

          if (i >= regs.size() || !regs[i].has_value()) {
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
      auto bytes = session.read_memory(mem_query->address, mem_query->size);
      std::ostringstream out;
      out << "  mem[" << format_address(mem_query->address) << ":" << mem_query->size << "]:";
      for (const auto& byte : bytes) {
        out << " " << format_byte(byte);
      }
      std::cout << out.str() << std::endl;
    }
  };

  if (options.count == 0) {
    return 0;
  }

  w1::rewind::flow_step step{};
  auto emit_notice = [&]() {
    auto notice = session.take_notice();
    if (!notice.has_value()) {
      return;
    }
    log.warn("replay notice", redlog::field("message", notice->message));
    std::cerr << "warning: " << notice->message << std::endl;
  };

  if (options.reverse) {
    if (options.instruction_steps) {
      if (!session.step_flow()) {
        log.err("failed to read step", redlog::field("error", session.error()));
        std::cerr << "error: " << session.error() << std::endl;
        return 1;
      }
      step = session.current_step();
      if (!step.is_block) {
        print_step(step);
        emit_notice();
        for (uint32_t i = 1; i < options.count; ++i) {
          if (!session.step_instruction_backward()) {
            log.err("failed to step backward", redlog::field("error", session.error()));
            std::cerr << "error: " << session.error() << std::endl;
            return 1;
          }
          step = session.current_step();
          print_step(step);
          emit_notice();
        }
        return 0;
      }

      if (!session.step_instruction_backward()) {
        log.err("failed to step backward", redlog::field("error", session.error()));
        std::cerr << "error: " << session.error() << std::endl;
        return 1;
      }
      step = session.current_step();
      print_step(step);
      emit_notice();
      for (uint32_t i = 1; i < options.count; ++i) {
        if (!session.step_instruction_backward()) {
          log.err("failed to step backward", redlog::field("error", session.error()));
          std::cerr << "error: " << session.error() << std::endl;
          return 1;
        }
        step = session.current_step();
        print_step(step);
        emit_notice();
      }
      return 0;
    }

    if (!session.step_flow()) {
      log.err("failed to read step", redlog::field("error", session.error()));
      std::cerr << "error: " << session.error() << std::endl;
      return 1;
    }
    step = session.current_step();
    print_step(step);
    emit_notice();
    for (uint32_t i = 1; i < options.count; ++i) {
      if (!session.step_backward()) {
        log.err("failed to step backward", redlog::field("error", session.error()));
        std::cerr << "error: " << session.error() << std::endl;
        return 1;
      }
      step = session.current_step();
      print_step(step);
      emit_notice();
    }
    return 0;
  }

  for (uint32_t i = 0; i < options.count; ++i) {
    bool ok = options.instruction_steps ? session.step_instruction() : session.step_flow();
    if (!ok) {
      log.err("failed to read step", redlog::field("error", session.error()));
      std::cerr << "error: " << session.error() << std::endl;
      return 1;
    }
    step = session.current_step();
    print_step(step);
    emit_notice();
  }

  return 0;
}

} // namespace w1replay::commands
