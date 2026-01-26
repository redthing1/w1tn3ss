#include "inspect.hpp"

#include <cstddef>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <sstream>

#include <redlog.hpp>

#include "w1replay/memory/memory_view.hpp"
#include "w1replay/modules/address_index.hpp"
#include "w1replay/modules/asmr_block_decoder.hpp"
#include "w1replay/modules/composite_image_provider.hpp"
#include "w1replay/modules/path_resolver.hpp"
#include "w1replay/trace_loader/trace_loader.hpp"
#include "w1rewind/replay/replay_session.hpp"

namespace w1replay::commands {

namespace {

std::string format_address(uint64_t address) {
  std::ostringstream out;
  out << "0x" << std::hex << address;
  return out.str();
}

std::string format_byte(std::byte value, bool known) {
  if (!known) {
    return "??";
  }
  std::ostringstream out;
  out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(std::to_integer<uint8_t>(value));
  return out.str();
}

std::string format_bytes(std::span<const std::byte> bytes) {
  std::ostringstream out;
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i > 0) {
      out << " ";
    }
    out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(std::to_integer<uint8_t>(bytes[i]));
  }
  return out.str();
}

void write_json_string(std::ostream& out, std::string_view value) {
  out << '"';
  for (unsigned char c : value) {
    switch (c) {
    case '"':
      out << "\\\"";
      break;
    case '\\':
      out << "\\\\";
      break;
    case '\b':
      out << "\\b";
      break;
    case '\f':
      out << "\\f";
      break;
    case '\n':
      out << "\\n";
      break;
    case '\r':
      out << "\\r";
      break;
    case '\t':
      out << "\\t";
      break;
    default:
      if (c < 0x20) {
        out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
      } else {
        out << static_cast<char>(c);
      }
      break;
    }
  }
  out << '"';
}

struct memory_query {
  uint64_t address = 0;
  size_t size = 0;
  std::optional<std::string> space;
};

std::optional<memory_query> parse_memory_query(const std::string& input, std::string& error) {
  if (input.empty()) {
    return std::nullopt;
  }
  auto first = input.find(':');
  if (first == std::string::npos) {
    error = "invalid --mem format (expected addr:size or space:addr:size)";
    return std::nullopt;
  }
  auto second = input.find(':', first + 1);
  std::string space_text;
  std::string addr_text;
  std::string size_text;
  if (second == std::string::npos) {
    addr_text = input.substr(0, first);
    size_text = input.substr(first + 1);
  } else if (input.find(':', second + 1) == std::string::npos) {
    space_text = input.substr(0, first);
    addr_text = input.substr(first + 1, second - first - 1);
    size_text = input.substr(second + 1);
  } else {
    error = "invalid --mem format (expected addr:size or space:addr:size)";
    return std::nullopt;
  }
  if (addr_text.empty() || size_text.empty()) {
    error = "invalid --mem format (expected addr:size or space:addr:size)";
    return std::nullopt;
  }
  if (!space_text.empty() && space_text.find_first_not_of(" \t") == std::string::npos) {
    error = "invalid --mem space selector";
    return std::nullopt;
  }
  try {
    uint64_t address = std::stoull(addr_text, nullptr, 0);
    uint64_t size = std::stoull(size_text, nullptr, 0);
    if (size == 0) {
      error = "--mem size must be > 0";
      return std::nullopt;
    }
    memory_query query{};
    query.address = address;
    query.size = static_cast<size_t>(size);
    if (!space_text.empty()) {
      query.space = space_text;
    }
    return query;
  } catch (const std::exception&) {
    error = "invalid --mem format (expected addr:size or space:addr:size)";
    return std::nullopt;
  }
}

std::optional<uint32_t> parse_space_id(std::string_view text) {
  try {
    size_t idx = 0;
    unsigned long value = std::stoul(std::string(text), &idx, 0);
    if (idx != text.size()) {
      return std::nullopt;
    }
    if (value > std::numeric_limits<uint32_t>::max()) {
      return std::nullopt;
    }
    return static_cast<uint32_t>(value);
  } catch (const std::exception&) {
    return std::nullopt;
  }
}

std::optional<uint32_t> resolve_space_id(
    const w1::rewind::replay_context& context, std::string_view selector, std::string& error
) {
  if (selector.empty()) {
    return 0;
  }
  if (auto parsed = parse_space_id(selector)) {
    return *parsed;
  }
  for (const auto& space : context.address_spaces) {
    if (space.name == selector) {
      return space.space_id;
    }
  }
  error = "unknown address space: " + std::string(selector);
  return std::nullopt;
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
  if (!options.memory_space.empty() && !mem_query.has_value()) {
    log.err("memory space requires --mem");
    std::cerr << "error: --space requires --mem" << std::endl;
    return 1;
  }
  if (mem_query.has_value() && mem_query->space.has_value() && !options.memory_space.empty()) {
    log.err("multiple memory space selectors provided");
    std::cerr << "error: specify space once via --space or mem prefix" << std::endl;
    return 1;
  }

  w1replay::trace_loader::trace_load_options load_options{};
  load_options.trace_path = options.trace_path;
  load_options.index_path = options.index_path;
  load_options.index_stride = options.index_stride;
  load_options.checkpoint_path = options.checkpoint_path;
  load_options.auto_build_checkpoint = false;

  w1replay::trace_loader::trace_load_result load_result;
  if (!w1replay::trace_loader::load_trace(load_options, load_result)) {
    log.err("failed to load trace", redlog::field("error", load_result.error));
    std::cerr << "error: " << load_result.error << std::endl;
    return 1;
  }

  w1::rewind::replay_session_config config{};
  config.stream = load_result.stream;
  config.index = load_result.index;
  config.checkpoint = load_result.checkpoint;
  config.context = load_result.context;
  config.history_size = options.history_size;
  config.track_registers = options.show_registers;
  config.track_memory = mem_query.has_value();
  config.strict_instructions = options.instruction_steps;
  config.thread_id = options.thread_id;
  config.start_sequence = options.start_sequence;

  std::optional<asmr_block_decoder> decoder;
  if (options.instruction_steps) {
    if (asmr_decoder_available()) {
      decoder.emplace();
      config.block_decoder = &*decoder;
    }
  }

  w1::rewind::replay_session session(config);
  if (!session.open()) {
    log.err("failed to open trace", redlog::field("error", session.error()));
    std::cerr << "error: " << session.error() << std::endl;
    return 1;
  }

  auto resolver = make_image_path_resolver(options.image_mappings, options.image_dirs);
  w1replay::image_address_index image_index(load_result.context, session.mappings());
  std::string layout_error;
  auto layout_provider = w1replay::make_layout_provider(options.image_layout, layout_error);
  if (!layout_error.empty()) {
    log.err("invalid image layout mode", redlog::field("error", layout_error));
    std::cerr << "error: " << layout_error << std::endl;
    return 1;
  }
  w1replay::composite_image_provider_config provider_config{};
  provider_config.context = &load_result.context;
  provider_config.resolver = resolver.get();
  provider_config.address_index = &image_index;
  provider_config.mapping_state = session.mappings();
  provider_config.layout_provider = std::move(layout_provider);
  w1replay::composite_image_provider provider(provider_config);

  w1replay::replay_memory_view memory_view(&session.context(), session.state(), &provider);
  if (decoder.has_value()) {
    decoder->set_memory_view(&memory_view);
  }

  uint32_t mem_space_id = 0;
  if (mem_query.has_value()) {
    std::string space_error;
    std::string_view selector{};
    if (mem_query->space.has_value()) {
      selector = *mem_query->space;
    } else if (!options.memory_space.empty()) {
      selector = options.memory_space;
    }
    if (!selector.empty()) {
      auto resolved = resolve_space_id(session.context(), selector, space_error);
      if (!resolved.has_value()) {
        log.err("invalid memory space", redlog::field("error", space_error));
        std::cerr << "error: " << space_error << std::endl;
        return 1;
      }
      mem_space_id = *resolved;
    }
  }

  struct register_value {
    std::string name;
    std::string value;
  };
  struct memory_dump {
    uint32_t space_id = 0;
    uint64_t address = 0;
    size_t size = 0;
    std::vector<std::optional<uint8_t>> bytes;
  };

  auto print_step = [&](const w1::rewind::flow_step& step, bool json, bool first) {
    std::string image_label = "?";
    uint64_t lookup_size = step.size == 0 ? 1 : step.size;
    auto match = image_index.find(step.address, lookup_size, step.space_id);
    if (match.has_value()) {
      const auto* mapping = match->mapping;
      const auto* image = match->image;
      if (image) {
        std::string resolved_path;
        if (resolver) {
          if (auto resolved = resolver->resolve_image_path(*image)) {
            resolved_path = *resolved;
          }
        }
        if (!resolved_path.empty()) {
          image_label = std::filesystem::path(resolved_path).filename().string();
        } else if (!image->name.empty()) {
          image_label = image->name;
        } else if (!image->identity.empty()) {
          image_label = image->identity;
        } else {
          image_label = format_address(mapping ? mapping->base : step.address);
        }
      } else if (mapping && !mapping->name.empty()) {
        if (resolver) {
          if (auto resolved = resolver->resolve_region_name(mapping->name)) {
            image_label = *resolved;
          } else {
            image_label = mapping->name;
          }
        } else {
          image_label = mapping->name;
        }
      } else if (mapping) {
        image_label = format_address(mapping->base);
      }

      if (match->image_offset != 0) {
        std::ostringstream with_offset;
        with_offset << image_label << "+0x" << std::hex << match->image_offset;
        image_label = with_offset.str();
      }
    }

    std::string space_label = std::to_string(step.space_id);
    if (auto* space = session.context().find_address_space(step.space_id)) {
      if (!space->name.empty()) {
        space_label = space->name;
      }
    }

    std::vector<register_value> reg_values;
    bool regs_available = false;
    if (options.show_registers) {
      const auto& names = session.register_names();
      const auto& specs = session.register_specs();
      auto regs = session.read_registers();
      if (!names.empty()) {
        for (size_t i = 0; i < names.size() && i < specs.size(); ++i) {
          const auto& spec = specs[i];
          size_t size = (spec.bit_size + 7u) / 8u;
          if (size == 0) {
            continue;
          }
          if (spec.bit_size <= 64 && i < regs.size() && regs[i].has_value()) {
            reg_values.push_back({names[i], format_address(*regs[i])});
            continue;
          }
          std::vector<std::byte> buffer(size);
          bool known = false;
          if (!session.read_register_bytes(static_cast<uint32_t>(i), buffer, known) || !known) {
            continue;
          }
          reg_values.push_back({names[i], format_bytes(buffer)});
        }
        regs_available = !reg_values.empty();
      }
    }

    std::optional<memory_dump> mem_dump;
    if (mem_query.has_value()) {
      auto bytes = memory_view.read(mem_space_id, mem_query->address, mem_query->size);
      memory_dump dump{};
      dump.space_id = mem_space_id;
      dump.address = mem_query->address;
      dump.size = mem_query->size;
      dump.bytes.reserve(bytes.bytes.size());
      for (size_t i = 0; i < bytes.bytes.size(); ++i) {
        bool known = i < bytes.known.size() && bytes.known[i] != 0;
        if (known) {
          dump.bytes.emplace_back(std::to_integer<uint8_t>(bytes.bytes[i]));
        } else {
          dump.bytes.emplace_back(std::nullopt);
        }
      }
      mem_dump = std::move(dump);
    }

    if (!json) {
      std::cout << "seq=" << step.sequence << " addr=" << format_address(step.address) << " space=" << space_label
                << " image=" << image_label << " kind=" << (step.is_block ? "block" : "instruction") << std::endl;

      if (options.show_registers) {
        if (!regs_available) {
          std::cout << "  regs: unknown" << std::endl;
        } else {
          std::ostringstream out;
          out << "  regs:";
          for (const auto& reg : reg_values) {
            out << " " << reg.name << "=" << reg.value;
          }
          std::cout << out.str() << std::endl;
        }
      }

      if (mem_dump.has_value()) {
        std::ostringstream out;
        std::string mem_space_label = std::to_string(mem_dump->space_id);
        if (auto* space = session.context().find_address_space(mem_dump->space_id)) {
          if (!space->name.empty()) {
            mem_space_label = space->name;
          }
        }
        out << "  mem[" << mem_space_label << ":" << format_address(mem_dump->address) << ":" << mem_dump->size
            << "]:";
        for (const auto& entry : mem_dump->bytes) {
          if (entry.has_value()) {
            out << " " << format_byte(static_cast<std::byte>(*entry), true);
          } else {
            out << " " << format_byte(std::byte{0}, false);
          }
        }
        std::cout << out.str() << std::endl;
      }
      return;
    }

    if (!first) {
      std::cout << ",";
    }
    std::cout << "{";
    std::cout << "\"seq\":" << step.sequence << ",";
    std::cout << "\"addr\":";
    write_json_string(std::cout, format_address(step.address));
    std::cout << ",";
    std::cout << "\"space_id\":" << step.space_id << ",";
    std::cout << "\"space\":";
    write_json_string(std::cout, space_label);
    std::cout << ",";
    std::cout << "\"image\":";
    write_json_string(std::cout, image_label);
    std::cout << ",";
    std::cout << "\"kind\":";
    write_json_string(std::cout, step.is_block ? "block" : "instruction");

    if (options.show_registers) {
      std::cout << ",\"regs\":{";
      for (size_t i = 0; i < reg_values.size(); ++i) {
        if (i > 0) {
          std::cout << ",";
        }
        write_json_string(std::cout, reg_values[i].name);
        std::cout << ":";
        write_json_string(std::cout, reg_values[i].value);
      }
      std::cout << "}";
    }

    if (mem_dump.has_value()) {
      std::cout << ",\"mem\":{";
      std::cout << "\"space_id\":" << mem_dump->space_id << ",";
      std::cout << "\"space\":";
      std::string mem_space_label = std::to_string(mem_dump->space_id);
      if (auto* space = session.context().find_address_space(mem_dump->space_id)) {
        if (!space->name.empty()) {
          mem_space_label = space->name;
        }
      }
      write_json_string(std::cout, mem_space_label);
      std::cout << ",";
      std::cout << "\"addr\":";
      write_json_string(std::cout, format_address(mem_dump->address));
      std::cout << ",";
      std::cout << "\"size\":" << mem_dump->size << ",";
      std::cout << "\"bytes\":[";
      for (size_t i = 0; i < mem_dump->bytes.size(); ++i) {
        if (i > 0) {
          std::cout << ",";
        }
        if (!mem_dump->bytes[i].has_value()) {
          std::cout << "null";
        } else {
          std::ostringstream byte_hex;
          byte_hex << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<int>(*mem_dump->bytes[i]);
          write_json_string(std::cout, byte_hex.str());
        }
      }
      std::cout << "]}";
    }

    std::cout << "}";
  };

  if (options.count == 0) {
    if (options.json_output) {
      std::cout << "{\"steps\":[]}" << std::endl;
    }
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

  bool json = options.json_output;
  bool first = true;
  auto emit_step = [&](const w1::rewind::flow_step& current) {
    print_step(current, json, first);
    if (json) {
      first = false;
    }
  };
  auto finish_json = [&]() {
    if (json) {
      std::cout << "]}" << std::endl;
    }
  };

  if (json) {
    std::cout << "{\"steps\":[";
  }

  if (options.reverse) {
    if (options.instruction_steps) {
      if (!session.step_flow()) {
        log.err("failed to read step", redlog::field("error", session.error()));
        std::cerr << "error: " << session.error() << std::endl;
        finish_json();
        return 1;
      }
      step = session.current_step();
      if (!step.is_block) {
        emit_step(step);
        emit_notice();
        for (uint32_t i = 1; i < options.count; ++i) {
          if (!session.step_instruction_backward()) {
            log.err("failed to step backward", redlog::field("error", session.error()));
            std::cerr << "error: " << session.error() << std::endl;
            finish_json();
            return 1;
          }
          step = session.current_step();
          emit_step(step);
          emit_notice();
        }
        finish_json();
        return 0;
      }

      if (!session.step_instruction_backward()) {
        log.err("failed to step backward", redlog::field("error", session.error()));
        std::cerr << "error: " << session.error() << std::endl;
        finish_json();
        return 1;
      }
      step = session.current_step();
      emit_step(step);
      emit_notice();
      for (uint32_t i = 1; i < options.count; ++i) {
        if (!session.step_instruction_backward()) {
          log.err("failed to step backward", redlog::field("error", session.error()));
          std::cerr << "error: " << session.error() << std::endl;
          finish_json();
          return 1;
        }
        step = session.current_step();
        emit_step(step);
        emit_notice();
      }
      finish_json();
      return 0;
    }

    if (!session.step_flow()) {
      log.err("failed to read step", redlog::field("error", session.error()));
      std::cerr << "error: " << session.error() << std::endl;
      finish_json();
      return 1;
    }
    step = session.current_step();
    emit_step(step);
    emit_notice();
    for (uint32_t i = 1; i < options.count; ++i) {
      if (!session.step_backward()) {
        log.err("failed to step backward", redlog::field("error", session.error()));
        std::cerr << "error: " << session.error() << std::endl;
        finish_json();
        return 1;
      }
      step = session.current_step();
      emit_step(step);
      emit_notice();
    }
    finish_json();
    return 0;
  }

  for (uint32_t i = 0; i < options.count; ++i) {
    bool ok = options.instruction_steps ? session.step_instruction() : session.step_flow();
    if (!ok) {
      log.err("failed to read step", redlog::field("error", session.error()));
      std::cerr << "error: " << session.error() << std::endl;
      finish_json();
      return 1;
    }
    step = session.current_step();
    emit_step(step);
    emit_notice();
  }

  finish_json();
  return 0;
}

} // namespace w1replay::commands
