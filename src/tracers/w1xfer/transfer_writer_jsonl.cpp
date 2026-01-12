#include "transfer_writer_jsonl.hpp"

#include <sstream>
#include <string_view>

namespace w1xfer {
namespace {

void append_field(std::stringstream& json, bool& first, const std::string& field) {
  if (!first) {
    json << ",";
  }
  json << field;
  first = false;
}

std::string escape(std::string_view value) {
  std::string out;
  out.reserve(value.size());
  for (char ch : value) {
    switch (ch) {
    case '"':
      out += "\\\"";
      break;
    case '\\':
      out += "\\\\";
      break;
    case '\b':
      out += "\\b";
      break;
    case '\f':
      out += "\\f";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default: {
      unsigned char uch = static_cast<unsigned char>(ch);
      if (uch < 0x20) {
        constexpr char hex[] = "0123456789abcdef";
        out += "\\u00";
        out += hex[(uch >> 4) & 0xF];
        out += hex[uch & 0xF];
      } else {
        out += ch;
      }
      break;
    }
    }
  }
  return out;
}

} // namespace

transfer_writer_jsonl::transfer_writer_jsonl(const std::string& output_path, bool emit_metadata)
    : emit_metadata_(emit_metadata) {
  if (!output_path.empty()) {
    writer_ = std::make_unique<w1::io::jsonl_writer>(output_path);
    if (!writer_->is_open()) {
      writer_.reset();
    }
  }
}

bool transfer_writer_jsonl::is_open() const { return writer_ && writer_->is_open(); }

void transfer_writer_jsonl::ensure_metadata(const w1::runtime::module_registry& modules) {
  if (!emit_metadata_ || metadata_written_ || !is_open()) {
    return;
  }

  write_metadata(modules);
  metadata_written_ = true;
}

void transfer_writer_jsonl::write_record(const transfer_record& record) {
  if (!is_open()) {
    return;
  }

  write_event(record);
}

void transfer_writer_jsonl::write_metadata(const w1::runtime::module_registry& modules) {
  if (!is_open()) {
    return;
  }

  std::stringstream json;
  json << "{\"type\":\"metadata\",\"tracer\":\"w1xfer\",\"version\":2";
  json << ",\"modules\":[";

  bool first = true;
  size_t module_id = 0;
  for (const auto& mod : modules.list_modules()) {
    if (!first) {
      json << ",";
    }
    first = false;

    json << "{\"id\":" << module_id++ << ",\"name\":\"" << escape(mod.name) << "\""
         << ",\"path\":\"" << escape(mod.path) << "\""
         << ",\"base\":" << mod.base_address << ",\"size\":" << mod.size
         << ",\"is_system\":" << (mod.is_system ? "true" : "false") << "}";
  }

  json << "]}";
  writer_->write_line(json.str());
}

void transfer_writer_jsonl::write_event(const transfer_record& record) {
  std::stringstream json;
  json << "{\"type\":\"event\"";
  json << ",\"event\":\"" << (record.event.type == transfer_type::CALL ? "call" : "return") << "\"";
  json << ",\"source_address\":" << record.event.source_address;
  json << ",\"target_address\":" << record.event.target_address;
  json << ",\"instruction_index\":" << record.event.instruction_index;
  json << ",\"timestamp\":" << record.event.timestamp;
  json << ",\"thread_id\":" << record.event.thread_id;
  json << ",\"call_depth\":" << record.event.call_depth;

  bool first = false;

  if (record.source) {
    std::stringstream src_json;
    src_json << "{";
    bool src_first = true;
    if (!record.source->module_name.empty()) {
      append_field(src_json, src_first, "\"module\":\"" + escape(record.source->module_name) + "\"");
      append_field(src_json, src_first, "\"module_offset\":" + std::to_string(record.source->module_offset));
    }
    if (record.source->symbol && !record.source->symbol->symbol_name.empty()) {
      std::stringstream sym_json;
      sym_json << "{";
      bool sym_first = true;
      append_field(sym_json, sym_first, "\"name\":\"" + escape(record.source->symbol->symbol_name) + "\"");
      if (!record.source->symbol->demangled_name.empty()) {
        append_field(sym_json, sym_first, "\"demangled\":\"" + escape(record.source->symbol->demangled_name) + "\"");
      }
      append_field(sym_json, sym_first, "\"symbol_offset\":" + std::to_string(record.source->symbol->symbol_offset));
      append_field(sym_json, sym_first, "\"module_offset\":" + std::to_string(record.source->symbol->module_offset));
      append_field(
          sym_json, sym_first, "\"is_exported\":" + std::string(record.source->symbol->is_exported ? "true" : "false")
      );
      append_field(
          sym_json, sym_first, "\"is_imported\":" + std::string(record.source->symbol->is_imported ? "true" : "false")
      );
      sym_json << "}";
      append_field(src_json, src_first, "\"symbol\":" + sym_json.str());
    }
    src_json << "}";
    append_field(json, first, "\"source\":" + src_json.str());
  }

  if (record.target) {
    std::stringstream tgt_json;
    tgt_json << "{";
    bool tgt_first = true;
    if (!record.target->module_name.empty()) {
      append_field(tgt_json, tgt_first, "\"module\":\"" + escape(record.target->module_name) + "\"");
      append_field(tgt_json, tgt_first, "\"module_offset\":" + std::to_string(record.target->module_offset));
    }
    if (record.target->symbol && !record.target->symbol->symbol_name.empty()) {
      std::stringstream sym_json;
      sym_json << "{";
      bool sym_first = true;
      append_field(sym_json, sym_first, "\"name\":\"" + escape(record.target->symbol->symbol_name) + "\"");
      if (!record.target->symbol->demangled_name.empty()) {
        append_field(sym_json, sym_first, "\"demangled\":\"" + escape(record.target->symbol->demangled_name) + "\"");
      }
      append_field(sym_json, sym_first, "\"symbol_offset\":" + std::to_string(record.target->symbol->symbol_offset));
      append_field(sym_json, sym_first, "\"module_offset\":" + std::to_string(record.target->symbol->module_offset));
      append_field(
          sym_json, sym_first, "\"is_exported\":" + std::string(record.target->symbol->is_exported ? "true" : "false")
      );
      append_field(
          sym_json, sym_first, "\"is_imported\":" + std::string(record.target->symbol->is_imported ? "true" : "false")
      );
      sym_json << "}";
      append_field(tgt_json, tgt_first, "\"symbol\":" + sym_json.str());
    }
    tgt_json << "}";
    append_field(json, first, "\"target\":" + tgt_json.str());
  }

  if (record.registers && !record.registers->values.empty()) {
    std::stringstream regs_json;
    regs_json << "{";
    bool reg_first = true;
    for (const auto& [name, value] : record.registers->values) {
      if (!reg_first) {
        regs_json << ",";
      }
      regs_json << "\"" << escape(name) << "\":" << value;
      reg_first = false;
    }
    regs_json << "}";
    append_field(json, first, "\"registers\":" + regs_json.str());
  }

  if (record.stack) {
    std::stringstream stack_json;
    stack_json << "{";
    bool stack_first = true;
    append_field(stack_json, stack_first, "\"stack_pointer\":" + std::to_string(record.stack->stack_pointer));
    append_field(stack_json, stack_first, "\"frame_pointer\":" + std::to_string(record.stack->frame_pointer));
    append_field(stack_json, stack_first, "\"return_address\":" + std::to_string(record.stack->return_address));

    std::stringstream values_json;
    values_json << "[";
    for (size_t i = 0; i < record.stack->values.size(); ++i) {
      if (i > 0) {
        values_json << ",";
      }
      values_json << record.stack->values[i];
    }
    values_json << "]";

    append_field(stack_json, stack_first, "\"values\":" + values_json.str());
    stack_json << "}";
    append_field(json, first, "\"stack\":" + stack_json.str());
  }

  if (record.api) {
    std::stringstream api_json;
    api_json << "{";
    bool api_first = true;

    if (!record.api->category.empty()) {
      append_field(api_json, api_first, "\"category\":\"" + escape(record.api->category) + "\"");
    }
    if (!record.api->description.empty()) {
      append_field(api_json, api_first, "\"description\":\"" + escape(record.api->description) + "\"");
    }
    if (!record.api->formatted_call.empty()) {
      append_field(api_json, api_first, "\"formatted_call\":\"" + escape(record.api->formatted_call) + "\"");
    }

    append_field(
        api_json, api_first, "\"analysis_complete\":" + std::string(record.api->analysis_complete ? "true" : "false")
    );
    append_field(
        api_json, api_first, "\"has_return_value\":" + std::string(record.api->has_return_value ? "true" : "false")
    );

    if (!record.api->arguments.empty()) {
      std::stringstream args_json;
      args_json << "[";
      for (size_t i = 0; i < record.api->arguments.size(); ++i) {
        if (i > 0) {
          args_json << ",";
        }
        const auto& arg = record.api->arguments[i];
        args_json << "{\"name\":\"" << escape(arg.name) << "\""
                  << ",\"type\":\"" << escape(arg.type) << "\""
                  << ",\"raw_value\":" << arg.raw_value << ",\"interpreted_value\":\"" << escape(arg.interpreted_value)
                  << "\""
                  << ",\"is_pointer\":" << (arg.is_pointer ? "true" : "false") << "}";
      }
      args_json << "]";
      append_field(api_json, api_first, "\"arguments\":" + args_json.str());
    }

    if (record.api->return_value) {
      const auto& ret = record.api->return_value.value();
      std::stringstream ret_json;
      ret_json << "{\"type\":\"" << escape(ret.type) << "\""
               << ",\"raw_value\":" << ret.raw_value << ",\"interpreted_value\":\"" << escape(ret.interpreted_value)
               << "\""
               << ",\"is_pointer\":" << (ret.is_pointer ? "true" : "false")
               << ",\"is_null\":" << (ret.is_null ? "true" : "false") << "}";
      append_field(api_json, api_first, "\"return_value\":" + ret_json.str());
    }

    api_json << "}";
    append_field(json, first, "\"api\":" + api_json.str());
  }

  json << "}";
  writer_->write_line(json.str());
}

} // namespace w1xfer
