#include "argument_extractor.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <unordered_map>

namespace w1::abi {

class argument_extractor::impl {
public:
  impl(
      std::shared_ptr<api_knowledge_db> api_db, std::shared_ptr<calling_convention_detector> detector,
      const extractor_config& config
  )
      : api_db_(api_db), detector_(detector), config_(config), log_("w1::abi::argument_extractor") {

    if (!detector_) {
      detector_ = std::make_shared<calling_convention_detector>();
    }
    log_.debug("initialized argument extractor with detector");
  }

  impl(
      std::shared_ptr<calling_convention_base> convention, std::shared_ptr<api_knowledge_db> api_db,
      const extractor_config& config
  )
      : default_convention_(convention), api_db_(api_db), config_(config), log_("w1::abi::argument_extractor") {
    log_.debug("initialized argument extractor with fixed convention");
  }

  extracted_call_info extract_call(
      const std::string& api_name, const std::string& module_name, const util::safe_memory_reader& memory,
      const call_context& ctx
  ) const {
    // determine calling convention
    calling_convention_ptr convention;

    if (default_convention_) {
      convention = default_convention_;
    } else {
      // try to get from cache first
      std::string cache_key = module_name + "::" + api_name;
      auto it = convention_cache_.find(cache_key);
      if (it != convention_cache_.end()) {
        convention = it->second;
      } else {
        // detect convention
        convention = detector_->detect(module_name, api_name);
        convention_cache_[cache_key] = convention;
      }
    }

    return extract_call_with_convention(api_name, module_name, convention, memory, ctx);
  }

  extracted_call_info extract_call_with_convention(
      const std::string& api_name, const std::string& module_name, calling_convention_ptr convention,
      const util::safe_memory_reader& memory, const call_context& ctx
  ) const {
    log_.debug(
        "extracting call arguments", redlog::field("api", api_name), redlog::field("module", module_name),
        redlog::field("convention", convention->get_name())
    );

    extracted_call_info info;
    info.api_name = api_name;
    info.module_name = module_name;
    info.timestamp = 0; // todo: add timestamp to context
    info.call_address = ctx.call_address;
    info.return_address = 0; // todo: calculate return address

    // create extraction context
    calling_convention_base::extraction_context extract_ctx{ctx.gpr, ctx.fpr, [&memory](uint64_t addr) -> uint64_t {
                                                              auto val = memory.read<uint64_t>(addr);
                                                              return val.value_or(0);
                                                            }};

    // look up api info
    auto api_info = api_db_->lookup(module_name, api_name);
    if (!api_info) {
      // try without module
      api_info = api_db_->lookup(api_name);
    }

    if (api_info) {
      log_.debug(
          "found api info", redlog::field("api", api_name), redlog::field("params", api_info->parameters.size()),
          redlog::field("category", static_cast<int>(api_info->api_category))
      );

      info.category = api_info->api_category;
      info.behavior_flags = api_info->flags;
      info.description = api_info->description;

      // extract raw arguments
      auto raw_args = convention->extract_integer_args(extract_ctx, api_info->parameters.size());

      // extract each parameter
      for (size_t i = 0; i < api_info->parameters.size(); ++i) {
        const auto& param = api_info->parameters[i];
        uint64_t raw_value = i < raw_args.size() ? raw_args[i] : 0;

        log_.debug(
            "extracting parameter", redlog::field("index", i), redlog::field("name", param.name),
            redlog::field("type", static_cast<int>(param.param_type)), redlog::field("raw_value", raw_value)
        );

        auto arg = extract_argument(param, raw_value, memory);
        info.arguments.push_back(std::move(arg));
      }
    } else {
      log_.debug("no api info found, extracting raw arguments", redlog::field("api", api_name));

      // extract raw arguments without semantic info
      size_t max_args = 6; // reasonable default
      auto raw_args = convention->extract_integer_args(extract_ctx, max_args);

      for (size_t i = 0; i < raw_args.size(); ++i) {
        if (raw_args[i] == 0 && i > 2) {
          break; // heuristic
        }

        param_info generic_param;
        generic_param.name = "arg" + std::to_string(i);
        generic_param.param_type = param_info::type::UNKNOWN;

        auto arg = extract_argument(generic_param, raw_args[i], memory);
        info.arguments.push_back(std::move(arg));
      }
    }

    return info;
  }

  void extract_return_value(
      extracted_call_info& call_info, const util::safe_memory_reader& memory, const call_context& ctx
  ) const {
    log_.debug("extracting return value", redlog::field("api", call_info.api_name));

    // determine convention
    calling_convention_ptr convention;
    if (default_convention_) {
      convention = default_convention_;
    } else {
      std::string cache_key = call_info.module_name + "::" + call_info.api_name;
      auto it = convention_cache_.find(cache_key);
      if (it != convention_cache_.end()) {
        convention = it->second;
      } else {
        convention = detector_->detect(call_info.module_name, call_info.api_name);
      }
    }

    uint64_t ret_val = convention->get_integer_return(ctx.gpr);

    // look up api info for return type
    auto api_info = api_db_->lookup(call_info.module_name, call_info.api_name);
    if (!api_info) {
      api_info = api_db_->lookup(call_info.api_name);
    }

    if (api_info && api_info->return_value.param_type != param_info::type::VOID) {
      call_info.return_value = extract_argument(api_info->return_value, ret_val, memory);
    } else {
      // generic return value
      param_info generic_ret;
      generic_ret.name = "return";
      generic_ret.param_type = param_info::type::UNKNOWN;
      call_info.return_value = extract_argument(generic_ret, ret_val, memory);
    }
  }

  extracted_argument extract_argument(
      const param_info& param, uint64_t raw_value, const util::safe_memory_reader& memory
  ) const {
    extracted_argument arg;
    arg.raw_value = raw_value;
    arg.param_name = param.name;
    arg.param_type = param.param_type;
    arg.type_description = param.type_description;

    // check for null pointer
    if (param.param_type == param_info::type::POINTER || param.param_type == param_info::type::STRING ||
        param.param_type == param_info::type::BUFFER) {
      arg.is_null_pointer = (raw_value == 0);
      arg.is_valid_pointer = arg_utils::is_valid_pointer(raw_value, memory);
    }

    // interpret based on type
    switch (param.param_type) {
    case param_info::type::INTEGER:
      arg.interpreted_value = static_cast<int64_t>(raw_value);
      break;

    case param_info::type::UNSIGNED:
      arg.interpreted_value = raw_value;
      break;

    case param_info::type::BOOLEAN:
      arg.interpreted_value = (raw_value != 0);
      break;

    case param_info::type::SIZE:
      arg.interpreted_value = raw_value;
      break;

    case param_info::type::POINTER:
      if (!arg.is_null_pointer && config_.follow_pointers) {
        // try to read string preview
        auto str = arg_utils::read_string(raw_value, memory, 64);
        if (str) {
          arg.string_preview = *str;
        }
      }
      break;

    case param_info::type::STRING:
      if (!arg.is_null_pointer && config_.follow_pointers) {
        auto str = arg_utils::read_string(raw_value, memory, config_.max_string_length);
        if (str) {
          arg.interpreted_value = *str;
          arg.string_preview = *str;
        }
      }
      break;

    case param_info::type::WSTRING:
      if (!arg.is_null_pointer && config_.follow_pointers) {
        auto str = arg_utils::read_wide_string(raw_value, memory, config_.max_string_length);
        if (str) {
          arg.interpreted_value = *str;
          arg.string_preview = *str;
        }
      }
      break;

    case param_info::type::BUFFER:
      if (!arg.is_null_pointer && config_.follow_pointers) {
        // read buffer preview
        auto buffer_result = memory.read_buffer(raw_value, std::min(config_.max_buffer_preview, size_t(256)));
        if (buffer_result) {
          arg.buffer_preview = std::move(buffer_result->data);
          arg.buffer_size = param.buffer_size; // if known
        }
      }
      break;

    case param_info::type::FLAGS:
      arg.interpreted_value = raw_value;
      if (config_.decode_flags && !param.flag_values.empty()) {
        for (const auto& [flag_val, flag_name] : param.flag_values) {
          if (raw_value & flag_val) {
            arg.flag_names.push_back(flag_name);
          }
        }
      }
      break;

    case param_info::type::HANDLE:
    case param_info::type::FILE_DESCRIPTOR:
      arg.interpreted_value = raw_value;
      break;

    case param_info::type::FLOAT: {
      float f = *reinterpret_cast<float*>(&raw_value);
      arg.interpreted_value = static_cast<double>(f);
    } break;

    case param_info::type::DOUBLE:
      arg.interpreted_value = *reinterpret_cast<double*>(&raw_value);
      break;

    default:
      // keep as raw value
      break;
    }

    return arg;
  }

  std::string format_call(const extracted_call_info& call) const {
    std::ostringstream oss;

    // format: module!api(arg1, arg2, ...) = return_value
    if (!call.module_name.empty()) {
      oss << call.module_name << "!";
    }
    oss << call.api_name << "(";

    for (size_t i = 0; i < call.arguments.size(); ++i) {
      if (i > 0) {
        oss << ", ";
      }
      oss << format_argument(call.arguments[i]);
    }

    oss << ")";

    // add return value if available
    if (call.return_value.raw_value != 0 || call.return_value.param_type != param_info::type::UNKNOWN) {
      oss << " = " << format_argument(call.return_value);
    }

    return oss.str();
  }

  extractor_config config_;

private:
  std::shared_ptr<calling_convention_base> default_convention_;
  std::shared_ptr<calling_convention_detector> detector_;
  std::shared_ptr<api_knowledge_db> api_db_;
  mutable std::unordered_map<std::string, calling_convention_ptr> convention_cache_;
  redlog::logger log_;

  std::string format_argument(const extracted_argument& arg) const {
    std::ostringstream oss;

    // special formatting for different types
    if (arg.is_null_pointer) {
      oss << "NULL";
    } else if (std::holds_alternative<std::string>(arg.interpreted_value)) {
      oss << "\"" << std::get<std::string>(arg.interpreted_value) << "\"";
    } else if (std::holds_alternative<bool>(arg.interpreted_value)) {
      oss << (std::get<bool>(arg.interpreted_value) ? "true" : "false");
    } else if (std::holds_alternative<int64_t>(arg.interpreted_value)) {
      oss << std::get<int64_t>(arg.interpreted_value);
    } else if (std::holds_alternative<uint64_t>(arg.interpreted_value)) {
      oss << "0x" << std::hex << std::get<uint64_t>(arg.interpreted_value);
    } else if (std::holds_alternative<double>(arg.interpreted_value)) {
      oss << std::get<double>(arg.interpreted_value);
    } else {
      // raw value
      oss << "0x" << std::hex << arg.raw_value;
    }

    // add type hint if available
    if (!arg.param_name.empty()) {
      oss << " /* " << arg.param_name << " */";
    }

    return oss.str();
  }
};

// public interface implementation

argument_extractor::argument_extractor(
    std::shared_ptr<api_knowledge_db> api_db, std::shared_ptr<calling_convention_detector> detector,
    const extractor_config& config
)
    : pimpl(std::make_unique<impl>(api_db, detector, config)) {}

argument_extractor::argument_extractor(
    std::shared_ptr<calling_convention_base> convention, std::shared_ptr<api_knowledge_db> api_db,
    const extractor_config& config
)
    : pimpl(std::make_unique<impl>(convention, api_db, config)) {}

argument_extractor::~argument_extractor() = default;

extracted_call_info argument_extractor::extract_call(
    const std::string& api_name, const std::string& module_name, const util::safe_memory_reader& memory,
    const call_context& ctx
) const {
  return pimpl->extract_call(api_name, module_name, memory, ctx);
}

extracted_call_info argument_extractor::extract_call_with_convention(
    const std::string& api_name, const std::string& module_name, calling_convention_ptr convention,
    const util::safe_memory_reader& memory, const call_context& ctx
) const {
  return pimpl->extract_call_with_convention(api_name, module_name, convention, memory, ctx);
}

void argument_extractor::extract_return_value(
    extracted_call_info& call_info, const util::safe_memory_reader& memory, const call_context& ctx
) const {
  pimpl->extract_return_value(call_info, memory, ctx);
}

extracted_argument argument_extractor::extract_argument(
    const param_info& param, uint64_t raw_value, const util::safe_memory_reader& memory
) const {
  return pimpl->extract_argument(param, raw_value, memory);
}

std::string argument_extractor::format_call(const extracted_call_info& call) const { return pimpl->format_call(call); }

const extractor_config& argument_extractor::get_config() const { return pimpl->config_; }

void argument_extractor::set_config(const extractor_config& config) { pimpl->config_ = config; }

// utility functions implementation

namespace arg_utils {

bool is_valid_pointer(uint64_t addr, const util::safe_memory_reader& memory) {
  if (addr == 0) {
    return false;
  }

  // try to read one byte
  auto byte = memory.read<uint8_t>(addr);
  return byte.has_value();
}

std::optional<std::string> read_string(uint64_t addr, const util::safe_memory_reader& memory, size_t max_length) {

  if (addr == 0) {
    return std::nullopt;
  }

  std::string result;
  result.reserve(std::min(max_length, size_t(256)));

  for (size_t i = 0; i < max_length; ++i) {
    auto ch_opt = memory.read<char>(addr + i);
    if (!ch_opt) {
      break;
    }
    char ch = *ch_opt;
    if (ch == '\0') {
      return result;
    }
    result.push_back(ch);
  }

  // didn't find null terminator
  return result;
}

std::optional<std::string> read_wide_string(uint64_t addr, const util::safe_memory_reader& memory, size_t max_length) {

  if (addr == 0) {
    return std::nullopt;
  }

  std::string result;
  result.reserve(std::min(max_length, size_t(256)));

  for (size_t i = 0; i < max_length; ++i) {
    auto wch_opt = memory.read<uint16_t>(addr + i * 2);
    if (!wch_opt) {
      break;
    }
    uint16_t wch = *wch_opt;
    if (wch == 0) {
      return result;
    }
    // simple ascii conversion
    if (wch < 128) {
      result.push_back(static_cast<char>(wch));
    } else {
      result.push_back('?');
    }
  }

  return result;
}

std::string format_pointer(uint64_t addr) {
  std::ostringstream oss;
  oss << "0x" << std::hex << addr;
  return oss.str();
}

std::vector<std::string> decode_flags(uint32_t flags, const std::string& flag_type) {
  std::vector<std::string> result;

  // todo: implement common flag decoding based on flag_type
  // for now just return hex representation
  if (flags != 0) {
    std::ostringstream oss;
    oss << "0x" << std::hex << flags;
    result.push_back(oss.str());
  }

  return result;
}

} // namespace arg_utils

} // namespace w1::abi