#include "api_event_builder.hpp"

#include "util/value_formatter.hpp"

namespace w1::abi {

api_event api_event_builder::build_call_event(const api_context& ctx, const api_analysis_result& analysis) {
  api_event event;
  event.type = api_event::event_type::CALL;
  event.timestamp = ctx.timestamp;
  event.source_address = ctx.call_address;
  event.target_address = ctx.target_address;
  event.module_name = analysis.module_name.empty() ? ctx.module_name : analysis.module_name;
  event.symbol_name = analysis.symbol_name.empty() ? ctx.symbol_name : analysis.symbol_name;
  event.category = analysis.category;
  event.description = analysis.description;
  event.formatted_call = analysis.formatted_call;
  event.analysis_complete = analysis.analysis_complete;
  event.has_return_value = analysis.has_return_value;

  event.arguments.reserve(analysis.arguments.size());
  for (const auto& arg : analysis.arguments) {
    event.arguments.push_back(to_event_argument(arg));
  }

  return event;
}

api_event api_event_builder::build_return_event(
    const api_context& ctx, const api_analysis_result& analysis, const extracted_argument& return_value
) {
  api_event event;
  event.type = api_event::event_type::RETURN;
  event.timestamp = ctx.timestamp;
  event.source_address = ctx.call_address;
  event.target_address = ctx.target_address;
  event.module_name = analysis.module_name.empty() ? ctx.module_name : analysis.module_name;
  event.symbol_name = analysis.symbol_name.empty() ? ctx.symbol_name : analysis.symbol_name;
  event.category = analysis.category;
  event.description = analysis.description;
  event.formatted_call = analysis.formatted_call;
  event.analysis_complete = analysis.analysis_complete;
  event.has_return_value = analysis.has_return_value;

  event.return_value = to_event_return(return_value);

  return event;
}

api_event_argument api_event_builder::to_event_argument(const extracted_argument& arg) {
  api_event_argument evt_arg;
  evt_arg.raw_value = arg.raw_value;
  evt_arg.param_name = arg.param_name;
  evt_arg.param_type = arg.param_type;
  evt_arg.is_pointer = arg.is_valid_pointer;
  evt_arg.interpreted_value = format_interpreted_value(arg);
  return evt_arg;
}

api_event_return api_event_builder::to_event_return(const extracted_argument& arg) {
  api_event_return evt_ret;
  evt_ret.raw_value = arg.raw_value;
  evt_ret.param_type = arg.param_type;
  evt_ret.is_pointer = arg.is_valid_pointer;
  evt_ret.interpreted_value = format_interpreted_value(arg);
  return evt_ret;
}

std::string api_event_builder::format_interpreted_value(const extracted_argument& arg) {
  util::value_formatter::format_options fmt_opts;
  fmt_opts.max_string_length = 256;

  if (!arg.string_preview.empty()) {
    return util::value_formatter::format_string(arg.string_preview, fmt_opts);
  }

  if (arg.is_null_pointer) {
    return "NULL";
  }

  if (std::holds_alternative<std::string>(arg.interpreted_value)) {
    return util::value_formatter::format_string(std::get<std::string>(arg.interpreted_value), fmt_opts);
  }

  if (std::holds_alternative<bool>(arg.interpreted_value)) {
    return util::value_formatter::format_bool(std::get<bool>(arg.interpreted_value));
  }

  if (std::holds_alternative<std::vector<uint8_t>>(arg.interpreted_value)) {
    return util::value_formatter::format_buffer(std::get<std::vector<uint8_t>>(arg.interpreted_value), fmt_opts);
  }

  auto value_type = util::value_formatter::value_type::UNKNOWN;
  if (arg.param_type == param_info::type::BOOLEAN) {
    value_type = util::value_formatter::value_type::BOOLEAN;
  } else if (arg.param_type == param_info::type::ERROR_CODE) {
    value_type = util::value_formatter::value_type::ERROR_CODE;
  } else if (arg.is_valid_pointer) {
    value_type = util::value_formatter::value_type::POINTER;
  }

  return util::value_formatter::format_typed_value(arg.raw_value, value_type, fmt_opts);
}

} // namespace w1::abi
