#pragma once

#include <string>

#include "api_types.hpp"

namespace w1::abi {

class api_event_builder {
public:
  static api_event build_call_event(const api_context& ctx, const api_analysis_result& analysis);
  static api_event build_return_event(
      const api_context& ctx, const api_analysis_result& analysis, const extracted_argument& return_value
  );

private:
  static api_event_argument to_event_argument(const extracted_argument& arg);
  static api_event_return to_event_return(const extracted_argument& arg);
  static std::string format_interpreted_value(const extracted_argument& arg);
};

} // namespace w1::abi
