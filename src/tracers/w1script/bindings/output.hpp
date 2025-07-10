#pragma once

#include <sol/sol.hpp>
#include <memory>
#include <string>

namespace w1::util {
class jsonl_writer;
}

namespace w1::tracers::script::bindings {

/**
 * native c++ implementation of the w1.output module
 * replaces the embedded lua code with a clean api
 */
class output_module {
private:
  std::shared_ptr<w1::util::jsonl_writer> writer_;
  bool initialized_ = false;
  size_t event_count_ = 0;

public:
  output_module() = default;
  ~output_module();

  // initialize output file with optional metadata
  bool init(sol::state_view lua, const std::string& filename, sol::optional<sol::table> metadata);

  // write an event to the output file
  bool write_event(sol::table event);

  // close the output file with summary
  void close();

  // check if output is initialized
  bool is_initialized() const { return initialized_; }

  // get event count
  size_t get_event_count() const { return event_count_; }
};

// setup output bindings for lua
void setup_output(sol::state& lua, sol::table& w1_module);

} // namespace w1::tracers::script::bindings