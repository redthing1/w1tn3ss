#pragma once

#include "script_tracer.hpp"
#include "script_config.hpp"
#include <w1tn3ss/engine/session_base.hpp>

namespace w1::tracers::script {

class session : public w1::session_base<session, script_tracer, config> {
public:
  session() = default;
  explicit session(const config& cfg) : session_base(cfg) {}

  // script-specific configuration
  void set_script_path(const std::string& path) { config_.script_path = path; }

  void set_script_config(const std::string& key, const std::string& value) { config_.script_config[key] = value; }
};

} // namespace w1::tracers::script