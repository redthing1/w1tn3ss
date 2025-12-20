#pragma once

#include "script_config.hpp"
#include "runtime/lua_runtime.hpp"
#include "runtime/script_context.hpp"

#include <w1tn3ss/engine/tracer_engine.hpp>

#include <memory>
#include <redlog.hpp>

namespace w1::tracers::script {

class script_tracer {
private:
  config cfg_;
  redlog::logger logger_;

  QBDI::VM* vm_ = nullptr;
  std::unique_ptr<runtime::script_context> context_;
  std::unique_ptr<runtime::lua_runtime> runtime_;

  bool setup_configuration();

public:
  script_tracer();
  explicit script_tracer(const config& cfg);
  ~script_tracer();

  bool initialize(w1::tracer_engine<script_tracer>& engine);
  void shutdown();
  const char* get_name() const { return "w1script"; }

  QBDI::VMAction on_vm_start(QBDI::VMInstanceRef vm);
};

} // namespace w1::tracers::script
