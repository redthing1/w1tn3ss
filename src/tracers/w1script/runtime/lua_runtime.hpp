#pragma once

#include "api_manager.hpp"
#include "callback_registry.hpp"
#include "callback_store.hpp"
#include "script_context.hpp"

#include <sol/sol.hpp>
#include <redlog.hpp>

#include <string>

namespace w1::tracers::script::runtime {

class lua_runtime {
public:
  explicit lua_runtime(script_context& context);

  bool initialize();
  void shutdown();

  QBDI::VMAction dispatch_vm_start(QBDI::VMInstanceRef vm);

private:
  bool open_libraries();
  void configure_package_paths();
  bool register_bindings();
  bool load_script();
  bool call_init();

  script_context& context_;
  sol::state lua_;
  sol::table script_table_;

  callback_store vm_callback_store_;
  api_manager api_manager_;
  callback_registry callback_registry_;

  redlog::logger logger_;
};

} // namespace w1::tracers::script::runtime
