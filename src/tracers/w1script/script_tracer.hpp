#pragma once

#include "script_config.hpp"
#include <w1tn3ss/engine/tracer_engine.hpp>

#ifdef WITNESS_SCRIPT_ENABLED
#include <sol/sol.hpp>
#include <unordered_set>
#include <string>
#endif

namespace w1::tracers::script {

class script_tracer {
private:
  config cfg_;

#ifdef WITNESS_SCRIPT_ENABLED
  sol::state lua_;
  sol::table script_table_;
  std::unordered_set<std::string> enabled_callbacks_;

  // Lua callback wrapper functions
  sol::function lua_on_instruction_preinst_;
  sol::function lua_on_instruction_postinst_;
  sol::function lua_on_basic_block_entry_;
  sol::function lua_on_basic_block_exit_;
  sol::function lua_on_memory_read_;
  sol::function lua_on_memory_write_;

  bool load_script();
  void setup_callbacks();
  bool is_callback_enabled(const std::string& callback_name) const;
#endif

public:
  script_tracer() = default;
  ~script_tracer() = default;

  bool initialize(w1::tracer_engine<script_tracer>& engine);
  void shutdown();
  const char* get_name() const { return "w1script"; }

  // QBDI callbacks - only defined when Lua is enabled
#ifdef WITNESS_SCRIPT_ENABLED
  QBDI::VMAction on_instruction_preinst(QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr);
  QBDI::VMAction on_instruction_postinst(QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr);
  QBDI::VMAction on_basic_block_entry(
      QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  QBDI::VMAction on_basic_block_exit(
      QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  QBDI::VMAction on_memory_read(QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr);
  QBDI::VMAction on_memory_write(QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr);
#endif
};

} // namespace w1::tracers::script