#pragma once

#include <sol/sol.hpp>

#include <w1tn3ss/abi/api_listener.hpp>
#include <w1tn3ss/util/module_range_index.hpp>
#include <w1tn3ss/symbols/symbol_resolver.hpp>

#include <QBDI.h>
#include <redlog.hpp>

#include <memory>
#include <string>

namespace w1::tracers::script::runtime {

class api_manager {
public:
  api_manager();

  void set_lua_state(lua_State* state) { lua_state_ = state; }

  void initialize(const w1::util::module_range_index& index, w1::symbols::symbol_resolver* resolver);
  void refresh_modules(const w1::util::module_range_index& index);

  void register_symbol_callback(
      const std::string& module, const std::string& symbol, sol::protected_function callback
  );
  void register_module_callback(const std::string& module, sol::protected_function callback);
  void register_category_callback(w1::abi::api_info::category category, sol::protected_function callback);

  bool has_callbacks() const { return callback_count_ > 0; }

  void process_call(QBDI::VM* vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr);
  void process_return(QBDI::VM* vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr);

  void shutdown();

private:
  void ensure_listener();
  sol::table to_lua_event(const w1::abi::api_event& event) const;

  std::unique_ptr<w1::abi::api_listener> listener_;
  const w1::util::module_range_index* module_index_ = nullptr;
  w1::symbols::symbol_resolver* symbol_resolver_ = nullptr;
  lua_State* lua_state_ = nullptr;
  size_t callback_count_ = 0;
  bool initialized_ = false;
  redlog::logger logger_;
};

} // namespace w1::tracers::script::runtime
