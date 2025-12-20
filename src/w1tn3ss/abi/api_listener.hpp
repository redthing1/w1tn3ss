#pragma once

#include "api_dispatcher.hpp"

namespace w1::abi {

// api listener for monitoring and analyzing API calls
//
// THREAD SAFETY: This class is NOT thread-safe. All methods must be called
// from the same thread, or external synchronization must be provided.
// This includes:
// - Registration/unregistration of callbacks
// - Processing of call/return events
// - Initialization and shutdown
//
// Note: Callbacks are invoked synchronously in the context of process_call/return
class api_listener {
public:
  explicit api_listener(const analyzer_config& config = analyzer_config{});

  void initialize(const util::module_range_index& index);

  std::optional<api_event> analyze_call(const api_context& ctx);
  std::optional<api_event> analyze_return(const api_context& ctx);

  void process_call(const api_context& ctx);
  void process_return(const api_context& ctx);

  void register_symbol_callback(const std::string& module, const std::string& symbol, api_callback_fn callback);
  void register_module_callback(const std::string& module, api_callback_fn callback);
  void register_category_callback(api_info::category category, api_callback_fn callback);

  void unregister_symbol_callback(const std::string& module, const std::string& symbol);
  void unregister_module_callback(const std::string& module);
  void unregister_category_callback(api_info::category category);
  void clear_all_callbacks();

  api_analyzer& get_analyzer();
  const api_knowledge_db& get_api_db() const;

  using stats = api_dispatcher::stats;
  stats get_stats() const;

private:
  api_dispatcher dispatcher_;
};

} // namespace w1::abi
