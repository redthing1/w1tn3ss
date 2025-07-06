#pragma once

#include "api_analyzer.hpp"
#include "api_knowledge_db.hpp"
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace w1::util {
class module_range_index;
}

namespace w1::abi {

// forward declarations
struct api_context;

// unified event structure for both calls and returns
struct api_event {
  enum class event_type { CALL, RETURN };

  event_type type;
  uint64_t timestamp;
  uint64_t source_address;
  uint64_t target_address;
  
  // api identification
  std::string module_name;
  std::string symbol_name;
  
  // analysis results
  api_info::category category;
  std::string description;
  std::string formatted_call;
  bool analysis_complete;
  
  // extracted arguments (for calls)
  struct argument {
    uint64_t raw_value;
    std::string param_name;
    param_info::type param_type;
    bool is_pointer;
    std::string interpreted_value;
  };
  std::vector<argument> arguments;
  
  // return value (for returns)
  std::optional<argument> return_value;
};

// callback function type
using api_callback_fn = std::function<void(const api_event&)>;

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
  // constructor with optional custom analyzer config
  explicit api_listener(const analyzer_config& config = analyzer_config{});
  ~api_listener();
  
  // initialization (must be called before processing)
  void initialize(const util::module_range_index& index);
  
  // direct analysis - analyze and return event (for w1xfer)
  // returns nullopt if the call/return is not an API
  std::optional<api_event> analyze_call(const api_context& ctx);
  std::optional<api_event> analyze_return(const api_context& ctx);
  
  // callback-based processing - analyze and dispatch to callbacks (for scripts)
  // only analyzes if there are matching callbacks registered
  void process_call(const api_context& ctx);
  void process_return(const api_context& ctx);
  
  // callback registration (for callback-based processing)
  void register_symbol_callback(const std::string& module, const std::string& symbol, 
                                api_callback_fn callback);
  void register_module_callback(const std::string& module, api_callback_fn callback);
  void register_category_callback(api_info::category category, api_callback_fn callback);
  
  // remove callbacks
  void unregister_symbol_callback(const std::string& module, const std::string& symbol);
  void unregister_module_callback(const std::string& module);
  void unregister_category_callback(api_info::category category);
  void clear_all_callbacks();
  
  // access to underlying components
  api_analyzer& get_analyzer();
  const api_knowledge_db& get_api_db() const;
  
  // statistics
  struct stats {
    uint64_t total_calls_processed;
    uint64_t total_returns_processed;
    uint64_t calls_analyzed;
    uint64_t returns_analyzed;
    uint64_t calls_filtered_out;
  };
  stats get_stats() const;
  
private:
  class impl;
  std::unique_ptr<impl> pimpl_;
};

} // namespace w1::abi