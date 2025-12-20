#pragma once

#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "api_analyzer.hpp"
#include "api_call_tracker.hpp"

namespace w1::abi {

using api_callback_fn = std::function<void(const api_event&)>;

class api_dispatcher {
public:
  struct stats {
    uint64_t total_calls_processed = 0;
    uint64_t total_returns_processed = 0;
    uint64_t calls_analyzed = 0;
    uint64_t returns_analyzed = 0;
    uint64_t calls_filtered_out = 0;
    uint64_t returns_filtered_out = 0;
  };

  explicit api_dispatcher(const analyzer_config& config = analyzer_config{});

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

  stats get_stats() const { return stats_; }

private:
  struct callback_sets {
    std::unordered_map<std::string, std::vector<api_callback_fn>> symbol_callbacks;
    std::unordered_map<std::string, std::vector<api_callback_fn>> module_callbacks;
    std::unordered_map<api_info::category, std::vector<api_callback_fn>> category_callbacks;
  };

  api_analyzer analyzer_;
  api_call_tracker call_tracker_;
  callback_sets callbacks_;
  stats stats_{};
  bool has_callbacks_for(const std::string& module, const std::string& symbol, api_info::category category) const;
  void dispatch_event(const api_event& event);
  std::string make_filter_key(const std::string& module, const std::string& symbol) const;
  api_call_tracker::tracked_call to_tracked_call(const api_context& ctx, const api_analysis_result& analysis) const;
  std::optional<api_event> analyze_call_internal(const api_context& ctx);
  std::optional<api_event> analyze_return_internal(
      const api_context& ctx, const api_call_tracker::tracked_call& call
  );
};

} // namespace w1::abi
