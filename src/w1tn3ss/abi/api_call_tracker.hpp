#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "api_knowledge_db.hpp"

namespace w1::abi {

class api_call_tracker {
public:
  struct tracked_call {
    uint64_t call_address = 0;
    uint64_t target_address = 0;
    uint64_t timestamp = 0;
    std::string module_name;
    std::string symbol_name;
    api_info::category category = api_info::category::UNKNOWN;
    std::string description;
    std::string formatted_call;
    param_info return_param;
    bool has_return_value = false;
  };

  explicit api_call_tracker(size_t max_pending = 10000);

  void record_call(const tracked_call& call);
  std::optional<tracked_call> consume_return(uint64_t return_from_address);
  void clear();
  size_t size() const;

private:
  size_t max_pending_;
  std::vector<tracked_call> calls_;
};

} // namespace w1::abi
