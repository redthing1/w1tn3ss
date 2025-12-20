#include "api_call_tracker.hpp"

#include <algorithm>

namespace w1::abi {

api_call_tracker::api_call_tracker(size_t max_pending) : max_pending_(max_pending) {}

void api_call_tracker::record_call(const tracked_call& call) {
  if (calls_.size() >= max_pending_) {
    calls_.erase(calls_.begin());
  }
  calls_.push_back(call);
}

std::optional<api_call_tracker::tracked_call> api_call_tracker::consume_return(uint64_t return_from_address) {
  auto call_it = std::find_if(calls_.rbegin(), calls_.rend(), [return_from_address](const tracked_call& call) {
    return call.target_address == return_from_address;
  });

  if (call_it == calls_.rend()) {
    return std::nullopt;
  }

  tracked_call result = *call_it;
  calls_.erase(std::next(call_it).base());
  return result;
}

void api_call_tracker::clear() { calls_.clear(); }

size_t api_call_tracker::size() const { return calls_.size(); }

} // namespace w1::abi
