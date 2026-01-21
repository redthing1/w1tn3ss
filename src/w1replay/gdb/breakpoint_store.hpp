#pragma once

#include <cstdint>
#include <unordered_set>

namespace w1replay::gdb {

class breakpoint_store {
public:
  void add(uint64_t address) { breakpoints_.insert(address); }
  void remove(uint64_t address) { breakpoints_.erase(address); }
  bool contains(uint64_t address) const { return breakpoints_.find(address) != breakpoints_.end(); }
  const std::unordered_set<uint64_t>& all() const { return breakpoints_; }

private:
  std::unordered_set<uint64_t> breakpoints_;
};

} // namespace w1replay::gdb
