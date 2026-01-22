#pragma once

#include <cstdint>
#include <optional>
#include <utility>

namespace w1::core {

template <typename ValueT>
struct module_lookup {
  ValueT value{};
  uint64_t base = 0;
  uint64_t end = 0;
  uint64_t epoch = 0;
};

template <typename ValueT>
class module_cache {
public:
  module_cache() = default;

  void reset() { entry_ = {}; }

  template <typename Resolver>
  std::optional<ValueT> resolve(uint64_t address, uint64_t epoch, Resolver&& resolver) {
    if (entry_.valid && entry_.epoch == epoch && address >= entry_.base && address < entry_.end) {
      return entry_.value;
    }

    auto lookup = resolver(address);
    if (!lookup) {
      return std::nullopt;
    }

    entry_.value = lookup->value;
    entry_.base = lookup->base;
    entry_.end = lookup->end;
    entry_.epoch = lookup->epoch;
    entry_.valid = true;
    return entry_.value;
  }

private:
  struct cache_entry {
    ValueT value{};
    uint64_t base = 0;
    uint64_t end = 0;
    uint64_t epoch = 0;
    bool valid = false;
  };

  cache_entry entry_{};
};

} // namespace w1::core
