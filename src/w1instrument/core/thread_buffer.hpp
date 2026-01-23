#pragma once

#include <cstddef>
#include <optional>
#include <unordered_map>
#include <utility>

namespace w1::core {

template <typename KeyT, typename EntryT, typename MergeT> class thread_buffer {
public:
  thread_buffer(MergeT merge, size_t reserve = 0, size_t flush_threshold = 0)
      : merge_(std::move(merge)), flush_threshold_(flush_threshold) {
    if (reserve > 0) {
      buffer_.reserve(reserve);
    }
  }

  void clear() { buffer_.clear(); }

  void flush() {
    if (buffer_.empty()) {
      return;
    }
    merge_(buffer_);
    buffer_.clear();
  }

  size_t size() const { return buffer_.size(); }

  template <typename UpdateFn, typename CreateFn> void record(const KeyT& key, UpdateFn&& update, CreateFn&& create) {
    auto it = buffer_.find(key);
    if (it != buffer_.end()) {
      update(it->second);
      return;
    }

    auto created = create();
    if (!created) {
      return;
    }

    buffer_.emplace(key, std::move(*created));
    if (flush_threshold_ != 0 && buffer_.size() >= flush_threshold_) {
      flush();
    }
  }

private:
  std::unordered_map<KeyT, EntryT> buffer_{};
  MergeT merge_;
  size_t flush_threshold_ = 0;
};

} // namespace w1::core
