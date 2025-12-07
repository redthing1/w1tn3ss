#pragma once

#include <memory>
#include <vector>

#include "trace_types.hpp"

namespace w1::rewind {

struct trace_sink_options {
  // placeholder for future extensibility
};

class trace_sink {
public:
  virtual ~trace_sink() = default;

  virtual bool initialize() = 0;
  virtual void close() = 0;
  virtual bool write_event(const trace_event& event) = 0;
  virtual void flush() = 0;
  virtual bool good() const = 0;

  virtual void attach_observer(std::shared_ptr<class trace_observer> observer) {
    observers_.push_back(std::move(observer));
  }

protected:
  void notify_observers(const trace_event& event) {
    for (const auto& observer : observers_) {
      if (observer) {
        observer->on_event(event);
      }
    }
  }

private:
  std::vector<std::shared_ptr<class trace_observer>> observers_;
};

using trace_sink_ptr = std::shared_ptr<trace_sink>;

} // namespace w1::rewind
