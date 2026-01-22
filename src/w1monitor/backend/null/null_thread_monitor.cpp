#include "w1monitor/backend/null/null_thread_monitor.hpp"

namespace w1::monitor::backend::null_backend {
namespace {

class null_thread_monitor final : public thread_monitor {
public:
  void start() override {}
  void stop() override {}
  bool poll(thread_event&) override { return false; }
};

} // namespace

std::unique_ptr<thread_monitor> make_thread_monitor() {
  return std::make_unique<null_thread_monitor>();
}

} // namespace w1::monitor::backend::null_backend
