#include "w1monitor/backend/null/null_module_monitor.hpp"

namespace w1::monitor::backend::null_backend {
namespace {

class null_module_monitor final : public module_monitor {
public:
  void start() override {}
  void stop() override {}
  bool poll(module_event&) override { return false; }
};

} // namespace

std::unique_ptr<module_monitor> make_module_monitor() {
  return std::make_unique<null_module_monitor>();
}

} // namespace w1::monitor::backend::null_backend
