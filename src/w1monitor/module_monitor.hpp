#pragma once

#include <cstddef>
#include <string>

namespace w1::monitor {

struct module_event {
  enum class kind { loaded, unloaded };
  kind type = kind::loaded;
  std::string path{};
  void* base = nullptr;
  size_t size = 0;
};

class module_monitor {
public:
  virtual ~module_monitor() = default;
  virtual void start() = 0;
  virtual void stop() = 0;
  virtual bool poll(module_event& out) = 0;
};

} // namespace w1::monitor
