#include "context.hpp"
#include "platform.hpp"

namespace p1ll {

std::unique_ptr<context> context::create_static() {
  auto& detector = get_platform_detector();
  auto platform = detector.get_detected_platform();
  return std::unique_ptr<context>(new context(mode::static_buffer, platform));
}

std::unique_ptr<context> context::create_static(const platform_key& platform) {
  return std::unique_ptr<context>(new context(mode::static_buffer, platform));
}

std::unique_ptr<context> context::create_dynamic() {
  auto& detector = get_platform_detector();
  auto platform = detector.get_detected_platform();
  return std::unique_ptr<context>(new context(mode::dynamic_memory, platform));
}

} // namespace p1ll