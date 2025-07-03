#include "context.hpp"
#include <stdexcept>
#include <thread>

namespace p1ll::core {

// thread-local storage for current context
thread_local std::unique_ptr<p1ll_context> current_context_;

std::unique_ptr<p1ll_context> p1ll_context::create_static(std::vector<uint8_t>& buffer) {
  return std::unique_ptr<p1ll_context>(new p1ll_context(mode::static_buffer, buffer));
}

std::unique_ptr<p1ll_context> p1ll_context::create_dynamic() {
  return std::unique_ptr<p1ll_context>(new p1ll_context(mode::dynamic_memory));
}

std::vector<uint8_t>& p1ll_context::get_buffer() const {
  if (operation_mode_ != mode::static_buffer) {
    throw std::logic_error("attempted to get buffer from non-static context");
  }

  if (!buffer_data_.has_value()) {
    throw std::logic_error("static context has no buffer reference");
  }

  return buffer_data_->get();
}

void set_current_context(std::unique_ptr<p1ll_context> context) { current_context_ = std::move(context); }

p1ll_context* get_current_context() { return current_context_.get(); }

void clear_current_context() { current_context_.reset(); }

} // namespace p1ll::core