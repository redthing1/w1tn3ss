#include "session.hpp"

namespace p1ll::engine {

session::session(std::unique_ptr<address_space> space, platform::platform_key platform_key, bool dynamic)
    : space_(std::move(space)), platform_(std::move(platform_key)), dynamic_(dynamic) {}

session session::for_process() {
  auto platform_key = platform::detect_platform();
  return session(std::make_unique<process_address_space>(), platform_key, true);
}

session session::for_buffer(std::span<uint8_t> buffer) {
  auto platform_key = platform::detect_platform();
  return session(std::make_unique<buffer_address_space>(buffer), platform_key, false);
}

session session::for_buffer(std::span<uint8_t> buffer, platform::platform_key platform_override) {
  return session(std::make_unique<buffer_address_space>(buffer), std::move(platform_override), false);
}

result<std::vector<memory_region>> session::regions(const scan_filter& filter) const { return space_->regions(filter); }

result<std::vector<scan_result>> session::scan(std::string_view pattern, const scan_options& options) const {
  auto parsed = parse_signature(pattern);
  if (!parsed.ok()) {
    return error_result<std::vector<scan_result>>(parsed.status.code, parsed.status.message);
  }

  scanner scanner(*space_);
  return scanner.scan(parsed.value, options);
}

result<std::vector<plan_entry>> session::plan(const recipe& recipe) const {
  plan_builder builder(*space_, platform_);
  return builder.build(recipe);
}

result<apply_report> session::apply(const std::vector<plan_entry>& plan, const apply_options& options) {
  return apply_plan(*space_, plan, options);
}

} // namespace p1ll::engine
