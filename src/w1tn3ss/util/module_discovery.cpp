#include "module_discovery.hpp"

namespace w1 {
namespace util {

module_discovery::module_discovery() : index_(std::vector<module_info>{}) {}

void module_discovery::take_snapshot() {
  log_.vrb("taking module snapshot");
  std::unique_lock<std::shared_mutex> lock(mutex_);

  // scan all executable modules
  auto modules = scanner_.scan_executable_modules();

  // rebuild index with new modules
  index_ = module_range_index(std::move(modules));

  log_.vrb("module snapshot complete", redlog::field("modules", index_.size()));
}

const module_info* module_discovery::find_containing(QBDI::rword address) const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return index_.find_containing(address);
}

const module_info* module_discovery::find_by_name(const std::string& name) const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return index_.find_by_name(name);
}

std::vector<module_info> module_discovery::get_modules(std::function<bool(const module_info&)> filter) const {
  std::shared_lock<std::shared_mutex> lock(mutex_);

  std::vector<module_info> result;

  index_.visit_all([&](const auto& interval) {
    const module_info& mod = interval.value;
    if (!filter || filter(mod)) {
      result.push_back(mod);
    }
  });

  return result;
}

std::vector<module_info> module_discovery::get_user_modules() const { return scanner_.scan_user_modules(); }

} // namespace util
} // namespace w1