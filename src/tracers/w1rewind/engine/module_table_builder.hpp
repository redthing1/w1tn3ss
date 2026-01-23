#pragma once

#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "w1base/arch_spec.hpp"
#include "w1rewind/format/trace_format.hpp"
#include "w1runtime/module_catalog.hpp"

namespace w1rewind {

struct module_metadata {
  w1::rewind::module_format format = w1::rewind::module_format::unknown;
  std::string identity;
  uint32_t identity_age = 0;
  uint32_t flags = 0;
  uint64_t link_base = 0;
  std::optional<uint64_t> entry_point;
};

class module_metadata_cache {
public:
  explicit module_metadata_cache(w1::arch::arch_spec arch) : arch_(arch) {}

  module_metadata lookup(const std::string& path);

private:
  w1::arch::arch_spec arch_{};
  std::mutex mutex_{};
  std::unordered_map<std::string, module_metadata> cache_{};
};

w1::rewind::module_record build_module_record(
    const w1::runtime::module_info& module, uint64_t id, module_metadata_cache& cache
);

std::vector<w1::rewind::memory_region_record> collect_memory_map(const std::vector<w1::rewind::module_record>& modules);

} // namespace w1rewind
