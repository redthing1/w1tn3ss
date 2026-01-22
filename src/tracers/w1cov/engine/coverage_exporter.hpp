#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include <redlog.hpp>

#include <w1formats/drcov.hpp>

#include "coverage_snapshot.hpp"
#include "w1runtime/module_catalog.hpp"

namespace w1cov {

class coverage_exporter {
public:
  drcov::coverage_data to_drcov(const coverage_snapshot& snapshot,
                                const std::vector<w1::runtime::module_info>& modules) const;

private:
  static std::string format_hex(uint64_t value);
  redlog::logger log_ = redlog::get_logger("w1cov.exporter");
};

} // namespace w1cov
