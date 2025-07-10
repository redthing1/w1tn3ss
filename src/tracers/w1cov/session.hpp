#pragma once

#include "coverage_tracer.hpp"
#include "coverage_config.hpp"
#include <w1tn3ss/engine/session_base.hpp>
#include <w1tn3ss/formats/drcov.hpp>
#include <redlog.hpp>
#include <iostream>
#include <iomanip>

namespace w1cov {

class session : public w1::session_base<session, coverage_tracer, coverage_config> {
public:
  session() = default;
  explicit session(const coverage_config& config) : session_base(config) {}

  // coverage-specific metrics
  size_t get_coverage_unit_count() const { return get_tracer() ? get_tracer()->get_coverage_unit_count() : 0; }

  size_t get_module_count() const { return get_tracer() ? get_tracer()->get_module_count() : 0; }

  uint64_t get_total_hits() const { return get_tracer() ? get_tracer()->get_total_hits() : 0; }

  void print_statistics() const {
    if (!get_tracer()) {
      std::cout << "session not initialized\n";
      return;
    }

    size_t units = get_coverage_unit_count();
    size_t modules = get_module_count();
    uint64_t hits = get_total_hits();

    std::cout << "coverage statistics:\n";
    std::cout << "  coverage units: " << units << "\n";
    std::cout << "  modules: " << modules << "\n";
    std::cout << "  total hits: " << hits << "\n";

    if (units > 0 && hits > 0) {
      double avg = static_cast<double>(hits) / units;
      std::cout << "  avg hits/unit: " << std::fixed << std::setprecision(2) << avg << "\n";
    }
  }

  bool export_coverage(const std::string& output_path) const {
    if (!get_tracer()) {
      return false;
    }

    auto log = redlog::get_logger("w1cov.session");

    try {
      const auto& collector = get_tracer()->get_collector();
      auto data = collector.build_drcov_data();

      if (data.basic_blocks.empty()) {
        log.wrn("no coverage data to export");
        return false;
      }

      drcov::write(output_path, data);
      log.inf(
          "coverage exported", redlog::field("file", output_path), redlog::field("blocks", data.basic_blocks.size())
      );
      return true;

    } catch (const std::exception& e) {
      log.err("export failed", redlog::field("error", e.what()));
      return false;
    }
  }
};

} // namespace w1cov