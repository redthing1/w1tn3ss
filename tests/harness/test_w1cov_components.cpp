#include <iostream>
#include <vector>

#include "engine/coverage_exporter.hpp"
#include "engine/coverage_store.hpp"
#include "w1runtime/module_catalog.hpp"

int main() {
  w1cov::coverage_store store;

  w1cov::coverage_buffer buffer;
  buffer[0x1000] = w1cov::coverage_buffer_entry{0, 4, 2};
  buffer[0x2000] = w1cov::coverage_buffer_entry{1, 8, 1};
  store.merge(buffer);
  store.record(0x1000, 4, 0, 3);

  if (store.unit_count() != 2) {
    std::cerr << "unexpected unit count\n";
    return 1;
  }

  auto snapshot = store.snapshot();
  if (snapshot.total_hits != 6) {
    std::cerr << "unexpected total hits\n";
    return 1;
  }

  std::vector<w1::runtime::module_info> modules;
  w1::runtime::module_info mod0{};
  mod0.name = "mod0";
  mod0.path = "/fake/mod0";
  mod0.base_address = 0x1000;
  mod0.size = 0x1000;
  modules.push_back(mod0);

  w1::runtime::module_info mod1{};
  mod1.name = "mod1";
  mod1.path = "/fake/mod1";
  mod1.base_address = 0x2000;
  mod1.size = 0x1000;
  modules.push_back(mod1);

  w1cov::coverage_exporter exporter;
  auto data = exporter.to_drcov(snapshot, modules);
  if (data.basic_blocks.empty()) {
    std::cerr << "no basic blocks exported\n";
    return 1;
  }
  if (!data.has_hitcounts()) {
    std::cerr << "missing hitcounts\n";
    return 1;
  }
  if (data.modules.size() != 2) {
    std::cerr << "unexpected module count\n";
    return 1;
  }
  if (data.basic_blocks.size() != data.hitcounts.size()) {
    std::cerr << "hitcount size mismatch\n";
    return 1;
  }

  std::cout << "w1cov component test completed\n";
  return 0;
}
