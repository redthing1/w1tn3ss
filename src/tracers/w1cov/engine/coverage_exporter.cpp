#include "coverage_exporter.hpp"

#include <iomanip>
#include <sstream>
#include <unordered_set>

namespace w1cov {

std::string coverage_exporter::format_hex(uint64_t value) {
  std::ostringstream oss;
  oss << "0x" << std::hex << std::setw(static_cast<int>(sizeof(uint64_t) * 2)) << std::setfill('0') << value;
  return oss.str();
}

drcov::coverage_data coverage_exporter::to_drcov(
    const coverage_snapshot& snapshot, const std::vector<w1::runtime::module_info>& modules
) const {
  if (modules.empty()) {
    log_.wrn("no modules to export");
    return drcov::coverage_data{};
  }

  log_.trc(
      "building drcov data", redlog::field("module_count", modules.size()),
      redlog::field("coverage_unit_count", snapshot.units.size()), redlog::field("total_hits", snapshot.total_hits)
  );

  std::unordered_set<uint16_t> used_module_ids;
  used_module_ids.reserve(snapshot.units.size());
  for (const auto& unit : snapshot.units) {
    if (unit.module_id < modules.size()) {
      used_module_ids.insert(unit.module_id);
    }
  }

  std::unordered_map<uint16_t, uint16_t> module_id_remap;
  module_id_remap.reserve(used_module_ids.size());
  uint16_t new_id = 0;
  for (uint16_t old_id = 0; old_id < modules.size(); ++old_id) {
    if (used_module_ids.count(old_id) > 0) {
      module_id_remap[old_id] = new_id++;
    }
  }

  auto builder =
      drcov::builder().set_flavor("w1cov").enable_hitcounts().set_module_version(drcov::module_table_version::v2);

  size_t valid_modules = 0;
  size_t invalid_modules = 0;
  size_t skipped_modules = 0;

  for (size_t i = 0; i < modules.size(); ++i) {
    if (used_module_ids.count(static_cast<uint16_t>(i)) == 0) {
      skipped_modules++;
      continue;
    }

    const auto& module = modules[i];
    uint64_t module_end = module.base_address + module.size;
    if (module.base_address >= module_end) {
      log_.wrn(
          "invalid module address range detected", redlog::field("id", i), redlog::field("name", module.name),
          redlog::field("base", module.base_address), redlog::field("end", module_end)
      );
      invalid_modules++;
      continue;
    }

    if (module.path.empty() && module.name.empty()) {
      log_.wrn("module has empty path and name", redlog::field("id", i), redlog::field("base", module.base_address));
      invalid_modules++;
      continue;
    }

    std::string module_path = !module.path.empty() ? module.path : module.name;
    builder.add_module(module_path, module.base_address, module.base_address + module.size, module.base_address);
    valid_modules++;
  }

  log_.inf(
      "module processing completed", redlog::field("valid", valid_modules), redlog::field("invalid", invalid_modules),
      redlog::field("skipped", skipped_modules)
  );

  size_t valid_units = 0;
  size_t invalid_units = 0;
  size_t orphaned_units = 0;

  for (const auto& unit : snapshot.units) {
    if (unit.module_id >= modules.size()) {
      orphaned_units++;
      continue;
    }

    auto remap_it = module_id_remap.find(unit.module_id);
    if (remap_it == module_id_remap.end()) {
      invalid_units++;
      continue;
    }

    const auto& module = modules[unit.module_id];
    if (unit.address < module.base_address || unit.address >= module.base_address + module.size) {
      log_.wrn(
          "coverage unit address outside module bounds", redlog::field("module_id", unit.module_id),
          redlog::field("address", format_hex(unit.address)), redlog::field("base", format_hex(module.base_address)),
          redlog::field("end", format_hex(module.base_address + module.size))
      );
      invalid_units++;
      continue;
    }

    uint32_t offset = static_cast<uint32_t>(unit.address - module.base_address);
    if (offset >= module.size) {
      invalid_units++;
      continue;
    }

    builder.add_coverage(remap_it->second, offset, unit.size, unit.hitcount);
    valid_units++;
  }

  log_.dbg(
      "coverage unit processing completed", redlog::field("valid", valid_units),
      redlog::field("invalid", invalid_units), redlog::field("orphaned", orphaned_units)
  );

  if (valid_units == 0 && !snapshot.units.empty()) {
    log_.wrn("no valid coverage units were exported despite having collected data");
  }

  return builder.build();
}

} // namespace w1cov
