#include "coverage_collector.hpp"

#include <algorithm>
#include <iomanip>
#include <limits>
#include <sstream>
#include <unordered_set>

#include <redlog.hpp>

namespace w1cov {
namespace {

std::string format_hex(uint64_t value) {
  std::ostringstream oss;
  oss << "0x" << std::hex << std::setw(static_cast<int>(sizeof(uint64_t) * 2)) << std::setfill('0') << value;
  return oss.str();
}

} // namespace

coverage_collector::coverage_collector() {}

uint16_t coverage_collector::add_module(const w1::runtime::module_info& mod) {
  auto it = std::find_if(modules_.begin(), modules_.end(), [&mod](const w1::runtime::module_info& existing) {
    return existing.base_address == mod.base_address;
  });

  if (it != modules_.end()) {
    return static_cast<uint16_t>(std::distance(modules_.begin(), it));
  }

  modules_.push_back(mod);
  return static_cast<uint16_t>(modules_.size() - 1);
}

void coverage_collector::record_coverage_unit(QBDI::rword address, uint16_t size, uint16_t module_id, uint32_t hits) {
  if (hits == 0) {
    return;
  }

  auto& hitcount = hitcounts_[address];
  uint64_t new_total = static_cast<uint64_t>(hitcount) + static_cast<uint64_t>(hits);
  if (new_total > std::numeric_limits<uint32_t>::max()) {
    hitcount = std::numeric_limits<uint32_t>::max();
  } else {
    hitcount = static_cast<uint32_t>(new_total);
  }

  auto it = address_to_bb_index_.find(address);
  if (it == address_to_bb_index_.end()) {
    basic_block_info bb;
    bb.address = address;
    bb.size = size;
    bb.module_id = module_id;
    bb.hitcount = hitcount;

    size_t index = basic_blocks_.size();
    basic_blocks_.push_back(bb);
    address_to_bb_index_[address] = index;
  } else {
    auto& existing = basic_blocks_[it->second];
    if (existing.size == 0 && size != 0) {
      existing.size = size;
    }
    existing.hitcount = hitcount;
  }
}

drcov::coverage_data coverage_collector::build_drcov_data() const {
  auto log = redlog::get_logger("w1cov.collector");

  // ensure we have modules to export
  if (modules_.empty()) {
    log.wrn("no modules to export");
    return drcov::coverage_data{};
  }

  log.trc(
      "building drcov data", redlog::field("module_count", modules_.size()),
      redlog::field("coverage_unit_count", basic_blocks_.size()), redlog::field("total_hits", get_total_hits())
  );

  // pass 1: identify modules that have coverage data
  std::unordered_set<uint16_t> used_module_ids;
  for (const auto& bb : basic_blocks_) {
    if (bb.module_id < modules_.size()) {
      used_module_ids.insert(bb.module_id);
    }
  }

  log.dbg(
      "identified modules with coverage", redlog::field("total_modules", modules_.size()),
      redlog::field("used_modules", used_module_ids.size()),
      redlog::field("unused_modules", modules_.size() - used_module_ids.size())
  );

  // pass 2: build module id remapping (old id -> new sequential id)
  std::unordered_map<uint16_t, uint16_t> module_id_remap;
  uint16_t new_id = 0;
  for (uint16_t old_id = 0; old_id < modules_.size(); ++old_id) {
    if (used_module_ids.count(old_id) > 0) {
      module_id_remap[old_id] = new_id++;
    }
  }

  // create drcov builder with hitcount support enabled
  auto builder =
      drcov::builder().set_flavor("w1cov").enable_hitcounts().set_module_version(drcov::module_table_version::v2);

  // pass 3: add only modules that have coverage with validation
  size_t valid_modules = 0;
  size_t invalid_modules = 0;
  size_t skipped_modules = 0;

  log.trc("adding modules with coverage to drcov data");

  for (size_t i = 0; i < modules_.size(); ++i) {
    // skip modules without coverage
    if (used_module_ids.count(static_cast<uint16_t>(i)) == 0) {
      log.ped(
          "skipping module without coverage", redlog::field("id", i), redlog::field("name", modules_[i].name),
          redlog::field("base", format_hex(modules_[i].base_address))
      );
      skipped_modules++;
      continue;
    }

    const auto& mod = modules_[i];

    try {
      // validate module data before adding
      uint64_t module_end = mod.base_address + mod.size;
      if (mod.base_address >= module_end) {
        log.wrn(
            "invalid module address range detected", redlog::field("id", i), redlog::field("name", mod.name),
            redlog::field("base", mod.base_address), redlog::field("end", module_end)
        );
        invalid_modules++;
        continue;
      }

      if (mod.path.empty() && mod.name.empty()) {
        log.wrn("module has empty path and name", redlog::field("id", i), redlog::field("base", mod.base_address));
        invalid_modules++;
        continue;
      }

      // use path if available, otherwise use name
      std::string module_path = !mod.path.empty() ? mod.path : mod.name;

      builder.add_module(module_path, mod.base_address, mod.base_address + mod.size, mod.base_address);
      valid_modules++;

      log.dbg(
          "added module to drcov", redlog::field("old_id", i), redlog::field("new_id", module_id_remap[i]),
          redlog::field("name", mod.name), redlog::field("base", format_hex(mod.base_address)),
          redlog::field("size", mod.size)
      );

    } catch (const std::exception& e) {
      log.err(
          "failed to add module to drcov builder", redlog::field("id", i), redlog::field("name", mod.name),
          redlog::field("error", e.what())
      );
      invalid_modules++;
    }
  }

  log.inf(
      "module processing completed", redlog::field("valid", valid_modules), redlog::field("invalid", invalid_modules),
      redlog::field("skipped", skipped_modules)
  );

  // pass 4: add coverage units with remapped module ids and validation
  size_t valid_units = 0;
  size_t invalid_units = 0;
  size_t orphaned_units = 0;

  log.trc("adding coverage units to drcov data");

  for (const auto& bb : basic_blocks_) {
    try {
      // validate module id
      if (bb.module_id >= modules_.size()) {
        log.wrn(
            "coverage unit references unknown module", redlog::field("module_id", bb.module_id),
            redlog::field("address", format_hex(bb.address))
        );
        orphaned_units++;
        continue;
      }

      // check if module was included (has coverage)
      auto remap_it = module_id_remap.find(bb.module_id);
      if (remap_it == module_id_remap.end()) {
        // this shouldn't happen since we built the remap from basic blocks
        log.err(
            "coverage unit references module not in remap", redlog::field("module_id", bb.module_id),
            redlog::field("address", format_hex(bb.address))
        );
        invalid_units++;
        continue;
      }

      const auto& module = modules_[bb.module_id];
      uint16_t new_module_id = remap_it->second;

      // validate unit is within module bounds
      if (bb.address < module.base_address || bb.address >= module.base_address + module.size) {
        log.wrn(
            "coverage unit address outside module bounds", redlog::field("module_id", bb.module_id),
            redlog::field("address", format_hex(bb.address)), redlog::field("base", format_hex(module.base_address)),
            redlog::field("end", format_hex(module.base_address + module.size))
        );
        invalid_units++;
        continue;
      }

      // calculate module-relative offset
      uint32_t offset = static_cast<uint32_t>(bb.address - module.base_address);

      // validate offset calculation
      if (offset >= module.size) {
        log.wrn(
            "calculated offset exceeds module size", redlog::field("module_id", bb.module_id),
            redlog::field("offset", offset), redlog::field("module_size", module.size)
        );
        invalid_units++;
        continue;
      }

      // get hitcount for this address
      uint32_t hitcount = bb.hitcount;
      if (hitcount == 0) {
        // fallback to hitcounts map
        auto hitcount_it = hitcounts_.find(bb.address);
        if (hitcount_it != hitcounts_.end()) {
          hitcount = hitcount_it->second;
        } else {
          hitcount = 1; // default fallback
        }
      }

      builder.add_coverage(new_module_id, offset, bb.size, hitcount);
      valid_units++;

    } catch (const std::exception& e) {
      log.err(
          "failed to add coverage unit to drcov builder", redlog::field("module_id", bb.module_id),
          redlog::field("address", format_hex(bb.address)), redlog::field("error", e.what())
      );
      invalid_units++;
    }
  }

  log.dbg(
      "coverage unit processing completed", redlog::field("valid", valid_units),
      redlog::field("invalid", invalid_units), redlog::field("orphaned", orphaned_units)
  );

  if (valid_units == 0 && !basic_blocks_.empty()) {
    log.wrn("no valid coverage units were exported despite having collected data");
  }

  try {
    auto result = builder.build();

    log.trc(
        "drcov data export completed successfully", redlog::field("modules", valid_modules),
        redlog::field("units", valid_units)
    );

    return result;

  } catch (const std::exception& e) {
    log.err("failed to build drcov data structure", redlog::field("error", e.what()));
    throw; // re-throw to be handled by caller
  }
}

size_t coverage_collector::get_coverage_unit_count() const { return basic_blocks_.size(); }

size_t coverage_collector::get_module_count() const { return modules_.size(); }

uint64_t coverage_collector::get_total_hits() const {
  uint64_t total = 0;
  for (const auto& [addr, count] : hitcounts_) {
    total += count;
  }
  return total;
}

uint32_t coverage_collector::get_hitcount(QBDI::rword address) const {
  auto it = hitcounts_.find(address);
  return (it != hitcounts_.end()) ? it->second : 0;
}

const w1::runtime::module_info* coverage_collector::find_module_by_id(uint16_t id) const {
  if (id >= modules_.size()) {
    return nullptr;
  }
  return &modules_[id];
}

} // namespace w1cov
