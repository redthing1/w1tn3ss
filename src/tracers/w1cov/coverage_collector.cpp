#include "coverage_collector.hpp"
#include <w1tn3ss/formats/drcov.hpp>
#include <redlog.hpp>
#include <algorithm>

namespace w1cov {

coverage_collector::coverage_collector() {}

uint16_t coverage_collector::add_module(const w1::util::module_info& mod) {
  auto it = std::find_if(modules_.begin(), modules_.end(), [&mod](const w1::util::module_info& existing) {
    return existing.base_address == mod.base_address;
  });

  if (it != modules_.end()) {
    return static_cast<uint16_t>(std::distance(modules_.begin(), it));
  }

  modules_.push_back(mod);
  return static_cast<uint16_t>(modules_.size() - 1);
}

void coverage_collector::record_basic_block(QBDI::rword address, uint16_t size, uint16_t module_id) {
  // increment hitcount for this address
  hitcounts_[address]++;

  // check if this is a new address
  auto it = address_to_bb_index_.find(address);
  if (it == address_to_bb_index_.end()) {
    // new basic block
    basic_block_info bb;
    bb.address = address;
    bb.size = size;
    bb.module_id = module_id;
    bb.hitcount = hitcounts_[address];

    size_t index = basic_blocks_.size();
    basic_blocks_.push_back(bb);
    address_to_bb_index_[address] = index;
  } else {
    // existing basic block - update hitcount
    basic_blocks_[it->second].hitcount = hitcounts_[address];
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
      redlog::field("basic_block_count", basic_blocks_.size()), redlog::field("total_hits", get_total_hits())
  );

  // create drcov builder with hitcount support enabled
  auto builder =
      drcov::builder().set_flavor("w1cov").enable_hitcounts().set_module_version(drcov::module_table_version::v2);

  // pass 1: add modules with validation
  size_t valid_modules = 0;
  size_t invalid_modules = 0;

  log.dbg("adding modules to drcov data");

  for (size_t i = 0; i < modules_.size(); ++i) {
    const auto& mod = modules_[i];

    try {
      // validate module data before adding
      if (mod.base_address >= mod.base_address + mod.size) {
        log.wrn(
            "invalid module address range detected", redlog::field("id", i), redlog::field("name", mod.name),
            redlog::field("base", mod.base_address), redlog::field("end", mod.base_address + mod.size)
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

      log.trc(
          "added module to drcov", redlog::field("id", i), redlog::field("name", mod.name),
          redlog::field("base", "0x%08x", mod.base_address), redlog::field("size", mod.size)
      );

    } catch (const std::exception& e) {
      log.err(
          "failed to add module to drcov builder", redlog::field("id", i), redlog::field("name", mod.name),
          redlog::field("error", e.what())
      );
      invalid_modules++;
    }
  }

  log.dbg(
      "module processing completed", redlog::field("valid", valid_modules), redlog::field("invalid", invalid_modules)
  );

  // pass 2: add basic blocks with hitcounts and validation
  size_t valid_blocks = 0;
  size_t invalid_blocks = 0;
  size_t orphaned_blocks = 0;

  log.dbg("adding basic blocks to drcov data");

  for (const auto& bb : basic_blocks_) {
    try {
      // validate module id
      if (bb.module_id >= modules_.size()) {
        log.trc(
            "basic block references unknown module", redlog::field("module_id", bb.module_id),
            redlog::field("address", "0x%08x", bb.address)
        );
        orphaned_blocks++;
        continue;
      }

      const auto& module = modules_[bb.module_id];

      // validate block is within module bounds
      if (bb.address < module.base_address || bb.address >= module.base_address + module.size) {
        log.wrn(
            "basic block address outside module bounds", redlog::field("module_id", bb.module_id),
            redlog::field("address", "0x%08x", bb.address), redlog::field("base", "0x%08x", module.base_address),
            redlog::field("end", "0x%08x", module.base_address + module.size)
        );
        invalid_blocks++;
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
        invalid_blocks++;
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

      builder.add_coverage(bb.module_id, offset, bb.size, hitcount);
      valid_blocks++;

    } catch (const std::exception& e) {
      log.err(
          "failed to add basic block to drcov builder", redlog::field("module_id", bb.module_id),
          redlog::field("address", "0x%08x", bb.address), redlog::field("error", e.what())
      );
      invalid_blocks++;
    }
  }

  log.dbg(
      "basic block processing completed", redlog::field("valid", valid_blocks),
      redlog::field("invalid", invalid_blocks), redlog::field("orphaned", orphaned_blocks)
  );

  if (valid_blocks == 0 && !basic_blocks_.empty()) {
    log.wrn("no valid basic blocks were exported despite having collected data");
  }

  try {
    auto result = builder.build();

    log.dbg(
        "drcov data export completed successfully", redlog::field("modules", valid_modules),
        redlog::field("blocks", valid_blocks)
    );

    return result;

  } catch (const std::exception& e) {
    log.err("failed to build drcov data structure", redlog::field("error", e.what()));
    throw; // re-throw to be handled by caller
  }
}

size_t coverage_collector::get_basic_block_count() const { return basic_blocks_.size(); }

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

const w1::util::module_info* coverage_collector::find_module_by_id(uint16_t id) const {
  if (id >= modules_.size()) {
    return nullptr;
  }
  return &modules_[id];
}

} // namespace w1cov