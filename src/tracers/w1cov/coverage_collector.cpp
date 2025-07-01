#include "coverage_collector.hpp"
#include <redlog/redlog.hpp>
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

  auto it = address_to_bb_index_.find(address);
  if (it != address_to_bb_index_.end()) {
    basic_blocks_[it->second].hitcount++;
  } else {
    basic_block_info bb;
    bb.address = address;
    bb.size = size;
    bb.module_id = module_id;
    bb.hitcount = 1;

    size_t index = basic_blocks_.size();
    basic_blocks_.push_back(bb);
    address_to_bb_index_[address] = index;
  }
}

drcov::coverage_data coverage_collector::build_drcov_data() const {
  auto log = redlog::get_logger("w1cov.collector");
  drcov::coverage_data data;

  // ensure we have modules to export
  if (modules_.empty()) {
    log.wrn("no modules to export");
    return data;
  }

  log.trc(
      "building drcov data", redlog::field("module_count", modules_.size()),
      redlog::field("basic_block_count", basic_blocks_.size())
  );

  log.dbg("processing modules for export", redlog::field("total_modules", modules_.size()));

  // create mapping from original module index to exported module index
  std::vector<int> export_id_map(modules_.size(), -1);
  size_t exported_count = 0;
  size_t skipped_count = 0;

  // first pass: determine which modules to export and assign new IDs
  for (size_t i = 0; i < modules_.size(); ++i) {
    const auto& mod = modules_[i];

    // Skip modules with invalid data
    if (mod.base_address >= mod.base_address + mod.size) {
      log.dbg(
          "skipping module with invalid address range", redlog::field("module_index", i),
          redlog::field("module_name", mod.name)
      );
      skipped_count++;
      continue;
    }

    if (mod.path.empty() && mod.name.empty()) {
      log.dbg("skipping module with empty path and name", redlog::field("module_index", i));
      skipped_count++;
      continue;
    }

    export_id_map[i] = static_cast<int>(exported_count++);

    log.dbg(
        "exporting module", redlog::field("module_index", i), redlog::field("module_name", mod.name),
        redlog::field("export_id", export_id_map[i])
    );
  }

  // second pass: create the actual module entries
  for (size_t i = 0; i < modules_.size(); ++i) {
    if (export_id_map[i] == -1) {
      continue; // skip this module
    }

    const auto& mod = modules_[i];
    drcov::module_entry entry;

    // use the mapped export ID
    entry.id = static_cast<uint16_t>(export_id_map[i]);
    entry.containing_id = entry.id;
    entry.base = mod.base_address;
    entry.end = mod.base_address + mod.size;
    entry.entry = mod.base_address;
    // use name if path is empty, or fallback to <unknown>
    if (!mod.path.empty()) {
      entry.path = mod.path;
    } else if (!mod.name.empty()) {
      entry.path = mod.name;
    } else {
      entry.path = "<unknown>";
    }
    entry.checksum = 0;
    entry.timestamp = 0;

    data.modules.push_back(entry);
  }

  log.dbg(
      "module processing completed", redlog::field("exported_modules", exported_count),
      redlog::field("skipped_modules", skipped_count)
  );

  log.dbg("processing basic blocks for export", redlog::field("total_basic_blocks", basic_blocks_.size()));

  size_t bb_count = 0;
  size_t bb_skipped = 0;

  for (const auto& bb : basic_blocks_) {
    // only include basic blocks from modules that are being exported
    if (bb.module_id >= export_id_map.size() || export_id_map[bb.module_id] == -1) {
      bb_skipped++;
      continue; // skip basic blocks from excluded modules
    }

    drcov::basic_block entry;
    entry.start = static_cast<uint32_t>(bb.address);
    entry.size = bb.size;
    entry.module_id = static_cast<uint16_t>(export_id_map[bb.module_id]); // use mapped ID

    data.basic_blocks.push_back(entry);
    bb_count++;
  }

  log.dbg(
      "basic block processing completed", redlog::field("exported_basic_blocks", bb_count),
      redlog::field("skipped_basic_blocks", bb_skipped)
  );

  return data;
}

size_t coverage_collector::get_basic_block_count() const { return basic_blocks_.size(); }

size_t coverage_collector::get_module_count() const { return modules_.size(); }

} // namespace w1cov