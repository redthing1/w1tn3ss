#include "coverage.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <redlog.hpp>

#include "w1base/format_utils.hpp"
#include "w1formats/drcov.hpp"
#include "w1replay/modules/path_resolver.hpp"
#include "w1rewind/replay/flow_extractor.hpp"
#include "w1rewind/replay/mapping_state.hpp"
#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/trace/trace_reader.hpp"

namespace w1replay::commands {

namespace {

using w1::util::format_address;

enum class flow_mode { auto_detect, blocks, instructions };

struct coverage_build_options {
  flow_mode mode = flow_mode::auto_detect;
  uint64_t thread_id = 0;
  std::optional<uint32_t> space_id;
  bool include_unknown = false;
};

struct module_key {
  enum class kind { image_id, named_mapping, anonymous_mapping };

  kind kind = kind::image_id;
  uint64_t image_id = 0;
  std::string name;
  uint32_t space_id = 0;
  uint64_t base_hint = 0;

  bool operator==(const module_key& other) const {
    return kind == other.kind && image_id == other.image_id && name == other.name && space_id == other.space_id &&
           base_hint == other.base_hint;
  }
};

struct module_key_hash {
  size_t operator()(const module_key& key) const noexcept {
    size_t seed = static_cast<size_t>(key.kind);
    seed ^= std::hash<uint64_t>{}(key.image_id) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
    seed ^= std::hash<std::string>{}(key.name) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
    seed ^= std::hash<uint32_t>{}(key.space_id) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
    seed ^= std::hash<uint64_t>{}(key.base_hint) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
    return seed;
  }
};

struct module_state {
  module_key key{};
  std::string path;
  uint64_t base = 0;
  uint64_t end = 0;
  bool has_bounds = false;
};

struct coverage_unit_key {
  size_t module_index = 0;
  uint32_t offset = 0;
  uint16_t size = 0;

  bool operator==(const coverage_unit_key& other) const {
    return module_index == other.module_index && offset == other.offset && size == other.size;
  }
};

struct coverage_unit_key_hash {
  size_t operator()(const coverage_unit_key& key) const noexcept {
    size_t seed = std::hash<size_t>{}(key.module_index);
    seed ^= std::hash<uint32_t>{}(key.offset) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
    seed ^= std::hash<uint16_t>{}(key.size) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
    return seed;
  }
};

struct coverage_stats {
  uint64_t flow_records = 0;
  uint64_t flow_mapped = 0;
  uint64_t flow_unmapped = 0;
  uint64_t flow_skipped_thread = 0;
  uint64_t flow_skipped_space = 0;
  uint64_t units_overflow_offset = 0;
  uint64_t units_overflow_size = 0;
  uint64_t units_skipped_unknown = 0;
  uint64_t total_hits = 0;
};

std::string to_lower(std::string text) {
  std::transform(text.begin(), text.end(), text.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return text;
}

bool is_unknown_name(std::string_view name) {
  if (name.empty()) {
    return true;
  }
  return to_lower(std::string(name)) == "unknown";
}

uint64_t safe_end(uint64_t base, uint64_t size) {
  if (size == 0) {
    return base;
  }
  uint64_t end = base + size;
  if (end < base) {
    return std::numeric_limits<uint64_t>::max();
  }
  return end;
}

std::optional<flow_mode> parse_flow_mode(std::string_view value) {
  if (value.empty()) {
    return flow_mode::auto_detect;
  }
  std::string lower = to_lower(std::string(value));
  if (lower == "auto") {
    return flow_mode::auto_detect;
  }
  if (lower == "block" || lower == "blocks") {
    return flow_mode::blocks;
  }
  if (lower == "inst" || lower == "instruction" || lower == "instructions") {
    return flow_mode::instructions;
  }
  return std::nullopt;
}

std::optional<uint32_t> parse_space_id(std::string_view text) {
  try {
    size_t idx = 0;
    unsigned long value = std::stoul(std::string(text), &idx, 0);
    if (idx != text.size()) {
      return std::nullopt;
    }
    if (value > std::numeric_limits<uint32_t>::max()) {
      return std::nullopt;
    }
    return static_cast<uint32_t>(value);
  } catch (const std::exception&) {
    return std::nullopt;
  }
}

std::optional<uint32_t> resolve_space_id(
    const w1::rewind::replay_context& context, std::string_view selector, std::string& error
) {
  if (selector.empty()) {
    return std::nullopt;
  }
  if (auto parsed = parse_space_id(selector)) {
    return *parsed;
  }
  for (const auto& space : context.address_spaces) {
    if (space.name == selector) {
      return space.space_id;
    }
  }
  error = "unknown address space: " + std::string(selector);
  return std::nullopt;
}

std::string resolve_image_path(
    const w1::rewind::replay_context& context, const w1::rewind::mapping_record& mapping,
    const image_path_resolver* resolver
) {
  if (mapping.image_id != 0) {
    if (const auto* image = context.find_image(mapping.image_id)) {
      if (resolver) {
        if (auto resolved = resolver->resolve_image_path(*image)) {
          return *resolved;
        }
      }
      if (!image->path.empty()) {
        return image->path;
      }
      if (!image->name.empty()) {
        return image->name;
      }
      if (!image->identity.empty()) {
        return image->identity;
      }
    }
  }

  if (!mapping.name.empty()) {
    if (resolver) {
      if (auto resolved = resolver->resolve_region_name(mapping.name)) {
        return *resolved;
      }
    }
    return mapping.name;
  }

  return {};
}

class coverage_accumulator {
public:
  coverage_accumulator(
      const w1::rewind::replay_context& context, w1::rewind::flow_kind flow_kind, const image_path_resolver* resolver,
      coverage_build_options options
  )
      : context_(context), resolver_(resolver), options_(std::move(options)), extractor_(&context) {
    extractor_.set_flow_kind(flow_kind);
  }

  bool handle_record(const w1::rewind::trace_record& record, std::string& error) {
    if (std::holds_alternative<w1::rewind::mapping_record>(record)) {
      if (!apply_mapping(std::get<w1::rewind::mapping_record>(record), error)) {
        return false;
      }
    }

    w1::rewind::flow_step flow{};
    bool is_flow = false;
    std::string extract_error;
    if (!extractor_.try_extract(record, flow, is_flow, extract_error)) {
      error = extract_error.empty() ? "failed to extract flow record" : extract_error;
      return false;
    }
    if (!is_flow) {
      return true;
    }
    return handle_flow(flow);
  }

  drcov::coverage_data build_drcov(std::string& error) {
    error.clear();

    std::unordered_set<size_t> used_modules;
    used_modules.reserve(hitcounts_.size());
    for (const auto& entry : hitcounts_) {
      used_modules.insert(entry.first.module_index);
    }

    std::unordered_map<size_t, uint16_t> module_id_map;
    module_id_map.reserve(used_modules.size());

    auto builder = drcov::builder().enable_hitcounts().set_module_version(drcov::module_table_version::v2);
    uint16_t next_id = 0;

    for (size_t index = 0; index < modules_.size(); ++index) {
      if (used_modules.count(index) == 0) {
        continue;
      }
      auto& module = modules_[index];
      if (!module.has_bounds || module.end <= module.base) {
        continue;
      }
      if (next_id == std::numeric_limits<uint16_t>::max()) {
        error = "too many modules to export";
        return drcov::coverage_data{};
      }
      module_id_map[index] = next_id++;
      std::string path = module.path.empty() ? ("module@" + format_address(module.base)) : module.path;
      builder.add_module(path, module.base, module.end, module.base);
    }

    for (const auto& entry : hitcounts_) {
      auto it = module_id_map.find(entry.first.module_index);
      if (it == module_id_map.end()) {
        continue;
      }
      uint32_t hitcount = entry.second > std::numeric_limits<uint32_t>::max() ? std::numeric_limits<uint32_t>::max()
                                                                              : static_cast<uint32_t>(entry.second);
      builder.add_coverage(it->second, entry.first.offset, entry.first.size, hitcount);
    }

    return builder.build();
  }

  const coverage_stats& stats() const { return stats_; }

  size_t module_count() const { return modules_.size(); }
  size_t unit_count() const { return hitcounts_.size(); }

private:
  std::optional<size_t> ensure_module(const w1::rewind::mapping_record& mapping) {
    module_key key{};
    std::string path = resolve_image_path(context_, mapping, resolver_);

    if (mapping.image_id != 0) {
      key.kind = module_key::kind::image_id;
      key.image_id = mapping.image_id;
    } else if (!is_unknown_name(path)) {
      key.kind = module_key::kind::named_mapping;
      key.name = path;
    } else {
      if (!options_.include_unknown) {
        return std::nullopt;
      }
      key.kind = module_key::kind::anonymous_mapping;
      key.space_id = mapping.space_id;
      key.base_hint = mapping.base;
      path = "unknown@" + format_address(mapping.base);
    }

    auto it = module_lookup_.find(key);
    if (it != module_lookup_.end()) {
      auto& module = modules_[it->second];
      if (module.path.empty() && !path.empty()) {
        module.path = path;
      }
      update_module_bounds(module, mapping);
      return it->second;
    }

    module_state module{};
    module.key = key;
    module.path = path;
    update_module_bounds(module, mapping);

    modules_.push_back(std::move(module));
    module_lookup_.emplace(modules_.back().key, modules_.size() - 1);
    return modules_.size() - 1;
  }

  void update_module_bounds(module_state& module, const w1::rewind::mapping_record& mapping) {
    if (mapping.size == 0) {
      return;
    }

    uint64_t base_candidate = mapping.base;
    if (mapping.image_id != 0 && mapping.image_offset <= mapping.base) {
      base_candidate = mapping.base - mapping.image_offset;
    }
    uint64_t end_candidate = safe_end(mapping.base, mapping.size);

    if (!module.has_bounds) {
      module.base = base_candidate;
      module.end = end_candidate;
      module.has_bounds = true;
      return;
    }

    module.base = std::min(module.base, base_candidate);
    module.end = std::max(module.end, end_candidate);
  }

  bool apply_mapping(const w1::rewind::mapping_record& mapping, std::string& error) {
    std::string apply_error;
    if (!mappings_.apply_event(mapping, apply_error)) {
      error = apply_error.empty() ? "failed to apply mapping event" : apply_error;
      return false;
    }

    if (mapping.kind == w1::rewind::mapping_event_kind::map) {
      ensure_module(mapping);
    }

    return true;
  }

  bool handle_flow(const w1::rewind::flow_step& flow) {
    if (options_.thread_id != 0 && flow.thread_id != options_.thread_id) {
      stats_.flow_skipped_thread++;
      return true;
    }
    if (options_.space_id.has_value() && flow.space_id != *options_.space_id) {
      stats_.flow_skipped_space++;
      return true;
    }

    stats_.flow_records++;

    const uint64_t lookup_size = flow.size == 0 ? 1 : flow.size;
    uint64_t mapping_offset = 0;
    const auto* mapping = mappings_.find_mapping_for_address(flow.space_id, flow.address, lookup_size, mapping_offset);
    if (!mapping) {
      stats_.flow_unmapped++;
      return true;
    }

    auto module_index = ensure_module(*mapping);
    if (!module_index.has_value()) {
      stats_.units_skipped_unknown++;
      return true;
    }

    auto& module = modules_[*module_index];
    if (!module.has_bounds) {
      update_module_bounds(module, *mapping);
    }

    if (flow.address < module.base) {
      stats_.flow_unmapped++;
      return true;
    }
    uint64_t offset64 = flow.address - module.base;
    if (offset64 > std::numeric_limits<uint32_t>::max()) {
      stats_.units_overflow_offset++;
      return true;
    }
    uint32_t offset = static_cast<uint32_t>(offset64);

    uint32_t size32 = flow.size == 0 ? 1u : flow.size;
    if (size32 > std::numeric_limits<uint16_t>::max()) {
      stats_.units_overflow_size++;
      return true;
    }

    coverage_unit_key key{};
    key.module_index = *module_index;
    key.offset = offset;
    key.size = static_cast<uint16_t>(size32);
    hitcounts_[key] += 1;
    stats_.total_hits += 1;
    stats_.flow_mapped++;
    return true;
  }

  const w1::rewind::replay_context& context_;
  const image_path_resolver* resolver_ = nullptr;
  coverage_build_options options_;
  w1::rewind::mapping_state mappings_;
  w1::rewind::flow_extractor extractor_;

  std::vector<module_state> modules_;
  std::unordered_map<module_key, size_t, module_key_hash> module_lookup_;
  std::unordered_map<coverage_unit_key, uint64_t, coverage_unit_key_hash> hitcounts_;
  coverage_stats stats_{};
};

} // namespace

int coverage(const coverage_options& options) {
  auto log = redlog::get_logger("w1replay.coverage");

  if (options.trace_path.empty()) {
    log.err("trace path required");
    std::cerr << "error: --trace is required" << std::endl;
    return 1;
  }

  w1::rewind::replay_context context;
  std::string context_error;
  if (!w1::rewind::load_replay_context(options.trace_path, context, context_error)) {
    log.err("failed to load trace metadata", redlog::field("error", context_error));
    std::cerr << "error: " << context_error << std::endl;
    return 1;
  }

  std::string flow_error;
  auto parsed_mode = parse_flow_mode(options.flow);
  if (!parsed_mode.has_value()) {
    log.err("invalid flow mode", redlog::field("value", options.flow));
    std::cerr << "error: invalid --flow (use auto, blocks, instructions)" << std::endl;
    return 1;
  }
  flow_mode mode = *parsed_mode;

  if (mode == flow_mode::auto_detect) {
    if (context.features.has_block_exec) {
      mode = flow_mode::blocks;
    } else if (context.features.has_flow_instruction) {
      mode = flow_mode::instructions;
    } else {
      log.err("trace has no flow records");
      std::cerr << "error: trace has no flow records" << std::endl;
      return 1;
    }
  }

  if (mode == flow_mode::blocks && !context.features.has_block_exec) {
    log.err("trace has no block flow records");
    std::cerr << "error: trace has no block flow records" << std::endl;
    return 1;
  }
  if (mode == flow_mode::instructions && !context.features.has_flow_instruction) {
    log.err("trace has no instruction flow records");
    std::cerr << "error: trace has no instruction flow records" << std::endl;
    return 1;
  }

  std::string space_error;
  auto space_id = resolve_space_id(context, options.space, space_error);
  if (!space_error.empty()) {
    log.err("invalid address space", redlog::field("error", space_error));
    std::cerr << "error: " << space_error << std::endl;
    return 1;
  }

  auto resolver = make_image_path_resolver(options.image_mappings, options.image_dirs);

  coverage_build_options build_options{};
  build_options.mode = mode;
  build_options.thread_id = options.thread_id;
  build_options.space_id = space_id;
  build_options.include_unknown = options.include_unknown;

  w1::rewind::trace_reader reader(options.trace_path);
  if (!reader.open()) {
    log.err("failed to open trace", redlog::field("error", reader.error()));
    std::cerr << "error: " << reader.error() << std::endl;
    return 1;
  }

  w1::rewind::flow_kind flow_kind =
      mode == flow_mode::blocks ? w1::rewind::flow_kind::blocks : w1::rewind::flow_kind::instructions;
  coverage_accumulator accumulator(context, flow_kind, resolver.get(), build_options);

  w1::rewind::trace_record record;
  std::string scan_error;
  while (reader.read_next(record)) {
    if (!accumulator.handle_record(record, scan_error)) {
      log.err("failed to scan trace", redlog::field("error", scan_error));
      std::cerr << "error: " << scan_error << std::endl;
      return 1;
    }
  }

  if (!reader.error().empty()) {
    log.err("trace read failed", redlog::field("error", reader.error()));
    std::cerr << "error: " << reader.error() << std::endl;
    return 1;
  }

  std::string output_path = options.output_path;
  if (output_path.empty()) {
    output_path = options.trace_path + ".drcov";
  }

  std::string build_error;
  auto data = accumulator.build_drcov(build_error);
  if (!build_error.empty()) {
    log.err("failed to build drcov data", redlog::field("error", build_error));
    std::cerr << "error: " << build_error << std::endl;
    return 1;
  }

  try {
    drcov::write(output_path, data);
  } catch (const std::exception& e) {
    log.err("failed to write drcov output", redlog::field("error", e.what()));
    std::cerr << "error: " << e.what() << std::endl;
    return 1;
  }

  const auto& stats = accumulator.stats();
  std::cout << "coverage export completed successfully.\n";
  std::cout << "  output=" << output_path << "\n";
  std::cout << "  mode=" << (mode == flow_mode::blocks ? "blocks" : "instructions") << "\n";
  std::cout << "  modules=" << data.modules.size() << "/" << accumulator.module_count()
            << " units=" << data.basic_blocks.size() << " hits=" << stats.total_hits << "\n";
  std::cout << "  flow_records=" << stats.flow_records << " mapped=" << stats.flow_mapped
            << " unmapped=" << stats.flow_unmapped << "\n";
  if (stats.units_skipped_unknown > 0) {
    std::cout << "  skipped_unknown=" << stats.units_skipped_unknown << "\n";
  }
  if (stats.units_overflow_offset > 0 || stats.units_overflow_size > 0) {
    std::cout << "  skipped_overflow=offset:" << stats.units_overflow_offset << " size:" << stats.units_overflow_size
              << "\n";
  }

  return 0;
}

} // namespace w1replay::commands
