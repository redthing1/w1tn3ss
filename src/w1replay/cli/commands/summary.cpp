#include "summary.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <redlog.hpp>

#include "w1rewind/format/register_metadata.hpp"
#include "w1rewind/format/trace_format.hpp"
#include "w1rewind/format/trace_io.hpp"
#include "w1rewind/format/trace_validator.hpp"
#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/trace/replay_checkpoint.hpp"
#include "w1rewind/trace/trace_index.hpp"
#include "w1rewind/trace/trace_reader.hpp"

namespace w1replay::commands {

namespace summary_detail {

constexpr const char* k_indent1 = "  ";
constexpr const char* k_indent2 = "    ";
constexpr const char* k_indent3 = "      ";

struct address_span {
  bool has = false;
  uint64_t min = 0;
  uint64_t max = 0;

  void update(uint64_t address, uint64_t size) {
    if (size == 0) {
      return;
    }
    uint64_t end = address + size;
    if (end < address) {
      end = std::numeric_limits<uint64_t>::max();
    }
    if (!has) {
      min = address;
      max = end;
      has = true;
      return;
    }
    min = std::min(min, address);
    max = std::max(max, end);
  }
};

struct record_counters {
  uint64_t total = 0;
  uint64_t target_info = 0;
  uint64_t target_environment = 0;
  uint64_t register_spec = 0;
  uint64_t module_table = 0;
  uint64_t module_load = 0;
  uint64_t module_unload = 0;
  uint64_t memory_map = 0;
  uint64_t thread_start = 0;
  uint64_t thread_end = 0;
  uint64_t instruction = 0;
  uint64_t block_definition = 0;
  uint64_t block_exec = 0;
  uint64_t register_deltas = 0;
  uint64_t register_bytes = 0;
  uint64_t memory_access = 0;
  uint64_t snapshot = 0;
};

struct thread_stats {
  bool has_flow = false;
  uint64_t flow_count = 0;
  uint64_t first_seq = 0;
  uint64_t last_seq = 0;
  uint64_t mem_access = 0;
  uint64_t mem_read = 0;
  uint64_t mem_write = 0;
  uint64_t mem_bytes = 0;
  uint64_t mem_known = 0;
  uint64_t mem_truncated = 0;
  uint64_t snapshots = 0;
  uint64_t snapshot_stack_bytes = 0;
  uint64_t reg_delta_records = 0;
  uint64_t reg_delta_entries = 0;
  uint64_t reg_bytes_records = 0;
  uint64_t reg_bytes_entries = 0;
  uint64_t reg_bytes_data = 0;
};

struct module_hit_stats {
  uint64_t flow_hits = 0;
  uint64_t mem_hits = 0;
  uint64_t mem_bytes = 0;
};

struct scan_stats {
  record_counters records{};
  uint64_t instruction_bytes = 0;
  uint64_t block_bytes = 0;
  uint64_t register_delta_entries = 0;
  uint64_t register_bytes_entries = 0;
  uint64_t register_bytes_data = 0;
  uint64_t memory_access_bytes = 0;
  uint64_t memory_access_known = 0;
  uint64_t memory_access_truncated = 0;
  uint64_t memory_access_reads = 0;
  uint64_t memory_access_writes = 0;
  uint64_t snapshot_stack_bytes = 0;
  uint64_t snapshot_register_entries = 0;
  uint64_t chunk_count = 0;
  uint64_t compressed_bytes = 0;
  uint64_t uncompressed_bytes = 0;
  uint64_t flow_records = 0;
  uint64_t flow_mapped = 0;
  uint64_t flow_unmapped = 0;
  uint64_t memory_mapped = 0;
  uint64_t memory_unmapped = 0;
  address_span flow_span{};
  std::unordered_map<uint64_t, thread_stats> threads{};
  std::unordered_map<uint64_t, module_hit_stats> module_hits{};
};

struct scan_result {
  w1::rewind::replay_context context;
  scan_stats stats;
};

struct checkpoint_info {
  bool exists = false;
  bool valid = false;
  std::string path;
  std::string error;
  w1::rewind::replay_checkpoint_header header{};
  uint32_t thread_count = 0;
  uint32_t entry_count = 0;
};

struct index_info {
  w1::rewind::trace_index_status status = w1::rewind::trace_index_status::missing;
  std::string path;
  std::string error;
  std::optional<w1::rewind::trace_index> index;
};

struct column_spec {
  std::string header;
  bool right = false;
  size_t width = 0;
};

struct summary_context {
  const summary_options& options;
  const scan_result& scan;
  const index_info& index;
  const checkpoint_info& checkpoint;
  const std::vector<std::string>& warnings;
};

std::string format_number(uint64_t value) {
  std::string out = std::to_string(value);
  for (std::ptrdiff_t i = static_cast<std::ptrdiff_t>(out.size()) - 3; i > 0; i -= 3) {
    out.insert(static_cast<size_t>(i), ",");
  }
  return out;
}

std::string format_decimal(double value, int precision) {
  std::ostringstream out;
  out << std::fixed << std::setprecision(precision) << value;
  std::string text = out.str();
  if (precision > 0) {
    while (!text.empty() && text.back() == '0') {
      text.pop_back();
    }
    if (!text.empty() && text.back() == '.') {
      text.pop_back();
    }
  }
  if (text.empty()) {
    return "0";
  }
  return text;
}

std::string format_bytes(uint64_t bytes) {
  static constexpr const char* suffixes[] = {"b", "kb", "mb", "gb", "tb", "pb"};
  constexpr size_t suffix_count = sizeof(suffixes) / sizeof(suffixes[0]);
  double value = static_cast<double>(bytes);
  size_t suffix_index = 0;
  while (value >= 1024.0 && suffix_index + 1 < suffix_count) {
    value /= 1024.0;
    ++suffix_index;
  }
  if (suffix_index == 0) {
    return format_number(bytes) + "b";
  }
  return format_decimal(value, 1) + suffixes[suffix_index];
}

std::string format_address(uint64_t address) {
  std::ostringstream out;
  out << "0x" << std::hex << address;
  return out.str();
}

std::string format_bool(bool value) { return value ? "true" : "false"; }

std::string format_byte_order(w1::arch::byte_order order) {
  switch (order) {
  case w1::arch::byte_order::little:
    return "little";
  case w1::arch::byte_order::big:
    return "big";
  default:
    return "unknown";
  }
}

std::string format_arch_family(w1::arch::family family) {
  switch (family) {
  case w1::arch::family::x86:
    return "x86";
  case w1::arch::family::arm:
    return "arm";
  case w1::arch::family::riscv:
    return "riscv";
  case w1::arch::family::mips:
    return "mips";
  case w1::arch::family::ppc:
    return "ppc";
  case w1::arch::family::sparc:
    return "sparc";
  case w1::arch::family::systemz:
    return "systemz";
  case w1::arch::family::wasm:
    return "wasm";
  default:
    return "unknown";
  }
}

std::string format_arch_mode(w1::arch::mode mode) {
  switch (mode) {
  case w1::arch::mode::x86_32:
    return "x86";
  case w1::arch::mode::x86_64:
    return "x86_64";
  case w1::arch::mode::arm:
    return "arm";
  case w1::arch::mode::thumb:
    return "thumb";
  case w1::arch::mode::aarch64:
    return "arm64";
  case w1::arch::mode::riscv32:
    return "riscv32";
  case w1::arch::mode::riscv64:
    return "riscv64";
  case w1::arch::mode::mips32:
    return "mips32";
  case w1::arch::mode::mips64:
    return "mips64";
  case w1::arch::mode::ppc32:
    return "ppc32";
  case w1::arch::mode::ppc64:
    return "ppc64";
  case w1::arch::mode::sparc32:
    return "sparc32";
  case w1::arch::mode::sparc64:
    return "sparc64";
  case w1::arch::mode::systemz:
    return "systemz";
  case w1::arch::mode::wasm32:
    return "wasm32";
  case w1::arch::mode::wasm64:
    return "wasm64";
  default:
    return "unknown";
  }
}

std::string format_trace_flags(uint64_t flags) {
  std::vector<std::string> parts;
  if ((flags & w1::rewind::trace_flag_instructions) != 0) {
    parts.emplace_back("instruction");
  }
  if ((flags & w1::rewind::trace_flag_blocks) != 0) {
    parts.emplace_back("blocks");
  }
  if ((flags & w1::rewind::trace_flag_register_deltas) != 0) {
    parts.emplace_back("reg_deltas");
  }
  if ((flags & w1::rewind::trace_flag_memory_access) != 0) {
    parts.emplace_back("mem_access");
  }
  if ((flags & w1::rewind::trace_flag_memory_values) != 0) {
    parts.emplace_back("mem_values");
  }
  if ((flags & w1::rewind::trace_flag_snapshots) != 0) {
    parts.emplace_back("snapshots");
  }
  if ((flags & w1::rewind::trace_flag_stack_snapshot) != 0) {
    parts.emplace_back("stack_snapshots");
  }
  if (parts.empty()) {
    return "none";
  }
  std::ostringstream out;
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i > 0) {
      out << "|";
    }
    out << parts[i];
  }
  return out.str();
}

std::string format_compression(w1::rewind::trace_compression compression) {
  switch (compression) {
  case w1::rewind::trace_compression::none:
    return "none";
  case w1::rewind::trace_compression::zstd:
    return "zstd";
  default:
    return "unknown";
  }
}

std::string format_module_format(w1::rewind::module_format format) {
  switch (format) {
  case w1::rewind::module_format::elf:
    return "elf";
  case w1::rewind::module_format::macho:
    return "macho";
  case w1::rewind::module_format::pe:
    return "pe";
  default:
    return "unknown";
  }
}

std::string format_perms(w1::rewind::module_perm perms) {
  std::string out = "---";
  if ((perms & w1::rewind::module_perm::read) != w1::rewind::module_perm::none) {
    out[0] = 'r';
  }
  if ((perms & w1::rewind::module_perm::write) != w1::rewind::module_perm::none) {
    out[1] = 'w';
  }
  if ((perms & w1::rewind::module_perm::exec) != w1::rewind::module_perm::none) {
    out[2] = 'x';
  }
  return out;
}

std::string format_flow_kind(uint64_t flags) {
  bool use_blocks = (flags & w1::rewind::trace_flag_blocks) != 0;
  bool use_instructions = (flags & w1::rewind::trace_flag_instructions) != 0;
  if (use_blocks == use_instructions) {
    return "unknown";
  }
  return use_blocks ? "blocks" : "instruction";
}

std::string format_index_status(w1::rewind::trace_index_status status) {
  switch (status) {
  case w1::rewind::trace_index_status::ok:
    return "ok";
  case w1::rewind::trace_index_status::missing:
    return "missing";
  case w1::rewind::trace_index_status::stale:
    return "stale";
  case w1::rewind::trace_index_status::incompatible:
    return "incompatible";
  default:
    return "unknown";
  }
}

std::string format_span(const address_span& span) {
  if (!span.has) {
    return "n/a";
  }
  std::ostringstream out;
  out << format_address(span.min) << "-" << format_address(span.max);
  return out.str();
}

std::string format_reg_class(w1::rewind::register_class cls) {
  switch (cls) {
  case w1::rewind::register_class::gpr:
    return "gpr";
  case w1::rewind::register_class::fpr:
    return "fpr";
  case w1::rewind::register_class::simd:
    return "simd";
  case w1::rewind::register_class::flags:
    return "flags";
  case w1::rewind::register_class::system:
    return "system";
  default:
    return "unknown";
  }
}

std::string format_reg_classes(const std::vector<w1::rewind::register_spec>& specs) {
  std::map<std::string, uint64_t> counts;
  for (const auto& spec : specs) {
    counts[format_reg_class(spec.reg_class)] += 1;
  }
  if (counts.empty()) {
    return "none";
  }
  std::ostringstream out;
  bool first = true;
  for (const auto& [name, count] : counts) {
    if (!first) {
      out << " ";
    }
    first = false;
    out << name << ":" << format_number(count);
  }
  return out.str();
}

std::string format_permissions_summary(const std::vector<w1::rewind::memory_region_record>& regions) {
  if (regions.empty()) {
    return "none";
  }
  struct bucket {
    uint64_t count = 0;
    uint64_t bytes = 0;
  };
  std::map<std::string, bucket> buckets;
  for (const auto& region : regions) {
    auto key = format_perms(region.permissions);
    buckets[key].count += 1;
    buckets[key].bytes += region.size;
  }
  std::ostringstream out;
  bool first = true;
  for (const auto& [perm, info] : buckets) {
    if (!first) {
      out << " ";
    }
    first = false;
    out << perm << ":" << format_number(info.count) << "(" << format_bytes(info.bytes) << ")";
  }
  return out.str();
}

void push_if(std::vector<std::string>& items, bool cond, std::string value) {
  if (cond) {
    items.push_back(std::move(value));
  }
}

void print_kv_line(const std::vector<std::string>& items) {
  if (items.empty()) {
    return;
  }
  std::cout << k_indent2 << items.front();
  for (size_t i = 1; i < items.size(); ++i) {
    std::cout << "  " << items[i];
  }
  std::cout << "\n";
}

void print_table(const std::vector<column_spec>& columns, const std::vector<std::vector<std::string>>& rows) {
  if (columns.empty()) {
    return;
  }
  std::vector<column_spec> resolved = columns;
  for (auto& column : resolved) {
    column.width = column.header.size();
  }
  for (const auto& row : rows) {
    for (size_t i = 0; i < resolved.size() && i < row.size(); ++i) {
      resolved[i].width = std::max(resolved[i].width, row[i].size());
    }
  }

  std::cout << k_indent2;
  for (size_t i = 0; i < resolved.size(); ++i) {
    const auto& column = resolved[i];
    std::ostringstream cell;
    cell << (column.right ? std::right : std::left) << std::setw(static_cast<int>(column.width)) << column.header;
    std::cout << cell.str();
    if (i + 1 < resolved.size()) {
      std::cout << "  ";
    }
  }
  std::cout << "\n";

  for (const auto& row : rows) {
    std::cout << k_indent2;
    for (size_t i = 0; i < resolved.size(); ++i) {
      const auto& column = resolved[i];
      std::string value = i < row.size() ? row[i] : "";
      std::ostringstream cell;
      cell << (column.right ? std::right : std::left) << std::setw(static_cast<int>(column.width)) << value;
      std::cout << cell.str();
      if (i + 1 < resolved.size()) {
        std::cout << "  ";
      }
    }
    std::cout << "\n";
  }
}

void apply_module_load(std::vector<w1::rewind::module_record>& modules, w1::rewind::module_record module) {
  auto it = std::find_if(modules.begin(), modules.end(), [&](const w1::rewind::module_record& entry) {
    return entry.id == module.id;
  });
  if (it != modules.end()) {
    *it = std::move(module);
    return;
  }
  modules.push_back(std::move(module));
}

void apply_module_unload(
    std::vector<w1::rewind::module_record>& modules, const w1::rewind::module_unload_record& record
) {
  auto it = std::find_if(modules.begin(), modules.end(), [&](const w1::rewind::module_record& entry) {
    return entry.id == record.module_id;
  });
  if (it != modules.end()) {
    modules.erase(it);
    return;
  }

  if (record.base == 0 && record.size == 0 && record.path.empty()) {
    return;
  }

  auto fallback = std::find_if(modules.begin(), modules.end(), [&](const w1::rewind::module_record& entry) {
    if (record.base != 0 && entry.base != record.base) {
      return false;
    }
    if (record.size != 0 && entry.size != record.size) {
      return false;
    }
    if (!record.path.empty() && entry.path != record.path) {
      return false;
    }
    return true;
  });

  if (fallback != modules.end()) {
    modules.erase(fallback);
  }
}

std::optional<uint16_t> find_register_with_flag(const std::vector<w1::rewind::register_spec>& specs, uint16_t flag) {
  for (const auto& spec : specs) {
    if ((spec.flags & flag) != 0) {
      return spec.reg_id;
    }
  }
  return std::nullopt;
}

bool read_checkpoint_header(
    std::istream& in, w1::rewind::replay_checkpoint_header& header, uint32_t& thread_count, uint32_t& entry_count
) {
  std::array<uint8_t, 8> magic{};
  if (!w1::rewind::read_stream_bytes(in, magic.data(), magic.size())) {
    return false;
  }
  if (std::memcmp(
          magic.data(), w1::rewind::k_replay_checkpoint_magic.data(), w1::rewind::k_replay_checkpoint_magic.size()
      ) != 0) {
    return false;
  }

  uint16_t arch_family = 0;
  uint16_t arch_mode = 0;
  uint8_t arch_order = 0;
  uint8_t reserved = 0;
  if (!w1::rewind::read_stream_u16(in, header.version) || !w1::rewind::read_stream_u16(in, header.trace_version) ||
      !w1::rewind::read_stream_u16(in, arch_family) || !w1::rewind::read_stream_u16(in, arch_mode) ||
      !w1::rewind::read_stream_bytes(in, &arch_order, sizeof(arch_order)) ||
      !w1::rewind::read_stream_bytes(in, &reserved, sizeof(reserved)) ||
      !w1::rewind::read_stream_u32(in, header.arch.pointer_bits) ||
      !w1::rewind::read_stream_u32(in, header.arch.flags) || !w1::rewind::read_stream_u64(in, header.trace_flags) ||
      !w1::rewind::read_stream_u32(in, header.register_count) || !w1::rewind::read_stream_u32(in, header.stride) ||
      !w1::rewind::read_stream_u32(in, thread_count) || !w1::rewind::read_stream_u32(in, entry_count)) {
    return false;
  }

  header.arch.arch_family = static_cast<w1::arch::family>(arch_family);
  header.arch.arch_mode = static_cast<w1::arch::mode>(arch_mode);
  header.arch.arch_byte_order = static_cast<w1::arch::byte_order>(arch_order);
  return true;
}

bool load_checkpoint_info(const std::string& trace_path, const std::string& checkpoint_path, checkpoint_info& out) {
  out = checkpoint_info{};
  out.path = checkpoint_path.empty() ? w1::rewind::default_replay_checkpoint_path(trace_path) : checkpoint_path;

  std::error_code ec;
  out.exists = std::filesystem::exists(out.path, ec);
  if (ec || !out.exists) {
    out.exists = false;
    return true;
  }

  std::ifstream in(out.path, std::ios::binary);
  if (!in.is_open()) {
    out.error = "failed to open";
    return true;
  }

  if (!read_checkpoint_header(in, out.header, out.thread_count, out.entry_count)) {
    out.error = "invalid header";
    return true;
  }

  out.valid = (out.header.version == w1::rewind::k_replay_checkpoint_version);
  if (!out.valid) {
    out.error = "unsupported version";
  }
  return true;
}

index_info load_index_info(const std::string& trace_path, const std::string& index_path, bool allow_build) {
  index_info out{};
  out.path = index_path.empty() ? w1::rewind::default_trace_index_path(trace_path) : index_path;

  std::error_code ec;
  bool exists = std::filesystem::exists(out.path, ec);
  if (ec) {
    out.status = w1::rewind::trace_index_status::missing;
    out.error = "failed to stat index";
    return out;
  }

  auto log = redlog::get_logger("w1replay.summary");

  if (allow_build) {
    w1::rewind::trace_index index;
    std::string error;
    if (w1::rewind::ensure_trace_index(trace_path, out.path, w1::rewind::trace_index_options{}, index, error, true)) {
      out.status = w1::rewind::trace_index_status::ok;
      out.index = std::move(index);
      return out;
    }
    out.status = w1::rewind::trace_index_status::missing;
    out.error = error.empty() ? "failed to build index" : error;
    return out;
  }

  if (!exists) {
    out.status = w1::rewind::trace_index_status::missing;
    return out;
  }

  w1::rewind::trace_index index;
  if (!w1::rewind::load_trace_index(out.path, index, log)) {
    out.status = w1::rewind::trace_index_status::incompatible;
    out.error = "failed to load index";
    return out;
  }

  std::string status_error;
  out.status = w1::rewind::evaluate_trace_index(trace_path, index, status_error);
  if (out.status == w1::rewind::trace_index_status::ok) {
    std::error_code trace_ec;
    std::error_code index_ec;
    auto trace_time = std::filesystem::last_write_time(trace_path, trace_ec);
    auto index_time = std::filesystem::last_write_time(out.path, index_ec);
    if (!trace_ec && !index_ec && trace_time > index_time) {
      out.status = w1::rewind::trace_index_status::stale;
      status_error = "trace index stale";
    }
  }

  if (out.status != w1::rewind::trace_index_status::ok) {
    out.error = status_error;
  }
  out.index = std::move(index);
  return out;
}

class trace_scanner {
public:
  explicit trace_scanner(bool full) : full_(full) {}

  bool scan(const std::string& path, scan_result& out, std::string& error) {
    error.clear();
    result_ = scan_result{};
    thread_map_.clear();
    last_chunk_index_ = std::numeric_limits<uint32_t>::max();

    w1::rewind::trace_reader reader(path);
    if (!reader.open()) {
      error = reader.error().empty() ? "failed to open trace" : std::string(reader.error());
      return false;
    }

    result_.context.header = reader.header();

    w1::rewind::trace_record record;
    w1::rewind::trace_record_location location{};
    while (reader.read_next(record, &location)) {
      result_.stats.records.total += 1;
      account_chunk(reader, location);
      std::visit([this](const auto& entry) { handle(entry); }, record);
    }

    if (!reader.error().empty()) {
      error = std::string(reader.error());
      return false;
    }

    if (!finalize(error)) {
      return false;
    }

    out = std::move(result_);
    return true;
  }

private:
  void account_chunk(const w1::rewind::trace_reader& reader, const w1::rewind::trace_record_location& location) {
    if (location.chunk_index == last_chunk_index_) {
      return;
    }
    result_.stats.chunk_count += 1;
    if (auto info = reader.last_chunk_info()) {
      result_.stats.compressed_bytes += info->compressed_size;
      result_.stats.uncompressed_bytes += info->uncompressed_size;
    }
    last_chunk_index_ = location.chunk_index;
  }

  void note_flow(uint64_t thread_id, uint64_t sequence) {
    auto& thread = result_.stats.threads[thread_id];
    if (!thread.has_flow) {
      thread.has_flow = true;
      thread.first_seq = sequence;
      thread.last_seq = sequence;
    } else {
      thread.first_seq = std::min(thread.first_seq, sequence);
      thread.last_seq = std::max(thread.last_seq, sequence);
    }
    thread.flow_count += 1;
  }

  void map_flow(uint64_t address, uint32_t size) {
    result_.stats.flow_span.update(address, size);
    uint64_t offset = 0;
    if (auto* module = result_.context.find_module_for_address(address, size, offset)) {
      result_.stats.flow_mapped += 1;
      result_.stats.module_hits[module->id].flow_hits += 1;
    } else {
      result_.stats.flow_unmapped += 1;
    }
  }

  void map_memory(uint64_t address, uint32_t size) {
    uint64_t offset = 0;
    if (auto* module = result_.context.find_module_for_address(address, size, offset)) {
      result_.stats.memory_mapped += 1;
      auto& hits = result_.stats.module_hits[module->id];
      hits.mem_hits += 1;
      hits.mem_bytes += size;
    } else {
      result_.stats.memory_unmapped += 1;
    }
  }

  void handle(const w1::rewind::target_info_record& record) {
    result_.stats.records.target_info += 1;
    result_.context.target_info = record;
  }

  void handle(const w1::rewind::target_environment_record& record) {
    result_.stats.records.target_environment += 1;
    result_.context.target_environment = record;
  }

  void handle(const w1::rewind::register_spec_record& record) {
    result_.stats.records.register_spec += 1;
    result_.context.register_specs = record.registers;
  }

  void handle(const w1::rewind::module_table_record& record) {
    result_.stats.records.module_table += 1;
    result_.context.modules = record.modules;
  }

  void handle(const w1::rewind::module_load_record& record) {
    result_.stats.records.module_load += 1;
    apply_module_load(result_.context.modules, record.module);
  }

  void handle(const w1::rewind::module_unload_record& record) {
    result_.stats.records.module_unload += 1;
    apply_module_unload(result_.context.modules, record);
  }

  void handle(const w1::rewind::memory_map_record& record) {
    result_.stats.records.memory_map += 1;
    result_.context.memory_map = record.regions;
  }

  void handle(const w1::rewind::block_definition_record& record) {
    result_.stats.records.block_definition += 1;
    result_.context.blocks_by_id[record.block_id] = record;
    result_.stats.block_bytes += record.size;
  }

  void handle(const w1::rewind::thread_start_record& record) {
    result_.stats.records.thread_start += 1;
    auto& info = thread_map_[record.thread_id];
    info.thread_id = record.thread_id;
    info.started = true;
    if (!record.name.empty() && info.name.empty()) {
      info.name = record.name;
    }
  }

  void handle(const w1::rewind::thread_end_record& record) {
    result_.stats.records.thread_end += 1;
    auto& info = thread_map_[record.thread_id];
    info.thread_id = record.thread_id;
    info.ended = true;
  }

  void handle(const w1::rewind::instruction_record& record) {
    result_.stats.records.instruction += 1;
    result_.stats.flow_records += 1;
    result_.stats.instruction_bytes += record.size;
    note_flow(record.thread_id, record.sequence);
    if (full_) {
      map_flow(record.address, record.size);
    }
  }

  void handle(const w1::rewind::block_exec_record& record) {
    result_.stats.records.block_exec += 1;
    result_.stats.flow_records += 1;
    note_flow(record.thread_id, record.sequence);
    if (full_) {
      auto def_it = result_.context.blocks_by_id.find(record.block_id);
      if (def_it != result_.context.blocks_by_id.end()) {
        map_flow(def_it->second.address, def_it->second.size);
      } else {
        result_.stats.flow_unmapped += 1;
      }
    }
  }

  void handle(const w1::rewind::register_delta_record& record) {
    result_.stats.records.register_deltas += 1;
    result_.stats.register_delta_entries += record.deltas.size();
    auto& thread = result_.stats.threads[record.thread_id];
    thread.reg_delta_records += 1;
    thread.reg_delta_entries += record.deltas.size();
  }

  void handle(const w1::rewind::register_bytes_record& record) {
    result_.stats.records.register_bytes += 1;
    result_.stats.register_bytes_entries += record.entries.size();
    result_.stats.register_bytes_data += record.data.size();
    auto& thread = result_.stats.threads[record.thread_id];
    thread.reg_bytes_records += 1;
    thread.reg_bytes_entries += record.entries.size();
    thread.reg_bytes_data += record.data.size();
  }

  void handle(const w1::rewind::memory_access_record& record) {
    result_.stats.records.memory_access += 1;
    result_.stats.memory_access_bytes += record.size;
    if (record.kind == w1::rewind::memory_access_kind::read) {
      result_.stats.memory_access_reads += 1;
    } else {
      result_.stats.memory_access_writes += 1;
    }
    if (record.value_known) {
      result_.stats.memory_access_known += 1;
    }
    if (record.value_truncated) {
      result_.stats.memory_access_truncated += 1;
    }
    auto& thread = result_.stats.threads[record.thread_id];
    thread.mem_access += 1;
    if (record.kind == w1::rewind::memory_access_kind::read) {
      thread.mem_read += 1;
    } else {
      thread.mem_write += 1;
    }
    thread.mem_bytes += record.size;
    if (record.value_known) {
      thread.mem_known += 1;
    }
    if (record.value_truncated) {
      thread.mem_truncated += 1;
    }
    if (full_) {
      map_memory(record.address, record.size);
    }
  }

  void handle(const w1::rewind::snapshot_record& record) {
    result_.stats.records.snapshot += 1;
    result_.stats.snapshot_register_entries += record.registers.size();
    uint64_t snapshot_bytes = 0;
    for (const auto& segment : record.stack_segments) {
      snapshot_bytes += segment.bytes.size();
    }
    result_.stats.snapshot_stack_bytes += snapshot_bytes;
    auto& thread = result_.stats.threads[record.thread_id];
    thread.snapshots += 1;
    thread.snapshot_stack_bytes += snapshot_bytes;
  }

  bool finalize(std::string& error) {
    if (!w1::rewind::validate_trace_arch(result_.context.header.arch, error)) {
      return false;
    }

    w1::rewind::register_spec_validation_options reg_options{};
    reg_options.allow_empty = (result_.context.header.flags & w1::rewind::trace_flag_register_deltas) == 0;
    if (!w1::rewind::normalize_register_specs(result_.context.register_specs, error, reg_options)) {
      return false;
    }

    result_.context.register_names.clear();
    result_.context.register_names.reserve(result_.context.register_specs.size());
    for (const auto& spec : result_.context.register_specs) {
      result_.context.register_names.push_back(spec.name);
    }

    result_.context.modules_by_id.clear();
    result_.context.modules_by_id.reserve(result_.context.modules.size());
    for (const auto& module : result_.context.modules) {
      result_.context.modules_by_id[module.id] = module;
    }

    for (const auto& [thread_id, stats] : result_.stats.threads) {
      if (thread_map_.find(thread_id) == thread_map_.end()) {
        w1::rewind::replay_thread_info info{};
        info.thread_id = thread_id;
        thread_map_.emplace(thread_id, std::move(info));
      }
    }

    result_.context.threads.clear();
    result_.context.threads.reserve(thread_map_.size());
    for (const auto& [_, info] : thread_map_) {
      result_.context.threads.push_back(info);
    }
    std::sort(
        result_.context.threads.begin(), result_.context.threads.end(),
        [](const w1::rewind::replay_thread_info& lhs, const w1::rewind::replay_thread_info& rhs) {
          return lhs.thread_id < rhs.thread_id;
        }
    );

    if (!result_.context.register_names.empty()) {
      result_.context.sp_reg_id = find_register_with_flag(result_.context.register_specs, w1::rewind::register_flag_sp);
      if (!result_.context.sp_reg_id.has_value()) {
        result_.context.sp_reg_id =
            w1::rewind::resolve_sp_reg_id(result_.context.header.arch, result_.context.register_names);
      }
    }

    return true;
  }

  bool full_ = false;
  scan_result result_{};
  std::unordered_map<uint64_t, w1::rewind::replay_thread_info> thread_map_{};
  uint32_t last_chunk_index_ = std::numeric_limits<uint32_t>::max();
};

std::vector<std::string> build_warnings(
    const scan_result& scan, const index_info& index, const checkpoint_info& checkpoint
) {
  std::vector<std::string> warnings;
  bool use_blocks = (scan.context.header.flags & w1::rewind::trace_flag_blocks) != 0;
  bool use_instructions = (scan.context.header.flags & w1::rewind::trace_flag_instructions) != 0;
  if (use_blocks == use_instructions) {
    warnings.emplace_back("flow flags ambiguous");
  }
  if (scan.context.threads.empty()) {
    warnings.emplace_back("no thread records");
  }
  if (scan.context.modules.empty()) {
    warnings.emplace_back("no module records");
  }
  if ((scan.context.header.flags & w1::rewind::trace_flag_register_deltas) != 0 &&
      scan.context.register_specs.empty()) {
    warnings.emplace_back("register specs missing");
  }
  if ((scan.context.header.flags & w1::rewind::trace_flag_blocks) != 0 && scan.context.blocks_by_id.empty()) {
    warnings.emplace_back("block definitions missing");
  }
  if (index.status != w1::rewind::trace_index_status::ok) {
    warnings.emplace_back("index " + format_index_status(index.status));
  }
  if (checkpoint.exists && !checkpoint.valid) {
    warnings.emplace_back("checkpoint invalid");
  }
  return warnings;
}

void render_trace_section(const summary_context& ctx, uint64_t file_size, bool has_file_size) {
  const auto& header = ctx.scan.context.header;
  std::cout << k_indent1 << "trace\n";

  std::vector<std::string> line;
  line.push_back("path=" + ctx.options.trace_path);
  if (has_file_size) {
    line.push_back("size=" + format_bytes(file_size));
  }
  line.push_back("version=" + format_number(header.version));
  line.push_back("arch=" + format_arch_mode(header.arch.arch_mode));
  line.push_back("family=" + format_arch_family(header.arch.arch_family));
  line.push_back("endian=" + format_byte_order(header.arch.arch_byte_order));
  if (header.arch.pointer_bits != 0) {
    line.push_back("ptr=" + format_number(header.arch.pointer_bits / 8));
  }
  print_kv_line(line);

  std::vector<std::string> line2;
  line2.push_back("flags=" + format_trace_flags(header.flags));
  line2.push_back("compression=" + format_compression(header.compression));
  if (header.chunk_size != 0) {
    line2.push_back("chunk_size=" + format_number(header.chunk_size));
  }
  if (ctx.scan.stats.chunk_count != 0) {
    line2.push_back("chunks=" + format_number(ctx.scan.stats.chunk_count));
  }
  if (ctx.scan.stats.compressed_bytes != 0) {
    line2.push_back("compressed=" + format_bytes(ctx.scan.stats.compressed_bytes));
  }
  if (ctx.scan.stats.uncompressed_bytes != 0) {
    line2.push_back("uncompressed=" + format_bytes(ctx.scan.stats.uncompressed_bytes));
  }
  print_kv_line(line2);
}

void render_index_section(const summary_context& ctx) {
  std::cout << k_indent1 << "index\n";

  std::vector<std::string> line;
  line.push_back("status=" + format_index_status(ctx.index.status));
  line.push_back("path=" + ctx.index.path);
  if (ctx.index.index.has_value()) {
    line.push_back("anchor_stride=" + format_number(ctx.index.index->header.anchor_stride));
    line.push_back("anchors=" + format_number(ctx.index.index->anchors.size()));
    line.push_back("snapshots=" + format_number(ctx.index.index->snapshots.size()));
  }
  if (ctx.index.status != w1::rewind::trace_index_status::ok && !ctx.index.error.empty()) {
    line.push_back("error=" + ctx.index.error);
  }
  print_kv_line(line);
}

void render_checkpoint_section(const summary_context& ctx) {
  std::cout << k_indent1 << "checkpoints\n";

  std::vector<std::string> line;
  if (!ctx.checkpoint.exists) {
    line.push_back("status=missing");
    line.push_back("path=" + ctx.checkpoint.path);
    print_kv_line(line);
    return;
  }
  if (!ctx.checkpoint.valid) {
    line.push_back("status=invalid");
    line.push_back("path=" + ctx.checkpoint.path);
    if (!ctx.checkpoint.error.empty()) {
      line.push_back("error=" + ctx.checkpoint.error);
    }
    print_kv_line(line);
    return;
  }

  line.push_back("status=ok");
  line.push_back("path=" + ctx.checkpoint.path);
  line.push_back("version=" + format_number(ctx.checkpoint.header.version));
  line.push_back("trace_version=" + format_number(ctx.checkpoint.header.trace_version));
  line.push_back("trace_flags=" + format_trace_flags(ctx.checkpoint.header.trace_flags));
  line.push_back("stride=" + format_number(ctx.checkpoint.header.stride));
  line.push_back("threads=" + format_number(ctx.checkpoint.thread_count));
  line.push_back("entries=" + format_number(ctx.checkpoint.entry_count));
  line.push_back("registers=" + format_number(ctx.checkpoint.header.register_count));
  print_kv_line(line);
}

void render_flow_section(const summary_context& ctx) {
  std::cout << k_indent1 << "flow\n";

  std::vector<std::string> line;
  line.push_back("kind=" + format_flow_kind(ctx.scan.context.header.flags));
  line.push_back("records=" + format_number(ctx.scan.stats.flow_records));
  line.push_back("threads=" + format_number(ctx.scan.context.threads.size()));
  line.push_back("modules=" + format_number(ctx.scan.context.modules.size()));
  push_if(line, ctx.options.full, "addr_span=" + format_span(ctx.scan.stats.flow_span));
  print_kv_line(line);

  if (!ctx.options.full) {
    return;
  }

  bool use_blocks = (ctx.scan.context.header.flags & w1::rewind::trace_flag_blocks) != 0;
  bool use_instructions = (ctx.scan.context.header.flags & w1::rewind::trace_flag_instructions) != 0;

  std::vector<std::string> line2;
  if (use_instructions) {
    line2.push_back("inst_bytes=" + format_bytes(ctx.scan.stats.instruction_bytes));
  }
  if (use_blocks) {
    line2.push_back("block_defs=" + format_number(ctx.scan.context.blocks_by_id.size()));
    line2.push_back("block_bytes=" + format_bytes(ctx.scan.stats.block_bytes));
  }
  if (ctx.scan.stats.flow_records != 0) {
    line2.push_back("mapped=" + format_number(ctx.scan.stats.flow_mapped));
    line2.push_back("unmapped=" + format_number(ctx.scan.stats.flow_unmapped));
  }
  print_kv_line(line2);
}

void render_threads_section(const summary_context& ctx) {
  std::cout << k_indent1 << "threads\n";

  std::unordered_map<uint64_t, w1::rewind::trace_thread_index> index_threads;
  if (ctx.index.index.has_value()) {
    for (const auto& entry : ctx.index.index->threads) {
      index_threads.emplace(entry.thread_id, entry);
    }
  }

  std::vector<column_spec> columns{
      {"id", true},        {"name", false},    {"started", false}, {"ended", false},    {"flow_count", true},
      {"first_seq", true}, {"last_seq", true}, {"anchors", true},  {"snapshots", true}, {"mem_access", true},
  };
  std::vector<std::vector<std::string>> rows;
  rows.reserve(ctx.scan.context.threads.size());

  for (const auto& info : ctx.scan.context.threads) {
    thread_stats stats{};
    if (auto it = ctx.scan.stats.threads.find(info.thread_id); it != ctx.scan.stats.threads.end()) {
      stats = it->second;
    }

    std::string anchor_value = "n/a";
    if (auto it = index_threads.find(info.thread_id); it != index_threads.end()) {
      anchor_value = format_number(it->second.anchor_count);
    }

    std::vector<std::string> row;
    row.push_back(format_number(info.thread_id));
    row.push_back(info.name.empty() ? "unknown" : info.name);
    row.push_back(format_bool(info.started));
    row.push_back(format_bool(info.ended));
    row.push_back(format_number(stats.flow_count));
    row.push_back(stats.has_flow ? format_number(stats.first_seq) : "n/a");
    row.push_back(stats.has_flow ? format_number(stats.last_seq) : "n/a");
    row.push_back(anchor_value);
    row.push_back(format_number(stats.snapshots));
    row.push_back(format_number(stats.mem_access));
    rows.push_back(std::move(row));
  }

  print_table(columns, rows);

  if (!ctx.options.full) {
    return;
  }

  for (const auto& info : ctx.scan.context.threads) {
    auto stats_it = ctx.scan.stats.threads.find(info.thread_id);
    if (stats_it == ctx.scan.stats.threads.end()) {
      continue;
    }
    const auto& stats = stats_it->second;
    std::vector<std::string> detail;
    detail.push_back("mem=r:" + format_number(stats.mem_read));
    detail.push_back("w:" + format_number(stats.mem_write));
    detail.push_back("mem_bytes=" + format_bytes(stats.mem_bytes));
    if (stats.mem_access != 0) {
      detail.push_back("known=" + format_number(stats.mem_known));
      detail.push_back("trunc=" + format_number(stats.mem_truncated));
    }
    detail.push_back("reg_deltas=" + format_number(stats.reg_delta_records));
    detail.push_back("delta_entries=" + format_number(stats.reg_delta_entries));
    detail.push_back("reg_bytes=" + format_number(stats.reg_bytes_records));
    detail.push_back("byte_entries=" + format_number(stats.reg_bytes_entries));
    detail.push_back("reg_bytes_data=" + format_bytes(stats.reg_bytes_data));
    detail.push_back("snapshots=" + format_number(stats.snapshots));
    detail.push_back("stack=" + format_bytes(stats.snapshot_stack_bytes));

    std::cout << k_indent3 << "thread=" << format_number(info.thread_id) << " ";
    for (size_t i = 0; i < detail.size(); ++i) {
      if (i > 0) {
        std::cout << "  ";
      }
      std::cout << detail[i];
    }
    std::cout << "\n";
  }
}

void render_modules_section(const summary_context& ctx) {
  std::cout << k_indent1 << "modules\n";

  uint64_t unresolved = 0;
  std::vector<w1::rewind::module_record> modules = ctx.scan.context.modules;
  for (const auto& module : modules) {
    if (module.path.empty()) {
      unresolved += 1;
    }
  }
  std::sort(modules.begin(), modules.end(), [](const auto& lhs, const auto& rhs) { return lhs.base < rhs.base; });

  std::vector<std::string> line;
  line.push_back("count=" + format_number(modules.size()));
  line.push_back("unresolved=" + format_number(unresolved));
  push_if(line, ctx.options.full, "loads=" + format_number(ctx.scan.stats.records.module_load));
  push_if(line, ctx.options.full, "unloads=" + format_number(ctx.scan.stats.records.module_unload));
  print_kv_line(line);

  std::vector<column_spec> columns{{"base", true}, {"size", true}, {"perms", false}, {"fmt", false}, {"path", false}};
  std::vector<std::vector<std::string>> rows;
  rows.reserve(modules.size());

  for (const auto& module : modules) {
    std::vector<std::string> row;
    row.push_back(format_address(module.base));
    row.push_back(format_bytes(module.size));
    row.push_back(format_perms(module.permissions));
    row.push_back(format_module_format(module.format));
    row.push_back(module.path.empty() ? "unknown" : module.path);
    rows.push_back(std::move(row));
  }

  print_table(columns, rows);

  if (!ctx.options.full || modules.empty()) {
    return;
  }

  for (const auto& module : modules) {
    std::vector<std::string> detail;
    detail.push_back("id=" + format_number(module.id));
    if ((module.flags & w1::rewind::module_record_flag_link_base_valid) != 0) {
      detail.push_back("link_base=" + format_address(module.link_base));
    }
    if (!module.identity.empty()) {
      detail.push_back("identity=" + module.identity);
    }
    if (module.identity_age != 0) {
      detail.push_back("age=" + format_number(module.identity_age));
    }
    auto hit_it = ctx.scan.stats.module_hits.find(module.id);
    if (hit_it != ctx.scan.stats.module_hits.end()) {
      detail.push_back("flow_hits=" + format_number(hit_it->second.flow_hits));
      detail.push_back("mem_hits=" + format_number(hit_it->second.mem_hits));
      detail.push_back("mem_bytes=" + format_bytes(hit_it->second.mem_bytes));
    }
    if (!detail.empty()) {
      std::cout << k_indent3 << "module=" << format_address(module.base) << " ";
      for (size_t i = 0; i < detail.size(); ++i) {
        if (i > 0) {
          std::cout << "  ";
        }
        std::cout << detail[i];
      }
      std::cout << "\n";
    }
  }
}

void render_state_section(const summary_context& ctx) {
  std::cout << k_indent1 << "state\n";

  std::vector<std::string> line;
  line.push_back(
      "registers=" +
      std::string((ctx.scan.context.header.flags & w1::rewind::trace_flag_register_deltas) != 0 ? "on" : "off")
  );
  line.push_back("reg_specs=" + format_number(ctx.scan.context.register_specs.size()));
  if (!ctx.scan.context.register_specs.empty()) {
    line.push_back("reg_classes=" + format_reg_classes(ctx.scan.context.register_specs));
  }
  line.push_back(
      "mem_access=" +
      std::string((ctx.scan.context.header.flags & w1::rewind::trace_flag_memory_access) != 0 ? "on" : "off")
  );
  line.push_back(
      "mem_values=" +
      std::string((ctx.scan.context.header.flags & w1::rewind::trace_flag_memory_values) != 0 ? "on" : "off")
  );
  line.push_back(
      "stack_snapshots=" +
      std::string((ctx.scan.context.header.flags & w1::rewind::trace_flag_stack_snapshot) != 0 ? "on" : "off")
  );
  print_kv_line(line);

  if (!ctx.scan.context.register_names.empty()) {
    std::vector<std::string> line2;
    if (auto pc_id = w1::rewind::resolve_pc_reg_id(ctx.scan.context.header.arch, ctx.scan.context.register_names)) {
      line2.push_back("pc=" + ctx.scan.context.register_names[*pc_id]);
    }
    if (ctx.scan.context.sp_reg_id.has_value()) {
      line2.push_back("sp=" + ctx.scan.context.register_names[*ctx.scan.context.sp_reg_id]);
    }
    print_kv_line(line2);
  }

  if (ctx.options.full) {
    std::vector<std::string> line3;
    line3.push_back("reg_deltas=" + format_number(ctx.scan.stats.records.register_deltas));
    line3.push_back("delta_entries=" + format_number(ctx.scan.stats.register_delta_entries));
    line3.push_back("reg_bytes=" + format_number(ctx.scan.stats.records.register_bytes));
    line3.push_back("byte_entries=" + format_number(ctx.scan.stats.register_bytes_entries));
    line3.push_back("byte_data=" + format_bytes(ctx.scan.stats.register_bytes_data));
    print_kv_line(line3);
  }
}

void render_memory_section(const summary_context& ctx) {
  std::cout << k_indent1 << "memory\n";

  uint64_t total = 0;
  for (const auto& region : ctx.scan.context.memory_map) {
    total += region.size;
  }
  std::vector<std::string> line;
  line.push_back("regions=" + format_number(ctx.scan.context.memory_map.size()));
  push_if(line, total != 0, "total=" + format_bytes(total));
  push_if(
      line, !ctx.scan.context.memory_map.empty(), "perms=" + format_permissions_summary(ctx.scan.context.memory_map)
  );
  print_kv_line(line);

  if (!ctx.options.full) {
    return;
  }

  std::vector<std::string> line2;
  line2.push_back("access=" + format_number(ctx.scan.stats.records.memory_access));
  line2.push_back("reads=" + format_number(ctx.scan.stats.memory_access_reads));
  line2.push_back("writes=" + format_number(ctx.scan.stats.memory_access_writes));
  line2.push_back("known=" + format_number(ctx.scan.stats.memory_access_known));
  line2.push_back("trunc=" + format_number(ctx.scan.stats.memory_access_truncated));
  line2.push_back("bytes=" + format_bytes(ctx.scan.stats.memory_access_bytes));
  if (ctx.scan.stats.records.memory_access != 0) {
    line2.push_back("mapped=" + format_number(ctx.scan.stats.memory_mapped));
    line2.push_back("unmapped=" + format_number(ctx.scan.stats.memory_unmapped));
  }
  line2.push_back("snapshots=" + format_number(ctx.scan.stats.records.snapshot));
  push_if(
      line2, ctx.scan.stats.snapshot_stack_bytes != 0,
      "stack_bytes=" + format_bytes(ctx.scan.stats.snapshot_stack_bytes)
  );
  push_if(
      line2, ctx.scan.stats.snapshot_register_entries != 0,
      "snapshot_regs=" + format_number(ctx.scan.stats.snapshot_register_entries)
  );
  print_kv_line(line2);
}

void render_records_section(const summary_context& ctx) {
  if (!ctx.options.full) {
    return;
  }

  std::cout << k_indent1 << "records\n";

  std::vector<std::string> line;
  line.push_back("total=" + format_number(ctx.scan.stats.records.total));
  line.push_back("instruction=" + format_number(ctx.scan.stats.records.instruction));
  line.push_back("block_exec=" + format_number(ctx.scan.stats.records.block_exec));
  line.push_back("register_deltas=" + format_number(ctx.scan.stats.records.register_deltas));
  line.push_back("register_bytes=" + format_number(ctx.scan.stats.records.register_bytes));
  line.push_back("memory_access=" + format_number(ctx.scan.stats.records.memory_access));
  line.push_back("snapshot=" + format_number(ctx.scan.stats.records.snapshot));
  print_kv_line(line);

  std::vector<std::string> line2;
  line2.push_back("module_table=" + format_number(ctx.scan.stats.records.module_table));
  line2.push_back("module_load=" + format_number(ctx.scan.stats.records.module_load));
  line2.push_back("module_unload=" + format_number(ctx.scan.stats.records.module_unload));
  line2.push_back("memory_map=" + format_number(ctx.scan.stats.records.memory_map));
  line2.push_back("thread_start=" + format_number(ctx.scan.stats.records.thread_start));
  line2.push_back("thread_end=" + format_number(ctx.scan.stats.records.thread_end));
  print_kv_line(line2);

  std::vector<std::string> line3;
  line3.push_back("target_info=" + format_number(ctx.scan.stats.records.target_info));
  line3.push_back("target_env=" + format_number(ctx.scan.stats.records.target_environment));
  line3.push_back("register_spec=" + format_number(ctx.scan.stats.records.register_spec));
  line3.push_back("block_def=" + format_number(ctx.scan.stats.records.block_definition));
  print_kv_line(line3);
}

void render_environment_section(const summary_context& ctx) {
  std::cout << k_indent1 << "environment\n";

  bool wrote_any = false;
  if (ctx.scan.context.target_info.has_value()) {
    const auto& info = ctx.scan.context.target_info.value();
    std::vector<std::string> line;
    push_if(line, !info.os.empty(), "os=" + info.os);
    push_if(line, !info.abi.empty(), "abi=" + info.abi);
    push_if(line, !info.cpu.empty(), "cpu=" + info.cpu);
    print_kv_line(line);
    wrote_any = wrote_any || !line.empty();
  }

  if (ctx.scan.context.target_environment.has_value()) {
    const auto& env = ctx.scan.context.target_environment.value();
    std::vector<std::string> line;
    push_if(line, !env.os_version.empty(), "os_version=" + env.os_version);
    push_if(line, !env.os_build.empty(), "os_build=" + env.os_build);
    push_if(line, !env.os_kernel.empty(), "kernel=" + env.os_kernel);
    push_if(line, !env.hostname.empty(), "host=" + env.hostname);
    push_if(line, env.pid != 0, "pid=" + format_number(env.pid));
    push_if(line, env.addressing_bits != 0, "addr_bits=" + format_number(env.addressing_bits));
    push_if(line, env.low_mem_addressing_bits != 0, "low_addr_bits=" + format_number(env.low_mem_addressing_bits));
    push_if(line, env.high_mem_addressing_bits != 0, "high_addr_bits=" + format_number(env.high_mem_addressing_bits));
    print_kv_line(line);
    wrote_any = wrote_any || !line.empty();
  }

  if (!wrote_any) {
    std::cout << k_indent2 << "none\n";
  }
}

void render_warnings_section(const summary_context& ctx) {
  std::cout << k_indent1 << "warnings\n";
  if (ctx.warnings.empty()) {
    std::cout << k_indent2 << "none\n";
    return;
  }
  for (const auto& warning : ctx.warnings) {
    std::cout << k_indent2 << warning << "\n";
  }
}

} // namespace summary_detail

int summary(const summary_options& options) {
  using namespace summary_detail;

  auto log = redlog::get_logger("w1replay.summary");

  if (options.trace_path.empty()) {
    log.err("trace path required");
    std::cerr << "error: --trace is required" << std::endl;
    return 1;
  }

  scan_result scan;
  std::string error;
  trace_scanner scanner(options.full);
  if (!scanner.scan(options.trace_path, scan, error)) {
    log.err("failed to scan trace", redlog::field("error", error));
    std::cerr << "error: " << error << std::endl;
    return 1;
  }

  std::error_code size_ec;
  uint64_t file_size = static_cast<uint64_t>(std::filesystem::file_size(options.trace_path, size_ec));
  bool has_file_size = !size_ec;

  index_info index = load_index_info(options.trace_path, options.index_path, options.full);
  checkpoint_info checkpoint;
  load_checkpoint_info(options.trace_path, options.checkpoint_path, checkpoint);

  std::vector<std::string> warnings = build_warnings(scan, index, checkpoint);

  summary_context ctx{options, scan, index, checkpoint, warnings};

  std::cout << "summary\n";
  render_trace_section(ctx, file_size, has_file_size);
  render_index_section(ctx);
  render_checkpoint_section(ctx);
  render_flow_section(ctx);
  render_threads_section(ctx);
  render_modules_section(ctx);
  render_state_section(ctx);
  render_memory_section(ctx);
  render_records_section(ctx);
  render_environment_section(ctx);
  render_warnings_section(ctx);

  return 0;
}

} // namespace w1replay::commands
