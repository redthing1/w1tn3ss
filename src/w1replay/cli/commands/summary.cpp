#include "summary.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
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

#include "w1base/format_utils.hpp"
#include "w1base/uuid_format.hpp"
#include "w1rewind/format/trace_format.hpp"
#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/trace/replay_checkpoint.hpp"
#include "w1rewind/trace/trace_index.hpp"
#include "w1rewind/trace/trace_reader.hpp"

namespace w1replay::commands {

namespace summary_detail {

constexpr const char* k_indent1 = "  ";
constexpr const char* k_indent2 = "    ";
constexpr const char* k_indent3 = "      ";

using w1::util::format_address;
using w1::util::format_bool;
using w1::util::format_bytes;
using w1::util::format_number;
using w1::util::format_uuid;

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
  uint64_t record_dictionary = 0;
  uint64_t arch_descriptor = 0;
  uint64_t environment = 0;
  uint64_t address_space = 0;
  uint64_t register_file = 0;
  uint64_t image = 0;
  uint64_t image_metadata = 0;
  uint64_t image_blob = 0;
  uint64_t mapping = 0;
  uint64_t thread_start = 0;
  uint64_t thread_end = 0;
  uint64_t flow_instruction = 0;
  uint64_t block_definition = 0;
  uint64_t block_exec = 0;
  uint64_t reg_write = 0;
  uint64_t mem_access = 0;
  uint64_t snapshot = 0;
  uint64_t meta = 0;
};

struct thread_stats {
  bool has_flow = false;
  uint64_t flow_count = 0;
  uint64_t first_seq = 0;
  uint64_t last_seq = 0;
  uint64_t reg_write_records = 0;
  uint64_t reg_write_entries = 0;
  uint64_t mem_access = 0;
  uint64_t mem_read = 0;
  uint64_t mem_write = 0;
  uint64_t mem_bytes = 0;
  uint64_t mem_known = 0;
  uint64_t mem_truncated = 0;
  uint64_t snapshots = 0;
  uint64_t snapshot_regs = 0;
  uint64_t snapshot_mem_bytes = 0;
};

struct scan_stats {
  record_counters records{};
  uint64_t instruction_bytes = 0;
  uint64_t block_bytes = 0;
  uint64_t reg_write_entries = 0;
  uint64_t mem_access_bytes = 0;
  uint64_t mem_access_known = 0;
  uint64_t mem_access_truncated = 0;
  uint64_t mem_access_reads = 0;
  uint64_t mem_access_writes = 0;
  uint64_t snapshot_register_entries = 0;
  uint64_t snapshot_mem_bytes = 0;
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
  bool has_chunk_codec = false;
  w1::rewind::compression chunk_codec = w1::rewind::compression::none;
  bool mixed_codec = false;
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

std::string format_endian(w1::rewind::endian order) {
  switch (order) {
  case w1::rewind::endian::little:
    return "little";
  case w1::rewind::endian::big:
    return "big";
  default:
    return "unknown";
  }
}

std::string format_compression(w1::rewind::compression codec) {
  switch (codec) {
  case w1::rewind::compression::none:
    return "none";
  case w1::rewind::compression::zstd:
    return "zstd";
  default:
    return "unknown";
  }
}

std::string format_flow_kind(const w1::rewind::replay_context& context) {
  bool has_blocks = context.features.has_block_exec;
  bool has_insts = context.features.has_flow_instruction;
  if (has_blocks && has_insts) {
    return "mixed";
  }
  if (has_blocks) {
    return "blocks";
  }
  if (has_insts) {
    return "instruction";
  }
  return "none";
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

class trace_scanner {
public:
  explicit trace_scanner(bool full) : full_(full) {}

  bool scan(const std::string& path, scan_result& out, std::string& error) {
    error.clear();
    result_ = scan_result{};
    last_chunk_index_ = std::numeric_limits<uint32_t>::max();

    if (!w1::rewind::load_replay_context(path, result_.context, error)) {
      return false;
    }

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
      if (!result_.stats.has_chunk_codec) {
        result_.stats.chunk_codec = info->codec;
        result_.stats.has_chunk_codec = true;
      } else if (result_.stats.chunk_codec != info->codec) {
        result_.stats.mixed_codec = true;
      }
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

  void map_flow(uint32_t space_id, uint64_t address, uint32_t size) {
    uint64_t mapping_offset = 0;
    uint64_t lookup_size = size == 0 ? 1u : size;
    result_.stats.flow_span.update(address, lookup_size);
    if (result_.context.find_mapping_for_address(space_id, address, lookup_size, mapping_offset)) {
      result_.stats.flow_mapped += 1;
    } else {
      result_.stats.flow_unmapped += 1;
    }
  }

  void map_memory(uint32_t space_id, uint64_t address, uint32_t size) {
    uint64_t mapping_offset = 0;
    uint64_t lookup_size = size == 0 ? 1u : size;
    if (result_.context.find_mapping_for_address(space_id, address, lookup_size, mapping_offset)) {
      result_.stats.memory_mapped += 1;
    } else {
      result_.stats.memory_unmapped += 1;
    }
  }

  void handle(const w1::rewind::record_type_dictionary_record&) { result_.stats.records.record_dictionary += 1; }
  void handle(const w1::rewind::arch_descriptor_record&) { result_.stats.records.arch_descriptor += 1; }
  void handle(const w1::rewind::environment_record&) { result_.stats.records.environment += 1; }
  void handle(const w1::rewind::address_space_record&) { result_.stats.records.address_space += 1; }
  void handle(const w1::rewind::register_file_record&) { result_.stats.records.register_file += 1; }
  void handle(const w1::rewind::image_record&) { result_.stats.records.image += 1; }
  void handle(const w1::rewind::image_metadata_record&) { result_.stats.records.image_metadata += 1; }
  void handle(const w1::rewind::image_blob_record&) { result_.stats.records.image_blob += 1; }
  void handle(const w1::rewind::mapping_record&) { result_.stats.records.mapping += 1; }

  void handle(const w1::rewind::thread_start_record& record) {
    result_.stats.records.thread_start += 1;
    (void) result_.stats.threads[record.thread_id];
  }

  void handle(const w1::rewind::thread_end_record& record) {
    result_.stats.records.thread_end += 1;
    (void) result_.stats.threads[record.thread_id];
  }

  void handle(const w1::rewind::flow_instruction_record& record) {
    result_.stats.records.flow_instruction += 1;
    result_.stats.flow_records += 1;
    result_.stats.instruction_bytes += record.size;
    note_flow(record.thread_id, record.sequence);
    if (full_) {
      map_flow(record.space_id, record.address, record.size);
    } else {
      result_.stats.flow_span.update(record.address, record.size == 0 ? 1u : record.size);
    }
  }

  void handle(const w1::rewind::block_definition_record& record) {
    result_.stats.records.block_definition += 1;
    result_.stats.block_bytes += record.size;
  }

  void handle(const w1::rewind::block_exec_record& record) {
    result_.stats.records.block_exec += 1;
    result_.stats.flow_records += 1;
    note_flow(record.thread_id, record.sequence);
    if (!full_) {
      return;
    }
    auto def_it = result_.context.blocks_by_id.find(record.block_id);
    if (def_it != result_.context.blocks_by_id.end()) {
      map_flow(def_it->second.space_id, def_it->second.address, def_it->second.size);
    } else {
      result_.stats.flow_unmapped += 1;
    }
  }

  void handle(const w1::rewind::reg_write_record& record) {
    result_.stats.records.reg_write += 1;
    result_.stats.reg_write_entries += record.entries.size();
    auto& thread = result_.stats.threads[record.thread_id];
    thread.reg_write_records += 1;
    thread.reg_write_entries += record.entries.size();
  }

  void handle(const w1::rewind::mem_access_record& record) {
    result_.stats.records.mem_access += 1;
    result_.stats.mem_access_bytes += record.access_size;
    if (record.op == w1::rewind::mem_access_op::read) {
      result_.stats.mem_access_reads += 1;
    } else {
      result_.stats.mem_access_writes += 1;
    }
    if ((record.flags & w1::rewind::mem_access_value_known) != 0) {
      result_.stats.mem_access_known += 1;
    }
    if ((record.flags & w1::rewind::mem_access_value_truncated) != 0) {
      result_.stats.mem_access_truncated += 1;
    }
    auto& thread = result_.stats.threads[record.thread_id];
    thread.mem_access += 1;
    if (record.op == w1::rewind::mem_access_op::read) {
      thread.mem_read += 1;
    } else {
      thread.mem_write += 1;
    }
    thread.mem_bytes += record.access_size;
    if ((record.flags & w1::rewind::mem_access_value_known) != 0) {
      thread.mem_known += 1;
    }
    if ((record.flags & w1::rewind::mem_access_value_truncated) != 0) {
      thread.mem_truncated += 1;
    }
    if (full_) {
      map_memory(record.space_id, record.address, record.access_size);
    }
  }

  void handle(const w1::rewind::snapshot_record& record) {
    result_.stats.records.snapshot += 1;
    result_.stats.snapshot_register_entries += record.registers.size();
    uint64_t snapshot_bytes = 0;
    for (const auto& segment : record.memory_segments) {
      snapshot_bytes += segment.bytes.size();
    }
    result_.stats.snapshot_mem_bytes += snapshot_bytes;
    auto& thread = result_.stats.threads[record.thread_id];
    thread.snapshots += 1;
    thread.snapshot_regs += record.registers.size();
    thread.snapshot_mem_bytes += snapshot_bytes;
  }

  void handle(const w1::rewind::meta_record&) { result_.stats.records.meta += 1; }

  bool full_ = false;
  scan_result result_{};
  uint32_t last_chunk_index_ = std::numeric_limits<uint32_t>::max();
};

index_info load_index_info(const std::string& trace_path, const std::string& index_path) {
  index_info out{};
  out.path = index_path.empty() ? w1::rewind::default_trace_index_path(trace_path) : index_path;
  w1::rewind::trace_index index;
  redlog::logger log = redlog::get_logger("w1replay.summary");
  if (!std::filesystem::exists(out.path)) {
    out.status = w1::rewind::trace_index_status::missing;
    out.error = "index missing";
    return out;
  }
  if (!w1::rewind::load_trace_index(out.path, index, log)) {
    out.status = w1::rewind::trace_index_status::incompatible;
    out.error = "failed to load index";
    return out;
  }
  std::string status_error;
  out.status = w1::rewind::evaluate_trace_index(trace_path, out.path, index, status_error);
  if (out.status != w1::rewind::trace_index_status::ok && out.error.empty()) {
    out.error = status_error;
  }
  out.index = std::move(index);
  return out;
}

checkpoint_info load_checkpoint_info(const std::string& trace_path, const std::string& checkpoint_path) {
  checkpoint_info out{};
  out.path = checkpoint_path.empty() ? w1::rewind::default_replay_checkpoint_path(trace_path) : checkpoint_path;
  if (!std::filesystem::exists(out.path)) {
    out.exists = false;
    return out;
  }
  out.exists = true;

  w1::rewind::replay_checkpoint_index index;
  std::string error;
  if (!w1::rewind::load_replay_checkpoint(out.path, index, error)) {
    out.valid = false;
    out.error = error.empty() ? "failed to load checkpoint" : error;
    return out;
  }

  out.valid = true;
  out.header = index.header;
  out.thread_count = static_cast<uint32_t>(index.threads.size());
  out.entry_count = static_cast<uint32_t>(index.entries.size());
  return out;
}

std::vector<std::string> build_warnings(
    const scan_result& scan, const index_info& index, const checkpoint_info& checkpoint
) {
  std::vector<std::string> warnings;
  if (!scan.context.arch.has_value()) {
    warnings.emplace_back("arch descriptor missing");
  }
  if (scan.context.address_spaces.empty()) {
    warnings.emplace_back("address spaces missing");
  }
  if (scan.context.register_files.empty()) {
    warnings.emplace_back("register files missing");
  }
  if (!scan.context.features.has_flow_instruction && !scan.context.features.has_block_exec) {
    warnings.emplace_back("no flow records");
  }
  if (scan.context.features.has_block_exec && scan.context.blocks_by_id.empty()) {
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
  line.push_back("uuid=" + format_uuid(header.trace_uuid));
  print_kv_line(line);

  std::vector<std::string> line2;
  if (header.default_chunk_size != 0) {
    line2.push_back("chunk_size=" + format_number(header.default_chunk_size));
  }
  if (ctx.scan.stats.has_chunk_codec) {
    std::string codec = ctx.scan.stats.mixed_codec ? "mixed" : format_compression(ctx.scan.stats.chunk_codec);
    line2.push_back("compression=" + codec);
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

void render_arch_section(const summary_context& ctx) {
  std::cout << k_indent1 << "arch\n";
  if (!ctx.scan.context.arch.has_value()) {
    print_kv_line({"arch=unknown"});
    return;
  }
  const auto& arch = *ctx.scan.context.arch;
  std::vector<std::string> line;
  line.push_back("arch_id=" + (arch.arch_id.empty() ? std::string("unknown") : arch.arch_id));
  line.push_back("endian=" + format_endian(arch.byte_order));
  if (arch.pointer_bits != 0) {
    line.push_back("ptr_bits=" + format_number(arch.pointer_bits));
  }
  if (arch.address_bits != 0) {
    line.push_back("addr_bits=" + format_number(arch.address_bits));
  }
  push_if(line, !arch.gdb_arch.empty(), "gdb_arch=" + arch.gdb_arch);
  push_if(line, !arch.gdb_feature.empty(), "gdb_feature=" + arch.gdb_feature);
  push_if(line, ctx.options.full, "modes=" + format_number(arch.modes.size()));
  print_kv_line(line);
}

void render_environment_section(const summary_context& ctx) {
  std::cout << k_indent1 << "environment\n";
  if (!ctx.scan.context.environment.has_value()) {
    print_kv_line({"status=missing"});
    return;
  }
  const auto& env = *ctx.scan.context.environment;
  std::vector<std::string> line;
  line.push_back("os_id=" + (env.os_id.empty() ? std::string("unknown") : env.os_id));
  push_if(line, !env.abi.empty(), "abi=" + env.abi);
  push_if(line, !env.cpu.empty(), "cpu=" + env.cpu);
  push_if(line, !env.hostname.empty(), "host=" + env.hostname);
  if (env.pid != 0) {
    line.push_back("pid=" + format_number(env.pid));
  }
  print_kv_line(line);
}

void render_address_spaces_section(const summary_context& ctx) {
  std::cout << k_indent1 << "address_spaces\n";
  std::vector<std::string> line;
  line.push_back("count=" + format_number(ctx.scan.context.address_spaces.size()));
  print_kv_line(line);

  if (!ctx.options.full || ctx.scan.context.address_spaces.empty()) {
    return;
  }

  std::vector<column_spec> columns{{"id", true}, {"name", false}, {"bits", true}, {"endian", false}};
  std::vector<std::vector<std::string>> rows;
  rows.reserve(ctx.scan.context.address_spaces.size());
  for (const auto& space : ctx.scan.context.address_spaces) {
    rows.push_back(
        {format_number(space.space_id), space.name.empty() ? "unknown" : space.name,
         space.address_bits == 0 ? "n/a" : format_number(space.address_bits), format_endian(space.byte_order)}
    );
  }
  print_table(columns, rows);
}

void render_register_files_section(const summary_context& ctx) {
  std::cout << k_indent1 << "register_files\n";
  std::vector<std::string> line;
  line.push_back("count=" + format_number(ctx.scan.context.register_files.size()));
  line.push_back("default_regs=" + format_number(ctx.scan.context.default_registers.size()));
  if (ctx.scan.context.sp_reg_id.has_value() &&
      *ctx.scan.context.sp_reg_id < ctx.scan.context.default_register_names.size()) {
    line.push_back("sp=" + ctx.scan.context.default_register_names[*ctx.scan.context.sp_reg_id]);
  }
  if (ctx.scan.context.pc_reg_id.has_value() &&
      *ctx.scan.context.pc_reg_id < ctx.scan.context.default_register_names.size()) {
    line.push_back("pc=" + ctx.scan.context.default_register_names[*ctx.scan.context.pc_reg_id]);
  }
  print_kv_line(line);

  if (!ctx.options.full || ctx.scan.context.register_files.empty()) {
    return;
  }

  std::vector<column_spec> columns{{"id", true}, {"name", false}, {"regs", true}};
  std::vector<std::vector<std::string>> rows;
  rows.reserve(ctx.scan.context.register_files.size());
  for (const auto& regfile : ctx.scan.context.register_files) {
    rows.push_back(
        {format_number(regfile.regfile_id), regfile.name.empty() ? "unknown" : regfile.name,
         format_number(regfile.registers.size())}
    );
  }
  print_table(columns, rows);
}

void render_images_section(const summary_context& ctx) {
  std::cout << k_indent1 << "images\n";
  size_t blob_count = 0;
  for (const auto& [_, blobs] : ctx.scan.context.image_blobs_by_id) {
    blob_count += blobs.size();
  }
  std::vector<std::string> line;
  line.push_back("images=" + format_number(ctx.scan.context.images.size()));
  line.push_back("mappings=" + format_number(ctx.scan.context.mappings.size()));
  line.push_back("mapping_events=" + format_number(ctx.scan.context.mapping_events.size()));
  line.push_back("blobs=" + format_number(blob_count));
  print_kv_line(line);

  if (!ctx.options.full) {
    return;
  }

  if (!ctx.scan.context.images.empty()) {
    std::vector<column_spec> columns{{"id", true}, {"kind", false}, {"name", false}, {"identity", false}};
    std::vector<std::vector<std::string>> rows;
    rows.reserve(ctx.scan.context.images.size());
    for (const auto& image : ctx.scan.context.images) {
      rows.push_back(
          {format_number(image.image_id), image.kind.empty() ? "unknown" : image.kind,
           image.name.empty() ? "unknown" : image.name, image.identity.empty() ? "unknown" : image.identity}
      );
    }
    print_table(columns, rows);
  }

  if (!ctx.scan.context.mappings.empty()) {
    std::vector<column_spec> columns{{"space", false}, {"base", true},     {"size", true},
                                     {"perms", false}, {"image_id", true}, {"name", false}};
    std::vector<std::vector<std::string>> rows;
    rows.reserve(ctx.scan.context.mappings.size());
    for (const auto& mapping : ctx.scan.context.mappings) {
      std::string space_label = format_number(mapping.space_id);
      if (auto* space = ctx.scan.context.find_address_space(mapping.space_id)) {
        if (!space->name.empty()) {
          space_label = space->name;
        }
      }
      const auto perms = mapping.perms;
      const std::string perms_label = w1::util::format_permissions(
          (perms & w1::rewind::mapping_perm::read) != w1::rewind::mapping_perm::none,
          (perms & w1::rewind::mapping_perm::write) != w1::rewind::mapping_perm::none,
          (perms & w1::rewind::mapping_perm::exec) != w1::rewind::mapping_perm::none
      );
      rows.push_back(
          {space_label, format_address(mapping.base), format_bytes(mapping.size), perms_label,
           format_number(mapping.image_id), mapping.name.empty() ? "unknown" : mapping.name}
      );
    }
    print_table(columns, rows);
  }
}

void render_flow_section(const summary_context& ctx) {
  std::cout << k_indent1 << "flow\n";
  std::vector<std::string> line;
  line.push_back("kind=" + format_flow_kind(ctx.scan.context));
  line.push_back("records=" + format_number(ctx.scan.stats.flow_records));
  line.push_back("threads=" + format_number(ctx.scan.context.threads.size()));
  push_if(line, ctx.options.full, "addr_span=" + format_span(ctx.scan.stats.flow_span));
  print_kv_line(line);

  if (!ctx.options.full) {
    return;
  }

  std::vector<std::string> line2;
  if (ctx.scan.stats.instruction_bytes != 0) {
    line2.push_back("inst_bytes=" + format_bytes(ctx.scan.stats.instruction_bytes));
  }
  if (ctx.scan.stats.block_bytes != 0) {
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
      {"id", true},         {"name", false},      {"started", false},  {"ended", false},
      {"flow_count", true}, {"first_seq", true},  {"last_seq", true},  {"anchors", true},
      {"reg_writes", true}, {"mem_access", true}, {"snapshots", true},
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

    rows.push_back({
        format_number(info.thread_id),
        info.name.empty() ? "unknown" : info.name,
        format_bool(info.started),
        format_bool(info.ended),
        format_number(stats.flow_count),
        stats.has_flow ? format_number(stats.first_seq) : "n/a",
        stats.has_flow ? format_number(stats.last_seq) : "n/a",
        anchor_value,
        format_number(stats.reg_write_records),
        format_number(stats.mem_access),
        format_number(stats.snapshots),
    });
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
    detail.push_back("reg_entries=" + format_number(stats.reg_write_entries));
    detail.push_back("snapshots=" + format_number(stats.snapshots));
    detail.push_back("snapshot_regs=" + format_number(stats.snapshot_regs));
    detail.push_back("snapshot_mem=" + format_bytes(stats.snapshot_mem_bytes));

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

void render_state_section(const summary_context& ctx) {
  std::cout << k_indent1 << "state\n";

  std::vector<std::string> line;
  line.push_back("reg_writes=" + format_number(ctx.scan.stats.records.reg_write));
  line.push_back("reg_entries=" + format_number(ctx.scan.stats.reg_write_entries));
  line.push_back("mem_access=" + format_number(ctx.scan.stats.records.mem_access));
  line.push_back("snapshots=" + format_number(ctx.scan.stats.records.snapshot));
  print_kv_line(line);

  std::vector<std::string> line2;
  if (ctx.scan.stats.records.mem_access != 0) {
    line2.push_back("reads=" + format_number(ctx.scan.stats.mem_access_reads));
    line2.push_back("writes=" + format_number(ctx.scan.stats.mem_access_writes));
    line2.push_back("known=" + format_number(ctx.scan.stats.mem_access_known));
    line2.push_back("trunc=" + format_number(ctx.scan.stats.mem_access_truncated));
    line2.push_back("bytes=" + format_bytes(ctx.scan.stats.mem_access_bytes));
    if (ctx.options.full) {
      line2.push_back("mapped=" + format_number(ctx.scan.stats.memory_mapped));
      line2.push_back("unmapped=" + format_number(ctx.scan.stats.memory_unmapped));
    }
  }
  if (ctx.scan.stats.records.snapshot != 0) {
    line2.push_back("snapshot_regs=" + format_number(ctx.scan.stats.snapshot_register_entries));
    line2.push_back("snapshot_mem=" + format_bytes(ctx.scan.stats.snapshot_mem_bytes));
  }
  print_kv_line(line2);
}

void render_records_section(const summary_context& ctx) {
  std::cout << k_indent1 << "records\n";
  const auto& r = ctx.scan.stats.records;

  std::vector<std::string> line;
  line.push_back("total=" + format_number(r.total));
  line.push_back("flow_instruction=" + format_number(r.flow_instruction));
  line.push_back("block_exec=" + format_number(r.block_exec));
  line.push_back("reg_write=" + format_number(r.reg_write));
  line.push_back("mem_access=" + format_number(r.mem_access));
  line.push_back("snapshot=" + format_number(r.snapshot));
  line.push_back("meta=" + format_number(r.meta));
  print_kv_line(line);

  std::vector<std::string> line2;
  line2.push_back("arch=" + format_number(r.arch_descriptor));
  line2.push_back("env=" + format_number(r.environment));
  line2.push_back("addr_space=" + format_number(r.address_space));
  line2.push_back("reg_file=" + format_number(r.register_file));
  line2.push_back("image=" + format_number(r.image));
  line2.push_back("image_meta=" + format_number(r.image_metadata));
  line2.push_back("image_blob=" + format_number(r.image_blob));
  line2.push_back("mapping=" + format_number(r.mapping));
  line2.push_back("thread_start=" + format_number(r.thread_start));
  line2.push_back("thread_end=" + format_number(r.thread_end));
  line2.push_back("block_def=" + format_number(r.block_definition));
  line2.push_back("dict=" + format_number(r.record_dictionary));
  print_kv_line(line2);
}

void render_index_section(const summary_context& ctx) {
  std::cout << k_indent1 << "index\n";

  std::vector<std::string> line;
  line.push_back("status=" + format_index_status(ctx.index.status));
  line.push_back("path=" + ctx.index.path);
  if (ctx.index.index.has_value()) {
    line.push_back("anchor_stride=" + format_number(ctx.index.index->header.anchor_stride));
    line.push_back("threads=" + format_number(ctx.index.index->threads.size()));
    line.push_back("anchors=" + format_number(ctx.index.index->anchors.size()));
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
  line.push_back("stride=" + format_number(ctx.checkpoint.header.stride));
  line.push_back("threads=" + format_number(ctx.checkpoint.thread_count));
  line.push_back("entries=" + format_number(ctx.checkpoint.entry_count));
  print_kv_line(line);
}

void render_warnings_section(const summary_context& ctx) {
  if (ctx.warnings.empty()) {
    return;
  }
  std::cout << k_indent1 << "warnings\n";
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

  auto index = load_index_info(options.trace_path, options.index_path);
  auto checkpoint = load_checkpoint_info(options.trace_path, options.checkpoint_path);
  if (checkpoint.exists && checkpoint.valid && checkpoint.header.trace_uuid != scan.context.header.trace_uuid) {
    checkpoint.valid = false;
    checkpoint.error = "trace uuid mismatch";
  }

  std::vector<std::string> warnings = build_warnings(scan, index, checkpoint);
  summary_context ctx{options, scan, index, checkpoint, warnings};

  bool has_file_size = false;
  uint64_t file_size = 0;
  std::error_code ec;
  auto size = std::filesystem::file_size(options.trace_path, ec);
  if (!ec) {
    has_file_size = true;
    file_size = size;
  }

  std::cout << "summary\n";
  render_trace_section(ctx, file_size, has_file_size);
  render_arch_section(ctx);
  render_environment_section(ctx);
  render_address_spaces_section(ctx);
  render_register_files_section(ctx);
  render_images_section(ctx);
  render_flow_section(ctx);
  render_threads_section(ctx);
  render_state_section(ctx);
  render_records_section(ctx);
  render_index_section(ctx);
  render_checkpoint_section(ctx);
  render_warnings_section(ctx);

  return 0;
}

} // namespace w1replay::commands
