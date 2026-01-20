#include "rewind_recorder.hpp"

#include "w1runtime/memory_reader.hpp"
#include "w1rewind/format/register_numbering.hpp"
#include "w1rewind/record/memory_map_utils.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <span>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#include <sys/utsname.h>
#endif

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

#if defined(WITNESS_LIEF_ENABLED)
#include <LIEF/LIEF.hpp>
#include <LIEF/ELF/Note.hpp>
#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/FatBinary.hpp>
#include <LIEF/MachO/Header.hpp>
#include <LIEF/MachO/Parser.hpp>
#include <LIEF/MachO/UUIDCommand.hpp>
#include <LIEF/PE/Binary.hpp>
#include <LIEF/PE/debug/CodeViewPDB.hpp>
#endif

namespace {
w1::rewind::module_perm module_perm_from_qbdi(uint32_t perms) {
  w1::rewind::module_perm out = w1::rewind::module_perm::none;
  if (perms & QBDI::PF_READ) {
    out = out | w1::rewind::module_perm::read;
  }
  if (perms & QBDI::PF_WRITE) {
    out = out | w1::rewind::module_perm::write;
  }
  if (perms & QBDI::PF_EXEC) {
    out = out | w1::rewind::module_perm::exec;
  }
  return out;
}

std::vector<w1::rewind::memory_region_record> collect_memory_map(
    const std::vector<w1::rewind::module_record>& modules
) {
  std::vector<w1::rewind::memory_region_record> regions;
  auto maps = QBDI::getCurrentProcessMaps(true);
  regions.reserve(maps.size());
  for (const auto& map : maps) {
    uint64_t start = map.range.start();
    uint64_t end = map.range.end();
    if (end <= start) {
      continue;
    }
    w1::rewind::memory_region_record region{};
    region.base = start;
    region.size = end - start;
    region.permissions = module_perm_from_qbdi(map.permission);
    region.image_id = 0;
    region.name = map.name;
    regions.push_back(std::move(region));
  }
  w1::rewind::assign_memory_map_image_ids(regions, modules);
  std::sort(regions.begin(), regions.end(), [](const auto& left, const auto& right) {
    return left.base < right.base;
  });
  return regions;
}

std::string detect_os_id() {
#if defined(_WIN32)
  return "windows";
#elif defined(__APPLE__)
  return "macos";
#elif defined(__linux__)
  return "linux";
#else
  return {};
#endif
}

#if defined(WITNESS_LIEF_ENABLED)
std::string hex_encode(LIEF::span<const uint8_t> bytes) {
  static const char k_hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t value : bytes) {
    out.push_back(k_hex[(value >> 4) & 0x0f]);
    out.push_back(k_hex[value & 0x0f]);
  }
  return out;
}

std::string format_uuid(const std::array<uint8_t, 16>& bytes) {
  static const char k_hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(36);
  auto append_byte = [&](uint8_t value) {
    out.push_back(k_hex[(value >> 4) & 0x0f]);
    out.push_back(k_hex[value & 0x0f]);
  };
  size_t idx = 0;
  const size_t groups[] = {4, 2, 2, 2, 6};
  for (size_t group = 0; group < 5; ++group) {
    if (group > 0) {
      out.push_back('-');
    }
    for (size_t i = 0; i < groups[group]; ++i) {
      append_byte(bytes[idx++]);
    }
  }
  return out;
}

bool is_all_zero_uuid(const std::array<uint8_t, 16>& bytes) {
  for (uint8_t value : bytes) {
    if (value != 0) {
      return false;
    }
  }
  return true;
}

LIEF::MachO::Header::CPU_TYPE macho_cpu_type_for_arch(const w1::arch::arch_spec& arch) {
  using cpu_type = LIEF::MachO::Header::CPU_TYPE;
  switch (arch.arch_mode) {
  case w1::arch::mode::x86_64:
    return cpu_type::X86_64;
  case w1::arch::mode::x86_32:
    return cpu_type::X86;
  case w1::arch::mode::aarch64:
    return cpu_type::ARM64;
  case w1::arch::mode::arm:
  case w1::arch::mode::thumb:
    return cpu_type::ARM;
  default:
    break;
  }
  return cpu_type::ANY;
}

std::optional<std::string> read_macho_uuid(const std::string& path, const w1::arch::arch_spec& arch) {
  auto fat = LIEF::MachO::Parser::parse(path);
  if (!fat || fat->empty()) {
    return std::nullopt;
  }

  const auto target = macho_cpu_type_for_arch(arch);
  const LIEF::MachO::Binary* selected = nullptr;
  for (const auto& binary : *fat) {
    if (target == LIEF::MachO::Header::CPU_TYPE::ANY || binary.header().cpu_type() == target) {
      selected = &binary;
      break;
    }
  }
  if (!selected) {
    selected = fat->front();
  }
  if (!selected || !selected->has_uuid()) {
    return std::nullopt;
  }
  const auto* uuid_cmd = selected->uuid();
  if (!uuid_cmd) {
    return std::nullopt;
  }
  const auto& uuid_bytes = uuid_cmd->uuid();
  if (is_all_zero_uuid(uuid_bytes)) {
    return std::nullopt;
  }
  return format_uuid(uuid_bytes);
}

void populate_module_identity(w1::rewind::module_record& record, const w1::arch::arch_spec& arch) {
  if (record.path.empty()) {
    return;
  }
  auto binary = LIEF::Parser::parse(record.path);
  if (!binary) {
    return;
  }

  switch (binary->format()) {
  case LIEF::Binary::FORMATS::ELF: {
    record.format = w1::rewind::module_format::elf;
    auto* elf = dynamic_cast<LIEF::ELF::Binary*>(binary.get());
    if (!elf) {
      return;
    }
    const auto* note = elf->get(LIEF::ELF::Note::TYPE::GNU_BUILD_ID);
    if (!note) {
      return;
    }
    auto desc = note->description();
    if (desc.empty()) {
      return;
    }
    record.identity = hex_encode(desc);
    return;
  }
  case LIEF::Binary::FORMATS::MACHO: {
    record.format = w1::rewind::module_format::macho;
    auto uuid = read_macho_uuid(record.path, arch);
    if (uuid.has_value()) {
      record.identity = *uuid;
      return;
    }
    auto* macho = dynamic_cast<LIEF::MachO::Binary*>(binary.get());
    if (!macho || !macho->has_uuid()) {
      return;
    }
    const auto* uuid_cmd = macho->uuid();
    if (!uuid_cmd) {
      return;
    }
    const auto& uuid_bytes = uuid_cmd->uuid();
    if (is_all_zero_uuid(uuid_bytes)) {
      return;
    }
    record.identity = format_uuid(uuid_bytes);
    return;
  }
  case LIEF::Binary::FORMATS::PE: {
    record.format = w1::rewind::module_format::pe;
    auto* pe = dynamic_cast<LIEF::PE::Binary*>(binary.get());
    if (!pe) {
      return;
    }
    const auto* pdb = pe->codeview_pdb();
    if (!pdb) {
      return;
    }
    auto guid = pdb->guid();
    if (!guid.empty()) {
      record.identity = std::move(guid);
      record.identity_age = pdb->age();
    }
    return;
  }
  default:
    break;
  }
}
#else
void populate_module_identity(w1::rewind::module_record&, const w1::arch::arch_spec&) {}
#endif

struct addressing_bits_info {
  uint32_t addressing_bits = 0;
  uint32_t low_mem_addressing_bits = 0;
  uint32_t high_mem_addressing_bits = 0;
};

uint32_t bit_length_u64(uint64_t value) {
  uint32_t bits = 0;
  while (value != 0) {
    value >>= 1;
    ++bits;
  }
  return bits;
}

addressing_bits_info compute_addressing_bits(
    const std::vector<w1::rewind::memory_region_record>& memory_map,
    const std::vector<w1::rewind::module_record>& modules, uint32_t pointer_bits
) {
  addressing_bits_info out{};
  uint32_t address_bits = pointer_bits == 0 ? 64u : pointer_bits;
  if (address_bits <= 32) {
    out.addressing_bits = address_bits;
    out.low_mem_addressing_bits = address_bits;
    out.high_mem_addressing_bits = address_bits;
    return out;
  }

  bool found = false;
  uint32_t low_bits = 0;
  uint32_t high_bits = 0;

  auto consider_end = [&](uint64_t end) {
    found = true;
    if ((end & (1ull << 63)) != 0) {
      uint32_t bits = bit_length_u64(~end) + 1;
      high_bits = std::max(high_bits, bits);
    } else {
      uint32_t bits = bit_length_u64(end) + 1;
      low_bits = std::max(low_bits, bits);
    }
  };

  auto consider_range = [&](uint64_t base, uint64_t size) {
    if (size == 0) {
      return;
    }
    uint64_t end = base + size - 1;
    if (end < base) {
      end = std::numeric_limits<uint64_t>::max();
    }
    consider_end(end);
  };

  if (!memory_map.empty()) {
    for (const auto& region : memory_map) {
      consider_range(region.base, region.size);
    }
  } else {
    for (const auto& module : modules) {
      consider_range(module.base, module.size);
    }
  }

  if (!found) {
    out.addressing_bits = address_bits;
    out.low_mem_addressing_bits = address_bits;
    out.high_mem_addressing_bits = address_bits;
    return out;
  }

  if (low_bits == 0) {
    low_bits = high_bits;
  }
  if (high_bits == 0) {
    high_bits = low_bits;
  }
  if (low_bits == 0) {
    low_bits = address_bits;
  }
  if (high_bits == 0) {
    high_bits = address_bits;
  }

  if (low_bits > address_bits) {
    low_bits = address_bits;
  }
  if (high_bits > address_bits) {
    high_bits = address_bits;
  }

  uint32_t max_bits = std::max(low_bits, high_bits);
  if (max_bits == 0 || max_bits > address_bits) {
    max_bits = address_bits;
  }

  out.addressing_bits = max_bits;
  out.low_mem_addressing_bits = low_bits;
  out.high_mem_addressing_bits = high_bits;
  return out;
}

#if defined(__APPLE__)
std::string sysctl_string(const char* key) {
  size_t size = 0;
  if (sysctlbyname(key, nullptr, &size, nullptr, 0) != 0 || size == 0) {
    return {};
  }
  std::string out(size, '\0');
  if (sysctlbyname(key, out.data(), &size, nullptr, 0) != 0) {
    return {};
  }
  if (!out.empty() && out.back() == '\0') {
    out.pop_back();
  }
  return out;
}
#endif

std::string detect_host_name() {
#if defined(_WIN32)
  char buffer[MAX_COMPUTERNAME_LENGTH + 1] = {};
  DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
  if (GetComputerNameA(buffer, &size)) {
    return std::string(buffer, size);
  }
#else
  char buffer[256] = {};
  if (gethostname(buffer, sizeof(buffer) - 1) == 0) {
    buffer[sizeof(buffer) - 1] = '\0';
    return buffer;
  }
#endif
  return {};
}

std::string detect_os_version() {
#if defined(__APPLE__)
  return sysctl_string("kern.osproductversion");
#elif !defined(_WIN32)
  struct utsname info {};
  if (uname(&info) == 0) {
    return info.release;
  }
#endif
  return {};
}

std::string detect_os_build() {
#if defined(__APPLE__)
  return sysctl_string("kern.osversion");
#elif !defined(_WIN32)
  struct utsname info {};
  if (uname(&info) == 0) {
    return info.version;
  }
#endif
  return {};
}

std::string detect_os_kernel() {
#if defined(__APPLE__)
  return sysctl_string("kern.osrelease");
#elif defined(_WIN32)
  return "windows";
#else
  struct utsname info {};
  if (uname(&info) == 0) {
    return info.sysname;
  }
#endif
  return {};
}

uint64_t detect_pid() {
#if defined(_WIN32)
  return static_cast<uint64_t>(GetCurrentProcessId());
#else
  return static_cast<uint64_t>(getpid());
#endif
}

w1::rewind::target_environment_record build_target_environment(
    const std::vector<w1::rewind::memory_region_record>& memory_map,
    const std::vector<w1::rewind::module_record>& modules, const w1::arch::arch_spec& arch
) {
  w1::rewind::target_environment_record env{};
  env.os_version = detect_os_version();
  env.os_build = detect_os_build();
  env.os_kernel = detect_os_kernel();
  env.hostname = detect_host_name();
  if (env.hostname.empty()) {
    env.hostname = "w1rewind";
  }
  env.pid = detect_pid();
  auto bits = compute_addressing_bits(memory_map, modules, arch.pointer_bits);
  env.addressing_bits = bits.addressing_bits;
  env.low_mem_addressing_bits = bits.low_mem_addressing_bits;
  env.high_mem_addressing_bits = bits.high_mem_addressing_bits;
  return env;
}

bool is_pc_name(const std::string& name) { return name == "pc" || name == "rip" || name == "eip"; }

bool is_sp_name(const std::string& name) { return name == "sp" || name == "rsp" || name == "esp"; }

bool is_flags_name(const std::string& name) {
  return name == "eflags" || name == "rflags" || name == "nzcv" || name == "cpsr";
}

w1::rewind::register_class register_class_for_name(const std::string& name) {
  if (is_flags_name(name)) {
    return w1::rewind::register_class::flags;
  }
  return w1::rewind::register_class::gpr;
}

uint32_t register_bitsize_for_name(
    const w1::arch::arch_spec& arch, const std::string& name, uint32_t pointer_size_bytes
) {
  uint32_t pointer_bits = pointer_size_bytes * 8;
  if (arch.arch_mode == w1::arch::mode::x86_64 || arch.arch_mode == w1::arch::mode::x86_32) {
    if (name == "eflags" || name == "rflags") {
      return 32;
    }
    if (name == "fs" || name == "gs") {
      return 16;
    }
  }
  if (arch.arch_mode == w1::arch::mode::aarch64) {
    if (name == "nzcv") {
      return 32;
    }
  }
  if (arch.arch_mode == w1::arch::mode::arm || arch.arch_mode == w1::arch::mode::thumb) {
    if (name == "cpsr") {
      return 32;
    }
  }
  return pointer_bits;
}

std::string gdb_name_for_register(const std::string& name, const w1::arch::arch_spec& arch) {
  if (arch.arch_mode == w1::arch::mode::aarch64 && name == "nzcv") {
    return "cpsr";
  }
  if (name == "rflags") {
    return "eflags";
  }
  return name;
}
} // namespace

namespace w1rewind {

rewind_recorder::rewind_recorder(rewind_config config, std::shared_ptr<w1::rewind::trace_writer> writer)
    : config_(std::move(config)),
      writer_(std::move(writer)),
      instruction_flow_(config_.flow.mode == rewind_config::flow_options::mode::instruction),
      memory_filter_(config_.memory) {
  w1::rewind::trace_builder_config builder_config;
  builder_config.writer = writer_;
  builder_config.log = log_;
  builder_config.options.record_instructions = instruction_flow_;
  builder_config.options.record_register_deltas = config_.registers.deltas;
  builder_config.options.record_memory_access = config_.memory.access != rewind_config::memory_access::none;
  builder_config.options.record_memory_values = config_.memory.values;
  builder_config.options.record_snapshots = config_.registers.snapshot_interval > 0;
  builder_config.options.record_stack_segments = config_.stack_snapshots.interval > 0;
  builder_ = std::make_unique<w1::rewind::trace_builder>(std::move(builder_config));
}

void rewind_recorder::on_thread_start(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  auto& state = threads_[event.thread_id];
  state.thread_id = event.thread_id;
  if (event.name) {
    state.thread_name = event.name;
  }
}

void rewind_recorder::on_basic_block_entry(
    w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  (void) vm;
  (void) state;
  (void) fpr;

  if (instruction_flow_) {
    return;
  }

  auto& thread = threads_[event.thread_id];
  if (thread.thread_id == 0) {
    thread.thread_id = event.thread_id;
  }

  if (!ensure_builder_ready(ctx, gpr)) {
    return;
  }

  if (!builder_->begin_thread(thread.thread_id, thread.thread_name)) {
    return;
  }

  uint64_t address = event.address;
  uint32_t size = event.size;
  if (address == 0 || size == 0) {
    return;
  }

  uint32_t flags = 0;
#if defined(QBDI_ARCH_ARM)
  if (arch_spec_.arch_family == w1::arch::family::arm &&
      (arch_spec_.arch_mode == w1::arch::mode::arm || arch_spec_.arch_mode == w1::arch::mode::thumb) && gpr) {
    bool thumb = ((gpr->cpsr >> 5) & 1U) != 0;
    flags |= w1::rewind::trace_block_flag_mode_valid;
    if (thumb) {
      flags |= w1::rewind::trace_block_flag_thumb;
    }
  }
#endif

  uint64_t sequence = 0;
  if (!builder_->emit_block(thread.thread_id, address, size, flags, sequence)) {
    return;
  }

  thread.flow_count += 1;

  if (config_.registers.snapshot_interval > 0 || config_.stack_snapshots.interval > 0) {
    w1::util::register_state regs = w1::util::register_capturer::capture(gpr);
    auto snapshot = maybe_capture_snapshot(ctx, thread, regs);
    if (snapshot.has_value()) {
      builder_->emit_snapshot(
          thread.thread_id, sequence, snapshot->snapshot_id, snapshot->registers, snapshot->stack_segments,
          std::move(snapshot->reason)
      );
    }
  }
}

void rewind_recorder::on_instruction_post(
    w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) fpr;

  if (!instruction_flow_) {
    return;
  }

  auto& state = threads_[event.thread_id];
  if (state.thread_id == 0) {
    state.thread_id = event.thread_id;
  }

  if (!ensure_builder_ready(ctx, gpr)) {
    return;
  }

  if (!builder_->begin_thread(state.thread_id, state.thread_name)) {
    return;
  }

  flush_pending(state);

  uint64_t address = event.address;
  uint32_t size = event.size;
  if ((address == 0 || size == 0) && vm) {
    if (const auto* analysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION)) {
      address = analysis->address;
      size = analysis->instSize;
    }
  }

  pending_instruction pending{};
  pending.thread_id = state.thread_id;
  pending.address = address;
  pending.size = size;
  pending.flags = 0;
#if defined(QBDI_ARCH_ARM)
  if (arch_spec_.arch_family == w1::arch::family::arm &&
      (arch_spec_.arch_mode == w1::arch::mode::arm || arch_spec_.arch_mode == w1::arch::mode::thumb) && gpr) {
    bool thumb = ((gpr->cpsr >> 5) & 1U) != 0;
    pending.flags |= w1::rewind::trace_inst_flag_mode_valid;
    if (thumb) {
      pending.flags |= w1::rewind::trace_inst_flag_thumb;
    }
  }
#endif

  bool need_registers = config_.registers.deltas || config_.registers.snapshot_interval > 0 ||
      config_.stack_snapshots.interval > 0;
  w1::util::register_state regs;
  if (need_registers) {
    regs = w1::util::register_capturer::capture(gpr);
  }

  if (config_.registers.deltas) {
    capture_register_deltas(state, regs, pending.register_deltas);
  }

  state.flow_count += 1;
  if (config_.registers.snapshot_interval > 0 || config_.stack_snapshots.interval > 0) {
    auto snapshot = maybe_capture_snapshot(ctx, state, regs);
    if (snapshot.has_value()) {
      pending.snapshot = std::move(snapshot);
    }
  }

  state.pending = std::move(pending);
}

void rewind_recorder::on_memory(
    w1::trace_context& ctx, const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) vm;
  (void) fpr;

  if (!instruction_flow_ || config_.memory.access == rewind_config::memory_access::none) {
    return;
  }

  auto it = threads_.find(event.thread_id);
  if (it == threads_.end()) {
    return;
  }
  auto& state = it->second;
  if (!state.pending.has_value()) {
    return;
  }
  if (event.size == 0) {
    return;
  }

  std::vector<stack_window_segment> stack_segments;
  if (memory_filter_.uses_stack_window()) {
    if (!gpr) {
      log_.err("missing gpr state for stack window filtering");
      return;
    }
    auto regs = w1::util::register_capturer::capture(gpr);
    auto window = compute_stack_window_segments(regs, config_.stack_window);
    if (window.frame_window_missing && !state.warned_missing_frame) {
      log_.wrn("frame pointer not available; stack window will use SP-only segments");
      state.warned_missing_frame = true;
    }
    stack_segments = std::move(window.segments);
  }

  auto segments = memory_filter_.filter(event.address, event.size, stack_segments);
  if (segments.empty()) {
    return;
  }

  bool capture_reads = config_.memory.access == rewind_config::memory_access::reads ||
      config_.memory.access == rewind_config::memory_access::reads_writes;
  bool capture_writes = config_.memory.access == rewind_config::memory_access::writes ||
      config_.memory.access == rewind_config::memory_access::reads_writes;

  if (event.is_read && capture_reads) {
    append_memory_access(state, ctx, event, w1::rewind::memory_access_kind::read, segments);
  }
  if (event.is_write && capture_writes) {
    append_memory_access(state, ctx, event, w1::rewind::memory_access_kind::write, segments);
  }
}

void rewind_recorder::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  auto it = threads_.find(event.thread_id);
  if (it == threads_.end()) {
    return;
  }

  auto& state = it->second;
  flush_pending(state);

  if (builder_ready_ && builder_ && builder_->good()) {
    builder_->begin_thread(state.thread_id, state.thread_name);
    builder_->end_thread(state.thread_id);
    builder_->flush();
  }

  log_.inf(
      "rewind stats", redlog::field("thread_id", state.thread_id),
      redlog::field("flow_kind", instruction_flow_ ? "instructions" : "blocks"),
      redlog::field("flow_events", state.flow_count), redlog::field("snapshots", state.snapshot_count),
      redlog::field("memory_events", state.memory_events)
  );
}

bool rewind_recorder::ensure_builder_ready(w1::trace_context& ctx, const QBDI::GPRState* gpr) {
  if (builder_ready_) {
    return true;
  }
  if (!builder_ || !builder_->good()) {
    log_.err("trace builder not ready");
    return false;
  }
  if (!gpr) {
    log_.err("missing gpr state for register specs");
    return false;
  }

  arch_spec_ = w1::arch::detect_host_arch_spec();
  if (arch_spec_.arch_family == w1::arch::family::unknown || arch_spec_.arch_mode == w1::arch::mode::unknown) {
    log_.err("unsupported host architecture");
    return false;
  }

  w1::util::register_state regs = w1::util::register_capturer::capture(gpr);
  update_register_table(regs);
  if (register_specs_.empty()) {
    log_.err("register specs missing");
    return false;
  }
  ctx.modules().refresh();
  update_module_table(ctx.modules());

  auto memory_map = collect_memory_map(module_table_);

  w1::rewind::target_info_record target{};
  target.os = detect_os_id();
  target.abi.clear();
  target.cpu.clear();
  auto environment = build_target_environment(memory_map, module_table_, arch_spec_);
  if (!builder_->begin_trace(arch_spec_, target, environment, register_specs_)) {
    log_.err("failed to begin trace", redlog::field("error", builder_->error()));
    return false;
  }

  if (!module_table_.empty()) {
    if (!builder_->set_module_table(module_table_)) {
      log_.err("failed to write module table", redlog::field("error", builder_->error()));
      return false;
    }
  }

  if (!memory_map.empty()) {
    if (!builder_->set_memory_map(std::move(memory_map))) {
      log_.err("failed to write memory map", redlog::field("error", builder_->error()));
      return false;
    }
  }

  builder_ready_ = true;
  return true;
}

void rewind_recorder::flush_pending(thread_state& state) {
  if (!state.pending.has_value()) {
    return;
  }

  pending_instruction pending = std::move(*state.pending);
  state.pending.reset();

  if (!builder_ || !builder_->good()) {
    return;
  }

  uint64_t sequence = 0;
  if (instruction_flow_) {
    if (!builder_->emit_instruction(pending.thread_id, pending.address, pending.size, pending.flags, sequence)) {
      return;
    }
  }

  if (config_.registers.deltas && !pending.register_deltas.empty()) {
    if (!builder_->emit_register_deltas(pending.thread_id, sequence, pending.register_deltas)) {
      return;
    }
  }

  if (config_.memory.access != rewind_config::memory_access::none) {
    for (const auto& access : pending.memory_accesses) {
      if (!builder_->emit_memory_access(
              pending.thread_id, sequence, access.kind, access.address, access.size, access.value_known,
              access.value_truncated, access.data
          )) {
        return;
      }
    }
  }

  if (pending.snapshot.has_value()) {
    builder_->emit_snapshot(
        pending.thread_id, sequence, pending.snapshot->snapshot_id, pending.snapshot->registers,
        pending.snapshot->stack_segments, std::move(pending.snapshot->reason)
    );
  }
}

void rewind_recorder::capture_register_deltas(
    thread_state& state, const w1::util::register_state& regs, std::vector<w1::rewind::register_delta>& out
) {
  const auto& current = regs.get_register_map();
  const auto* previous = state.last_registers ? &state.last_registers->get_register_map() : nullptr;

  out.clear();
  out.reserve(register_table_.size());

  for (const auto& name : register_table_) {
    auto current_it = current.find(name);
    if (current_it == current.end()) {
      continue;
    }
    bool changed = true;
    if (previous) {
      auto previous_it = previous->find(name);
      if (previous_it != previous->end() && previous_it->second == current_it->second) {
        changed = false;
      }
    }
    if (!changed) {
      continue;
    }

    auto id_it = register_ids_.find(name);
    if (id_it == register_ids_.end()) {
      continue;
    }

    w1::rewind::register_delta delta{};
    delta.reg_id = id_it->second;
    delta.value = current_it->second;
    out.push_back(delta);
  }

  state.last_registers = regs;
}

std::vector<w1::rewind::register_delta> rewind_recorder::capture_register_snapshot(
    const w1::util::register_state& regs
) const {
  std::vector<w1::rewind::register_delta> out;
  const auto& current = regs.get_register_map();
  out.reserve(register_table_.size());

  for (const auto& name : register_table_) {
    auto current_it = current.find(name);
    if (current_it == current.end()) {
      continue;
    }

    auto id_it = register_ids_.find(name);
    if (id_it == register_ids_.end()) {
      continue;
    }

    w1::rewind::register_delta delta{};
    delta.reg_id = id_it->second;
    delta.value = current_it->second;
    out.push_back(delta);
  }

  return out;
}

std::vector<w1::rewind::stack_segment> rewind_recorder::capture_stack_segments(
    w1::trace_context& ctx, thread_state& state, const w1::util::register_state& regs
) {
  std::vector<w1::rewind::stack_segment> out;
  if (config_.stack_snapshots.interval == 0 || config_.stack_window.mode == rewind_config::stack_window_options::mode::none) {
    return out;
  }
  if (regs.get_register_map().empty()) {
    return out;
  }

  auto window = compute_stack_window_segments(regs, config_.stack_window);
  if (window.frame_window_missing && !state.warned_missing_frame) {
    log_.wrn("frame pointer not available; stack snapshot will use SP-only segments");
    state.warned_missing_frame = true;
  }

  out.reserve(window.segments.size());
  for (const auto& segment : window.segments) {
    if (segment.size == 0) {
      continue;
    }
    auto bytes = ctx.memory().read_bytes(segment.base, static_cast<size_t>(segment.size));
    if (!bytes.has_value()) {
      continue;
    }
    w1::rewind::stack_segment record{};
    record.base = segment.base;
    record.size = segment.size;
    record.bytes = std::move(*bytes);
    out.push_back(std::move(record));
  }

  return out;
}

std::optional<rewind_recorder::pending_snapshot> rewind_recorder::maybe_capture_snapshot(
    w1::trace_context& ctx, thread_state& state, const w1::util::register_state& regs
) {
  bool want_register_snapshot = config_.registers.snapshot_interval > 0;
  bool want_stack_snapshot = config_.stack_snapshots.interval > 0;

  bool register_due = false;
  bool stack_due = false;

  if (want_register_snapshot) {
    state.flow_since_register_snapshot += 1;
    if (state.flow_since_register_snapshot >= config_.registers.snapshot_interval) {
      state.flow_since_register_snapshot = 0;
      register_due = true;
    }
  }

  if (want_stack_snapshot) {
    state.flow_since_stack_snapshot += 1;
    if (state.flow_since_stack_snapshot >= config_.stack_snapshots.interval) {
      state.flow_since_stack_snapshot = 0;
      stack_due = true;
    }
  }

  if (!register_due && !stack_due) {
    return std::nullopt;
  }

  pending_snapshot snapshot{};
  snapshot.snapshot_id = state.snapshot_count++;
  if (register_due) {
    snapshot.registers = capture_register_snapshot(regs);
  }
  if (stack_due) {
    snapshot.stack_segments = capture_stack_segments(ctx, state, regs);
  }
  snapshot.reason = "interval";
  return snapshot;
}

void rewind_recorder::update_register_table(const w1::util::register_state& regs) {
  register_table_ = regs.get_register_names();
  register_ids_.clear();
  register_specs_.clear();
  register_specs_.reserve(register_table_.size());
  const auto& arch = arch_spec_;
  const uint32_t pointer_size = arch.pointer_bits == 0 ? static_cast<uint32_t>(sizeof(void*)) : arch.pointer_bits / 8;
  for (size_t i = 0; i < register_table_.size(); ++i) {
    const auto& name = register_table_[i];
    auto reg_id = static_cast<uint16_t>(i);
    register_ids_[name] = reg_id;

    w1::rewind::register_spec spec{};
    spec.reg_id = reg_id;
    spec.name = name;
    spec.bits = static_cast<uint16_t>(register_bitsize_for_name(arch, name, pointer_size));
    spec.flags = 0;
    if (is_pc_name(name)) {
      spec.flags |= w1::rewind::register_flag_pc;
    }
    if (is_sp_name(name)) {
      spec.flags |= w1::rewind::register_flag_sp;
    }
    if (is_flags_name(name)) {
      spec.flags |= w1::rewind::register_flag_flags;
    }
    spec.gdb_name = gdb_name_for_register(name, arch);
    spec.reg_class = register_class_for_name(name);
    spec.value_kind = w1::rewind::register_value_kind::u64;
    if (auto numbering = w1::rewind::lookup_register_numbering(arch, spec.gdb_name)) {
      spec.dwarf_regnum = numbering->dwarf_regnum;
      spec.ehframe_regnum = numbering->ehframe_regnum;
    }
    register_specs_.push_back(std::move(spec));
  }
}

void rewind_recorder::update_module_table(const w1::runtime::module_registry& modules) {
  module_table_.clear();

  auto list = modules.list_modules();
  module_table_.reserve(list.size());

  uint64_t next_id = 1;
  for (const auto& module : list) {
    w1::rewind::module_record record{};
    record.id = next_id++;
    record.base = module.base_address;
    record.size = module.size;
    record.permissions = module_perm_from_qbdi(module.permissions);
    record.path = module.path.empty() ? module.name : module.path;
    populate_module_identity(record, arch_spec_);
    module_table_.push_back(std::move(record));
  }
}

void rewind_recorder::append_memory_access(
    thread_state& state, w1::trace_context& ctx, const w1::memory_event& event, w1::rewind::memory_access_kind kind,
    const std::vector<w1::address_range>& segments
) {
  if (!state.pending.has_value()) {
    return;
  }
  if (segments.empty()) {
    return;
  }

  bool capture_values = config_.memory.values && config_.memory.max_value_bytes > 0;
  uint32_t max_bytes = config_.memory.max_value_bytes;
  std::array<uint8_t, 8> value_bytes{};
  bool have_value_bytes = false;

  if (capture_values && event.value_valid) {
    uint64_t value = event.value;
    for (size_t i = 0; i < value_bytes.size(); ++i) {
      value_bytes[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
    }
    have_value_bytes = true;
  }

  for (const auto& segment : segments) {
    if (segment.end <= segment.start) {
      continue;
    }
    uint64_t seg_size_u64 = segment.end - segment.start;
    if (seg_size_u64 > std::numeric_limits<uint32_t>::max()) {
      continue;
    }
    uint32_t seg_size = static_cast<uint32_t>(seg_size_u64);

    pending_memory_access record{};
    record.kind = kind;
    record.address = segment.start;
    record.size = seg_size;

    if (capture_values && seg_size > 0) {
      uint32_t capture_size = std::min(seg_size, max_bytes);
      if (capture_size > 0) {
        if (segment.start < event.address) {
          continue;
        }
        uint64_t offset = segment.start - event.address;
        if (have_value_bytes && (offset + capture_size) <= value_bytes.size()) {
          record.data.assign(
              value_bytes.begin() + static_cast<std::ptrdiff_t>(offset),
              value_bytes.begin() + static_cast<std::ptrdiff_t>(offset + capture_size)
          );
          record.value_known = true;
        } else {
          auto bytes = ctx.memory().read_bytes(segment.start, capture_size);
          if (bytes.has_value()) {
            record.data = std::move(*bytes);
            record.value_known = true;
          }
        }
        record.value_truncated = seg_size > capture_size;
      }
    }

    state.pending->memory_accesses.push_back(std::move(record));
    state.memory_events += 1;
  }
}

} // namespace w1rewind
