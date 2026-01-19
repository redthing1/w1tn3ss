#include <cstdio>
#include <filesystem>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include <redlog.hpp>

#include "w1rewind/format/trace_format.hpp"
#include "w1rewind/record/trace_builder.hpp"
#include "w1rewind/replay/trace_reader.hpp"

namespace {

std::string make_temp_path() {
  auto base = std::filesystem::temp_directory_path() / "w1rewind_format_test.w1r";
  return base.string();
}

bool write_sample_trace(const std::string& path, bool include_modules, bool include_byte_reg) {
  w1::rewind::trace_writer_config writer_config;
  writer_config.path = path;
  writer_config.log = redlog::get_logger("w1rewind.test.trace");
  auto writer = w1::rewind::make_trace_writer(std::move(writer_config));
  if (!writer || !writer->open()) {
    std::cerr << "failed to open trace writer\n";
    return false;
  }

  w1::rewind::trace_builder_config builder_config;
  builder_config.writer = writer;
  builder_config.log = redlog::get_logger("w1rewind.test.builder");
  builder_config.options.record_instructions = true;
  builder_config.options.record_register_deltas = true;
  builder_config.options.record_memory_access = true;
  builder_config.options.record_memory_values = true;
  builder_config.options.record_snapshots = true;
  builder_config.options.record_stack_snapshot = true;

  w1::rewind::trace_builder builder(std::move(builder_config));

  w1::arch::arch_spec arch{};
  std::string arch_error;
  if (!w1::arch::parse_arch_spec("x86_64", arch, arch_error)) {
    std::cerr << "failed to parse arch spec: " << arch_error << "\n";
    return false;
  }

  w1::rewind::target_info_record target{};
  target.os = "test";
  target.abi = "test";
  target.cpu = "test";

  std::vector<w1::rewind::register_spec> regs;
  regs.push_back(
      w1::rewind::register_spec{
          0, "rax", 64, 0, "rax", w1::rewind::register_class::gpr, w1::rewind::register_value_kind::u64
      }
  );
  regs.push_back(
      w1::rewind::register_spec{
          1, "rsp", 64, w1::rewind::register_flag_sp, "rsp", w1::rewind::register_class::gpr,
          w1::rewind::register_value_kind::u64
      }
  );
  regs.push_back(
      w1::rewind::register_spec{
          2, "rip", 64, w1::rewind::register_flag_pc, "rip", w1::rewind::register_class::gpr,
          w1::rewind::register_value_kind::u64
      }
  );
  if (include_byte_reg) {
    regs.push_back(
        w1::rewind::register_spec{
            3, "v0", 128, 0, "v0", w1::rewind::register_class::simd, w1::rewind::register_value_kind::bytes
        }
    );
  }

  if (!builder.begin_trace(arch, target, regs)) {
    std::cerr << "failed to begin trace: " << builder.error() << "\n";
    return false;
  }

  if (include_modules) {
    w1::rewind::module_record module{};
    module.id = 1;
    module.base = 0x1000;
    module.size = 0x2000;
    module.permissions = w1::rewind::module_perm::read | w1::rewind::module_perm::exec;
    module.path = "test_module";
    builder.set_module_table({module});
  }

  if (!builder.begin_thread(1, "main")) {
    std::cerr << "failed to write thread start: " << builder.error() << "\n";
    return false;
  }

  uint64_t sequence = 0;
  if (!builder.emit_instruction(1, 0x1000 + 0x10, 4, 0, sequence)) {
    std::cerr << "failed to emit instruction: " << builder.error() << "\n";
    return false;
  }

  std::vector<w1::rewind::register_delta> deltas;
  deltas.push_back({0, 0x1234});
  deltas.push_back({1, 0x2000});
  deltas.push_back({2, 0x1010});
  if (!builder.emit_register_deltas(1, sequence, std::span<const w1::rewind::register_delta>(deltas))) {
    std::cerr << "failed to emit register deltas: " << builder.error() << "\n";
    return false;
  }

  if (include_byte_reg) {
    std::vector<uint8_t> reg_bytes = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    std::vector<w1::rewind::register_bytes_entry> entries;
    entries.push_back(w1::rewind::register_bytes_entry{3, 0, 16});
    if (!builder.emit_register_bytes(
            1, sequence, std::span<const w1::rewind::register_bytes_entry>(entries), std::span<const uint8_t>(reg_bytes)
        )) {
      std::cerr << "failed to emit register bytes: " << builder.error() << "\n";
      return false;
    }
  }

  std::vector<uint8_t> bytes = {0x11, 0x22, 0x33, 0x44};
  if (!builder.emit_memory_access(
          1, sequence, w1::rewind::memory_access_kind::write, 0x2000, 4, true, false, std::span<const uint8_t>(bytes)
      )) {
    std::cerr << "failed to emit memory access: " << builder.error() << "\n";
    return false;
  }

  std::vector<uint8_t> stack = {0xaa, 0xbb, 0xcc, 0xdd};
  if (!builder.emit_snapshot(
          1, sequence, 0, std::span<const w1::rewind::register_delta>(deltas), std::span<const uint8_t>(stack), "test"
      )) {
    std::cerr << "failed to emit snapshot: " << builder.error() << "\n";
    return false;
  }

  builder.end_thread(1);
  builder.flush();
  return true;
}

int run_test() {
  std::string path = make_temp_path();
  std::error_code ec;
  std::filesystem::remove(path, ec);

  if (!write_sample_trace(path, true, false)) {
    return 1;
  }

  w1::rewind::trace_reader reader(path);
  if (!reader.open()) {
    std::cerr << "failed to open trace reader: " << reader.error() << "\n";
    return 1;
  }

  bool saw_target = false;
  bool saw_regs = false;
  bool saw_instruction = false;
  bool saw_memory = false;
  bool saw_snapshot = false;

  w1::rewind::trace_record record;
  while (reader.read_next(record)) {
    if (std::holds_alternative<w1::rewind::target_info_record>(record)) {
      const auto& info = std::get<w1::rewind::target_info_record>(record);
      if (info.os != "test" || info.abi != "test" || info.cpu != "test") {
        std::cerr << "target info mismatch\n";
        return 1;
      }
      saw_target = true;
    } else if (std::holds_alternative<w1::rewind::register_spec_record>(record)) {
      const auto& specs = std::get<w1::rewind::register_spec_record>(record).registers;
      if (specs.size() != 3 || specs[1].name != "rsp") {
        std::cerr << "register specs mismatch\n";
        return 1;
      }
      saw_regs = true;
    } else if (std::holds_alternative<w1::rewind::instruction_record>(record)) {
      saw_instruction = true;
    } else if (std::holds_alternative<w1::rewind::memory_access_record>(record)) {
      saw_memory = true;
    } else if (std::holds_alternative<w1::rewind::snapshot_record>(record)) {
      saw_snapshot = true;
    }
  }

  if (!reader.error().empty()) {
    std::cerr << "trace reader error: " << reader.error() << "\n";
    return 1;
  }

  const auto& header = reader.header();
  if (header.arch.arch_mode != w1::arch::mode::x86_64 || header.arch.pointer_bits != 64 ||
      header.arch.arch_byte_order != w1::arch::byte_order::little) {
    std::cerr << "trace header arch mismatch\n";
    return 1;
  }

  if (!saw_target || !saw_regs || !saw_instruction || !saw_memory || !saw_snapshot) {
    std::cerr << "missing expected records\n";
    return 1;
  }

  std::filesystem::remove(path, ec);
  return 0;
}

} // namespace

int main(int argc, char** argv) {
  if (argc > 1) {
    std::string path = argv[1];
    bool include_modules = true;
    bool include_byte_reg = false;
    for (int i = 2; i < argc; ++i) {
      std::string arg = argv[i];
      if (arg == "--moduleless") {
        include_modules = false;
      } else if (arg == "--byte-reg") {
        include_byte_reg = true;
      }
    }
    return write_sample_trace(path, include_modules, include_byte_reg) ? 0 : 1;
  }
  return run_test();
}
