#include <cstdio>
#include <filesystem>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <redlog.hpp>

#include "w1rewind/format/trace_format.hpp"
#include "w1rewind/record/trace_builder.hpp"
#include "w1rewind/trace/trace_file_writer.hpp"
#include "w1rewind/trace/trace_reader.hpp"

namespace {

std::string make_temp_path() {
  auto base = std::filesystem::temp_directory_path() / "w1rewind_format_test.w1r";
  return base.string();
}

std::vector<uint8_t> encode_u64_le(uint64_t value, size_t size) {
  std::vector<uint8_t> bytes(size, 0);
  for (size_t i = 0; i < size; ++i) {
    bytes[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFFu);
  }
  return bytes;
}

std::optional<std::string> find_attr(
    const std::vector<std::pair<std::string, std::string>>& attrs, std::string_view key
) {
  for (const auto& [attr_key, value] : attrs) {
    if (attr_key == key) {
      return value;
    }
  }
  return std::nullopt;
}

bool write_sample_trace(const std::string& path, bool include_images, bool include_byte_reg) {
  w1::rewind::trace_file_writer_config writer_config;
  writer_config.path = path;
  writer_config.log = redlog::get_logger("w1rewind.test.trace");
  auto writer = w1::rewind::make_trace_file_writer(std::move(writer_config));
  if (!writer || !writer->open()) {
    std::cerr << "failed to open trace writer\n";
    return false;
  }

  w1::rewind::trace_builder_config builder_config;
  builder_config.sink = writer;
  builder_config.log = redlog::get_logger("w1rewind.test.builder");
  w1::rewind::trace_builder builder(std::move(builder_config));

  w1::rewind::file_header header{};
  header.default_chunk_size = 256;
  if (!builder.begin_trace(header)) {
    std::cerr << "failed to begin trace: " << builder.error() << "\n";
    return false;
  }

  w1::rewind::arch_descriptor_record arch{};
  arch.arch_id = "x86_64";
  arch.byte_order = w1::rewind::endian::little;
  arch.pointer_bits = 64;
  arch.address_bits = 64;
  arch.modes.push_back({0, "x86_64"});
  arch.gdb_arch = "i386:x86-64";
  arch.gdb_feature = "org.gnu.gdb.i386.x86-64";
  if (!builder.emit_arch_descriptor(arch)) {
    std::cerr << "failed to emit arch descriptor: " << builder.error() << "\n";
    return false;
  }

  w1::rewind::environment_record environment{};
  environment.os_id = "test";
  environment.abi = "test";
  environment.cpu = "test";
  environment.hostname = "test-host";
  environment.pid = 123;
  environment.attrs.emplace_back("os_version", "1.0");
  environment.attrs.emplace_back("os_build", "test-build");
  environment.attrs.emplace_back("os_kernel", "test-kernel");
  if (!builder.emit_environment(environment)) {
    std::cerr << "failed to emit environment: " << builder.error() << "\n";
    return false;
  }

  w1::rewind::address_space_record space{};
  space.space_id = 0;
  space.name = "default";
  space.address_bits = 64;
  space.byte_order = w1::rewind::endian::little;
  if (!builder.emit_address_space(space)) {
    std::cerr << "failed to emit address space: " << builder.error() << "\n";
    return false;
  }

  w1::rewind::register_file_record regfile{};
  regfile.regfile_id = 0;
  regfile.name = "default";
  regfile.registers.push_back({0, "rax", 64, 0, "rax"});
  regfile.registers.push_back({1, "rsp", 64, w1::rewind::register_flag_sp, "rsp"});
  regfile.registers.push_back({2, "rip", 64, w1::rewind::register_flag_pc, "rip"});
  if (include_byte_reg) {
    regfile.registers.push_back({3, "v0", 128, 0, "v0"});
  }
  if (!builder.emit_register_file(regfile)) {
    std::cerr << "failed to emit register file: " << builder.error() << "\n";
    return false;
  }

  if (include_images) {
    w1::rewind::image_record image{};
    image.image_id = 1;
    image.kind = "test";
    image.name = "test_module";
    image.identity = "test_module";
    image.path = "test_module";
    if (!builder.emit_image(image)) {
      std::cerr << "failed to emit image: " << builder.error() << "\n";
      return false;
    }

    w1::rewind::mapping_record mapping{};
    mapping.space_id = 0;
    mapping.base = 0x1000;
    mapping.size = 0x2000;
    mapping.perms = w1::rewind::mapping_perm::read | w1::rewind::mapping_perm::exec;
    mapping.image_id = 1;
    mapping.name = "test_module";
    if (!builder.emit_mapping(mapping)) {
      std::cerr << "failed to emit mapping: " << builder.error() << "\n";
      return false;
    }
  }

  w1::rewind::thread_start_record start{};
  start.thread_id = 1;
  start.name = "main";
  if (!builder.emit_thread_start(start)) {
    std::cerr << "failed to emit thread start: " << builder.error() << "\n";
    return false;
  }

  w1::rewind::flow_instruction_record flow{};
  flow.thread_id = 1;
  flow.sequence = 0;
  flow.space_id = 0;
  flow.address = 0x1010;
  flow.size = 4;
  if (!builder.emit_flow_instruction(flow)) {
    std::cerr << "failed to emit instruction: " << builder.error() << "\n";
    return false;
  }

  w1::rewind::reg_write_record reg_write{};
  reg_write.thread_id = 1;
  reg_write.sequence = 0;
  reg_write.regfile_id = 0;
  reg_write.entries.push_back({w1::rewind::reg_ref_kind::reg_id, 0, 0, 8, 0, "", encode_u64_le(0x1234, 8)});
  reg_write.entries.push_back({w1::rewind::reg_ref_kind::reg_id, 0, 0, 8, 1, "", encode_u64_le(0x2000, 8)});
  reg_write.entries.push_back({w1::rewind::reg_ref_kind::reg_id, 0, 0, 8, 2, "", encode_u64_le(0x1010, 8)});
  if (include_byte_reg) {
    std::vector<uint8_t> reg_bytes = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    reg_write.entries.push_back({w1::rewind::reg_ref_kind::reg_id, 0, 0, 16, 3, "", reg_bytes});
  }
  if (!builder.emit_reg_write(reg_write)) {
    std::cerr << "failed to emit reg write: " << builder.error() << "\n";
    return false;
  }

  w1::rewind::mem_access_record mem_access{};
  mem_access.thread_id = 1;
  mem_access.sequence = 0;
  mem_access.space_id = 0;
  mem_access.op = w1::rewind::mem_access_op::write;
  mem_access.flags = w1::rewind::mem_access_value_known;
  mem_access.address = 0x2000;
  mem_access.access_size = 4;
  mem_access.value = {0x11, 0x22, 0x33, 0x44};
  if (!builder.emit_mem_access(mem_access)) {
    std::cerr << "failed to emit memory access: " << builder.error() << "\n";
    return false;
  }

  w1::rewind::snapshot_record snapshot{};
  snapshot.thread_id = 1;
  snapshot.sequence = 0;
  snapshot.regfile_id = 0;
  snapshot.registers = reg_write.entries;
  snapshot.memory_segments.push_back({0, 0x3000, {0xaa, 0xbb, 0xcc, 0xdd}});
  if (!builder.emit_snapshot(snapshot)) {
    std::cerr << "failed to emit snapshot: " << builder.error() << "\n";
    return false;
  }

  w1::rewind::thread_end_record end{};
  end.thread_id = 1;
  if (!builder.emit_thread_end(end)) {
    std::cerr << "failed to emit thread end: " << builder.error() << "\n";
    return false;
  }

  builder.flush();
  writer->close();
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

  bool saw_arch = false;
  bool saw_environment = false;
  bool saw_regs = false;
  bool saw_instruction = false;
  bool saw_memory = false;
  bool saw_snapshot = false;
  bool saw_image = false;
  bool saw_mapping = false;

  w1::rewind::trace_record record;
  while (reader.read_next(record)) {
    if (std::holds_alternative<w1::rewind::arch_descriptor_record>(record)) {
      const auto& arch = std::get<w1::rewind::arch_descriptor_record>(record);
      if (arch.arch_id != "x86_64" || arch.pointer_bits != 64 || arch.byte_order != w1::rewind::endian::little) {
        std::cerr << "arch descriptor mismatch\n";
        return 1;
      }
      saw_arch = true;
    } else if (std::holds_alternative<w1::rewind::environment_record>(record)) {
      const auto& env = std::get<w1::rewind::environment_record>(record);
      if (env.hostname != "test-host" || env.pid != 123) {
        std::cerr << "environment mismatch\n";
        return 1;
      }
      auto os_version = find_attr(env.attrs, "os_version");
      if (!os_version.has_value() || *os_version != "1.0") {
        std::cerr << "environment attrs mismatch\n";
        return 1;
      }
      saw_environment = true;
    } else if (std::holds_alternative<w1::rewind::register_file_record>(record)) {
      const auto& regfile = std::get<w1::rewind::register_file_record>(record);
      if (regfile.registers.size() != 3 || regfile.registers[1].name != "rsp") {
        std::cerr << "register file mismatch\n";
        return 1;
      }
      saw_regs = true;
    } else if (std::holds_alternative<w1::rewind::flow_instruction_record>(record)) {
      saw_instruction = true;
    } else if (std::holds_alternative<w1::rewind::mem_access_record>(record)) {
      saw_memory = true;
    } else if (std::holds_alternative<w1::rewind::snapshot_record>(record)) {
      saw_snapshot = true;
    } else if (std::holds_alternative<w1::rewind::image_record>(record)) {
      saw_image = true;
    } else if (std::holds_alternative<w1::rewind::mapping_record>(record)) {
      saw_mapping = true;
    }
  }

  if (!reader.error().empty()) {
    std::cerr << "trace reader error: " << reader.error() << "\n";
    return 1;
  }

  const auto& header = reader.header();
  if (header.default_chunk_size != 256) {
    std::cerr << "trace header mismatch\n";
    return 1;
  }

  if (!saw_arch || !saw_environment || !saw_regs || !saw_instruction || !saw_memory || !saw_snapshot ||
      !saw_image || !saw_mapping) {
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
    bool include_images = true;
    bool include_byte_reg = false;
    for (int i = 2; i < argc; ++i) {
      std::string arg = argv[i];
      if (arg == "--moduleless") {
        include_images = false;
      } else if (arg == "--byte-reg") {
        include_byte_reg = true;
      }
    }
    return write_sample_trace(path, include_images, include_byte_reg) ? 0 : 1;
  }
  return run_test();
}
