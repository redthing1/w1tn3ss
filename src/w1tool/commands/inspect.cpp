#include "inspect.hpp"

#include <redlog.hpp>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <vector>

#include "w1base/uuid_format.hpp"

#ifdef WITNESS_LIEF_ENABLED
#include <LIEF/LIEF.hpp>
#include <LIEF/ELF/DynamicEntryRpath.hpp>
#include <LIEF/ELF/DynamicEntryRunPath.hpp>
#include <LIEF/ELF/DynamicSharedObject.hpp>
#include <LIEF/ELF/Parser.hpp>
#include <LIEF/ELF/Relocation.hpp>
#include <LIEF/MachO/BuildVersion.hpp>
#include <LIEF/MachO/DylinkerCommand.hpp>
#include <LIEF/MachO/Parser.hpp>
#include <LIEF/MachO/RPathCommand.hpp>
#include <LIEF/MachO/Relocation.hpp>
#include <LIEF/MachO/UUIDCommand.hpp>
#include <LIEF/PE/Parser.hpp>
#include <LIEF/PE/RelocationEntry.hpp>
#include <nlohmann/json.hpp>
#endif

namespace fs = std::filesystem;

namespace w1tool::commands {

#ifndef WITNESS_LIEF_ENABLED

int inspect(const inspect_request&) {
  auto log = redlog::get_logger("w1tool.inspect");
  log.error("binary inspection requires LIEF support");
  log.error("build with -DWITNESS_LIEF=ON to enable this feature");
  return 1;
}

#else

namespace detail {

struct summary_info {
  std::string path;
  std::string format;
  std::string architecture;
  std::string bitness;
  std::string endianness;
  std::string file_type;
  uint64_t entrypoint = 0;
  bool has_entrypoint = false;
  uint64_t imagebase = 0;
  bool has_imagebase = false;
  uint64_t file_size = 0;
  size_t sections = 0;
  size_t segments = 0;
  bool segments_supported = true;
  size_t imports = 0;
  size_t exports = 0;
  size_t symbols = 0;
  size_t relocations = 0;
  size_t libraries = 0;
};

struct elf_header_info {
  std::string os_abi;
  uint32_t abi_version = 0;
  std::string class_type;
  std::string data_encoding;
  std::string machine;
  std::string interpreter;
  std::string soname;
  std::string rpath;
  std::string runpath;
  std::string build_id;
};

struct pe_header_info {
  std::string machine;
  std::string subsystem;
  uint32_t timestamp = 0;
  uint8_t linker_major = 0;
  uint8_t linker_minor = 0;
  uint64_t imagebase = 0;
  uint32_t entrypoint_rva = 0;
  uint64_t entrypoint = 0;
  uint32_t section_alignment = 0;
  uint32_t file_alignment = 0;
  std::vector<std::string> dll_characteristics;
};

struct macho_header_info {
  std::string cpu_type;
  uint32_t cpu_subtype = 0;
  std::string file_type;
  std::vector<std::string> flags;
  uint32_t load_commands = 0;
  std::string uuid;
  std::string build_platform;
  std::string build_minos;
  std::string build_sdk;
  std::string dylinker;
  std::vector<std::string> rpaths;
};

struct section_info {
  std::string name;
  uint64_t address = 0;
  uint64_t size = 0;
  uint64_t offset = 0;
  std::string perms;
  std::string kind;
};

struct segment_info {
  std::string name;
  uint64_t address = 0;
  uint64_t vsize = 0;
  uint64_t offset = 0;
  uint64_t fsize = 0;
  std::string perms;
  std::string kind;
};

struct symbol_info {
  std::string name;
  uint64_t address = 0;
  uint64_t size = 0;
};

struct function_info {
  std::string name;
  uint64_t address = 0;
};

struct relocation_info {
  uint64_t address = 0;
  size_t size = 0;
  std::string type;
  std::string symbol;
  std::string origin;
};

struct inspect_report {
  summary_info summary;
  std::vector<section_info> sections;
  std::vector<segment_info> segments;
  std::vector<symbol_info> symbols;
  std::vector<function_info> imports;
  std::vector<function_info> exports;
  std::vector<relocation_info> relocations;
  std::vector<std::string> libraries;
  std::optional<elf_header_info> elf_header;
  std::optional<pe_header_info> pe_header;
  std::optional<macho_header_info> macho_header;
};

std::string to_lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

std::string format_address(uint64_t addr) {
  std::ostringstream out;
  out << "0x" << std::hex << addr;
  return out.str();
}

std::string format_bytes(uint64_t bytes) {
  if (bytes >= 1024ULL * 1024 * 1024) {
    double gb = static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0);
    std::ostringstream out;
    out << std::fixed << std::setprecision(1) << gb << " GB";
    return out.str();
  }
  if (bytes >= 1024ULL * 1024) {
    double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
    std::ostringstream out;
    out << std::fixed << std::setprecision(1) << mb << " MB";
    return out.str();
  }
  if (bytes >= 1024ULL) {
    double kb = static_cast<double>(bytes) / 1024.0;
    std::ostringstream out;
    out << std::fixed << std::setprecision(1) << kb << " KB";
    return out.str();
  }
  return std::to_string(bytes) + " B";
}

std::string format_permissions(bool read, bool write, bool exec) {
  std::string perms = "---";
  if (read) {
    perms[0] = 'r';
  }
  if (write) {
    perms[1] = 'w';
  }
  if (exec) {
    perms[2] = 'x';
  }
  return perms;
}

std::string format_version(const LIEF::MachO::BuildVersion::version_t& version) {
  std::ostringstream out;
  out << version[0] << "." << version[1] << "." << version[2];
  return out.str();
}

std::string format_build_id(LIEF::span<const uint8_t> bytes) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (uint8_t byte : bytes) {
    out << std::setw(2) << static_cast<int>(byte);
  }
  return out.str();
}

std::string macho_endianness(const LIEF::MachO::Header& header) {
  using LIEF::MachO::MACHO_TYPES;
  auto magic = header.magic();
  if (magic == MACHO_TYPES::MAGIC || magic == MACHO_TYPES::MAGIC_64 || magic == MACHO_TYPES::MAGIC_FAT) {
    return "big-endian";
  }
  if (magic == MACHO_TYPES::CIGAM || magic == MACHO_TYPES::CIGAM_64 || magic == MACHO_TYPES::CIGAM_FAT) {
    return "little-endian";
  }
  return "unknown";
}

std::unique_ptr<LIEF::Binary> parse_binary(const inspect_request& request, redlog::logger& log) {
  if (request.forced_format.empty()) {
    return LIEF::Parser::parse(request.binary_path);
  }

  std::string format = to_lower(request.forced_format);
  if (format == "elf") {
    return LIEF::ELF::Parser::parse(request.binary_path);
  }
  if (format == "pe") {
    return LIEF::PE::Parser::parse(request.binary_path);
  }
  if (format == "macho" || format == "mach-o" || format == "mach") {
    auto fat = LIEF::MachO::Parser::parse(request.binary_path);
    if (!fat || fat->empty()) {
      return nullptr;
    }
    return fat->take(fat->size() - 1);
  }

  log.error("unsupported format override", redlog::field("format", request.forced_format));
  return nullptr;
}

std::string format_name_or_placeholder(const std::string& name) { return name.empty() ? "-" : name; }

inspect_report build_report(const inspect_request& request, LIEF::Binary& binary) {
  inspect_report report;

  report.summary.path = request.binary_path;
  report.summary.file_size = fs::file_size(request.binary_path);

  switch (binary.format()) {
  case LIEF::Binary::FORMATS::ELF:
    report.summary.format = "ELF";
    break;
  case LIEF::Binary::FORMATS::PE:
    report.summary.format = "PE";
    break;
  case LIEF::Binary::FORMATS::MACHO:
    report.summary.format = "Mach-O";
    break;
  default:
    report.summary.format = "Unknown";
    break;
  }

  for (const auto& section : binary.sections()) {
    report.summary.sections++;
    if (request.show_sections) {
      section_info info;
      info.name = section.name();
      info.address = section.virtual_address();
      info.size = section.size();
      info.offset = section.offset();
      info.perms = "---";
      info.kind = "";

      if (auto elf_section = dynamic_cast<const LIEF::ELF::Section*>(&section)) {
        bool read = elf_section->has(LIEF::ELF::Section::FLAGS::ALLOC);
        bool write = elf_section->has(LIEF::ELF::Section::FLAGS::WRITE);
        bool exec = elf_section->has(LIEF::ELF::Section::FLAGS::EXECINSTR);
        info.perms = format_permissions(read, write, exec);
        info.kind = LIEF::ELF::to_string(elf_section->type());
      } else if (auto pe_section = dynamic_cast<const LIEF::PE::Section*>(&section)) {
        bool read = pe_section->has_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_READ);
        bool write = pe_section->has_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE);
        bool exec = pe_section->has_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE);
        info.perms = format_permissions(read, write, exec);
        if (pe_section->has_characteristic(LIEF::PE::Section::CHARACTERISTICS::CNT_CODE)) {
          info.kind = "CODE";
        } else if (pe_section->has_characteristic(LIEF::PE::Section::CHARACTERISTICS::CNT_INITIALIZED_DATA)) {
          info.kind = "DATA";
        } else if (pe_section->has_characteristic(LIEF::PE::Section::CHARACTERISTICS::CNT_UNINITIALIZED_DATA)) {
          info.kind = "BSS";
        } else {
          info.kind = "OTHER";
        }
      } else if (auto macho_section = dynamic_cast<const LIEF::MachO::Section*>(&section)) {
        bool read = false;
        bool write = false;
        bool exec = false;
        if (macho_section->has_segment()) {
          const auto* segment = macho_section->segment();
          if (segment != nullptr) {
            uint32_t init = segment->init_protection();
            read = (init & static_cast<uint32_t>(LIEF::MachO::SegmentCommand::VM_PROTECTIONS::READ)) != 0;
            write = (init & static_cast<uint32_t>(LIEF::MachO::SegmentCommand::VM_PROTECTIONS::WRITE)) != 0;
            exec = (init & static_cast<uint32_t>(LIEF::MachO::SegmentCommand::VM_PROTECTIONS::EXECUTE)) != 0;
          }
        }
        info.perms = format_permissions(read, write, exec);
        info.kind = LIEF::MachO::to_string(macho_section->type());
      }

      report.sections.push_back(std::move(info));
    }
  }

  for (const auto& symbol : binary.symbols()) {
    report.summary.symbols++;
    if (request.show_symbols) {
      symbol_info info;
      info.name = symbol.name();
      info.address = symbol.value();
      info.size = symbol.size();
      report.symbols.push_back(std::move(info));
    }
  }

  auto imported_functions = binary.imported_functions();
  auto exported_functions = binary.exported_functions();
  auto imported_libraries = binary.imported_libraries();

  report.summary.imports = imported_functions.size();
  report.summary.exports = exported_functions.size();
  report.summary.libraries = imported_libraries.size();

  if (request.show_imports) {
    for (const auto& func : imported_functions) {
      function_info info;
      info.name = func.name();
      info.address = func.address();
      report.imports.push_back(std::move(info));
    }
  }

  if (request.show_exports) {
    for (const auto& func : exported_functions) {
      function_info info;
      info.name = func.name();
      info.address = func.address();
      report.exports.push_back(std::move(info));
    }
  }

  if (request.show_libraries) {
    report.libraries = imported_libraries;
  }

  size_t relocation_count = 0;
  for (const auto& reloc : binary.relocations()) {
    relocation_count++;
    if (request.show_relocations) {
      relocation_info info;
      info.address = reloc.address();
      info.size = reloc.size();

      if (auto elf_reloc = dynamic_cast<const LIEF::ELF::Relocation*>(&reloc)) {
        info.type = LIEF::ELF::to_string(elf_reloc->type());
        if (elf_reloc->has_symbol() && elf_reloc->symbol() != nullptr) {
          info.symbol = elf_reloc->symbol()->name();
        }
      } else if (auto pe_reloc = dynamic_cast<const LIEF::PE::RelocationEntry*>(&reloc)) {
        info.type = LIEF::PE::to_string(pe_reloc->type());
      } else if (auto macho_reloc = dynamic_cast<const LIEF::MachO::Relocation*>(&reloc)) {
        info.type = std::to_string(macho_reloc->type());
        info.origin = LIEF::MachO::to_string(macho_reloc->origin());
        if (macho_reloc->has_symbol() && macho_reloc->symbol() != nullptr) {
          info.symbol = macho_reloc->symbol()->name();
        }
      }

      report.relocations.push_back(std::move(info));
    }
  }
  report.summary.relocations = relocation_count;

  if (binary.format() == LIEF::Binary::FORMATS::ELF) {
    const auto& elf = static_cast<const LIEF::ELF::Binary&>(binary);
    const auto& header = elf.header();

    report.summary.architecture = LIEF::ELF::to_string(header.machine_type());
    report.summary.bitness = header.identity_class() == LIEF::ELF::Header::CLASS::ELF64 ? "64-bit" : "32-bit";
    report.summary.endianness =
        header.identity_data() == LIEF::ELF::Header::ELF_DATA::LSB ? "little-endian" : "big-endian";
    report.summary.file_type = LIEF::ELF::to_string(header.file_type());
    report.summary.entrypoint = elf.entrypoint();
    report.summary.has_entrypoint = true;
    report.summary.imagebase = elf.imagebase();
    report.summary.has_imagebase = report.summary.imagebase != 0;

    if (request.show_segments) {
      for (const auto& segment : elf.segments()) {
        report.summary.segments++;
        segment_info info;
        info.name = LIEF::ELF::to_string(segment.type());
        info.address = segment.virtual_address();
        info.vsize = segment.virtual_size();
        info.offset = segment.file_offset();
        info.fsize = segment.physical_size();
        bool read = segment.has(LIEF::ELF::Segment::FLAGS::R);
        bool write = segment.has(LIEF::ELF::Segment::FLAGS::W);
        bool exec = segment.has(LIEF::ELF::Segment::FLAGS::X);
        info.perms = format_permissions(read, write, exec);
        info.kind = "ELF";
        report.segments.push_back(std::move(info));
      }
    } else {
      for (const auto& segment : elf.segments()) {
        report.summary.segments++;
        (void) segment;
      }
    }

    if (request.show_headers) {
      elf_header_info header_info;
      header_info.os_abi = LIEF::ELF::to_string(header.identity_os_abi());
      header_info.abi_version = header.identity_abi_version();
      header_info.class_type = LIEF::ELF::to_string(header.identity_class());
      header_info.data_encoding = LIEF::ELF::to_string(header.identity_data());
      header_info.machine = LIEF::ELF::to_string(header.machine_type());
      if (elf.has_interpreter()) {
        header_info.interpreter = elf.interpreter();
      }
      if (elf.has(LIEF::ELF::DynamicEntry::TAG::SONAME)) {
        if (const auto* soname =
                dynamic_cast<const LIEF::ELF::DynamicSharedObject*>(elf.get(LIEF::ELF::DynamicEntry::TAG::SONAME))) {
          header_info.soname = soname->name();
        }
      }
      if (elf.has(LIEF::ELF::DynamicEntry::TAG::RPATH)) {
        if (const auto* rpath =
                dynamic_cast<const LIEF::ELF::DynamicEntryRpath*>(elf.get(LIEF::ELF::DynamicEntry::TAG::RPATH))) {
          header_info.rpath = rpath->rpath();
        }
      }
      if (elf.has(LIEF::ELF::DynamicEntry::TAG::RUNPATH)) {
        if (const auto* runpath =
                dynamic_cast<const LIEF::ELF::DynamicEntryRunPath*>(elf.get(LIEF::ELF::DynamicEntry::TAG::RUNPATH))) {
          header_info.runpath = runpath->runpath();
        }
      }
      if (elf.has_notes()) {
        for (const auto& note : elf.notes()) {
          if (note.type() == LIEF::ELF::Note::TYPE::GNU_BUILD_ID) {
            header_info.build_id = format_build_id(note.description());
            break;
          }
        }
      }

      report.elf_header = header_info;
    }
  } else if (binary.format() == LIEF::Binary::FORMATS::PE) {
    const auto& pe = static_cast<const LIEF::PE::Binary&>(binary);
    const auto& header = pe.header();
    const auto& optional = pe.optional_header();

    report.summary.architecture = LIEF::PE::to_string(header.machine());
    report.summary.bitness = pe.type() == LIEF::PE::PE_TYPE::PE32_PLUS ? "64-bit" : "32-bit";
    report.summary.endianness = "little-endian";
    report.summary.file_type = header.has_characteristic(LIEF::PE::Header::CHARACTERISTICS::DLL) ? "DLL" : "Executable";
    report.summary.entrypoint = pe.entrypoint();
    report.summary.has_entrypoint = optional.addressof_entrypoint() != 0;
    report.summary.imagebase = pe.imagebase();
    report.summary.has_imagebase = report.summary.imagebase != 0;
    report.summary.segments_supported = false;

    if (request.show_headers) {
      pe_header_info header_info;
      header_info.machine = LIEF::PE::to_string(header.machine());
      header_info.subsystem = LIEF::PE::to_string(optional.subsystem());
      header_info.timestamp = header.time_date_stamp();
      header_info.linker_major = optional.major_linker_version();
      header_info.linker_minor = optional.minor_linker_version();
      header_info.imagebase = optional.imagebase();
      header_info.entrypoint_rva = optional.addressof_entrypoint();
      header_info.entrypoint = pe.entrypoint();
      header_info.section_alignment = optional.section_alignment();
      header_info.file_alignment = optional.file_alignment();
      for (auto flag : optional.dll_characteristics_list()) {
        header_info.dll_characteristics.emplace_back(LIEF::PE::to_string(flag));
      }
      report.pe_header = header_info;
    }
  } else if (binary.format() == LIEF::Binary::FORMATS::MACHO) {
    const auto& macho = static_cast<const LIEF::MachO::Binary&>(binary);
    const auto& header = macho.header();

    report.summary.architecture = LIEF::MachO::to_string(header.cpu_type());
    report.summary.bitness = header.is_64bit() ? "64-bit" : "32-bit";
    report.summary.endianness = macho_endianness(header);
    report.summary.file_type = LIEF::MachO::to_string(header.file_type());
    report.summary.entrypoint = macho.entrypoint();
    report.summary.has_entrypoint = macho.has_entrypoint();
    report.summary.imagebase = macho.imagebase();
    report.summary.has_imagebase = report.summary.imagebase != 0;

    if (request.show_segments) {
      for (const auto& segment : macho.segments()) {
        report.summary.segments++;
        segment_info info;
        info.name = segment.name();
        info.address = segment.virtual_address();
        info.vsize = segment.virtual_size();
        info.offset = segment.file_offset();
        info.fsize = segment.file_size();
        bool read =
            (segment.init_protection() & static_cast<uint32_t>(LIEF::MachO::SegmentCommand::VM_PROTECTIONS::READ)) != 0;
        bool write = (segment.init_protection() &
                      static_cast<uint32_t>(LIEF::MachO::SegmentCommand::VM_PROTECTIONS::WRITE)) != 0;
        bool exec = (segment.init_protection() &
                     static_cast<uint32_t>(LIEF::MachO::SegmentCommand::VM_PROTECTIONS::EXECUTE)) != 0;
        info.perms = format_permissions(read, write, exec);
        info.kind = "Mach-O";
        report.segments.push_back(std::move(info));
      }
    } else {
      for (const auto& segment : macho.segments()) {
        report.summary.segments++;
        (void) segment;
      }
    }

    if (request.show_headers) {
      macho_header_info header_info;
      header_info.cpu_type = LIEF::MachO::to_string(header.cpu_type());
      header_info.cpu_subtype = header.cpu_subtype();
      header_info.file_type = LIEF::MachO::to_string(header.file_type());
      header_info.load_commands = header.nb_cmds();
      for (auto flag : header.flags_list()) {
        header_info.flags.emplace_back(LIEF::MachO::to_string(flag));
      }
      if (macho.has_uuid()) {
        if (const auto* uuid = macho.uuid()) {
          header_info.uuid = w1::util::format_uuid(uuid->uuid());
        }
      }
      if (macho.has_build_version()) {
        if (const auto* build = macho.build_version()) {
          header_info.build_platform = LIEF::MachO::to_string(build->platform());
          header_info.build_minos = format_version(build->minos());
          header_info.build_sdk = format_version(build->sdk());
        }
      }
      if (macho.has_dylinker()) {
        if (const auto* dylinker = macho.dylinker()) {
          header_info.dylinker = dylinker->name();
        }
      }
      if (macho.has_rpath()) {
        for (const auto& rpath : macho.rpaths()) {
          header_info.rpaths.push_back(rpath.path());
        }
      }
      report.macho_header = header_info;
    }
  }

  return report;
}

namespace {
constexpr const char* kIndent = "  ";
constexpr const char* kSubIndent = "    ";

void print_section_title(const std::string& title) { std::cout << title << ":\n"; }

template <typename T> void print_kv(const std::string& key, const T& value, const char* indent = kIndent) {
  std::cout << indent << key << "=" << value << "\n";
}

void print_line(const std::string& line, const char* indent = kIndent) { std::cout << indent << line << "\n"; }

std::string join_csv(const std::vector<std::string>& items) {
  std::ostringstream out;
  for (size_t i = 0; i < items.size(); ++i) {
    if (i != 0) {
      out << ", ";
    }
    out << items[i];
  }
  return out.str();
}
} // namespace

void render_summary(const summary_info& summary) {
  print_section_title("binary");
  print_kv("path", summary.path);
  print_kv("format", summary.format);

  std::ostringstream arch_line;
  arch_line << "arch=" << summary.architecture << " bitness=" << summary.bitness << " endianness=" << summary.endianness
            << " type=" << summary.file_type;
  print_line(arch_line.str());

  std::ostringstream entry_line;
  entry_line << "entry=" << (summary.has_entrypoint ? format_address(summary.entrypoint) : "n/a")
             << " image_base=" << (summary.has_imagebase ? format_address(summary.imagebase) : "n/a");
  print_line(entry_line.str());

  std::ostringstream stats_line;
  stats_line << "size=" << format_bytes(summary.file_size) << " sections=" << summary.sections << " segments=";
  if (summary.segments_supported) {
    stats_line << summary.segments;
  } else {
    stats_line << "n/a";
  }
  stats_line << " imports=" << summary.imports << " exports=" << summary.exports << " symbols=" << summary.symbols
             << " relocs=" << summary.relocations << " libraries=" << summary.libraries;
  print_line(stats_line.str());
  std::cout << "\n";
}

void render_headers(const inspect_report& report) {
  print_section_title("headers");
  bool wrote_any = false;
  if (report.elf_header) {
    wrote_any = true;
    const auto& info = *report.elf_header;
    std::ostringstream base;
    base << "elf: os_abi=" << info.os_abi << " abi_version=" << info.abi_version << " class=" << info.class_type
         << " data=" << info.data_encoding << " machine=" << info.machine;
    print_line(base.str());
    if (!info.interpreter.empty()) {
      print_kv("interpreter", info.interpreter);
    }
    if (!info.soname.empty()) {
      print_kv("soname", info.soname);
    }
    if (!info.rpath.empty()) {
      print_kv("rpath", info.rpath);
    }
    if (!info.runpath.empty()) {
      print_kv("runpath", info.runpath);
    }
    if (!info.build_id.empty()) {
      print_kv("build_id", info.build_id);
    }
  } else if (report.pe_header) {
    wrote_any = true;
    const auto& info = *report.pe_header;
    std::ostringstream base;
    base << "pe: machine=" << info.machine << " subsystem=" << info.subsystem << " timestamp=" << info.timestamp;
    print_line(base.str());
    std::ostringstream entry_line;
    entry_line << "image_base=" << format_address(info.imagebase)
               << " entry_rva=" << format_address(info.entrypoint_rva)
               << " entry_va=" << format_address(info.entrypoint);
    print_line(entry_line.str());
    std::ostringstream align_line;
    align_line << "align_section=" << info.section_alignment << " align_file=" << info.file_alignment
               << " linker=" << static_cast<int>(info.linker_major) << "." << static_cast<int>(info.linker_minor);
    print_line(align_line.str());
    if (!info.dll_characteristics.empty()) {
      print_kv("dll_chars", join_csv(info.dll_characteristics));
    }
  } else if (report.macho_header) {
    wrote_any = true;
    const auto& info = *report.macho_header;
    std::ostringstream base;
    base << "macho: cpu=" << info.cpu_type << " subtype=" << info.cpu_subtype << " file_type=" << info.file_type
         << " load_cmds=" << info.load_commands;
    print_line(base.str());
    if (!info.flags.empty()) {
      print_kv("flags", join_csv(info.flags));
    }
    if (!info.uuid.empty()) {
      print_kv("uuid", info.uuid);
    }
    if (!info.build_platform.empty()) {
      print_kv("build_platform", info.build_platform);
    }
    if (!info.build_minos.empty()) {
      print_kv("build_minos", info.build_minos);
    }
    if (!info.build_sdk.empty()) {
      print_kv("build_sdk", info.build_sdk);
    }
    if (!info.dylinker.empty()) {
      print_kv("dylinker", info.dylinker);
    }
    if (!info.rpaths.empty()) {
      print_line("rpaths:");
      for (const auto& rpath : info.rpaths) {
        print_line(rpath, kSubIndent);
      }
    }
  }
  if (!wrote_any) {
    print_line("none");
  }
  std::cout << "\n";
}

void render_sections(const std::vector<section_info>& sections) {
  print_section_title("sections");
  if (sections.empty()) {
    print_line("none");
    std::cout << "\n";
    return;
  }
  print_line("name vaddr size offset perm type");
  for (const auto& section : sections) {
    std::cout << kIndent << std::left << std::setw(24) << format_name_or_placeholder(section.name) << std::setw(18)
              << format_address(section.address) << std::setw(12) << format_bytes(section.size) << std::setw(12)
              << format_address(section.offset) << std::setw(6) << section.perms << section.kind << "\n";
  }
  std::cout << "\n";
}

void render_segments(const inspect_report& report) {
  print_section_title("segments");
  if (!report.summary.segments_supported) {
    print_kv("status", "unsupported");
    std::cout << "\n";
    return;
  }
  if (report.segments.empty()) {
    print_line("none");
    std::cout << "\n";
    return;
  }
  print_line("name vaddr vsize offset fsize perm kind");
  for (const auto& segment : report.segments) {
    std::cout << kIndent << std::left << std::setw(18) << format_name_or_placeholder(segment.name) << std::setw(18)
              << format_address(segment.address) << std::setw(12) << format_bytes(segment.vsize) << std::setw(12)
              << format_address(segment.offset) << std::setw(12) << format_bytes(segment.fsize) << std::setw(6)
              << segment.perms << segment.kind << "\n";
  }
  std::cout << "\n";
}

void render_libraries(const std::vector<std::string>& libraries) {
  print_section_title("libraries");
  if (libraries.empty()) {
    print_line("none");
    std::cout << "\n";
    return;
  }
  for (const auto& lib : libraries) {
    print_line(lib);
  }
  std::cout << "\n";
}

void render_functions(const std::vector<function_info>& functions, const std::string& title) {
  print_section_title(title);
  if (functions.empty()) {
    print_line("none");
    std::cout << "\n";
    return;
  }
  print_line("address name");
  for (const auto& func : functions) {
    std::cout << kIndent << std::left << std::setw(18) << format_address(func.address)
              << format_name_or_placeholder(func.name) << "\n";
  }
  std::cout << "\n";
}

void render_symbols(const std::vector<symbol_info>& symbols) {
  print_section_title("symbols");
  if (symbols.empty()) {
    print_line("none");
    std::cout << "\n";
    return;
  }
  print_line("address size name");
  for (const auto& symbol : symbols) {
    std::cout << kIndent << std::left << std::setw(18) << format_address(symbol.address) << std::setw(12)
              << format_bytes(symbol.size) << format_name_or_placeholder(symbol.name) << "\n";
  }
  std::cout << "\n";
}

void render_relocations(const std::vector<relocation_info>& relocations) {
  print_section_title("relocations");
  if (relocations.empty()) {
    print_line("none");
    std::cout << "\n";
    return;
  }
  print_line("address size type symbol origin");
  for (const auto& reloc : relocations) {
    std::cout << kIndent << std::left << std::setw(18) << format_address(reloc.address) << std::setw(8) << reloc.size
              << std::setw(18) << reloc.type << std::setw(24) << format_name_or_placeholder(reloc.symbol)
              << reloc.origin << "\n";
  }
  std::cout << "\n";
}

void render_text(const inspect_report& report, const inspect_request& request) {
  render_summary(report.summary);

  if (request.show_headers) {
    render_headers(report);
  }
  if (request.show_sections) {
    render_sections(report.sections);
  }
  if (request.show_segments) {
    render_segments(report);
  }
  if (request.show_libraries) {
    render_libraries(report.libraries);
  }
  if (request.show_imports) {
    render_functions(report.imports, "imports");
  }
  if (request.show_exports) {
    render_functions(report.exports, "exports");
  }
  if (request.show_symbols) {
    render_symbols(report.symbols);
  }
  if (request.show_relocations) {
    render_relocations(report.relocations);
  }
}

nlohmann::json render_json(const inspect_report& report, const inspect_request& request) {
  nlohmann::json output;
  const auto& summary = report.summary;

  output["path"] = summary.path;
  output["format"] = summary.format;
  output["summary"] = {
      {"architecture", summary.architecture},
      {"bitness", summary.bitness},
      {"endianness", summary.endianness},
      {"file_type", summary.file_type},
      {"entrypoint", summary.entrypoint},
      {"has_entrypoint", summary.has_entrypoint},
      {"imagebase", summary.imagebase},
      {"has_imagebase", summary.has_imagebase},
      {"file_size", summary.file_size},
      {"sections", summary.sections},
      {"segments", summary.segments_supported ? nlohmann::json(summary.segments) : nlohmann::json()},
      {"segments_supported", summary.segments_supported},
      {"imports", summary.imports},
      {"exports", summary.exports},
      {"symbols", summary.symbols},
      {"relocations", summary.relocations},
      {"libraries", summary.libraries},
  };

  if (request.show_headers) {
    if (report.elf_header) {
      const auto& info = *report.elf_header;
      output["headers"]["elf"] = {
          {"os_abi", info.os_abi},    {"abi_version", info.abi_version},
          {"class", info.class_type}, {"data", info.data_encoding},
          {"machine", info.machine},  {"interpreter", info.interpreter},
          {"soname", info.soname},    {"rpath", info.rpath},
          {"runpath", info.runpath},  {"build_id", info.build_id},
      };
    } else if (report.pe_header) {
      const auto& info = *report.pe_header;
      output["headers"]["pe"] = {
          {"machine", info.machine},
          {"subsystem", info.subsystem},
          {"timestamp", info.timestamp},
          {"linker_major", info.linker_major},
          {"linker_minor", info.linker_minor},
          {"imagebase", info.imagebase},
          {"entrypoint_rva", info.entrypoint_rva},
          {"entrypoint", info.entrypoint},
          {"section_alignment", info.section_alignment},
          {"file_alignment", info.file_alignment},
          {"dll_characteristics", info.dll_characteristics},
      };
    } else if (report.macho_header) {
      const auto& info = *report.macho_header;
      output["headers"]["macho"] = {
          {"cpu_type", info.cpu_type},
          {"cpu_subtype", info.cpu_subtype},
          {"file_type", info.file_type},
          {"flags", info.flags},
          {"load_commands", info.load_commands},
          {"uuid", info.uuid},
          {"build_platform", info.build_platform},
          {"build_minos", info.build_minos},
          {"build_sdk", info.build_sdk},
          {"dylinker", info.dylinker},
          {"rpaths", info.rpaths},
      };
    }
  }

  if (request.show_sections) {
    nlohmann::json sections = nlohmann::json::array();
    for (const auto& section : report.sections) {
      sections.push_back({
          {"name", section.name},
          {"address", section.address},
          {"size", section.size},
          {"offset", section.offset},
          {"perms", section.perms},
          {"type", section.kind},
      });
    }
    output["sections"] = std::move(sections);
  }

  if (request.show_segments) {
    nlohmann::json segments = nlohmann::json::array();
    for (const auto& segment : report.segments) {
      segments.push_back({
          {"name", segment.name},
          {"address", segment.address},
          {"virtual_size", segment.vsize},
          {"offset", segment.offset},
          {"file_size", segment.fsize},
          {"perms", segment.perms},
          {"kind", segment.kind},
      });
    }
    output["segments"] = std::move(segments);
  }

  if (request.show_libraries) {
    output["libraries"] = report.libraries;
  }

  if (request.show_imports) {
    nlohmann::json imports = nlohmann::json::array();
    for (const auto& func : report.imports) {
      imports.push_back({
          {"name", func.name},
          {"address", func.address},
      });
    }
    output["imports"] = std::move(imports);
  }

  if (request.show_exports) {
    nlohmann::json exports = nlohmann::json::array();
    for (const auto& func : report.exports) {
      exports.push_back({
          {"name", func.name},
          {"address", func.address},
      });
    }
    output["exports"] = std::move(exports);
  }

  if (request.show_symbols) {
    nlohmann::json symbols = nlohmann::json::array();
    for (const auto& symbol : report.symbols) {
      symbols.push_back({
          {"name", symbol.name},
          {"address", symbol.address},
          {"size", symbol.size},
      });
    }
    output["symbols"] = std::move(symbols);
  }

  if (request.show_relocations) {
    nlohmann::json relocs = nlohmann::json::array();
    for (const auto& reloc : report.relocations) {
      relocs.push_back({
          {"address", reloc.address},
          {"size", reloc.size},
          {"type", reloc.type},
          {"symbol", reloc.symbol},
          {"origin", reloc.origin},
      });
    }
    output["relocations"] = std::move(relocs);
  }

  return output;
}

} // namespace detail

int inspect(const inspect_request& request) {
  auto log = redlog::get_logger("w1tool.inspect");

  if (request.binary_path.empty()) {
    log.error("binary path required for inspection");
    return 1;
  }

  if (!fs::exists(request.binary_path)) {
    log.error("binary file does not exist", redlog::field("path", request.binary_path));
    return 1;
  }

  try {
    auto binary = detail::parse_binary(request, log);
    if (!binary) {
      log.error("failed to parse binary - invalid format or corrupted file");
      return 1;
    }

    auto report = detail::build_report(request, *binary);
    if (request.json_output) {
      nlohmann::json output = detail::render_json(report, request);
      if (request.json_pretty) {
        std::cout << output.dump(2) << "\n";
      } else {
        std::cout << output.dump() << "\n";
      }
    } else {
      detail::render_text(report, request);
    }
    return 0;
  } catch (const std::exception& e) {
    log.error("analysis failed", redlog::field("error", e.what()));
    return 1;
  }
}

#endif // WITNESS_LIEF_ENABLED

} // namespace w1tool::commands
