#include "inspect.hpp"
#include <redlog.hpp>
#include <filesystem>
#include <iostream>
#include <iomanip>
#include <sstream>

#ifdef WITNESS_LIEF_ENABLED
#include <LIEF/LIEF.hpp>
#endif

namespace fs = std::filesystem;

namespace w1tool::commands {

#ifndef WITNESS_LIEF_ENABLED

int inspect(
    args::ValueFlag<std::string>& binary_flag, args::Flag& detailed_flag, args::Flag& sections_flag,
    args::Flag& symbols_flag, args::Flag& imports_flag, args::Flag& security_flag, args::Flag& json_flag,
    args::ValueFlag<std::string>& format_flag
) {
  auto log = redlog::get_logger("w1tool.inspect");
  log.error("binary inspection requires LIEF support");
  log.error("build with -DWITNESS_LIEF=ON to enable this feature");
  return 1;
}

#else

// forward declarations for internal analyzers
namespace detail {

struct analysis_options {
  bool detailed = false;
  bool sections = false;
  bool symbols = false;
  bool imports = false;
  bool security = false;
  bool json_output = false;
  std::string forced_format;
};

struct binary_info {
  std::string format;
  std::string architecture;
  std::string bitness;
  uint64_t entry_point = 0;
  uint64_t file_size = 0;
  std::string endianness;
  std::string binary_type;
};

// helper functions
std::string format_address(uint64_t addr);
std::string format_bytes(uint64_t bytes);
std::string format_permissions(uint32_t flags, const std::string& format);

// base analyzer class
class binary_analyzer {
public:
  virtual ~binary_analyzer() = default;
  virtual void analyze_basic_info(binary_info& info) = 0;
  virtual void analyze_security_features() {}
  virtual void analyze_sections() {}
  virtual void analyze_symbols() {}
  virtual void analyze_imports() {}
  virtual void print_results(const analysis_options& opts) = 0;

protected:
  redlog::logger log_;
  std::unique_ptr<LIEF::Binary> binary_;

  binary_analyzer(std::unique_ptr<LIEF::Binary> binary, const std::string& logger_name)
      : log_(redlog::get_logger(logger_name)), binary_(std::move(binary)) {}
};

// format-specific analyzers
class elf_analyzer : public binary_analyzer {
public:
  elf_analyzer(std::unique_ptr<LIEF::Binary> binary);
  void analyze_basic_info(binary_info& info) override;
  void analyze_security_features() override;
  void analyze_sections() override;
  void analyze_symbols() override;
  void analyze_imports() override;
  void print_results(const analysis_options& opts) override;

private:
  LIEF::ELF::Binary* elf_;
};

class pe_analyzer : public binary_analyzer {
public:
  pe_analyzer(std::unique_ptr<LIEF::Binary> binary);
  void analyze_basic_info(binary_info& info) override;
  void analyze_security_features() override;
  void analyze_sections() override;
  void analyze_symbols() override;
  void analyze_imports() override;
  void print_results(const analysis_options& opts) override;

private:
  LIEF::PE::Binary* pe_;
};

class macho_analyzer : public binary_analyzer {
public:
  macho_analyzer(std::unique_ptr<LIEF::Binary> binary);
  void analyze_basic_info(binary_info& info) override;
  void analyze_security_features() override;
  void analyze_sections() override;
  void analyze_symbols() override;
  void analyze_imports() override;
  void print_results(const analysis_options& opts) override;

private:
  LIEF::MachO::Binary* macho_;
};

std::unique_ptr<binary_analyzer> create_analyzer(std::unique_ptr<LIEF::Binary> binary);

} // namespace detail

int inspect(
    args::ValueFlag<std::string>& binary_flag, args::Flag& detailed_flag, args::Flag& sections_flag,
    args::Flag& symbols_flag, args::Flag& imports_flag, args::Flag& security_flag, args::Flag& json_flag,
    args::ValueFlag<std::string>& format_flag
) {
  auto log = redlog::get_logger("w1tool.inspect");

  // validate binary path
  if (!binary_flag) {
    log.error("binary path required for inspection");
    return 1;
  }

  std::string binary_path = args::get(binary_flag);

  if (!fs::exists(binary_path)) {
    log.error("binary file does not exist", redlog::field("path", binary_path));
    return 1;
  }

  // set up analysis options
  detail::analysis_options opts;
  opts.detailed = detailed_flag;
  opts.sections = sections_flag;
  opts.symbols = symbols_flag;
  opts.imports = imports_flag;
  opts.security = security_flag;
  opts.json_output = json_flag;
  if (format_flag) {
    opts.forced_format = args::get(format_flag);
  }

  log.info("starting binary analysis", redlog::field("binary_path", binary_path));

  try {
    // parse binary using LIEF
    std::unique_ptr<LIEF::Binary> binary;

    if (!opts.forced_format.empty()) {
      // TODO: implement forced format parsing when needed
      log.warn("forced format not yet implemented, using auto-detection");
    }

    binary = LIEF::Parser::parse(binary_path);
    if (!binary) {
      log.error("failed to parse binary - invalid format or corrupted file");
      return 1;
    }

    // create format-specific analyzer
    auto analyzer = detail::create_analyzer(std::move(binary));
    if (!analyzer) {
      log.error("unsupported binary format");
      return 1;
    }

    // perform basic analysis
    detail::binary_info info;
    analyzer->analyze_basic_info(info);

    // perform optional detailed analysis
    if (opts.security) {
      analyzer->analyze_security_features();
    }
    if (opts.sections) {
      analyzer->analyze_sections();
    }
    if (opts.symbols) {
      analyzer->analyze_symbols();
    }
    if (opts.imports) {
      analyzer->analyze_imports();
    }

    // output results
    analyzer->print_results(opts);

    log.info("binary analysis completed successfully");
    return 0;

  } catch (const std::exception& e) {
    log.error("analysis failed", redlog::field("error", e.what()));
    return 1;
  }
}

// implementation of helper functions and analyzer classes
namespace detail {

std::string format_address(uint64_t addr) {
  std::stringstream ss;
  ss << "0x" << std::hex << addr;
  return ss.str();
}

std::string format_bytes(uint64_t bytes) {
  if (bytes >= 1024ULL * 1024 * 1024) {
    double gb = static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0);
    std::stringstream ss;
    ss << std::fixed << std::setprecision(1) << gb << " GB";
    return ss.str();
  } else if (bytes >= 1024 * 1024) {
    double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
    std::stringstream ss;
    ss << std::fixed << std::setprecision(1) << mb << " MB";
    return ss.str();
  } else if (bytes >= 1024) {
    double kb = static_cast<double>(bytes) / 1024.0;
    std::stringstream ss;
    ss << std::fixed << std::setprecision(1) << kb << " KB";
    return ss.str();
  } else {
    return std::to_string(bytes) + " bytes";
  }
}

std::string format_permissions(uint32_t flags, const std::string& format) {
  std::string perms = "---";

  if (format == "elf") {
    if (flags & 0x4) {
      perms[0] = 'r'; // PF_R
    }
    if (flags & 0x2) {
      perms[1] = 'w'; // PF_W
    }
    if (flags & 0x1) {
      perms[2] = 'x'; // PF_X
    }
  } else if (format == "pe") {
    // PE section characteristics
    if (flags & 0x40000000) {
      perms[0] = 'r'; // IMAGE_SCN_MEM_READ
    }
    if (flags & 0x80000000) {
      perms[1] = 'w'; // IMAGE_SCN_MEM_WRITE
    }
    if (flags & 0x20000000) {
      perms[2] = 'x'; // IMAGE_SCN_MEM_EXECUTE
    }
  } else if (format == "macho") {
    if (flags & 0x1) {
      perms[0] = 'r'; // VM_PROT_READ
    }
    if (flags & 0x2) {
      perms[1] = 'w'; // VM_PROT_WRITE
    }
    if (flags & 0x4) {
      perms[2] = 'x'; // VM_PROT_EXECUTE
    }
  }

  return perms;
}

std::unique_ptr<binary_analyzer> create_analyzer(std::unique_ptr<LIEF::Binary> binary) {
  switch (binary->format()) {
  case LIEF::Binary::FORMATS::ELF:
    return std::make_unique<elf_analyzer>(std::move(binary));
  case LIEF::Binary::FORMATS::PE:
    return std::make_unique<pe_analyzer>(std::move(binary));
  case LIEF::Binary::FORMATS::MACHO:
    return std::make_unique<macho_analyzer>(std::move(binary));
  default:
    return nullptr;
  }
}

// ELF analyzer implementation
elf_analyzer::elf_analyzer(std::unique_ptr<LIEF::Binary> binary)
    : binary_analyzer(std::move(binary), "w1tool.inspect.elf"), elf_(static_cast<LIEF::ELF::Binary*>(binary_.get())) {}

void elf_analyzer::analyze_basic_info(binary_info& info) {
  info.format = "ELF";
  info.entry_point = elf_->entrypoint();

  // architecture and bitness
  auto machine = elf_->header().machine_type();
  switch (machine) {
  case LIEF::ELF::ARCH::I386:
    info.architecture = "x86";
    info.bitness = "32-bit";
    break;
  case LIEF::ELF::ARCH::X86_64:
    info.architecture = "x86_64";
    info.bitness = "64-bit";
    break;
  case LIEF::ELF::ARCH::ARM:
    info.architecture = "ARM";
    info.bitness = "32-bit";
    break;
  case LIEF::ELF::ARCH::AARCH64:
    info.architecture = "ARM64";
    info.bitness = "64-bit";
    break;
  default:
    info.architecture = "Unknown (" + std::to_string(static_cast<int>(machine)) + ")";
    info.bitness = elf_->header().identity_class() == LIEF::ELF::Header::CLASS::ELF64 ? "64-bit" : "32-bit";
    break;
  }

  // endianness
  info.endianness = elf_->header().identity_data() == LIEF::ELF::Header::ELF_DATA::LSB ? "Little-endian" : "Big-endian";

  // binary type
  auto type = elf_->header().file_type();
  switch (type) {
  case LIEF::ELF::Header::FILE_TYPE::EXEC:
    info.binary_type = "Executable";
    break;
  case LIEF::ELF::Header::FILE_TYPE::DYN:
    info.binary_type = "Shared Object/PIE";
    break;
  case LIEF::ELF::Header::FILE_TYPE::CORE:
    info.binary_type = "Core file";
    break;
  case LIEF::ELF::Header::FILE_TYPE::REL:
    info.binary_type = "Relocatable";
    break;
  default:
    info.binary_type = "Unknown";
    break;
  }
}

void elf_analyzer::analyze_security_features() {
  log_.dbg("analyzing elf security features");
  // Implementation for ELF security analysis will be added
}

void elf_analyzer::analyze_sections() {
  log_.dbg("analyzing elf sections");
  // Implementation for ELF section analysis will be added
}

void elf_analyzer::analyze_symbols() {
  log_.dbg("analyzing elf symbols");
  // Implementation for ELF symbol analysis will be added
}

void elf_analyzer::analyze_imports() {
  log_.dbg("analyzing elf imports");
  // Implementation for ELF import analysis will be added
}

void elf_analyzer::print_results(const analysis_options& opts) {
  detail::binary_info info;
  analyze_basic_info(info);

  std::cout << "=== Binary Analysis Results ===\n";
  std::cout << "Format: " << info.format << "\n";
  std::cout << "Architecture: " << info.architecture << "\n";
  std::cout << "Bitness: " << info.bitness << "\n";
  std::cout << "Entry Point: " << format_address(info.entry_point) << "\n";
  std::cout << "Endianness: " << info.endianness << "\n";
  std::cout << "Type: " << info.binary_type << "\n";

  // Add more detailed output based on options
  if (opts.detailed) {
    std::cout << "\n=== ELF Header Details ===\n";
    auto& header = elf_->header();
    std::cout << "ELF Class: " << (header.identity_class() == LIEF::ELF::Header::CLASS::ELF64 ? "64-bit" : "32-bit")
              << "\n";
    std::cout << "Version: " << static_cast<int>(header.object_file_version()) << "\n";
    std::cout << "Sections: " << elf_->sections().size() << "\n";
    std::cout << "Segments: " << elf_->segments().size() << "\n";
  }
}

// PE analyzer stub implementation
pe_analyzer::pe_analyzer(std::unique_ptr<LIEF::Binary> binary)
    : binary_analyzer(std::move(binary), "w1tool.inspect.pe"), pe_(static_cast<LIEF::PE::Binary*>(binary_.get())) {}

void pe_analyzer::analyze_basic_info(binary_info& info) {
  info.format = "PE";
  // Basic PE analysis implementation will be added
}

void pe_analyzer::analyze_security_features() {}
void pe_analyzer::analyze_sections() {}
void pe_analyzer::analyze_symbols() {}
void pe_analyzer::analyze_imports() {}

void pe_analyzer::print_results(const analysis_options& opts) {
  std::cout << "=== Binary Analysis Results ===\n";
  std::cout << "Format: PE (implementation in progress)\n";
}

// MachO analyzer stub implementation
macho_analyzer::macho_analyzer(std::unique_ptr<LIEF::Binary> binary)
    : binary_analyzer(std::move(binary), "w1tool.inspect.macho"),
      macho_(static_cast<LIEF::MachO::Binary*>(binary_.get())) {}

void macho_analyzer::analyze_basic_info(binary_info& info) {
  info.format = "Mach-O";
  info.entry_point = macho_->entrypoint();

  // architecture and bitness
  auto cpu_type = macho_->header().cpu_type();
  switch (cpu_type) {
  case LIEF::MachO::Header::CPU_TYPE::X86:
    info.architecture = "x86";
    info.bitness = "32-bit";
    break;
  case LIEF::MachO::Header::CPU_TYPE::X86_64:
    info.architecture = "x86_64";
    info.bitness = "64-bit";
    break;
  case LIEF::MachO::Header::CPU_TYPE::ARM:
    info.architecture = "ARM";
    info.bitness = "32-bit";
    break;
  case LIEF::MachO::Header::CPU_TYPE::ARM64:
    info.architecture = "ARM64";
    info.bitness = "64-bit";
    break;
  case LIEF::MachO::Header::CPU_TYPE::POWERPC:
    info.architecture = "PowerPC";
    info.bitness = "32-bit";
    break;
  case LIEF::MachO::Header::CPU_TYPE::POWERPC64:
    info.architecture = "PowerPC64";
    info.bitness = "64-bit";
    break;
  default:
    info.architecture = "Unknown (" + std::to_string(static_cast<int>(cpu_type)) + ")";
    info.bitness = (static_cast<int>(cpu_type) & LIEF::MachO::Header::ABI64) ? "64-bit" : "32-bit";
    break;
  }

  // endianness - Mach-O is always little-endian on supported platforms
  info.endianness = "Little-endian";

  // binary type
  auto file_type = macho_->header().file_type();
  switch (file_type) {
  case LIEF::MachO::Header::FILE_TYPE::EXECUTE:
    info.binary_type = "Executable";
    break;
  case LIEF::MachO::Header::FILE_TYPE::DYLIB:
    info.binary_type = "Dynamic Library";
    break;
  case LIEF::MachO::Header::FILE_TYPE::BUNDLE:
    info.binary_type = "Bundle";
    break;
  case LIEF::MachO::Header::FILE_TYPE::OBJECT:
    info.binary_type = "Object File";
    break;
  case LIEF::MachO::Header::FILE_TYPE::DSYM:
    info.binary_type = "Debug Symbols";
    break;
  case LIEF::MachO::Header::FILE_TYPE::KEXT_BUNDLE:
    info.binary_type = "Kernel Extension";
    break;
  default:
    info.binary_type = "Unknown";
    break;
  }
}

void macho_analyzer::analyze_security_features() {
  log_.dbg("analyzing mach-o security features");

  std::cout << "\n=== Security Analysis ===\n";

  auto& header = macho_->header();

  // PIE (Position Independent Executable)
  if (header.has(LIEF::MachO::Header::FLAGS::PIE)) {
    std::cout << "PIE (Position Independent): ✓ ENABLED\n";
  } else {
    std::cout << "PIE (Position Independent): ✗ DISABLED\n";
  }

  // Stack execution protection
  if (header.has(LIEF::MachO::Header::FLAGS::ALLOW_STACK_EXECUTION)) {
    std::cout << "Stack Execution Protection: ✗ DISABLED (Allows stack execution)\n";
  } else {
    std::cout << "Stack Execution Protection: ✓ ENABLED\n";
  }

  // Heap execution protection
  if (header.has(LIEF::MachO::Header::FLAGS::NO_HEAP_EXECUTION)) {
    std::cout << "Heap Execution Protection: ✓ ENABLED (NX bit)\n";
  } else {
    std::cout << "Heap Execution Protection: ? UNKNOWN\n";
  }

  // Code signing and validation
  bool has_codesign = false;
  for (const auto& cmd : macho_->commands()) {
    if (cmd.command() == LIEF::MachO::LoadCommand::TYPE::CODE_SIGNATURE) {
      has_codesign = true;
      break;
    }
  }

  if (has_codesign) {
    std::cout << "Code Signature: ✓ PRESENT\n";
  } else {
    std::cout << "Code Signature: ✗ NOT FOUND\n";
  }

  // Additional security flags
  if (header.has(LIEF::MachO::Header::FLAGS::SETUID_SAFE)) {
    std::cout << "SetUID Safe: ✓ ENABLED\n";
  }

  if (header.has(LIEF::MachO::Header::FLAGS::ROOT_SAFE)) {
    std::cout << "Root Safe: ✓ ENABLED\n";
  }

  // ARC (Automatic Reference Counting) detection - heuristic
  bool likely_arc = false;
  for (const auto& sym : macho_->symbols()) {
    if (sym.name().find("objc_release") != std::string::npos || sym.name().find("objc_retain") != std::string::npos) {
      likely_arc = true;
      break;
    }
  }

  if (likely_arc) {
    std::cout << "ARC (Automatic Reference Counting): ✓ LIKELY ENABLED\n";
  }

  // Print security summary
  int security_score = 0;
  int total_checks = 4;

  if (header.has(LIEF::MachO::Header::FLAGS::PIE)) {
    security_score++;
  }
  if (!header.has(LIEF::MachO::Header::FLAGS::ALLOW_STACK_EXECUTION)) {
    security_score++;
  }
  if (header.has(LIEF::MachO::Header::FLAGS::NO_HEAP_EXECUTION)) {
    security_score++;
  }
  if (has_codesign) {
    security_score++;
  }

  std::cout << "\nSecurity Score: " << security_score << "/" << total_checks;
  if (security_score == total_checks) {
    std::cout << " (EXCELLENT)";
  } else if (security_score >= total_checks * 0.75) {
    std::cout << " (GOOD)";
  } else if (security_score >= total_checks * 0.5) {
    std::cout << " (FAIR)";
  } else {
    std::cout << " (POOR)";
  }
  std::cout << "\n";
}
void macho_analyzer::analyze_sections() {
  log_.dbg("analyzing mach-o sections");

  std::cout << "\n=== Sections ===\n";
  std::cout << std::left << std::setw(20) << "Name" << std::setw(18) << "Virtual Address" << std::setw(12) << "Size"
            << std::setw(8) << "Perms"
            << "Segment\n";
  std::cout << std::string(66, '-') << "\n";

  for (const auto& section : macho_->sections()) {
    std::cout << std::left << std::setw(20) << section.name() << std::setw(18) << format_address(section.address())
              << std::setw(12) << format_bytes(section.size()) << std::setw(8)
              << "r--" // TODO: implement proper permission detection
              << section.segment_name() << "\n";
  }
}
void macho_analyzer::analyze_symbols() {
  log_.dbg("analyzing mach-o symbols");

  std::cout << "\n=== Symbols ===\n";

  // Show dynamic symbols (imported/exported)
  auto symbols = macho_->symbols();
  size_t total_symbols = symbols.size();
  size_t external_symbols = 0;
  size_t local_symbols = 0;

  for (const auto& sym : symbols) {
    if (sym.is_external()) {
      external_symbols++;
    } else {
      local_symbols++;
    }
  }

  std::cout << "Total Symbols: " << total_symbols << "\n";
  std::cout << "External Symbols: " << external_symbols << "\n";
  std::cout << "Local Symbols: " << local_symbols << "\n";

  // Show first 10 external symbols as examples
  std::cout << "\nSample External Symbols:\n";
  std::cout << std::left << std::setw(30) << "Name" << std::setw(18) << "Address"
            << "Type\n";
  std::cout << std::string(56, '-') << "\n";

  int count = 0;
  for (const auto& sym : symbols) {
    if (sym.is_external() && !sym.name().empty() && count < 10) {
      std::cout << std::left << std::setw(30) << sym.name() << std::setw(18) << format_address(sym.value())
                << "External\n";
      count++;
    }
  }
}
void macho_analyzer::analyze_imports() {
  log_.dbg("analyzing mach-o imports");

  std::cout << "\n=== Library Dependencies ===\n";

  // Show imported libraries
  auto libraries = macho_->libraries();
  std::cout << "Total Libraries: " << libraries.size() << "\n\n";

  for (const auto& lib : libraries) {
    std::cout << "- " << lib.name() << "\n";
  }

  // Show binding information (imports)
  std::cout << "\n=== Import Bindings ===\n";
  auto bindings = macho_->dyld_info();
  if (bindings) {
    std::cout << "Binding Info Available: Yes\n";
    // Note: Detailed binding analysis could be added here
  } else {
    std::cout << "Binding Info Available: No\n";
  }
}

void macho_analyzer::print_results(const analysis_options& opts) {
  detail::binary_info info;
  analyze_basic_info(info);

  std::cout << "=== Binary Analysis Results ===\n";
  std::cout << "Format: " << info.format << "\n";
  std::cout << "Architecture: " << info.architecture << "\n";
  std::cout << "Bitness: " << info.bitness << "\n";
  std::cout << "Entry Point: " << format_address(info.entry_point) << "\n";
  std::cout << "Endianness: " << info.endianness << "\n";
  std::cout << "Type: " << info.binary_type << "\n";

  // Add more detailed output based on options
  if (opts.detailed) {
    std::cout << "\n=== Mach-O Header Details ===\n";
    auto& header = macho_->header();
    std::cout << "CPU Type: " << static_cast<int>(header.cpu_type()) << "\n";
    std::cout << "CPU Subtype: " << header.cpu_subtype() << "\n";
    std::cout << "Load Commands: " << header.nb_cmds() << "\n";
    std::cout << "Sections: " << macho_->sections().size() << "\n";
    std::cout << "Segments: " << macho_->segments().size() << "\n";

    // Check for security flags
    if (header.has(LIEF::MachO::Header::FLAGS::PIE)) {
      std::cout << "PIE: Enabled\n";
    }
    if (header.has(LIEF::MachO::Header::FLAGS::NO_HEAP_EXECUTION)) {
      std::cout << "NX Heap: Enabled\n";
    }
    if (header.has(LIEF::MachO::Header::FLAGS::ALLOW_STACK_EXECUTION)) {
      std::cout << "Stack Execution: Allowed\n";
    }
  }

  // Note: sections analysis is handled via flag check in main function
}

} // namespace detail

#endif // WITNESS_LIEF_ENABLED

} // namespace w1tool::commands
