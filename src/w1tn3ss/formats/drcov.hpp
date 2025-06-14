/**
 * @file drcov.hpp
 * @brief Header-only C++17 library for parsing and writing DrCov coverage files
 *
 * This library provides a complete implementation for reading and writing
 * DrCov coverage files, supporting format version 2 with module table versions 2-4
 * and legacy module tables. It is designed to be portable and robust.
 *
 * References:
 * - DrCov format analysis: https://www.ayrx.me/drcov-file-format/
 * - DynamoRIO drcov tool: https://dynamorio.org/
 * - Lighthouse plugin: https://github.com/gaasedelen/lighthouse
 *
 * Example usage:
 * @code
 * // Reading a file
 * auto coverage = drcov::read("coverage.drcov");
 *
 * // Creating coverage data
 * auto builder = drcov::builder()
 *     .set_flavor("my_tool")
 *     .set_module_version(drcov::module_table_version::v4)
 *     .add_module("/bin/program", 0x400000, 0x450000)
 *     .add_module("/lib/libc.so", 0x7fff00000000, 0x7fff00100000)
 *     .add_coverage(0, 0x1000, 32)  // module 0, offset 0x1000, 32 bytes
 *     .build();
 *
 * // Writing to file
 * drcov::write("output.drcov", builder);
 * @endcode
 */

#ifndef DRCOV_HPP
#define DRCOV_HPP

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

// Endianness detection for portable binary I/O
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define DRCOV_LITTLE_ENDIAN 1
#elif defined(_WIN32)
#define DRCOV_LITTLE_ENDIAN 1
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define DRCOV_LITTLE_ENDIAN 0
#else
#warning "Could not determine endianness. Assuming little-endian."
#define DRCOV_LITTLE_ENDIAN 1
#endif

namespace drcov {

// forward declarations
class parse_error;
struct module_entry;
struct basic_block;
struct file_header;
struct coverage_data;
class coverage_builder;

/**
 * @brief Constants used throughout the library
 */
namespace constants {
constexpr uint32_t supported_file_version = 2;
constexpr size_t bb_entry_size = 8;
constexpr std::string_view version_prefix = "DRCOV VERSION: ";
constexpr std::string_view flavor_prefix = "DRCOV FLAVOR: ";
constexpr std::string_view module_table_prefix = "Module Table: ";
constexpr std::string_view bb_table_prefix = "BB Table: ";
constexpr std::string_view columns_prefix = "Columns: ";
} // namespace constants

/**
 * @brief Error codes for parse operations
 */
enum class error_code {
  success = 0,
  file_not_found,
  invalid_format,
  unsupported_version,
  invalid_module_table,
  invalid_bb_table,
  io_error,
  memory_error,
  invalid_binary_data,
  validation_error
};

/**
 * @brief Exception thrown by parse/write operations
 */
class parse_error : public std::runtime_error {
public:
  explicit parse_error(error_code code, const std::string& message) : std::runtime_error(message), code_(code) {}

  error_code code() const noexcept { return code_; }

private:
  error_code code_;
};

// internal utility functions
namespace detail {
inline std::string trim(const std::string& str) {
  auto start = str.find_first_not_of(" \t\r\n");
  auto end = str.find_last_not_of(" \t\r\n");
  return (start == std::string::npos) ? "" : str.substr(start, end - start + 1);
}

inline std::vector<std::string> split(const std::string& str, char delimiter) {
  std::vector<std::string> tokens;
  std::stringstream ss(str);
  std::string token;
  while (std::getline(ss, token, delimiter)) {
    tokens.push_back(trim(token));
  }
  return tokens;
}

template <typename T> inline T read_le(const uint8_t* data) {
  T value{};
#if DRCOV_LITTLE_ENDIAN
  std::memcpy(&value, data, sizeof(T));
#else
  for (size_t i = 0; i < sizeof(T); ++i) {
    value |= static_cast<T>(data[i]) << (i * 8);
  }
#endif
  return value;
}

template <typename T> inline void write_le(uint8_t* data, T value) {
#if DRCOV_LITTLE_ENDIAN
  std::memcpy(data, &value, sizeof(T));
#else
  for (size_t i = 0; i < sizeof(T); ++i) {
    data[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
  }
#endif
}
} // namespace detail

/**
 * @brief DrCov file header containing version and tool information
 */
struct file_header {
  uint32_t version{constants::supported_file_version};
  std::string flavor{"drcov"};

  std::string to_string() const {
    std::stringstream ss;
    ss << constants::version_prefix << version << "\n";
    ss << constants::flavor_prefix << flavor << "\n";
    return ss.str();
  }
};

/**
 * @brief Module table format versions
 */
enum class module_table_version : uint32_t { legacy = 1, v2 = 2, v3 = 3, v4 = 4 };

/**
 * @brief Represents a loaded module/library in the traced process
 */
struct module_entry {
  uint32_t id{0};
  uint64_t base{0};
  uint64_t end{0};
  uint64_t entry{0};
  std::string path;

  std::optional<int32_t> containing_id;
  std::optional<uint64_t> offset;
  std::optional<uint32_t> checksum;
  std::optional<uint32_t> timestamp;

  uint64_t size() const noexcept { return end - base; }

  bool contains_address(uint64_t addr) const noexcept { return addr >= base && addr < end; }

  module_entry() = default;

  module_entry(uint32_t id, const std::string& path, uint64_t base, uint64_t end, uint64_t entry = 0)
      : id(id), base(base), end(end), entry(entry), path(path) {}
};

/**
 * @brief Represents an executed basic block
 */
struct basic_block {
  uint32_t start{0};
  uint16_t size{0};
  uint16_t module_id{0};

  uint64_t absolute_address(const module_entry& module) const noexcept { return module.base + start; }

  basic_block() = default;

  basic_block(uint32_t start, uint16_t size, uint16_t module_id) : start(start), size(size), module_id(module_id) {}
};

/**
 * @brief Complete coverage data structure
 */
struct coverage_data {
  file_header header;
  module_table_version module_version{module_table_version::v2};
  std::vector<module_entry> modules;
  std::vector<basic_block> basic_blocks;

  std::optional<std::reference_wrapper<const module_entry>> find_module(uint16_t id) const {
    if (id < modules.size() && modules[id].id == id) {
      return std::cref(modules[id]);
    }
    auto it = std::find_if(modules.begin(), modules.end(), [id](const auto& m) { return m.id == id; });
    return it != modules.end() ? std::optional<std::reference_wrapper<const module_entry>>(*it) : std::nullopt;
  }

  std::optional<std::reference_wrapper<const module_entry>> find_module_by_address(uint64_t addr) const {
    auto it = std::find_if(modules.begin(), modules.end(), [addr](const auto& m) { return m.contains_address(addr); });
    return it != modules.end() ? std::optional<std::reference_wrapper<const module_entry>>(*it) : std::nullopt;
  }

  std::unordered_map<uint16_t, size_t> get_coverage_stats() const {
    std::unordered_map<uint16_t, size_t> stats;
    for (const auto& bb : basic_blocks) {
      stats[bb.module_id]++;
    }
    return stats;
  }

  void validate() const {
    for (size_t i = 0; i < modules.size(); ++i) {
      if (modules[i].id != i) {
        throw parse_error(
            error_code::validation_error,
            "Non-sequential module ID " + std::to_string(modules[i].id) + " at index " + std::to_string(i)
        );
      }
    }

    for (const auto& bb : basic_blocks) {
      if (bb.module_id >= modules.size()) {
        throw parse_error(
            error_code::validation_error, "Basic block references invalid module ID: " + std::to_string(bb.module_id)
        );
      }
    }
  }
};

/**
 * @brief Builder pattern for creating coverage data
 */
class coverage_builder {
public:
  coverage_builder() {
    data_.header.version = constants::supported_file_version;
    data_.header.flavor = "drcov";
    data_.module_version = module_table_version::v2;
  }

  coverage_builder& set_flavor(const std::string& flavor) {
    data_.header.flavor = flavor;
    return *this;
  }

  coverage_builder& set_module_version(module_table_version version) {
    data_.module_version = version;
    return *this;
  }

  coverage_builder& add_module(const std::string& path, uint64_t base, uint64_t end, uint64_t entry = 0) {
    uint32_t id = static_cast<uint32_t>(data_.modules.size());
    data_.modules.emplace_back(id, path, base, end, entry);
    return *this;
  }

  coverage_builder& add_module(module_entry module) {
    data_.modules.push_back(std::move(module));
    return *this;
  }

  coverage_builder& add_coverage(uint16_t module_id, uint32_t offset, uint16_t size) {
    data_.basic_blocks.emplace_back(offset, size, module_id);
    return *this;
  }

  coverage_builder& add_basic_block(basic_block block) {
    data_.basic_blocks.push_back(std::move(block));
    return *this;
  }

  coverage_builder& add_basic_blocks(const std::vector<basic_block>& blocks) {
    data_.basic_blocks.insert(data_.basic_blocks.end(), blocks.begin(), blocks.end());
    return *this;
  }

  coverage_builder& clear_coverage() {
    data_.basic_blocks.clear();
    return *this;
  }

  coverage_data build() {
    data_.validate();
    return std::move(data_);
  }

  coverage_data& data() { return data_; }
  const coverage_data& data() const { return data_; }

private:
  coverage_data data_;
};

// parser implementation
class parser {
public:
  static coverage_data parse_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
      throw parse_error(error_code::file_not_found, "Cannot open file: " + filepath);
    }
    return parse_stream(file);
  }

  static coverage_data parse_stream(std::istream& stream) {
    coverage_data data;
    data.header = parse_header(stream);
    std::tie(data.modules, data.module_version) = parse_module_table(stream);
    data.basic_blocks = parse_bb_table(stream);
    data.validate();
    return data;
  }

private:
  static file_header parse_header(std::istream& stream) {
    file_header header;
    std::string line;

    if (!std::getline(stream, line)) {
      throw parse_error(error_code::invalid_format, "Missing version header");
    }
    if (line.rfind(constants::version_prefix, 0) != 0) {
      throw parse_error(error_code::invalid_format, "Invalid version header format");
    }
    try {
      header.version = std::stoul(line.substr(constants::version_prefix.length()));
    } catch (const std::exception& e) {
      throw parse_error(error_code::invalid_format, "Malformed version number: " + std::string(e.what()));
    }

    if (!std::getline(stream, line)) {
      throw parse_error(error_code::invalid_format, "Missing flavor header");
    }
    if (line.rfind(constants::flavor_prefix, 0) != 0) {
      throw parse_error(error_code::invalid_format, "Invalid flavor header format");
    }
    header.flavor = detail::trim(line.substr(constants::flavor_prefix.length()));

    return header;
  }

  static std::pair<std::vector<module_entry>, module_table_version> parse_module_table(std::istream& stream) {
    std::string line;

    if (!std::getline(stream, line)) {
      throw parse_error(error_code::invalid_format, "Missing module table header");
    }
    if (line.rfind(constants::module_table_prefix, 0) != 0) {
      throw parse_error(error_code::invalid_format, "Invalid module table header");
    }

    auto [version, count] = parse_module_header(line);

    std::vector<std::string> columns;
    if (version != module_table_version::legacy) {
      if (!std::getline(stream, line)) {
        throw parse_error(error_code::invalid_format, "Missing columns header");
      }
      columns = parse_columns_header(line);
    } else {
      columns = {"id", "base", "end", "entry", "path"};
    }

    std::vector<module_entry> modules;
    modules.reserve(count);
    size_t modules_read = 0;

    while (modules_read < count && std::getline(stream, line)) {
      auto trimmed_line = detail::trim(line);
      if (trimmed_line.empty()) {
        continue;
      }

      auto module = parse_module_entry(trimmed_line, columns);
      if (module.id != modules_read) {
        throw parse_error(
            error_code::invalid_module_table,
            "Non-sequential module ID. Expected " + std::to_string(modules_read) + ", got " + std::to_string(module.id)
        );
      }

      modules.push_back(std::move(module));
      modules_read++;
    }

    if (modules_read != count) {
      throw parse_error(
          error_code::invalid_module_table, "Module table entry count mismatch. Expected " + std::to_string(count) +
                                                ", but found " + std::to_string(modules_read)
      );
    }

    return {modules, version};
  }

  static std::pair<module_table_version, size_t> parse_module_header(const std::string& line) {
    auto content = line.substr(constants::module_table_prefix.length());
    try {
      if (content.find("version") == std::string::npos) {
        return {module_table_version::legacy, std::stoul(content)};
      }
      auto parts = detail::split(content, ',');
      if (parts.size() != 2) {
        throw parse_error(error_code::invalid_format, "Invalid module table header format");
      }
      auto version_str = parts[0].substr(parts[0].find("version") + 8);
      auto count_str = parts[1].substr(parts[1].find("count") + 6);
      return {static_cast<module_table_version>(std::stoul(version_str)), std::stoul(count_str)};
    } catch (const std::exception& e) {
      throw parse_error(error_code::invalid_format, "Failed to parse module table header: " + std::string(e.what()));
    }
  }

  static std::vector<std::string> parse_columns_header(const std::string& line) {
    if (line.rfind(constants::columns_prefix, 0) != 0) {
      throw parse_error(error_code::invalid_format, "Invalid columns header");
    }
    return detail::split(line.substr(constants::columns_prefix.length()), ',');
  }

  static std::vector<std::string> parse_module_line(const std::string& line, size_t num_columns) {
    std::vector<std::string> values;
    if (num_columns == 0) {
      return values;
    }
    values.reserve(num_columns);
    std::string::size_type current_pos = 0;
    for (size_t i = 0; i < num_columns - 1; ++i) {
      auto comma_pos = line.find(',', current_pos);
      if (comma_pos == std::string::npos) {
        throw parse_error(error_code::invalid_module_table, "Module entry has too few columns");
      }
      values.push_back(detail::trim(line.substr(current_pos, comma_pos - current_pos)));
      current_pos = comma_pos + 1;
    }
    values.push_back(detail::trim(line.substr(current_pos)));
    return values;
  }

  static module_entry parse_module_entry(const std::string& line, const std::vector<std::string>& columns) {
    auto values = parse_module_line(line, columns.size());
    if (values.size() != columns.size()) {
      throw parse_error(error_code::invalid_module_table, "Module entry column count mismatch");
    }

    module_entry entry;
    std::unordered_map<std::string, std::string> value_map;
    for (size_t i = 0; i < columns.size(); ++i) {
      value_map[columns[i]] = values[i];
    }

    auto get_val = [&](const std::string& key) -> std::optional<std::string> {
      auto it = value_map.find(key);
      return (it != value_map.end()) ? std::optional(it->second) : std::nullopt;
    };

    try {
      if (auto val = get_val("id")) {
        entry.id = std::stoul(*val);
      }
      if (auto val = get_val("base")) {
        entry.base = std::stoull(*val, nullptr, 16);
      }
      if (auto val = get_val("start")) {
        entry.base = std::stoull(*val, nullptr, 16);
      }
      if (auto val = get_val("end")) {
        entry.end = std::stoull(*val, nullptr, 16);
      }
      if (auto val = get_val("entry")) {
        entry.entry = std::stoull(*val, nullptr, 16);
      }
      if (auto val = get_val("path")) {
        entry.path = *val;
      }
      if (auto val = get_val("containing_id")) {
        entry.containing_id = std::stol(*val);
      }
      if (auto val = get_val("offset")) {
        entry.offset = std::stoull(*val, nullptr, 16);
      }
      if (auto val = get_val("checksum")) {
        entry.checksum = std::stoul(*val, nullptr, 16);
      }
      if (auto val = get_val("timestamp")) {
        entry.timestamp = std::stoul(*val, nullptr, 16);
      }
    } catch (const std::exception& e) {
      throw parse_error(
          error_code::invalid_module_table, "Malformed numeric value in module entry '" + line + "': " + e.what()
      );
    }
    return entry;
  }

  static std::vector<basic_block> parse_bb_table(std::istream& stream) {
    std::string line;

    if (!std::getline(stream, line)) {
      if (stream.eof() && stream.gcount() == 0) {
        return {};
      }
      throw parse_error(error_code::invalid_format, "Missing BB table header");
    }

    if (line.rfind(constants::bb_table_prefix, 0) != 0) {
      throw parse_error(error_code::invalid_format, "Invalid BB table header");
    }

    size_t count = 0;
    try {
      auto content = line.substr(constants::bb_table_prefix.length());
      count = std::stoul(content.substr(0, content.find(' ')));
    } catch (const std::exception& e) {
      throw parse_error(error_code::invalid_bb_table, "Malformed BB table count: " + std::string(e.what()));
    }

    if (count == 0) {
      return {};
    }

    std::vector<uint8_t> binary_data(count * constants::bb_entry_size);
    stream.read(reinterpret_cast<char*>(binary_data.data()), binary_data.size());
    if (static_cast<size_t>(stream.gcount()) != binary_data.size()) {
      throw parse_error(error_code::invalid_binary_data, "Failed to read complete BB table binary data");
    }

    std::vector<basic_block> blocks;
    blocks.reserve(count);
    for (size_t i = 0; i < count; ++i) {
      const uint8_t* entry_data = binary_data.data() + (i * constants::bb_entry_size);
      blocks.emplace_back(
          detail::read_le<uint32_t>(entry_data), detail::read_le<uint16_t>(entry_data + 4),
          detail::read_le<uint16_t>(entry_data + 6)
      );
    }
    return blocks;
  }
};

// writer implementation
class writer {
public:
  static void write_file(const coverage_data& data, const std::string& filepath) {
    std::ofstream file(filepath, std::ios::binary);
    if (!file) {
      throw parse_error(error_code::io_error, "Cannot create file: " + filepath);
    }
    write_stream(data, file);
  }

  static void write_stream(const coverage_data& data, std::ostream& stream) {
    data.validate();
    stream << data.header.to_string();
    write_module_table(data, stream);
    write_bb_table(data.basic_blocks, stream);
    if (!stream) {
      throw parse_error(error_code::io_error, "Error writing to stream");
    }
  }

private:
  static void write_module_table(const coverage_data& data, std::ostream& stream) {
    if (data.module_version == module_table_version::legacy) {
      stream << constants::module_table_prefix << data.modules.size() << "\n";
      for (const auto& module : data.modules) {
        write_module_entry(module, data.module_version, false, stream);
        stream << "\n";
      }
    } else {
      stream << constants::module_table_prefix << "version " << static_cast<uint32_t>(data.module_version) << ", count "
             << data.modules.size() << "\n";
      std::string columns_str = get_columns_string(data);
      stream << constants::columns_prefix << columns_str << "\n";
      bool has_windows_fields = columns_str.find("checksum") != std::string::npos;
      for (const auto& module : data.modules) {
        write_module_entry(module, data.module_version, has_windows_fields, stream);
        stream << "\n";
      }
    }
  }

  static std::string get_columns_string(const coverage_data& data) {
    const bool has_windows_fields = std::any_of(data.modules.begin(), data.modules.end(), [](const auto& m) {
      return m.checksum.has_value() || m.timestamp.has_value();
    });

    switch (data.module_version) {
    case module_table_version::legacy:
      return "id, base, end, entry, path"; // Enforce fixed legacy format
    case module_table_version::v2:
      return has_windows_fields ? "id, base, end, entry, checksum, timestamp, path" : "id, base, end, entry, path";
    case module_table_version::v3:
      return has_windows_fields ? "id, containing_id, start, end, entry, checksum, timestamp, path"
                                : "id, containing_id, start, end, entry, path";
    case module_table_version::v4:
      return has_windows_fields ? "id, containing_id, start, end, entry, offset, checksum, timestamp, path"
                                : "id, containing_id, start, end, entry, offset, path";
    default: // Should be unreachable
      return "id, base, end, entry, path";
    }
  }

  static void write_module_entry(
      const module_entry& module, module_table_version version, bool has_windows_fields, std::ostream& stream
  ) {
    auto original_flags = stream.flags();
    auto original_fill = stream.fill();
    stream << std::dec << module.id;

    if (version >= module_table_version::v3) {
      stream << ", " << module.containing_id.value_or(-1);
    }

    stream << ", 0x" << std::hex << std::setfill('0') << std::setw(16) << module.base;
    stream << ", 0x" << std::hex << std::setfill('0') << std::setw(16) << module.end;
    stream << ", 0x" << std::hex << std::setfill('0') << std::setw(16) << module.entry;

    if (version >= module_table_version::v4) {
      stream << ", ";
      if (module.offset) {
        stream << "0x" << std::hex << std::setfill('0') << std::setw(16) << *module.offset;
      } else {
        stream << "0x0";
      }
    }

    if (has_windows_fields) {
      stream << ", 0x" << std::hex << std::setfill('0') << std::setw(8) << module.checksum.value_or(0);
      stream << ", 0x" << std::hex << std::setfill('0') << std::setw(8) << module.timestamp.value_or(0);
    }

    stream << ", " << module.path;
    stream.flags(original_flags);
    stream.fill(original_fill);
  }

  static void write_bb_table(const std::vector<basic_block>& blocks, std::ostream& stream) {
    stream << constants::bb_table_prefix << blocks.size() << " bbs\n";
    if (blocks.empty()) {
      return;
    }
    std::vector<uint8_t> binary_data(blocks.size() * constants::bb_entry_size);
    for (size_t i = 0; i < blocks.size(); ++i) {
      uint8_t* entry_data = binary_data.data() + (i * constants::bb_entry_size);
      detail::write_le<uint32_t>(entry_data, blocks[i].start);
      detail::write_le<uint16_t>(entry_data + 4, blocks[i].size);
      detail::write_le<uint16_t>(entry_data + 6, blocks[i].module_id);
    }
    stream.write(reinterpret_cast<const char*>(binary_data.data()), binary_data.size());
  }
};

inline coverage_data read(const std::string& filepath) { return parser::parse_file(filepath); }
inline coverage_data read(std::istream& stream) { return parser::parse_stream(stream); }
inline void write(const std::string& filepath, const coverage_data& data) { writer::write_file(data, filepath); }
inline void write(std::ostream& stream, const coverage_data& data) { writer::write_stream(data, stream); }
inline coverage_builder builder() { return coverage_builder(); }

} // namespace drcov

#undef DRCOV_LITTLE_ENDIAN

#endif // DRCOV_HPP