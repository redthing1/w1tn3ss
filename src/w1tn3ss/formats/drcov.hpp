/**
 * @file drcov.hpp
 * @brief Header-only C++17 library for parsing and writing DrCov coverage files
 * @author DrCov C++ Library
 * @version 2.0.0
 * 
 * This library provides a complete implementation for reading and writing
 * DrCov coverage files, supporting format version 2 with module table versions 2-4.
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
 * auto builder = drcov::coverage_builder()
 *     .set_flavor("my_tool")
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
}

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
    explicit parse_error(error_code code, const std::string& message)
        : std::runtime_error(message), code_(code) {}
    
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
    
    template<typename T>
    inline T read_le(const uint8_t* data) {
        T value{};
        std::memcpy(&value, data, sizeof(T));
        return value;
    }
    
    template<typename T>
    inline void write_le(uint8_t* data, T value) {
        std::memcpy(data, &value, sizeof(T));
    }
}

/**
 * @brief DrCov file header containing version and tool information
 */
struct file_header {
    uint32_t version{constants::supported_file_version};
    std::string flavor{"drcov"};
    
    /**
     * @brief Convert header to string representation for file writing
     */
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
enum class module_table_version : uint32_t {
    legacy = 1,  // no explicit version in header
    v2 = 2,      // base, end format
    v3 = 3,      // containing_id, start, end format
    v4 = 4       // containing_id, start, end, offset format
};

/**
 * @brief Represents a loaded module/library in the traced process
 */
struct module_entry {
    uint32_t id{0};           // unique module identifier
    uint64_t base{0};         // start address in memory
    uint64_t end{0};          // end address in memory
    uint64_t entry{0};        // entry point (usually 0 for libraries)
    std::string path;         // file system path
    
    // optional fields depending on version and platform
    std::optional<int32_t> containing_id;   // parent module ID (v3+)
    std::optional<uint64_t> offset;          // offset in container (v4+)
    std::optional<uint32_t> checksum;        // PE checksum (Windows)
    std::optional<uint32_t> timestamp;       // PE timestamp (Windows)
    
    /**
     * @brief Get module size in bytes
     */
    uint64_t size() const noexcept { return end - base; }
    
    /**
     * @brief Check if address falls within this module
     */
    bool contains_address(uint64_t addr) const noexcept { 
        return addr >= base && addr < end; 
    }
    
    /**
     * @brief Constructor for convenient module creation
     */
    module_entry() = default;
    
    module_entry(uint32_t id, const std::string& path, 
                 uint64_t base, uint64_t end, uint64_t entry = 0)
        : id(id), base(base), end(end), entry(entry), path(path) {}
};

/**
 * @brief Represents an executed basic block
 * 
 * A basic block is a sequence of instructions with single entry and exit point.
 * Size is 8 bytes when serialized to binary format.
 */
struct basic_block {
    uint32_t start{0};     // offset from module base
    uint16_t size{0};      // size in bytes
    uint16_t module_id{0}; // module identifier
    
    /**
     * @brief Get absolute address of this basic block
     */
    uint64_t absolute_address(const module_entry& module) const noexcept {
        return module.base + start;
    }
    
    /**
     * @brief Constructor for convenient basic block creation
     */
    basic_block() = default;
    
    basic_block(uint32_t start, uint16_t size, uint16_t module_id)
        : start(start), size(size), module_id(module_id) {}
};

/**
 * @brief Complete coverage data structure
 * 
 * This is the main data structure that represents a complete DrCov file.
 */
struct coverage_data {
    file_header header;
    module_table_version module_version{module_table_version::v2};
    std::vector<module_entry> modules;
    std::vector<basic_block> basic_blocks;
    
    /**
     * @brief Find module by ID
     * @return Optional reference to module if found
     */
    std::optional<std::reference_wrapper<const module_entry>> 
    find_module(uint16_t id) const {
        auto it = std::find_if(modules.begin(), modules.end(),
            [id](const auto& m) { return m.id == id; });
        return it != modules.end() 
            ? std::optional<std::reference_wrapper<const module_entry>>(*it)
            : std::nullopt;
    }
    
    /**
     * @brief Find module containing the given address
     * @return Optional reference to module if found
     */
    std::optional<std::reference_wrapper<const module_entry>>
    find_module_by_address(uint64_t addr) const {
        auto it = std::find_if(modules.begin(), modules.end(),
            [addr](const auto& m) { return m.contains_address(addr); });
        return it != modules.end()
            ? std::optional<std::reference_wrapper<const module_entry>>(*it)
            : std::nullopt;
    }
    
    /**
     * @brief Get coverage statistics
     * @return Map of module ID to number of basic blocks
     */
    std::unordered_map<uint16_t, size_t> get_coverage_stats() const {
        std::unordered_map<uint16_t, size_t> stats;
        for (const auto& bb : basic_blocks) {
            stats[bb.module_id]++;
        }
        return stats;
    }
    
    /**
     * @brief Validate coverage data integrity
     * @throws parse_error if validation fails
     */
    void validate() const {
        // check module IDs are sequential
        for (size_t i = 0; i < modules.size(); ++i) {
            if (modules[i].id != i) {
                throw parse_error(error_code::validation_error,
                    "Non-sequential module ID at index " + std::to_string(i));
            }
        }
        
        // check all basic blocks reference valid modules
        for (const auto& bb : basic_blocks) {
            if (bb.module_id >= modules.size()) {
                throw parse_error(error_code::validation_error,
                    "Basic block references invalid module ID: " + 
                    std::to_string(bb.module_id));
            }
        }
    }
};

/**
 * @brief Builder pattern for creating coverage data
 * 
 * Provides a fluent interface for constructing coverage data programmatically.
 */
class coverage_builder {
public:
    coverage_builder() {
        data_.header.version = constants::supported_file_version;
        data_.header.flavor = "drcov";
    }
    
    /**
     * @brief Set the tool name that generated the coverage
     */
    coverage_builder& set_flavor(const std::string& flavor) {
        data_.header.flavor = flavor;
        return *this;
    }
    
    /**
     * @brief Set the module table version
     */
    coverage_builder& set_module_version(module_table_version version) {
        data_.module_version = version;
        return *this;
    }
    
    /**
     * @brief Add a module with automatic ID assignment
     */
    coverage_builder& add_module(const std::string& path, 
                                uint64_t base, uint64_t end, 
                                uint64_t entry = 0) {
        uint32_t id = static_cast<uint32_t>(data_.modules.size());
        data_.modules.emplace_back(id, path, base, end, entry);
        return *this;
    }
    
    /**
     * @brief Add a module with full control
     */
    coverage_builder& add_module(module_entry module) {
        data_.modules.push_back(std::move(module));
        return *this;
    }
    
    /**
     * @brief Add coverage for a basic block
     * @param module_id Module containing the basic block
     * @param offset Offset from module base
     * @param size Size of the basic block in bytes
     */
    coverage_builder& add_coverage(uint16_t module_id, 
                                  uint32_t offset, uint16_t size) {
        data_.basic_blocks.emplace_back(offset, size, module_id);
        return *this;
    }
    
    /**
     * @brief Add a basic block directly
     */
    coverage_builder& add_basic_block(basic_block block) {
        data_.basic_blocks.push_back(std::move(block));
        return *this;
    }
    
    /**
     * @brief Add multiple basic blocks at once
     */
    coverage_builder& add_basic_blocks(const std::vector<basic_block>& blocks) {
        data_.basic_blocks.insert(data_.basic_blocks.end(), 
                                 blocks.begin(), blocks.end());
        return *this;
    }
    
    /**
     * @brief Clear all basic blocks
     */
    coverage_builder& clear_coverage() {
        data_.basic_blocks.clear();
        return *this;
    }
    
    /**
     * @brief Build and validate the coverage data
     * @throws parse_error if validation fails
     */
    coverage_data build() {
        data_.validate();
        return std::move(data_);
    }
    
    /**
     * @brief Get mutable reference to data (for advanced use)
     */
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
            throw parse_error(error_code::file_not_found, 
                "Cannot open file: " + filepath);
        }
        return parse_stream(file);
    }
    
    static coverage_data parse_stream(std::istream& stream) {
        coverage_data data;
        
        // parse header
        data.header = parse_header(stream);
        
        // parse module table
        std::tie(data.modules, data.module_version) = parse_module_table(stream);
        
        // parse basic block table
        data.basic_blocks = parse_bb_table(stream);
        
        // validate the parsed data
        data.validate();
        
        return data;
    }

private:
    static file_header parse_header(std::istream& stream) {
        file_header header;
        std::string line;
        
        // parse version line
        if (!std::getline(stream, line)) {
            throw parse_error(error_code::invalid_format, 
                "Missing version header");
        }
        
        if (line.find(constants::version_prefix) != 0) {
            throw parse_error(error_code::invalid_format, 
                "Invalid version header format");
        }
        
        header.version = std::stoul(line.substr(constants::version_prefix.length()));
        if (header.version != constants::supported_file_version) {
            throw parse_error(error_code::unsupported_version,
                "Unsupported file version: " + std::to_string(header.version));
        }
        
        // parse flavor line
        if (!std::getline(stream, line)) {
            throw parse_error(error_code::invalid_format, 
                "Missing flavor header");
        }
        
        if (line.find(constants::flavor_prefix) != 0) {
            throw parse_error(error_code::invalid_format, 
                "Invalid flavor header format");
        }
        
        header.flavor = detail::trim(line.substr(constants::flavor_prefix.length()));
        
        return header;
    }
    
    static std::pair<std::vector<module_entry>, module_table_version> 
    parse_module_table(std::istream& stream) {
        std::string line;
        
        // parse module table header
        if (!std::getline(stream, line)) {
            throw parse_error(error_code::invalid_format, 
                "Missing module table header");
        }
        
        if (line.find(constants::module_table_prefix) != 0) {
            throw parse_error(error_code::invalid_format, 
                "Invalid module table header");
        }
        
        auto header_parts = parse_module_header(line);
        auto version = header_parts.first;
        auto count = header_parts.second;
        
        // parse columns header
        if (!std::getline(stream, line)) {
            throw parse_error(error_code::invalid_format, 
                "Missing columns header");
        }
        
        auto columns = parse_columns_header(line);
        
        // parse module entries
        std::vector<module_entry> modules;
        modules.reserve(count);
        
        for (size_t i = 0; i < count; ++i) {
            if (!std::getline(stream, line)) {
                throw parse_error(error_code::invalid_module_table,
                    "Unexpected end of module table");
            }
            
            auto module = parse_module_entry(line, columns, version);
            if (module.id != i) {
                throw parse_error(error_code::invalid_module_table,
                    "Non-sequential module ID");
            }
            
            modules.push_back(std::move(module));
        }
        
        return {modules, version};
    }
    
    static std::pair<module_table_version, size_t> 
    parse_module_header(const std::string& line) {
        auto content = line.substr(constants::module_table_prefix.length());
        
        // check for legacy format
        if (content.find("version") == std::string::npos) {
            return {module_table_version::legacy, std::stoul(content)};
        }
        
        // parse modern format
        auto parts = detail::split(content, ',');
        if (parts.size() != 2) {
            throw parse_error(error_code::invalid_format,
                "Invalid module table header format");
        }
        
        auto version_str = parts[0].substr(parts[0].find("version") + 8);
        auto count_str = parts[1].substr(parts[1].find("count") + 6);
        
        auto version = static_cast<module_table_version>(std::stoul(version_str));
        auto count = std::stoul(count_str);
        
        return {version, count};
    }
    
    static std::vector<std::string> parse_columns_header(const std::string& line) {
        if (line.find(constants::columns_prefix) != 0) {
            throw parse_error(error_code::invalid_format,
                "Invalid columns header");
        }
        
        auto columns_str = line.substr(constants::columns_prefix.length());
        return detail::split(columns_str, ',');
    }
    
    static module_entry parse_module_entry(const std::string& line,
                                         const std::vector<std::string>& columns,
                                         module_table_version version) {
        auto values = detail::split(line, ',');
        if (values.size() != columns.size()) {
            throw parse_error(error_code::invalid_module_table,
                "Module entry column count mismatch");
        }
        
        module_entry entry;
        
        for (size_t i = 0; i < columns.size(); ++i) {
            const auto& col = columns[i];
            const auto& val = values[i];
            
            if (col == "id") {
                entry.id = std::stoul(val);
            } else if (col == "base" || col == "start") {
                entry.base = std::stoull(val, nullptr, 16);
            } else if (col == "end") {
                entry.end = std::stoull(val, nullptr, 16);
            } else if (col == "entry") {
                entry.entry = std::stoull(val, nullptr, 16);
            } else if (col == "path") {
                entry.path = val;
            } else if (col == "containing_id") {
                entry.containing_id = std::stol(val);
            } else if (col == "offset") {
                entry.offset = std::stoull(val, nullptr, 16);
            } else if (col == "checksum") {
                entry.checksum = std::stoul(val, nullptr, 16);
            } else if (col == "timestamp") {
                entry.timestamp = std::stoul(val, nullptr, 16);
            }
        }
        
        return entry;
    }
    
    static std::vector<basic_block> parse_bb_table(std::istream& stream) {
        std::string line;
        
        // parse bb table header
        if (!std::getline(stream, line)) {
            throw parse_error(error_code::invalid_format,
                "Missing BB table header");
        }
        
        if (line.find(constants::bb_table_prefix) != 0) {
            throw parse_error(error_code::invalid_format,
                "Invalid BB table header");
        }
        
        auto content = line.substr(constants::bb_table_prefix.length());
        auto space_pos = content.find(' ');
        auto count = std::stoul(content.substr(0, space_pos));
        
        // read binary data
        std::vector<uint8_t> binary_data(count * constants::bb_entry_size);
        stream.read(reinterpret_cast<char*>(binary_data.data()), binary_data.size());
        
        if (!stream) {
            throw parse_error(error_code::invalid_binary_data,
                "Failed to read BB table binary data");
        }
        
        // parse binary entries
        std::vector<basic_block> blocks;
        blocks.reserve(count);
        
        for (size_t i = 0; i < count; ++i) {
            const uint8_t* entry_data = binary_data.data() + (i * constants::bb_entry_size);
            
            basic_block block;
            block.start = detail::read_le<uint32_t>(entry_data);
            block.size = detail::read_le<uint16_t>(entry_data + 4);
            block.module_id = detail::read_le<uint16_t>(entry_data + 6);
            
            blocks.push_back(block);
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
            throw parse_error(error_code::io_error,
                "Cannot create file: " + filepath);
        }
        write_stream(data, file);
    }
    
    static void write_stream(const coverage_data& data, std::ostream& stream) {
        // validate before writing
        data.validate();
        
        // write header
        stream << data.header.to_string();
        
        // write module table
        write_module_table(data, stream);
        
        // write bb table
        write_bb_table(data.basic_blocks, stream);
        
        if (!stream) {
            throw parse_error(error_code::io_error,
                "Error writing to stream");
        }
    }

private:
    static void write_module_table(const coverage_data& data, std::ostream& stream) {
        // write module table header
        if (data.module_version == module_table_version::legacy) {
            stream << constants::module_table_prefix << data.modules.size() << "\n";
        } else {
            stream << constants::module_table_prefix 
                   << "version " << static_cast<uint32_t>(data.module_version)
                   << ", count " << data.modules.size() << "\n";
        }
        
        // write columns header based on version and platform
        stream << constants::columns_prefix << get_columns_string(data) << "\n";
        
        // write module entries
        for (const auto& module : data.modules) {
            write_module_entry(module, data, stream);
            stream << "\n";
        }
    }
    
    static std::string get_columns_string(const coverage_data& data) {
        const bool has_windows_fields = std::any_of(data.modules.begin(), 
            data.modules.end(), [](const auto& m) { 
                return m.checksum.has_value() || m.timestamp.has_value(); 
            });
        
        switch (data.module_version) {
            case module_table_version::v2:
                return has_windows_fields 
                    ? "id, base, end, entry, checksum, timestamp, path"
                    : "id, base, end, entry, path";
                    
            case module_table_version::v3:
                return has_windows_fields
                    ? "id, containing_id, start, end, entry, checksum, timestamp, path"
                    : "id, containing_id, start, end, entry, path";
                    
            case module_table_version::v4:
                return has_windows_fields
                    ? "id, containing_id, start, end, entry, offset, checksum, timestamp, path"
                    : "id, containing_id, start, end, entry, offset, path";
                    
            default:
                return "id, base, end, entry, path";
        }
    }
    
    static void write_module_entry(const module_entry& module, 
                                 const coverage_data& data,
                                 std::ostream& stream) {
        stream << module.id << ", ";
        
        if (data.module_version >= module_table_version::v3) {
            stream << module.containing_id.value_or(-1) << ", ";
        }
        
        // use appropriate field names based on version
        const bool use_start = (data.module_version >= module_table_version::v3);
        
        stream << "0x" << std::hex << std::setfill('0') << std::setw(use_start ? 8 : 16) 
               << module.base << ", ";
        stream << "0x" << std::hex << std::setfill('0') << std::setw(use_start ? 8 : 16) 
               << module.end << ", ";
        stream << "0x" << std::hex << std::setfill('0') << std::setw(16) << module.entry;
        
        if (data.module_version >= module_table_version::v4 && module.offset) {
            stream << ", 0x" << std::hex << std::setfill('0') << std::setw(8) 
                   << *module.offset;
        }
        
        if (module.checksum) {
            stream << ", 0x" << std::hex << std::setfill('0') << std::setw(8) 
                   << *module.checksum;
        }
        
        if (module.timestamp) {
            stream << ", 0x" << std::hex << std::setfill('0') << std::setw(8) 
                   << *module.timestamp;
        }
        
        stream << std::dec << ", " << module.path;
    }
    
    static void write_bb_table(const std::vector<basic_block>& blocks, 
                             std::ostream& stream) {
        // write bb table header
        stream << constants::bb_table_prefix << blocks.size() << " bbs\n";
        
        // write binary data
        std::vector<uint8_t> binary_data(blocks.size() * constants::bb_entry_size);
        
        for (size_t i = 0; i < blocks.size(); ++i) {
            uint8_t* entry_data = binary_data.data() + (i * constants::bb_entry_size);
            
            detail::write_le<uint32_t>(entry_data, blocks[i].start);
            detail::write_le<uint16_t>(entry_data + 4, blocks[i].size);
            detail::write_le<uint16_t>(entry_data + 6, blocks[i].module_id);
        }
        
        stream.write(reinterpret_cast<const char*>(binary_data.data()), 
                    binary_data.size());
    }
};

/**
 * @brief Read coverage data from a file
 * @param filepath Path to the DrCov file
 * @return Parsed coverage data
 * @throws parse_error on failure
 */
inline coverage_data read(const std::string& filepath) {
    return parser::parse_file(filepath);
}

/**
 * @brief Read coverage data from a stream
 * @param stream Input stream containing DrCov data
 * @return Parsed coverage data
 * @throws parse_error on failure
 */
inline coverage_data read(std::istream& stream) {
    return parser::parse_stream(stream);
}

/**
 * @brief Write coverage data to a file
 * @param filepath Output file path
 * @param data Coverage data to write
 * @throws parse_error on failure
 */
inline void write(const std::string& filepath, const coverage_data& data) {
    writer::write_file(data, filepath);
}

/**
 * @brief Write coverage data to a stream
 * @param stream Output stream
 * @param data Coverage data to write
 * @throws parse_error on failure
 */
inline void write(std::ostream& stream, const coverage_data& data) {
    writer::write_stream(data, stream);
}

/**
 * @brief Create a new coverage builder
 * @return Coverage builder instance
 */
inline coverage_builder builder() {
    return coverage_builder();
}

// deprecated API for compatibility
[[deprecated("Use drcov::read() instead")]]
inline coverage_data parse_file(const std::string& filepath) {
    return read(filepath);
}

[[deprecated("Use drcov::read() instead")]]
inline coverage_data parse_stream(std::istream& stream) {
    return read(stream);
}

[[deprecated("Use drcov::write() instead")]]
inline void write_file(const coverage_data& data, const std::string& filepath) {
    write(filepath, data);
}

[[deprecated("Use drcov::write() instead")]]
inline void write_stream(const coverage_data& data, std::ostream& stream) {
    write(stream, data);
}

} // namespace drcov

#endif // DRCOV_HPP