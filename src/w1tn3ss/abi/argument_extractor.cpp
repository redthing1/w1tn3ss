#include "argument_extractor.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

namespace w1::abi {

class argument_extractor::impl {
public:
    impl(std::shared_ptr<calling_convention> convention,
         std::shared_ptr<api_knowledge_db> api_db,
         const extractor_config& config)
        : convention_(convention), api_db_(api_db), config_(config),
          log_("w1::abi::argument_extractor") {
        log_.debug("initialized argument extractor");
    }
    
    extracted_call_info extract_call(
        const std::string& api_name,
        const std::string& module_name,
        const util::safe_memory_reader& memory,
        const call_context& ctx
    ) const {
        log_.debug("extracting call arguments",
                  redlog::field("api", api_name),
                  redlog::field("module", module_name));
        
        extracted_call_info info;
        info.api_name = api_name;
        info.module_name = module_name;
        info.timestamp = ctx.timestamp;
        info.call_address = ctx.call_address;
        info.return_address = ctx.return_address;
        
        // look up api info
        auto api_info = api_db_->lookup(module_name, api_name);
        if (!api_info) {
            // try without module
            api_info = api_db_->lookup(api_name);
        }
        
        if (api_info) {
            log_.debug("found api info",
                      redlog::field("api", api_name),
                      redlog::field("params", api_info->parameters.size()),
                      redlog::field("category", static_cast<int>(api_info->api_category)));
            
            info.category = api_info->api_category;
            info.behavior_flags = api_info->flags;
            info.description = api_info->description;
            
            // extract each parameter
            for (size_t i = 0; i < api_info->parameters.size(); ++i) {
                const auto& param = api_info->parameters[i];
                uint64_t raw_value = convention_->get_parameter(ctx, i);
                
                log_.debug("extracting parameter",
                          redlog::field("index", i),
                          redlog::field("name", param.name),
                          redlog::field("type", static_cast<int>(param.param_type)),
                          redlog::field("raw_value", raw_value));
                
                auto arg = extract_argument(param, raw_value, memory);
                info.arguments.push_back(std::move(arg));
            }
        } else {
            log_.debug("no api info found, extracting raw arguments",
                      redlog::field("api", api_name));
            
            // extract raw arguments without semantic info
            size_t max_args = 6;  // reasonable default
            for (size_t i = 0; i < max_args; ++i) {
                uint64_t raw_value = convention_->get_parameter(ctx, i);
                if (raw_value == 0 && i > 2) break;  // heuristic
                
                param_info generic_param;
                generic_param.name = "arg" + std::to_string(i);
                generic_param.param_type = param_info::type::UNKNOWN;
                
                auto arg = extract_argument(generic_param, raw_value, memory);
                info.arguments.push_back(std::move(arg));
            }
        }
        
        return info;
    }
    
    void extract_return_value(
        extracted_call_info& call_info,
        const util::safe_memory_reader& memory,
        const call_context& ctx
    ) const {
        log_.debug("extracting return value",
                  redlog::field("api", call_info.api_name));
        
        uint64_t ret_val = convention_->get_return_value(ctx);
        
        // look up return value info
        param_info ret_param;
        if (auto api_info = api_db_->lookup(call_info.module_name, call_info.api_name)) {
            ret_param = api_info->return_value;
        } else {
            ret_param.name = "return";
            ret_param.param_type = param_info::type::UNKNOWN;
        }
        
        call_info.return_value = extract_argument(ret_param, ret_val, memory);
        
        log_.debug("extracted return value",
                  redlog::field("api", call_info.api_name),
                  redlog::field("raw_value", ret_val),
                  redlog::field("type", static_cast<int>(ret_param.param_type)));
    }
    
    extracted_argument extract_argument(
        const param_info& param,
        uint64_t raw_value,
        const util::safe_memory_reader& memory
    ) const {
        log_.debug("extracting single argument",
                  redlog::field("name", param.name),
                  redlog::field("type", static_cast<int>(param.param_type)),
                  redlog::field("raw_value", raw_value));
        
        extracted_argument arg;
        arg.raw_value = raw_value;
        arg.param_name = param.name;
        arg.param_type = param.param_type;
        
        // check for null pointers
        if (raw_value == 0 && is_pointer_type(param.param_type)) {
            arg.is_null_pointer = true;
            arg.type_description = "NULL";
            log_.debug("detected null pointer", redlog::field("param", param.name));
            return arg;
        }
        
        // extract based on parameter type
        switch (param.param_type) {
        case param_info::type::INTEGER:
            extract_integer(arg, raw_value);
            break;
            
        case param_info::type::BOOLEAN:
            extract_boolean(arg, raw_value);
            break;
            
        case param_info::type::POINTER:
            extract_pointer(arg, raw_value, memory);
            break;
            
        case param_info::type::STRING:
            extract_string(arg, raw_value, memory);
            break;
            
        case param_info::type::PATH:
            extract_path(arg, raw_value, memory);
            break;
            
        case param_info::type::BUFFER:
            extract_buffer(arg, raw_value, memory, param);
            break;
            
        case param_info::type::SIZE:
        case param_info::type::COUNT:
            extract_size(arg, raw_value);
            break;
            
        case param_info::type::FLAGS:
            extract_flags(arg, raw_value, param.name);
            break;
            
        case param_info::type::HANDLE:
        case param_info::type::FILE_DESCRIPTOR:
            extract_handle(arg, raw_value);
            break;
            
        case param_info::type::ERROR_CODE:
            extract_error_code(arg, raw_value);
            break;
            
        default:
            // try to guess based on value
            guess_type(arg, raw_value, memory);
            break;
        }
        
        return arg;
    }
    
    std::string format_call(const extracted_call_info& call) const {
        std::stringstream ss;
        
        // format: module!api(arg1, arg2, ...) = return_value
        if (!call.module_name.empty()) {
            ss << call.module_name << "!";
        }
        ss << call.api_name << "(";
        
        for (size_t i = 0; i < call.arguments.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << format_argument(call.arguments[i]);
        }
        
        ss << ")";
        
        // add return value if available
        if (call.return_value.raw_value != 0 || 
            !std::holds_alternative<std::monostate>(call.return_value.interpreted_value)) {
            ss << " = " << format_argument(call.return_value);
        }
        
        return ss.str();
    }
    
    const extractor_config& get_config() const { return config_; }
    void set_config(const extractor_config& config) { config_ = config; }
    
private:
    std::shared_ptr<calling_convention> convention_;
    std::shared_ptr<api_knowledge_db> api_db_;
    extractor_config config_;
    mutable redlog::logger log_;
    
    bool is_pointer_type(param_info::type type) const {
        return type == param_info::type::POINTER ||
               type == param_info::type::STRING ||
               type == param_info::type::BUFFER ||
               type == param_info::type::PATH ||
               type == param_info::type::STRUCT;
    }
    
    void extract_integer(extracted_argument& arg, uint64_t value) const {
        arg.interpreted_value = static_cast<int64_t>(value);
        arg.type_description = "integer";
        
        // format with sign if negative
        if (static_cast<int64_t>(value) < 0) {
            arg.type_description = "signed integer";
        }
    }
    
    void extract_boolean(extracted_argument& arg, uint64_t value) const {
        arg.interpreted_value = (value != 0);
        arg.type_description = value ? "TRUE" : "FALSE";
    }
    
    void extract_pointer(extracted_argument& arg, uint64_t value, 
                        const util::safe_memory_reader& memory) const {
        arg.is_valid_pointer = arg_utils::is_valid_pointer(value, memory);
        arg.type_description = "pointer";
        
        if (arg.is_valid_pointer && config_.follow_pointers) {
            // try to read what it points to
            uint64_t pointed_value = 0;
            if (memory.read(value, &pointed_value, sizeof(pointed_value))) {
                arg.type_description = "pointer -> 0x" + 
                    arg_utils::format_pointer(pointed_value);
            }
        }
    }
    
    void extract_string(extracted_argument& arg, uint64_t value,
                       const util::safe_memory_reader& memory) const {
        if (auto str = arg_utils::read_string(value, memory, config_.max_string_length)) {
            arg.interpreted_value = *str;
            arg.string_preview = *str;
            arg.type_description = "string";
            arg.is_valid_pointer = true;
            
            log_.debug("extracted string",
                      redlog::field("addr", value),
                      redlog::field("str", *str));
        } else {
            arg.is_valid_pointer = false;
            arg.type_description = "invalid string pointer";
        }
    }
    
    void extract_path(extracted_argument& arg, uint64_t value,
                     const util::safe_memory_reader& memory) const {
        // similar to string but with path-specific handling
        extract_string(arg, value, memory);
        if (arg.is_valid_pointer) {
            arg.type_description = "path";
        }
    }
    
    void extract_buffer(extracted_argument& arg, uint64_t value,
                       const util::safe_memory_reader& memory,
                       const param_info& param) const {
        arg.is_valid_pointer = arg_utils::is_valid_pointer(value, memory);
        
        if (arg.is_valid_pointer && config_.follow_pointers) {
            // read buffer preview
            size_t preview_size = std::min(config_.max_buffer_preview, 
                                         param.size_hint);
            if (preview_size == 0) preview_size = config_.max_buffer_preview;
            
            arg.buffer_preview.resize(preview_size);
            size_t read = memory.read(value, arg.buffer_preview.data(), preview_size);
            arg.buffer_preview.resize(read);
            arg.buffer_size = param.size_hint;
            
            arg.type_description = "buffer[" + std::to_string(read) + " bytes]";
            
            log_.debug("extracted buffer",
                      redlog::field("addr", value),
                      redlog::field("preview_size", read));
        } else {
            arg.type_description = "invalid buffer pointer";
        }
    }
    
    void extract_size(extracted_argument& arg, uint64_t value) const {
        arg.interpreted_value = value;
        arg.type_description = "size";
        
        // add human-readable size
        if (value > 1024 * 1024) {
            arg.type_description += " (" + std::to_string(value / (1024 * 1024)) + " MB)";
        } else if (value > 1024) {
            arg.type_description += " (" + std::to_string(value / 1024) + " KB)";
        }
    }
    
    void extract_flags(extracted_argument& arg, uint64_t value, 
                      const std::string& param_name) const {
        arg.interpreted_value = value;
        arg.type_description = "flags";
        
        if (config_.decode_flags) {
            arg.flag_names = arg_utils::decode_flags(
                static_cast<uint32_t>(value), param_name);
            
            if (!arg.flag_names.empty()) {
                arg.type_description = "flags: " + join_strings(arg.flag_names, " | ");
            }
        }
    }
    
    void extract_handle(extracted_argument& arg, uint64_t value) const {
        arg.interpreted_value = value;
        arg.type_description = (value == static_cast<uint64_t>(-1)) ? 
                               "INVALID_HANDLE" : "handle";
    }
    
    void extract_error_code(extracted_argument& arg, uint64_t value) const {
        arg.interpreted_value = static_cast<int64_t>(value);
        arg.type_description = "error_code";
        
        // could map to error strings here
        if (value == 0) {
            arg.type_description = "SUCCESS";
        }
    }
    
    void guess_type(extracted_argument& arg, uint64_t value,
                   const util::safe_memory_reader& memory) const {
        // heuristic type guessing
        if (value == 0) {
            arg.type_description = "null/zero";
        } else if (value == static_cast<uint64_t>(-1)) {
            arg.type_description = "-1/error";
        } else if (value < 0x1000) {
            arg.interpreted_value = static_cast<int64_t>(value);
            arg.type_description = "small_int";
        } else if (arg_utils::is_valid_pointer(value, memory)) {
            // might be a pointer
            arg.is_valid_pointer = true;
            arg.type_description = "pointer?";
            
            // try string
            if (auto str = arg_utils::read_string(value, memory, 16)) {
                if (str->length() > 2) {
                    arg.string_preview = *str;
                    arg.type_description = "string?";
                }
            }
        } else {
            arg.type_description = "value";
        }
    }
    
    std::string format_argument(const extracted_argument& arg) const {
        std::stringstream ss;
        
        if (!arg.param_name.empty() && arg.param_name != "return") {
            ss << arg.param_name << "=";
        }
        
        // format based on interpreted value
        if (std::holds_alternative<std::string>(arg.interpreted_value)) {
            ss << "\"" << std::get<std::string>(arg.interpreted_value) << "\"";
        } else if (std::holds_alternative<bool>(arg.interpreted_value)) {
            ss << (std::get<bool>(arg.interpreted_value) ? "TRUE" : "FALSE");
        } else if (std::holds_alternative<int64_t>(arg.interpreted_value)) {
            ss << std::get<int64_t>(arg.interpreted_value);
        } else if (!arg.string_preview.empty()) {
            ss << "\"" << arg.string_preview << "\"";
        } else if (!arg.flag_names.empty()) {
            ss << join_strings(arg.flag_names, "|");
        } else if (arg.is_null_pointer) {
            ss << "NULL";
        } else if (!arg.buffer_preview.empty()) {
            ss << "[buffer:" << arg.buffer_preview.size() << " bytes]";
        } else {
            // raw hex value
            ss << "0x" << std::hex << arg.raw_value;
        }
        
        return ss.str();
    }
    
    std::string join_strings(const std::vector<std::string>& strings,
                            const std::string& delimiter) const {
        if (strings.empty()) return "";
        
        std::stringstream ss;
        for (size_t i = 0; i < strings.size(); ++i) {
            if (i > 0) ss << delimiter;
            ss << strings[i];
        }
        return ss.str();
    }
};

// argument_extractor implementation
argument_extractor::argument_extractor(
    std::shared_ptr<calling_convention> convention,
    std::shared_ptr<api_knowledge_db> api_db,
    const extractor_config& config
) : pimpl(std::make_unique<impl>(convention, api_db, config)) {}

argument_extractor::~argument_extractor() = default;

extracted_call_info argument_extractor::extract_call(
    const std::string& api_name,
    const std::string& module_name,
    const util::safe_memory_reader& memory,
    const call_context& ctx
) const {
    return pimpl->extract_call(api_name, module_name, memory, ctx);
}

void argument_extractor::extract_return_value(
    extracted_call_info& call_info,
    const util::safe_memory_reader& memory,
    const call_context& ctx
) const {
    pimpl->extract_return_value(call_info, memory, ctx);
}

extracted_argument argument_extractor::extract_argument(
    const param_info& param,
    uint64_t raw_value,
    const util::safe_memory_reader& memory
) const {
    return pimpl->extract_argument(param, raw_value, memory);
}

std::string argument_extractor::format_call(const extracted_call_info& call) const {
    return pimpl->format_call(call);
}

const extractor_config& argument_extractor::get_config() const {
    return pimpl->get_config();
}

void argument_extractor::set_config(const extractor_config& config) {
    pimpl->set_config(config);
}

// arg_utils implementation
namespace arg_utils {

bool is_valid_pointer(uint64_t addr, const util::safe_memory_reader& memory) {
    if (addr == 0) return false;
    
    // check if readable
    uint8_t test;
    return memory.read(addr, &test, 1) == 1;
}

std::optional<std::string> read_string(
    uint64_t addr, 
    const util::safe_memory_reader& memory,
    size_t max_length
) {
    if (addr == 0) return std::nullopt;
    
    std::string result;
    result.reserve(std::min(max_length, size_t(256)));
    
    for (size_t i = 0; i < max_length; ++i) {
        char ch;
        if (memory.read(addr + i, &ch, 1) != 1) {
            break;
        }
        
        if (ch == '\0') {
            return result;
        }
        
        // only printable chars
        if (ch >= 32 && ch < 127) {
            result += ch;
        } else {
            result += '.';
        }
    }
    
    // didn't find null terminator
    return result.empty() ? std::nullopt : std::optional(result);
}

std::optional<std::string> read_wide_string(
    uint64_t addr,
    const util::safe_memory_reader& memory,
    size_t max_length
) {
    if (addr == 0) return std::nullopt;
    
    std::string result;
    result.reserve(std::min(max_length, size_t(256)));
    
    for (size_t i = 0; i < max_length; ++i) {
        uint16_t wch;
        if (memory.read(addr + i * 2, &wch, 2) != 2) {
            break;
        }
        
        if (wch == 0) {
            return result;
        }
        
        // simple ascii conversion
        if (wch < 127 && wch >= 32) {
            result += static_cast<char>(wch);
        } else {
            result += '.';
        }
    }
    
    return result.empty() ? std::nullopt : std::optional(result);
}

std::string format_pointer(uint64_t addr) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << addr;
    return ss.str();
}

std::vector<std::string> decode_flags(uint32_t flags, const std::string& flag_type) {
    std::vector<std::string> result;
    
    // common file open flags
    if (flag_type == "flags" || flag_type == "openFlags") {
        if (flags & 0x0001) result.push_back("O_RDONLY");
        if (flags & 0x0002) result.push_back("O_WRONLY");
        if (flags & 0x0200) result.push_back("O_CREAT");
        if (flags & 0x0400) result.push_back("O_EXCL");
        if (flags & 0x0800) result.push_back("O_TRUNC");
        if (flags & 0x0008) result.push_back("O_APPEND");
    }
    
    // generic protection flags
    if (flag_type == "prot" || flag_type == "protection") {
        if (flags & 0x1) result.push_back("PROT_READ");
        if (flags & 0x2) result.push_back("PROT_WRITE");
        if (flags & 0x4) result.push_back("PROT_EXEC");
    }
    
    // if no specific decoding, show hex
    if (result.empty() && flags != 0) {
        std::stringstream ss;
        ss << "0x" << std::hex << flags;
        result.push_back(ss.str());
    }
    
    return result;
}

} // namespace arg_utils

} // namespace w1::abi