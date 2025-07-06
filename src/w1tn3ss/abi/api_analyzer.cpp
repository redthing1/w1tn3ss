#include "api_analyzer.hpp"
#include <redlog.hpp>
#include <sstream>
#include <iomanip>

namespace w1::abi {

class api_analyzer::impl {
public:
  impl(const analyzer_config& config)
      : config_(config), log_("w1::abi::api_analyzer"), api_db_(std::make_shared<api_knowledge_db>()),
        detector_(std::make_shared<calling_convention_detector>()), argument_extractor_(api_db_, detector_) {

#ifdef WITNESS_LIEF_ENABLED
    if (config_.resolve_symbols) {
      lief::lief_symbol_resolver::config lief_cfg;
      lief_cfg.max_cache_size = 50;
      lief_cfg.prepopulate_exports = true;
      symbol_resolver_ = std::make_unique<lief::lief_symbol_resolver>(lief_cfg);
    }
#endif
  }

  void initialize(const util::module_range_index& module_index) {
    module_index_ = &module_index;
    log_.dbg("initialized with module index", redlog::field("module_count", module_index.size()));
  }

  api_analysis_result analyze_call(const api_context& ctx) {
    api_analysis_result result;
    stats_.calls_analyzed++;

    try {
      // Step 1: Module identification
      auto module = module_index_->find_containing(ctx.target_address);
      if (!module) {
        result.error_message = "No module found for target address";
        return result;
      }

      result.module_name = module->name;
      result.module_offset = ctx.target_address - module->base_address;

      // Step 2: Symbol resolution
      if (config_.resolve_symbols) {
        resolve_symbol(result, ctx.target_address, *module);
      }

      // Step 3: API identification and knowledge lookup
      if (!result.symbol_name.empty()) {
        log_.dbg("looking up api in knowledge db", redlog::field("symbol", result.symbol_name));

        if (auto api_info = api_db_->lookup(result.symbol_name)) {
          result.category = api_info->api_category;
          result.behavior_flags = api_info->flags;
          result.description = api_info->description;
          stats_.apis_identified++;

          log_.dbg(
              "found api in knowledge db", redlog::field("symbol", result.symbol_name),
              redlog::field("category", static_cast<int>(api_info->api_category)),
              redlog::field("param_count", api_info->parameters.size()),
              redlog::field("extract_args", config_.extract_arguments)
          );

          // Step 4: Argument extraction
          if (config_.extract_arguments && !api_info->parameters.empty()) {
            log_.dbg(
                "extracting arguments", redlog::field("symbol", result.symbol_name),
                redlog::field("param_count", api_info->parameters.size())
            );
            extract_arguments(result, ctx, *api_info);
          } else if (config_.extract_arguments && api_info->parameters.empty()) {
            log_.dbg("no parameters defined for api", redlog::field("symbol", result.symbol_name));
          }
        } else {
          log_.dbg("api not found in knowledge db", redlog::field("symbol", result.symbol_name));
        }
      }

      // Step 5: Format the call
      if (config_.format_calls) {
        format_call(result);
      }

      result.analysis_complete = true;

    } catch (const std::exception& e) {
      log_.err("analysis failed", redlog::field("error", e.what()));
      result.error_message = e.what();
      stats_.errors++;
    }

    return result;
  }

  void analyze_return(api_analysis_result& result, const api_context& ctx) {
    if (!result.analysis_complete) {
      return;
    }

    try {
      // Extract return value based on API info
      if (auto api_info = api_db_->lookup(result.symbol_name)) {
        // Detect calling convention
        auto convention = detector_->detect(result.module_name, result.symbol_name);
        uint64_t ret_val = convention->get_integer_return(ctx.gpr_state);

        // Create safe memory reader
        util::safe_memory::memory_validator().refresh();

        result.return_value =
            argument_extractor_.extract_argument(api_info->return_value, ret_val, util::safe_memory_reader{ctx.vm});
      }
    } catch (const std::exception& e) {
      log_.err("return analysis failed", redlog::field("error", e.what()));
    }
  }

  const api_knowledge_db& get_api_db() const { return *api_db_; }

  stats get_stats() const { return stats_; }

  void clear_caches() {
#ifdef WITNESS_LIEF_ENABLED
    if (symbol_resolver_) {
      symbol_resolver_->clear_cache();
    }
#endif
  }

private:
  void resolve_symbol(api_analysis_result& result, uint64_t address, const util::module_info& module) {
#ifdef WITNESS_LIEF_ENABLED
    if (!symbol_resolver_) {
      return;
    }

    if (auto symbol = symbol_resolver_->resolve_in_module(module.path, result.module_offset)) {
      result.symbol_name = symbol->name;
      result.demangled_name = symbol->demangled_name;
      stats_.symbols_resolved++;

      log_.dbg(
          "resolved symbol", redlog::field("address", address), redlog::field("symbol", symbol->name),
          redlog::field("demangled", symbol->demangled_name)
      );
    }
#else
    // Fallback: use module name + offset
    std::stringstream ss;
    ss << module.name << "+0x" << std::hex << result.module_offset;
    result.symbol_name = ss.str();
#endif
  }

  void extract_arguments(api_analysis_result& result, const api_context& ctx, const api_info& api) {
    // Extract raw argument values
    size_t arg_count = std::min(api.parameters.size(), config_.max_arguments);
    log_.dbg("extracting raw argument values", redlog::field("count", arg_count));

    // Detect calling convention and extract args
    auto convention = detector_->detect(result.module_name, result.symbol_name);
    calling_convention_base::extraction_context extract_ctx{
        ctx.gpr_state, ctx.fpr_state, [&ctx](uint64_t addr) -> uint64_t {
          // use safe_memory for validated reads
          auto value = util::safe_memory::read<uint64_t>(ctx.vm, addr);
          return value.value_or(0);
        }
    };
    auto raw_args = convention->extract_integer_args(extract_ctx, arg_count);

    log_.dbg("extracted raw args", redlog::field("count", raw_args.size()));

    // Create safe memory reader
    util::safe_memory::memory_validator().refresh();
    util::safe_memory_reader memory{ctx.vm};

    // Extract and interpret each argument
    for (size_t i = 0; i < raw_args.size() && i < api.parameters.size(); ++i) {
      log_.dbg(
          "extracting argument", redlog::field("index", i), redlog::field("param_name", api.parameters[i].name),
          redlog::field("raw_value", raw_args[i]), redlog::field("type", static_cast<int>(api.parameters[i].param_type))
      );

      auto arg = argument_extractor_.extract_argument(api.parameters[i], raw_args[i], memory);

      log_.dbg(
          "extracted argument", redlog::field("index", i), redlog::field("param_name", arg.param_name),
          redlog::field("raw_value", arg.raw_value), redlog::field("string_preview", arg.string_preview),
          redlog::field("is_pointer", arg.is_valid_pointer)
      );

      result.arguments.push_back(arg);
      stats_.arguments_extracted++;
    }

    log_.dbg("argument extraction complete", redlog::field("extracted_count", result.arguments.size()));
  }

  void format_call(api_analysis_result& result) {
    std::stringstream ss;

    // Use demangled name if available, otherwise symbol name
    std::string name = !result.demangled_name.empty() ? result.demangled_name : result.symbol_name;
    if (name.empty()) {
      ss << result.module_name << "+0x" << std::hex << result.module_offset;
    } else {
      ss << name;
    }

    ss << "(";

    // Format arguments
    for (size_t i = 0; i < result.arguments.size(); ++i) {
      if (i > 0) {
        ss << ", ";
      }

      const auto& arg = result.arguments[i];

      // Add parameter name if known
      if (!arg.param_name.empty()) {
        ss << arg.param_name << "=";
      }

      // Format value based on type
      switch (arg.param_type) {
      case param_info::type::STRING:
        if (!arg.string_preview.empty()) {
          ss << "\"" << arg.string_preview << "\"";
        } else if (arg.is_null_pointer) {
          ss << "NULL";
        } else {
          ss << "0x" << std::hex << arg.raw_value;
        }
        break;

      case param_info::type::POINTER:
        if (arg.is_null_pointer) {
          ss << "NULL";
        } else {
          ss << "0x" << std::hex << arg.raw_value;
        }
        break;

      case param_info::type::BOOLEAN:
        ss << (arg.raw_value ? "true" : "false");
        break;

      case param_info::type::FLAGS:
        ss << "0x" << std::hex << arg.raw_value;
        if (!arg.flag_names.empty()) {
          ss << " [";
          for (size_t j = 0; j < arg.flag_names.size(); ++j) {
            if (j > 0) {
              ss << "|";
            }
            ss << arg.flag_names[j];
          }
          ss << "]";
        }
        break;

      case param_info::type::SIZE:
      case param_info::type::COUNT:
        ss << std::dec << arg.raw_value;
        break;

      default:
        if (arg.param_type == param_info::type::INTEGER || arg.raw_value < 1000) {
          ss << std::dec << static_cast<int64_t>(arg.raw_value);
        } else {
          ss << "0x" << std::hex << arg.raw_value;
        }
        break;
      }
    }

    ss << ")";

    result.formatted_call = ss.str();
  }

private:
  analyzer_config config_;
  redlog::logger log_;

  const util::module_range_index* module_index_ = nullptr;
  std::shared_ptr<api_knowledge_db> api_db_;
  std::shared_ptr<calling_convention_detector> detector_;
  argument_extractor argument_extractor_;

#ifdef WITNESS_LIEF_ENABLED
  std::unique_ptr<lief::lief_symbol_resolver> symbol_resolver_;
#endif

  mutable stats stats_;
};

// Public interface implementation

api_analyzer::api_analyzer(const analyzer_config& config) : pimpl(std::make_unique<impl>(config)) {}

api_analyzer::~api_analyzer() = default;

void api_analyzer::initialize(const util::module_range_index& module_index) { pimpl->initialize(module_index); }

api_analysis_result api_analyzer::analyze_call(const api_context& ctx) { return pimpl->analyze_call(ctx); }

void api_analyzer::analyze_return(api_analysis_result& result, const api_context& ctx) {
  pimpl->analyze_return(result, ctx);
}

const api_knowledge_db& api_analyzer::get_api_db() const { return pimpl->get_api_db(); }

api_analyzer::stats api_analyzer::get_stats() const { return pimpl->get_stats(); }

void api_analyzer::clear_caches() { pimpl->clear_caches(); }

// Helper functions implementation

namespace analysis_utils {

bool is_api_call(uint64_t address, const util::module_range_index& modules) {
  auto module = modules.find_containing(address);
  if (!module) {
    return false;
  }

  // Check if it's a system library
  return module->is_system_library;
}

std::string format_api_call(const std::string& api_name, const std::vector<extracted_argument>& args) {
  std::stringstream ss;
  ss << api_name << "(";

  for (size_t i = 0; i < args.size(); ++i) {
    if (i > 0) {
      ss << ", ";
    }
    ss << "0x" << std::hex << args[i].raw_value;
  }

  ss << ")";
  return ss.str();
}

std::string describe_api_behavior(const api_info& info) {
  std::vector<std::string> behaviors;

  if (has_flag(info, api_info::behavior_flags::ALLOCATES_MEMORY)) {
    behaviors.push_back("allocates memory");
  }
  if (has_flag(info, api_info::behavior_flags::OPENS_HANDLE)) {
    behaviors.push_back("opens handle");
  }
  if (has_flag(info, api_info::behavior_flags::NETWORK_IO)) {
    behaviors.push_back("network I/O");
  }
  if (has_flag(info, api_info::behavior_flags::FILE_IO)) {
    behaviors.push_back("file I/O");
  }
  if (has_flag(info, api_info::behavior_flags::SECURITY_SENSITIVE)) {
    behaviors.push_back("security-sensitive");
  }

  if (behaviors.empty()) {
    return info.description;
  }

  std::stringstream ss;
  for (size_t i = 0; i < behaviors.size(); ++i) {
    if (i > 0) {
      ss << ", ";
    }
    ss << behaviors[i];
  }

  return ss.str();
}

} // namespace analysis_utils

} // namespace w1::abi