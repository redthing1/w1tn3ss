#include "api_analyzer.hpp"
#include <redlog.hpp>
#include <sstream>
#include <iomanip>

namespace w1::abi {

class api_analyzer::impl {
public:
  impl(const analyzer_config& config)
      : config_(config), log_("w1.api_analyzer"), api_db_(std::make_shared<api_knowledge_db>()),
        detector_(std::make_shared<calling_convention_detector>()), argument_extractor_(api_db_, detector_) {

#ifdef WITNESS_LIEF_ENABLED
    if (config_.resolve_symbols) {
      lief::symbol_resolver::config lief_cfg;
      lief_cfg.max_cache_size = 50;
      lief_cfg.prepopulate_exports = true;
      symbol_resolver_ = std::make_unique<lief::symbol_resolver>(lief_cfg);
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
      // step 1: identify module containing the target address
      auto module = module_index_->find_containing(ctx.target_address);
      if (!module) {
        result.error_message = "No module found for target address";
        return result;
      }

      result.module_name = module->name;
      result.module_offset = ctx.target_address - module->base_address;

      // step 2: use symbol from context if available, otherwise resolve
      if (!ctx.symbol_name.empty()) {
        result.symbol_name = ctx.symbol_name;
        // note: demangled_name would need to be passed in context if needed
        log_.dbg("using symbol from context", redlog::field("symbol", result.symbol_name));
      } else if (config_.resolve_symbols) {
        resolve_symbol(result, ctx.target_address, *module);
      }

      // step 3: api identification and knowledge lookup
      if (!result.symbol_name.empty()) {
        log_.dbg("looking up api in knowledge db", redlog::field("symbol", result.symbol_name));

        if (auto api_info = api_db_->lookup(result.symbol_name)) {
          result.category = api_info->api_category;
          result.behavior_flags = api_info->flags;
          result.description = api_info->description;
          result.found_in_knowledge_db = true;
          stats_.apis_identified++;

          log_.dbg(
              "found api in knowledge db", redlog::field("symbol", result.symbol_name),
              redlog::field("category", static_cast<int>(api_info->api_category)),
              redlog::field("param_count", api_info->parameters.size()),
              redlog::field("extract_args", config_.extract_arguments)
          );

          // step 4: argument extraction
          if (config_.extract_arguments && !api_info->parameters.empty()) {
            log_.ped(
                "extracting arguments", redlog::field("symbol", result.symbol_name),
                redlog::field("param_count", api_info->parameters.size())
            );
            extract_arguments(result, ctx, *api_info);
          } else if (config_.extract_arguments && api_info->parameters.empty()) {
            log_.dbg("no parameters defined for api", redlog::field("symbol", result.symbol_name));
          }
        } else {
          log_.dbg("api not found in knowledge db", redlog::field("symbol", result.symbol_name));
          result.found_in_knowledge_db = false;
        }
      }

      // step 5: format the call
      if (config_.format_calls) {
        format_call(result);
      }

      result.analysis_complete = true;

      // log completed api analysis with formatted call details
      if (!result.symbol_name.empty() && config_.format_calls) {
        // build a concise argument summary with truncation for display
        std::stringstream arg_summary;
        for (size_t i = 0; i < result.arguments.size(); ++i) {
          if (i > 0) {
            arg_summary << ", ";
          }
          const auto& arg = result.arguments[i];

          // add parameter name if known
          if (!arg.param_name.empty()) {
            arg_summary << arg.param_name << "=";
          }

          // format value based on type with truncation
          if (arg.param_type == param_info::type::STRING && !arg.string_preview.empty()) {
            // truncate long strings for display
            std::string preview = arg.string_preview;
            if (preview.length() > 50) {
              preview = preview.substr(0, 47) + "...";
            }
            arg_summary << "\"" << preview << "\"";
          } else if (arg.is_null_pointer) {
            arg_summary << "NULL";
          } else if (arg.param_type == param_info::type::POINTER) {
            arg_summary << "0x" << std::hex << arg.raw_value;
          } else if (arg.param_type == param_info::type::BOOLEAN) {
            arg_summary << (arg.raw_value ? "true" : "false");
          } else {
            arg_summary << arg.raw_value;
          }

          // limit total length to prevent excessive output
          if (arg_summary.str().length() > 200) {
            arg_summary << ", ...";
            break;
          }
        }

        // format category name for display
        std::string category_name;
        if (result.category != api_info::category::UNKNOWN) {
          switch (result.category) {
          case api_info::category::FILE_IO:
          case api_info::category::FILE_MANAGEMENT:
            category_name = "File";
            break;
          case api_info::category::STDIO:
            category_name = "I/O";
            break;
          case api_info::category::DEVICE_IO:
            category_name = "Device";
            break;
          case api_info::category::PROCESS_CONTROL:
            category_name = "Process";
            break;
          case api_info::category::THREAD_CONTROL:
          case api_info::category::THREADING:
            category_name = "Threading";
            break;
          case api_info::category::MEMORY_MANAGEMENT:
            category_name = "Memory";
            break;
          case api_info::category::HEAP_MANAGEMENT:
            category_name = "Heap";
            break;
          case api_info::category::SYNCHRONIZATION:
          case api_info::category::MUTEX:
          case api_info::category::EVENT:
          case api_info::category::SEMAPHORE:
            category_name = "Sync";
            break;
          case api_info::category::NETWORK_SOCKET:
          case api_info::category::NETWORK_DNS:
          case api_info::category::NETWORK_HTTP:
            category_name = "Network";
            break;
          case api_info::category::REGISTRY:
            category_name = "Registry";
            break;
          case api_info::category::SECURITY:
            category_name = "Security";
            break;
          case api_info::category::CRYPTO:
            category_name = "Crypto";
            break;
          case api_info::category::SYSTEM_INFO:
            category_name = "System";
            break;
          case api_info::category::TIME:
            category_name = "Time";
            break;
          case api_info::category::ENVIRONMENT:
            category_name = "Environment";
            break;
          case api_info::category::STRING_MANIPULATION:
            category_name = "String";
            break;
          case api_info::category::LOCALE:
            category_name = "Locale";
            break;
          case api_info::category::LIBRARY_LOADING:
            category_name = "Library";
            break;
          case api_info::category::MATH:
            category_name = "Math";
            break;
          case api_info::category::SORTING:
            category_name = "Sorting";
            break;
          case api_info::category::IPC:
          case api_info::category::PIPE:
          case api_info::category::SHARED_MEMORY:
            category_name = "IPC";
            break;
          case api_info::category::UI:
          case api_info::category::WINDOW:
            category_name = "UI";
            break;
          case api_info::category::SYSTEM_HOOK:
            category_name = "Hook";
            break;
          case api_info::category::MISC:
          default:
            category_name = "Other";
            break;
          }
        }

        log_.vrb(
            "analyzed api call", redlog::field("call", result.formatted_call), redlog::field("category", category_name),
            redlog::field("module", result.module_name)
        );
      }

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
      // extract return value based on api info
      if (auto api_info = api_db_->lookup(result.symbol_name)) {
        // detect calling convention for return value extraction
        auto convention = detector_->detect(result.module_name, result.symbol_name);
        uint64_t ret_val = convention->get_integer_return(ctx.gpr_state);

        // create safe memory reader for return value extraction
        util::safe_memory::memory_validator().refresh();

        result.return_value =
            argument_extractor_.extract_argument(api_info->return_value, ret_val, util::safe_memory_reader{ctx.vm});

        // log return value analysis with formatted output
        if (api_info->return_value.param_type != param_info::type::VOID) {
          std::string return_str;

          // format return value based on type for display
          if (!result.return_value.string_preview.empty()) {
            return_str = "\"" + result.return_value.string_preview + "\"";
          } else if (result.return_value.is_null_pointer) {
            return_str = "NULL";
          } else if (result.return_value.param_type == param_info::type::BOOLEAN) {
            return_str = result.return_value.raw_value ? "true" : "false";
          } else if (result.return_value.param_type == param_info::type::ERROR_CODE) {
            std::stringstream ss;
            ss << "0x" << std::hex << result.return_value.raw_value << " ("
               << static_cast<int64_t>(result.return_value.raw_value) << ")";
            return_str = ss.str();
          } else if (result.return_value.param_type == param_info::type::POINTER) {
            std::stringstream ss;
            ss << "0x" << std::hex << result.return_value.raw_value;
            return_str = ss.str();
          } else {
            return_str = std::to_string(static_cast<int64_t>(result.return_value.raw_value));
          }

          // build formatted return string and log it
          std::string formatted_return = result.symbol_name + "() = " + return_str;

          log_.vrb(
              "analyzed api return", redlog::field("return", formatted_return),
              redlog::field("raw_value", result.return_value.raw_value), redlog::field("module", result.module_name)
          );
        }
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
    // fallback: use module name + offset when lief is not available
    std::stringstream ss;
    ss << module.name << "+0x" << std::hex << result.module_offset;
    result.symbol_name = ss.str();
#endif
  }

  void extract_arguments(api_analysis_result& result, const api_context& ctx, const api_info& api) {
    // extract raw argument values from registers/stack
    size_t arg_count = std::min(api.parameters.size(), config_.max_arguments);
    log_.ped("extracting raw argument values", redlog::field("count", arg_count));

    // detect calling convention and extract args
    auto convention = detector_->detect(result.module_name, result.symbol_name);
    calling_convention_base::extraction_context extract_ctx{
        ctx.gpr_state, ctx.fpr_state, [&ctx](uint64_t addr) -> uint64_t {
          // use safe_memory for validated reads
          auto value = util::safe_memory::read<uint64_t>(ctx.vm, addr);
          return value.value_or(0);
        }
    };
    auto raw_args = convention->extract_integer_args(extract_ctx, arg_count);

    log_.ped("extracted raw args", redlog::field("count", raw_args.size()));

    // create safe memory reader for argument extraction
    util::safe_memory::memory_validator().refresh();
    util::safe_memory_reader memory{ctx.vm};

    // extract and interpret each argument with semantic meaning
    for (size_t i = 0; i < raw_args.size() && i < api.parameters.size(); ++i) {
      log_.ped(
          "extracting argument", redlog::field("index", i), redlog::field("param_name", api.parameters[i].name),
          redlog::field("raw_value", raw_args[i]), redlog::field("type", static_cast<int>(api.parameters[i].param_type))
      );

      auto arg = argument_extractor_.extract_argument(api.parameters[i], raw_args[i], memory);

      log_.ped(
          "extracted argument", redlog::field("index", i), redlog::field("param_name", arg.param_name),
          redlog::field("raw_value", arg.raw_value), redlog::field("string_preview", arg.string_preview),
          redlog::field("is_pointer", arg.is_valid_pointer)
      );

      result.arguments.push_back(arg);
      stats_.arguments_extracted++;
    }

    log_.ped("argument extraction complete", redlog::field("extracted_count", result.arguments.size()));
  }

  void format_call(api_analysis_result& result) {
    std::stringstream ss;

    // use demangled name if available, otherwise symbol name
    std::string name = !result.demangled_name.empty() ? result.demangled_name : result.symbol_name;
    if (name.empty()) {
      ss << result.module_name << "+0x" << std::hex << result.module_offset;
    } else {
      ss << name;
    }

    ss << "(";

    // distinguish between:
    // 1. api not found in knowledge db (unknown args) -> show "?"
    // 2. api found with no parameters -> show "()"
    // 3. api found with parameters -> show formatted args
    if (!result.found_in_knowledge_db && !result.symbol_name.empty()) {
      // api not in knowledge db - arguments unknown
      ss << "?";
    } else if (result.arguments.empty()) {
      // either api has no parameters or we're not extracting args
      // empty parentheses is correct here
    } else {
      // format arguments with semantic information
      for (size_t i = 0; i < result.arguments.size(); ++i) {
        if (i > 0) {
          ss << ", ";
        }

        const auto& arg = result.arguments[i];

        // add parameter name if known
        if (!arg.param_name.empty()) {
          ss << arg.param_name << "=";
        }

        // format value based on type
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
  std::unique_ptr<lief::symbol_resolver> symbol_resolver_;
#endif

  mutable stats stats_;
};

// public interface implementation

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

// helper functions implementation

namespace analysis_utils {

bool is_api_call(uint64_t address, const util::module_range_index& modules) {
  auto module = modules.find_containing(address);
  if (!module) {
    return false;
  }

  // check if it's a system library
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