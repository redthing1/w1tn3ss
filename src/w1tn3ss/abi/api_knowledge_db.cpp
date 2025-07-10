#include "api_knowledge_db.hpp"
#include <redlog.hpp>
#include <unordered_set>
#include <algorithm>
#include <fstream>
#include <w1common/ext/jsonstruct.hpp>

// platform-specific api definitions
#ifdef __APPLE__
#include "apis/macos/system_apis.hpp"
#elif defined(__linux__)
#include "apis/linux/system_apis.hpp"
#elif defined(_WIN32)
#include "apis/windows/system_apis.hpp"
#endif

namespace w1::abi {

// implementation class
class api_knowledge_db::impl {
public:
  impl() : log_("w1.api_knowledge_db") {
    log_.dbg("initializing api knowledge database");
    load_builtin_apis();
    log_.info("loaded builtin apis", redlog::field("count", apis_.size()));
  }

  std::optional<api_info> lookup(const std::string& api_name) const {
    log_.dbg("looking up api", redlog::field("name", api_name));

    // try exact match first
    auto it = apis_.find(api_name);
    if (it != apis_.end()) {
      log_.trace(
          "found api info", redlog::field("name", api_name), redlog::field("module", it->second.module),
          redlog::field("category", static_cast<int>(it->second.api_category)),
          redlog::field("param_count", it->second.parameters.size())
      );
      return it->second;
    }

    // try without underscore prefix (for macos symbols)
    if (!api_name.empty() && api_name[0] == '_') {
      std::string without_underscore = api_name.substr(1);
      it = apis_.find(without_underscore);
      if (it != apis_.end()) {
        log_.dbg(
            "found api info without underscore", redlog::field("original", api_name),
            redlog::field("matched", without_underscore), redlog::field("module", it->second.module),
            redlog::field("param_count", it->second.parameters.size())
        );
        return it->second;
      }
    }

    // try with underscore prefix (for macos symbols)
    std::string with_underscore = "_" + api_name;
    it = apis_.find(with_underscore);
    if (it != apis_.end()) {
      log_.dbg(
          "found api info with underscore", redlog::field("original", api_name),
          redlog::field("matched", with_underscore), redlog::field("module", it->second.module),
          redlog::field("param_count", it->second.parameters.size())
      );
      return it->second;
    }

    log_.dbg("api not found", redlog::field("name", api_name));
    return std::nullopt;
  }

  std::optional<api_info> lookup(const std::string& module, const std::string& api_name) const {
    log_.dbg("looking up api with module", redlog::field("module", module), redlog::field("name", api_name));

    // try exact match first
    auto it = apis_.find(api_name);
    if (it != apis_.end() && it->second.module == module) {
      log_.dbg("found exact match", redlog::field("name", api_name));
      return it->second;
    }

    // try module prefix match (e.g., "libc.so.6" matches "libc.so")
    if (it != apis_.end()) {
      if (it->second.module.find(module) != std::string::npos || module.find(it->second.module) != std::string::npos) {
        log_.dbg(
            "found partial module match", redlog::field("name", api_name),
            redlog::field("actual_module", it->second.module)
        );
        return it->second;
      }
    }

    log_.dbg("api not found for module", redlog::field("module", module), redlog::field("name", api_name));
    return std::nullopt;
  }

  std::vector<std::string> get_apis_by_category(api_info::category category) const {
    log_.dbg("getting apis by category", redlog::field("category", static_cast<int>(category)));

    std::vector<std::string> result;
    for (const auto& [name, info] : apis_) {
      if (info.api_category == category) {
        result.push_back(name);
      }
    }

    log_.dbg(
        "found apis in category", redlog::field("category", static_cast<int>(category)),
        redlog::field("count", result.size())
    );
    return result;
  }

  std::vector<std::string> get_apis_with_flags(uint32_t flags) const {
    log_.dbg("getting apis with flags", redlog::field("flags", flags));

    std::vector<std::string> result;
    for (const auto& [name, info] : apis_) {
      if ((info.flags & flags) == flags) {
        result.push_back(name);
      }
    }

    log_.dbg("found apis with flags", redlog::field("flags", flags), redlog::field("count", result.size()));
    return result;
  }

  bool is_known_api(const std::string& api_name) const {
    bool known = apis_.find(api_name) != apis_.end();
    log_.dbg("checking if api is known", redlog::field("name", api_name), redlog::field("known", known));
    return known;
  }

  std::vector<std::string> get_module_apis(const std::string& module) const {
    log_.dbg("getting apis for module", redlog::field("module", module));

    std::vector<std::string> result;
    for (const auto& [name, info] : apis_) {
      if (info.module == module) {
        result.push_back(name);
      }
    }

    log_.dbg("found module apis", redlog::field("module", module), redlog::field("count", result.size()));
    return result;
  }

  void add_api(const api_info& info) {
    log_.dbg(
        "adding api to knowledge database", redlog::field("name", info.name), redlog::field("module", info.module),
        redlog::field("category", static_cast<int>(info.api_category))
    );

    apis_[info.name] = info;
    modules_.insert(info.module);
  }

  bool load_from_file(const std::string& path) {
    log_.info("loading api definitions from file", redlog::field("path", path));

    try {
      std::ifstream file(path);
      if (!file.is_open()) {
        log_.err("failed to open file", redlog::field("path", path));
        return false;
      }

      // read entire file into string
      std::string json_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

      // todo: parse using jsonstruct - need to define proper structs with js_object macros
      // for now, just log that we need to implement this
      log_.warn("JSON parsing using jsonstruct not yet implemented - need to define JS_OBJECT structs");
      return false;

    } catch (const std::exception& e) {
      log_.err("failed to read api definitions file", redlog::field("path", path), redlog::field("error", e.what()));
      return false;
    }
  }

  size_t get_api_count() const { return apis_.size(); }
  size_t get_module_count() const { return modules_.size(); }

private:
  redlog::logger log_;
  std::unordered_map<std::string, api_info> apis_;
  std::unordered_set<std::string> modules_;

  void load_builtin_apis() {
    log_.dbg("loading builtin apis for platform");

    // load platform-specific apis
#ifdef __APPLE__
    load_api_set(apis::macos::macos_system_apis, "macos system apis");
#elif defined(__linux__)
    load_api_set(apis::linux::linux_system_apis, "linux system apis");
#elif defined(_WIN32)
    auto windows_apis = apis::windows::get_all_windows_apis();
    load_api_set(windows_apis, "windows system apis");
#endif
  }

  void load_api_set(const std::vector<api_info>& api_set, const std::string& set_name) {
    log_.trc("loading api set", redlog::field("name", set_name));

    for (const auto& api : api_set) {
      add_api(api);
    }

    log_.trc("loaded api set", redlog::field("name", set_name), redlog::field("count", api_set.size()));
  }

  // string conversion helpers
  api_info::category string_to_category(const std::string& s) {
    static const std::unordered_map<std::string, api_info::category> map = {
        {"FILE_IO", api_info::category::FILE_IO},
        {"FILE_MANAGEMENT", api_info::category::FILE_MANAGEMENT},
        {"PROCESS_CONTROL", api_info::category::PROCESS_CONTROL},
        {"MEMORY_MANAGEMENT", api_info::category::MEMORY_MANAGEMENT},
        {"HEAP_MANAGEMENT", api_info::category::HEAP_MANAGEMENT},
        {"NETWORK_SOCKET", api_info::category::NETWORK_SOCKET}
        // add more as needed
    };

    auto it = map.find(s);
    return it != map.end() ? it->second : api_info::category::UNKNOWN;
  }

  uint32_t string_to_flag(const std::string& s) {
    static const std::unordered_map<std::string, api_info::behavior_flags> map = {
        {"ALLOCATES_MEMORY", api_info::behavior_flags::ALLOCATES_MEMORY},
        {"FREES_MEMORY", api_info::behavior_flags::FREES_MEMORY},
        {"OPENS_HANDLE", api_info::behavior_flags::OPENS_HANDLE},
        {"CLOSES_HANDLE", api_info::behavior_flags::CLOSES_HANDLE},
        {"BLOCKING", api_info::behavior_flags::BLOCKING},
        {"FILE_IO", api_info::behavior_flags::FILE_IO}
        // add more as needed
    };

    auto it = map.find(s);
    return it != map.end() ? static_cast<uint32_t>(it->second) : 0;
  }

  param_info::type string_to_param_type(const std::string& s) {
    static const std::unordered_map<std::string, param_info::type> map = {
        {"INTEGER", param_info::type::INTEGER}, {"POINTER", param_info::type::POINTER},
        {"SIZE", param_info::type::SIZE},       {"FLAGS", param_info::type::FLAGS},
        {"HANDLE", param_info::type::HANDLE},   {"FILE_DESCRIPTOR", param_info::type::FILE_DESCRIPTOR},
        {"STRING", param_info::type::STRING},   {"BUFFER", param_info::type::BUFFER},
        {"PATH", param_info::type::PATH}
        // add more as needed
    };

    auto it = map.find(s);
    return it != map.end() ? it->second : param_info::type::UNKNOWN;
  }

  param_info::direction string_to_direction(const std::string& s) {
    if (s == "OUT") {
      return param_info::direction::OUT;
    }
    if (s == "IN_OUT") {
      return param_info::direction::IN_OUT;
    }
    return param_info::direction::IN;
  }
};

// api_knowledge_db implementation
api_knowledge_db::api_knowledge_db() : pimpl(std::make_unique<impl>()) {}
api_knowledge_db::~api_knowledge_db() = default;

std::optional<api_info> api_knowledge_db::lookup(const std::string& api_name) const { return pimpl->lookup(api_name); }

std::optional<api_info> api_knowledge_db::lookup(const std::string& module, const std::string& api_name) const {
  return pimpl->lookup(module, api_name);
}

std::vector<std::string> api_knowledge_db::get_apis_by_category(api_info::category category) const {
  return pimpl->get_apis_by_category(category);
}

std::vector<std::string> api_knowledge_db::get_apis_with_flags(uint32_t flags) const {
  return pimpl->get_apis_with_flags(flags);
}

bool api_knowledge_db::is_known_api(const std::string& api_name) const { return pimpl->is_known_api(api_name); }

std::vector<std::string> api_knowledge_db::get_module_apis(const std::string& module) const {
  return pimpl->get_module_apis(module);
}

void api_knowledge_db::add_api(const api_info& info) { pimpl->add_api(info); }

bool api_knowledge_db::load_from_file(const std::string& path) { return pimpl->load_from_file(path); }

size_t api_knowledge_db::get_api_count() const { return pimpl->get_api_count(); }

size_t api_knowledge_db::get_module_count() const { return pimpl->get_module_count(); }

// helper functions
param_info::type infer_param_type(const std::string& param_name, const std::string& type_name) {
  // infer based on common naming patterns
  std::string lower_name = param_name;
  std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

  if (lower_name.find("path") != std::string::npos || lower_name.find("file") != std::string::npos) {
    return param_info::type::PATH;
  }

  if (lower_name.find("size") != std::string::npos || lower_name.find("len") != std::string::npos ||
      lower_name.find("count") != std::string::npos) {
    return param_info::type::SIZE;
  }

  if (lower_name.find("flags") != std::string::npos || lower_name.find("mode") != std::string::npos) {
    return param_info::type::FLAGS;
  }

  if (lower_name.find("handle") != std::string::npos || lower_name == "h" ||
      lower_name.find("hwnd") != std::string::npos) {
    return param_info::type::HANDLE;
  }

  if (lower_name == "fd" || lower_name.find("descriptor") != std::string::npos) {
    return param_info::type::FILE_DESCRIPTOR;
  }

  if (lower_name.find("buffer") != std::string::npos || lower_name.find("buf") != std::string::npos ||
      lower_name.find("data") != std::string::npos) {
    return param_info::type::BUFFER;
  }

  if (lower_name.find("str") != std::string::npos || lower_name.find("name") != std::string::npos ||
      lower_name.find("text") != std::string::npos) {
    return param_info::type::STRING;
  }

  // check type name hints
  std::string lower_type = type_name;
  std::transform(lower_type.begin(), lower_type.end(), lower_type.begin(), ::tolower);

  if (lower_type.find("char*") != std::string::npos || lower_type.find("wchar*") != std::string::npos) {
    return param_info::type::STRING;
  }

  if (lower_type.find("void*") != std::string::npos || lower_type.find("ptr") != std::string::npos) {
    return param_info::type::POINTER;
  }

  if (lower_type.find("int") != std::string::npos || lower_type.find("long") != std::string::npos ||
      lower_type.find("dword") != std::string::npos) {
    return param_info::type::INTEGER;
  }

  return param_info::type::UNKNOWN;
}

std::string format_api_signature(const api_info& info) {
  std::string sig = info.return_value.name + " " + info.name + "(";

  for (size_t i = 0; i < info.parameters.size(); ++i) {
    if (i > 0) {
      sig += ", ";
    }

    const auto& param = info.parameters[i];
    sig += param.name;

    if (param.param_direction == param_info::direction::OUT) {
      sig += " [out]";
    } else if (param.param_direction == param_info::direction::IN_OUT) {
      sig += " [in,out]";
    }

    if (param.is_optional) {
      sig += " [opt]";
    }
  }

  sig += ")";
  return sig;
}

} // namespace w1::abi
