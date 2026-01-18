#include <nanobind/nanobind.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include <Python.h>

#include "p1ll.hpp"

#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace nb = nanobind;

namespace {

using p1ll::engine::apply_options;
using p1ll::engine::apply_report;
using p1ll::engine::error_code;
using p1ll::engine::memory_protection;
using p1ll::engine::memory_region;
using p1ll::engine::patch_spec;
using p1ll::engine::plan_entry;
using p1ll::engine::recipe;
using p1ll::engine::result;
using p1ll::engine::scan_filter;
using p1ll::engine::scan_options;
using p1ll::engine::scan_result;
using p1ll::engine::session;
using p1ll::engine::signature_spec;
using p1ll::engine::status;
using p1ll::engine::platform::platform_key;

struct engine_error : public std::runtime_error {
  error_code code = error_code::internal_error;
  std::string message;

  explicit engine_error(status st) : std::runtime_error(st.message), code(st.code), message(std::move(st.message)) {}
};

void raise_engine_error(const status& st) { throw engine_error(st); }

template <typename T> T unwrap(result<T> res) {
  if (!res.ok()) {
    throw engine_error(res.status_info);
  }
  return std::move(res.value);
}

std::vector<uint8_t> buffer_to_vector(nb::handle data) {
  Py_buffer view{};
  if (PyObject_GetBuffer(data.ptr(), &view, PyBUF_SIMPLE) != 0) {
    throw nb::type_error("expected a bytes-like object");
  }

  auto* bytes = static_cast<const uint8_t*>(view.buf);
  std::vector<uint8_t> out(bytes, bytes + static_cast<size_t>(view.len));
  PyBuffer_Release(&view);
  return out;
}

struct py_session {
  std::unique_ptr<session> session_impl;
  std::vector<uint8_t> buffer;
  bool is_buffer = false;

  static py_session for_process() {
    py_session wrapper;
    wrapper.session_impl = std::make_unique<session>(session::for_process());
    wrapper.is_buffer = false;
    return wrapper;
  }

  static py_session for_buffer(nb::handle data, std::optional<std::string> platform_override) {
    py_session wrapper;
    wrapper.buffer = buffer_to_vector(data);
    if (platform_override.has_value()) {
      auto parsed = p1ll::engine::platform::parse_platform(*platform_override);
      if (!parsed.ok()) {
        raise_engine_error(parsed.status_info);
      }
      wrapper.session_impl = std::make_unique<session>(session::for_buffer(wrapper.buffer, parsed.value));
    } else {
      wrapper.session_impl = std::make_unique<session>(session::for_buffer(wrapper.buffer));
    }
    wrapper.is_buffer = true;
    return wrapper;
  }

  platform_key platform_key_value() const { return session_impl->platform_key(); }

  std::vector<memory_region> regions(const scan_filter& filter) const { return unwrap(session_impl->regions(filter)); }

  std::vector<scan_result> scan(const std::string& pattern, const scan_options& options) const {
    return unwrap(session_impl->scan(pattern, options));
  }

  std::vector<plan_entry> plan(const recipe& recipe) const { return unwrap(session_impl->plan(recipe)); }

  apply_report apply(const std::vector<plan_entry>& plan, const apply_options& options) {
    return unwrap(session_impl->apply(plan, options));
  }

  nb::bytes buffer_bytes() const {
    if (!is_buffer) {
      raise_engine_error(
          p1ll::engine::make_status(error_code::invalid_context, "buffer_bytes only valid for buffer sessions")
      );
    }
    if (buffer.empty()) {
      return nb::bytes("", 0);
    }
    return nb::bytes(buffer.data(), buffer.size());
  }
};

} // namespace

NB_MODULE(_p1ll, m) {
  nb::object engine_error_type =
      nb::steal<nb::object>(PyErr_NewException("p1ll.EngineError", PyExc_RuntimeError, nullptr));
  m.attr("EngineError") = engine_error_type;

  nb::register_exception_translator(
      [](const std::exception_ptr& p, void* payload) {
        try {
          std::rethrow_exception(p);
        } catch (const engine_error& e) {
          auto* type = static_cast<PyObject*>(payload);
          nb::object exc = nb::steal<nb::object>(PyObject_CallFunction(type, "s", e.message.c_str()));
          if (!exc.is_valid()) {
            return;
          }
          exc.attr("code") = nb::cast(e.code);
          exc.attr("message") = nb::str(e.message.c_str(), e.message.size());
          PyErr_SetObject(type, exc.ptr());
        }
      },
      engine_error_type.ptr()
  );

  auto error_code_enum = nb::enum_<error_code>(m, "ErrorCode", nb::is_arithmetic());
  error_code_enum.value("ok", error_code::ok)
      .value("invalid_argument", error_code::invalid_argument)
      .value("invalid_pattern", error_code::invalid_pattern)
      .value("not_found", error_code::not_found)
      .value("multiple_matches", error_code::multiple_matches)
      .value("io_error", error_code::io_error)
      .value("protection_error", error_code::protection_error)
      .value("verification_failed", error_code::verification_failed)
      .value("platform_mismatch", error_code::platform_mismatch)
      .value("overlap", error_code::overlap)
      .value("unsupported", error_code::unsupported)
      .value("invalid_context", error_code::invalid_context)
      .value("internal_error", error_code::internal_error);

  nb::class_<status>(m, "Status")
      .def(nb::init<>())
      .def_rw("code", &status::code)
      .def_rw("message", &status::message)
      .def("ok", &status::ok)
      .def("__repr__", [](const status& st) {
        return "Status(code=" + std::to_string(static_cast<int>(st.code)) + ", message='" + st.message + "')";
      });

  nb::enum_<memory_protection>(m, "MemoryProtection", nb::is_arithmetic())
      .value("none", memory_protection::none)
      .value("read", memory_protection::read)
      .value("write", memory_protection::write)
      .value("execute", memory_protection::execute)
      .value("read_write", memory_protection::read_write)
      .value("read_execute", memory_protection::read_execute)
      .value("read_write_execute", memory_protection::read_write_execute);

  nb::class_<memory_region>(m, "MemoryRegion")
      .def(nb::init<>())
      .def_rw("base_address", &memory_region::base_address)
      .def_rw("size", &memory_region::size)
      .def_rw("protection", &memory_region::protection)
      .def_rw("name", &memory_region::name)
      .def_rw("is_executable", &memory_region::is_executable)
      .def_rw("is_system", &memory_region::is_system);

  nb::class_<scan_filter>(m, "ScanFilter")
      .def(nb::init<>())
      .def_rw("name_regex", &scan_filter::name_regex)
      .def_rw("only_executable", &scan_filter::only_executable)
      .def_rw("exclude_system", &scan_filter::exclude_system)
      .def_rw("min_size", &scan_filter::min_size)
      .def_rw("min_address", &scan_filter::min_address)
      .def_rw("max_address", &scan_filter::max_address);

  nb::class_<scan_options>(m, "ScanOptions")
      .def(nb::init<>())
      .def_rw("filter", &scan_options::filter)
      .def_rw("single", &scan_options::single)
      .def_rw("max_matches", &scan_options::max_matches);

  nb::class_<scan_result>(m, "ScanResult")
      .def(nb::init<>())
      .def_rw("address", &scan_result::address)
      .def_rw("region_name", &scan_result::region_name);

  nb::class_<signature_spec>(m, "SignatureSpec")
      .def(nb::init<>())
      .def_rw("pattern", &signature_spec::pattern)
      .def_rw("options", &signature_spec::options)
      .def_rw("platforms", &signature_spec::platforms)
      .def_rw("required", &signature_spec::required);

  nb::class_<patch_spec>(m, "PatchSpec")
      .def(nb::init<>())
      .def_rw("signature", &patch_spec::signature)
      .def_rw("offset", &patch_spec::offset)
      .def_rw("patch", &patch_spec::patch)
      .def_rw("platforms", &patch_spec::platforms)
      .def_rw("required", &patch_spec::required);

  nb::class_<recipe>(m, "Recipe")
      .def(nb::init<>())
      .def_rw("name", &recipe::name)
      .def_rw("platforms", &recipe::platforms)
      .def_rw("validations", &recipe::validations)
      .def_rw("patches", &recipe::patches);

  nb::class_<plan_entry>(m, "PlanEntry")
      .def(nb::init<>())
      .def_rw("spec", &plan_entry::spec)
      .def_rw("address", &plan_entry::address)
      .def_rw("patch_bytes", &plan_entry::patch_bytes)
      .def_rw("patch_mask", &plan_entry::patch_mask);

  nb::class_<apply_options>(m, "ApplyOptions")
      .def(nb::init<>())
      .def_rw("verify", &apply_options::verify)
      .def_rw("flush_icache", &apply_options::flush_icache)
      .def_rw("rollback_on_failure", &apply_options::rollback_on_failure)
      .def_rw("allow_wx", &apply_options::allow_wx);

  nb::class_<apply_report>(m, "ApplyReport")
      .def(nb::init<>())
      .def_rw("success", &apply_report::success)
      .def_rw("applied", &apply_report::applied)
      .def_rw("failed", &apply_report::failed)
      .def_rw("diagnostics", &apply_report::diagnostics);

  nb::class_<platform_key>(m, "PlatformKey")
      .def(nb::init<>())
      .def_rw("os", &platform_key::os)
      .def_rw("arch", &platform_key::arch)
      .def("to_string", &platform_key::to_string)
      .def("__repr__", [](const platform_key& key) {
        return "PlatformKey(os='" + key.os + "', arch='" + key.arch + "')";
      });

  nb::class_<py_session>(m, "Session")
      .def_static("for_process", &py_session::for_process)
      .def_static("for_buffer", &py_session::for_buffer, nb::arg("data"), nb::arg("platform_override") = nb::none())
      .def_prop_ro("platform_key", &py_session::platform_key_value)
      .def("regions", &py_session::regions, nb::arg("filter") = scan_filter{})
      .def("scan", &py_session::scan, nb::arg("pattern"), nb::arg("options") = scan_options{})
      .def("plan", &py_session::plan)
      .def("apply", &py_session::apply, nb::arg("plan"), nb::arg("options") = apply_options{})
      .def("buffer_bytes", &py_session::buffer_bytes);

  nb::module_ platform = m.def_submodule("platform", "platform helpers");
  platform.def("detect_platform", &p1ll::engine::platform::detect_platform);
  platform.def("parse_platform", [](const std::string& key) {
    auto parsed = p1ll::engine::platform::parse_platform(key);
    if (!parsed.ok()) {
      raise_engine_error(parsed.status_info);
    }
    return parsed.value;
  });
  platform.def("platform_matches", [](const platform_key& selector, const platform_key& target) {
    return p1ll::engine::platform::platform_matches(selector, target);
  });
  platform.def("platform_matches", [](const std::string& selector, const platform_key& target) {
    return p1ll::engine::platform::platform_matches(selector, target);
  });
  platform.def("any_platform_matches", &p1ll::engine::platform::any_platform_matches);

  nb::module_ utils = m.def_submodule("utils", "utility helpers");
  utils.def("str2hex", &p1ll::utils::str2hex);
  utils.def("hex2str", &p1ll::utils::hex2str);
  utils.def("format_address", &p1ll::utils::format_address);
  utils.def("format_bytes", [](const nb::bytes& data) {
    const auto* bytes = static_cast<const uint8_t*>(data.data());
    std::vector<uint8_t> buffer(bytes, bytes + data.size());
    return p1ll::utils::format_bytes(buffer);
  });
  utils.def("is_hex_digit", [](const std::string& value) {
    if (value.size() != 1) {
      throw nb::value_error("is_hex_digit expects a single character");
    }
    return p1ll::utils::is_hex_digit(value[0]);
  });
  utils.def("parse_hex_digit", [](const std::string& value) {
    if (value.size() != 1) {
      throw nb::value_error("parse_hex_digit expects a single character");
    }
    return p1ll::utils::parse_hex_digit(value[0]);
  });
  utils.def("to_hex_string", &p1ll::utils::to_hex_string);
  utils.def("is_valid_hex_pattern", &p1ll::utils::is_valid_hex_pattern);
  utils.def("parse_hex_pattern", &p1ll::utils::parse_hex_pattern);
  utils.def("normalize_hex_pattern", &p1ll::utils::normalize_hex_pattern);
  utils.def("format_memory_range", &p1ll::utils::format_memory_range);
  utils.def("format_memory_region", &p1ll::utils::format_memory_region);
  utils.def(
      "format_hex_bytes",
      [](const nb::bytes& data, size_t max_bytes) {
        return p1ll::utils::format_hex_bytes(static_cast<const uint8_t*>(data.data()), data.size(), max_bytes);
      },
      nb::arg("data"), nb::arg("max_bytes") = 16
  );

  utils.def("read_file", [](const std::string& path) -> nb::object {
    auto value = p1ll::utils::read_file(path);
    if (!value.has_value()) {
      return nb::none();
    }
    if (value->empty()) {
      return nb::bytes("", 0);
    }
    return nb::bytes(value->data(), value->size());
  });
  utils.def("read_file_string", [](const std::string& path) -> nb::object {
    auto value = p1ll::utils::read_file_string(path);
    if (!value.has_value()) {
      return nb::none();
    }
    return nb::str(value->c_str(), value->size());
  });
  utils.def("write_file", [](const std::string& path, const nb::bytes& data) {
    const auto* bytes = static_cast<const uint8_t*>(data.data());
    std::vector<uint8_t> buffer(bytes, bytes + data.size());
    return p1ll::utils::write_file(path, buffer);
  });
  utils.def("write_file", [](const std::string& path, const std::string& data) {
    return p1ll::utils::write_file(path, data);
  });
  utils.def("file_exists", &p1ll::utils::file_exists);
  utils.def("get_file_size", &p1ll::utils::get_file_size);

  m.def("has_scripting_support", &p1ll::has_scripting_support);
}
