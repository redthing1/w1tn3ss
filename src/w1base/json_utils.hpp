#pragma once

#include <ostream>
#include <string>
#include <string_view>

namespace w1::util {

inline std::string quote_json_string(std::string_view value) {
  static constexpr char k_hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(value.size() + 2);
  out.push_back('"');
  for (unsigned char c : value) {
    switch (c) {
    case '"':
      out += "\\\"";
      break;
    case '\\':
      out += "\\\\";
      break;
    case '\b':
      out += "\\b";
      break;
    case '\f':
      out += "\\f";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      if (c < 0x20) {
        out += "\\u";
        out.push_back(k_hex[(c >> 12) & 0x0f]);
        out.push_back(k_hex[(c >> 8) & 0x0f]);
        out.push_back(k_hex[(c >> 4) & 0x0f]);
        out.push_back(k_hex[c & 0x0f]);
      } else {
        out.push_back(static_cast<char>(c));
      }
      break;
    }
  }
  out.push_back('"');
  return out;
}

inline void write_json_string(std::ostream& out, std::string_view value) {
  out << quote_json_string(value);
}

} // namespace w1::util
