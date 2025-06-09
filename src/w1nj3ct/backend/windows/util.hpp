#pragma once

#include <string>
#include <iostream>

// log helpers
static inline void log_msg(const std::string& msg) { std::cout << msg << std::endl; }
static inline void log_path(const std::string& msg, const std::string& path) { log_msg(msg + " [" + path + "]"); }
