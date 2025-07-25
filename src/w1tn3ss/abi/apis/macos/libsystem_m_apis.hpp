#pragma once

#include "abi/api_knowledge_db.hpp"
#include <vector>

namespace w1::abi::apis::macos {

// determine macOS calling convention based on architecture
#if defined(__x86_64__)
#define MACOS_API_CONVENTION calling_convention_id::X86_64_SYSTEM_V
#elif defined(__aarch64__)
#define MACOS_API_CONVENTION calling_convention_id::AARCH64_AAPCS
#elif defined(__arm__)
#define MACOS_API_CONVENTION calling_convention_id::ARM32_AAPCS
#elif defined(__i386__)
#define MACOS_API_CONVENTION calling_convention_id::X86_CDECL
#else
#warning "Unknown macOS architecture, using UNKNOWN calling convention"
#define MACOS_API_CONVENTION calling_convention_id::UNKNOWN
#endif

/**
 * @brief libsystem_m.dylib api definitions
 *
 * covers mathematical functions:
 * - trigonometric functions (sin, cos, tan)
 * - exponential and logarithmic functions
 * - power and root functions
 * - rounding and absolute value functions
 * - floating point manipulation
 */

static const std::vector<api_info> macos_libsystem_m_apis = {
    // ===== TRIGONOMETRIC FUNCTIONS =====
    {.name = "_sin",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute sine",
     .headers = {"math.h"}},
    {.name = "_sinf",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {{.name = "x", .param_type = param_info::type::FLOAT, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::FLOAT},
     .description = "compute sine (float)",
     .headers = {"math.h"}},
    {.name = "_cos",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute cosine",
     .headers = {"math.h"}},
    {.name = "_cosf",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {{.name = "x", .param_type = param_info::type::FLOAT, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::FLOAT},
     .description = "compute cosine (float)",
     .headers = {"math.h"}},
    {.name = "_tan",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute tangent",
     .headers = {"math.h"}},
    {.name = "_tanf",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {{.name = "x", .param_type = param_info::type::FLOAT, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::FLOAT},
     .description = "compute tangent (float)",
     .headers = {"math.h"}},
    {.name = "_asin",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute arc sine",
     .headers = {"math.h"}},
    {.name = "_acos",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute arc cosine",
     .headers = {"math.h"}},
    {.name = "_atan",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute arc tangent",
     .headers = {"math.h"}},
    {.name = "_atan2",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "y", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN},
          {.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute arc tangent of y/x",
     .headers = {"math.h"}},

    // ===== HYPERBOLIC FUNCTIONS =====
    {.name = "_sinh",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute hyperbolic sine",
     .headers = {"math.h"}},
    {.name = "_cosh",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute hyperbolic cosine",
     .headers = {"math.h"}},
    {.name = "_tanh",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute hyperbolic tangent",
     .headers = {"math.h"}},

    // ===== EXPONENTIAL AND LOGARITHMIC FUNCTIONS =====
    {.name = "_exp",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute exponential function",
     .headers = {"math.h"}},
    {.name = "_expf",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {{.name = "x", .param_type = param_info::type::FLOAT, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::FLOAT},
     .description = "compute exponential function (float)",
     .headers = {"math.h"}},
    {.name = "_exp2",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute 2^x",
     .headers = {"math.h"}},
    {.name = "_expm1",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute e^x - 1",
     .headers = {"math.h"}},
    {.name = "_log",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute natural logarithm",
     .headers = {"math.h"}},
    {.name = "_logf",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {{.name = "x", .param_type = param_info::type::FLOAT, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::FLOAT},
     .description = "compute natural logarithm (float)",
     .headers = {"math.h"}},
    {.name = "_log10",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute base-10 logarithm",
     .headers = {"math.h"}},
    {.name = "_log2",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute base-2 logarithm",
     .headers = {"math.h"}},
    {.name = "_log1p",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute log(1 + x)",
     .headers = {"math.h"}},

    // ===== POWER AND ROOT FUNCTIONS =====
    {.name = "_pow",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN},
          {.name = "y", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute x raised to power y",
     .headers = {"math.h"}},
    {.name = "_powf",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::FLOAT, .param_direction = param_info::direction::IN},
          {.name = "y", .param_type = param_info::type::FLOAT, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::FLOAT},
     .description = "compute x raised to power y (float)",
     .headers = {"math.h"}},
    {.name = "_sqrt",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute square root",
     .headers = {"math.h"}},
    {.name = "_sqrtf",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {{.name = "x", .param_type = param_info::type::FLOAT, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::FLOAT},
     .description = "compute square root (float)",
     .headers = {"math.h"}},
    {.name = "_cbrt",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute cube root",
     .headers = {"math.h"}},
    {.name = "_hypot",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN},
          {.name = "y", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute euclidean distance",
     .headers = {"math.h"}},

    // ===== ROUNDING AND ABSOLUTE VALUE FUNCTIONS =====
    {.name = "_fabs",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute absolute value",
     .headers = {"math.h"}},
    {.name = "_fabsf",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {{.name = "x", .param_type = param_info::type::FLOAT, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::FLOAT},
     .description = "compute absolute value (float)",
     .headers = {"math.h"}},
    {.name = "_ceil",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "round up to nearest integer",
     .headers = {"math.h"}},
    {.name = "_ceilf",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {{.name = "x", .param_type = param_info::type::FLOAT, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::FLOAT},
     .description = "round up to nearest integer (float)",
     .headers = {"math.h"}},
    {.name = "_floor",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "round down to nearest integer",
     .headers = {"math.h"}},
    {.name = "_floorf",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {{.name = "x", .param_type = param_info::type::FLOAT, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::FLOAT},
     .description = "round down to nearest integer (float)",
     .headers = {"math.h"}},
    {.name = "_round",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "round to nearest integer",
     .headers = {"math.h"}},
    {.name = "_trunc",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "truncate to integer value",
     .headers = {"math.h"}},

    // ===== FLOATING POINT MANIPULATION =====
    {.name = "_fmod",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN},
          {.name = "y", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute floating-point remainder",
     .headers = {"math.h"}},
    {.name = "_remainder",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN},
          {.name = "y", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "compute remainder of x/y",
     .headers = {"math.h"}},
    {.name = "_copysign",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN},
          {.name = "y", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "copy sign of y to x",
     .headers = {"math.h"}},
    {.name = "_nan",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "tagp", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "return quiet NaN",
     .headers = {"math.h"}},
    {.name = "_isnan",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::BOOLEAN},
     .description = "check if value is NaN",
     .headers = {"math.h"}},
    {.name = "_isinf",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::BOOLEAN},
     .description = "check if value is infinite",
     .headers = {"math.h"}},
    {.name = "_isfinite",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::BOOLEAN},
     .description = "check if value is finite",
     .headers = {"math.h"}},

    // ===== MISC MATH FUNCTIONS =====
    {.name = "_fmax",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN},
          {.name = "y", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "determine maximum of two values",
     .headers = {"math.h"}},
    {.name = "_fmin",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN},
          {.name = "y", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "determine minimum of two values",
     .headers = {"math.h"}},
    {.name = "_fdim",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN},
          {.name = "y", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "positive difference",
     .headers = {"math.h"}},
    {.name = "_fma",
     .module = "libsystem_m.dylib",
     .api_category = api_info::category::MATH,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN},
          {.name = "y", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN},
          {.name = "z", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
     .description = "fused multiply-add",
     .headers = {"math.h"}}
};

} // namespace w1::abi::apis::macos