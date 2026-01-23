#pragma once

#include <concepts>
#include <cstdint>
#include <utility>

#include <QBDI.h>

namespace w1::instrument {

template <typename Recipe>
concept tracer_recipe = requires {
  typename Recipe::config_t;
  typename Recipe::runtime_t;

  requires std::move_constructible<typename Recipe::config_t>;
  requires std::move_constructible<typename Recipe::runtime_t>;

  { Recipe::load_config() } -> std::same_as<typename Recipe::config_t>;
  { Recipe::configure_logging(std::declval<const typename Recipe::config_t&>()) } -> std::same_as<void>;
  { Recipe::apply_self_excludes(std::declval<typename Recipe::config_t&>(), (const void*)nullptr) } -> std::same_as<void>;
  { Recipe::log_config(std::declval<const typename Recipe::config_t&>()) } -> std::same_as<void>;

  { Recipe::make_runtime(std::declval<const typename Recipe::config_t&>()) } -> std::same_as<typename Recipe::runtime_t>;
  { Recipe::run_main(std::declval<typename Recipe::runtime_t&>(), (QBDI::VM*)nullptr, uint64_t{}, uint64_t{}) } ->
      std::same_as<bool>;
  { Recipe::on_exit(std::declval<typename Recipe::runtime_t&>(), std::declval<const typename Recipe::config_t&>(), 0) } ->
      std::same_as<void>;
};

} // namespace w1::instrument
