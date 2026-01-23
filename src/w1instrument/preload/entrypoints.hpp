#pragma once

#include <cstdint>
#include <memory>
#include <utility>

#include "QBDIPreload.h"

#include "w1instrument/preload/immortal_state.hpp"
#include "w1instrument/tracer/recipe.hpp"

namespace w1::instrument {

namespace detail {

template <tracer_recipe Recipe> struct preload_state {
  using config_t = typename Recipe::config_t;
  using runtime_t = typename Recipe::runtime_t;

  std::unique_ptr<config_t> config;
  std::unique_ptr<runtime_t> runtime;
};

template <tracer_recipe Recipe> preload_state<Recipe>& state() {
  return immortal_preload_state<preload_state<Recipe>>();
}

template <typename Recipe>
concept has_on_start = requires(void* main) {
  { Recipe::on_start(main) } -> std::same_as<int>;
};

template <typename Recipe>
concept has_on_premain = requires(void* gpr_ctx, void* fpu_ctx) {
  { Recipe::on_premain(gpr_ctx, fpu_ctx) } -> std::same_as<int>;
};

template <typename Recipe>
concept has_on_main = requires(int argc, char** argv) {
  { Recipe::on_main(argc, argv) } -> std::same_as<int>;
};

} // namespace detail

template <tracer_recipe Recipe> int preload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  using config_t = typename Recipe::config_t;
  using runtime_t = typename Recipe::runtime_t;

  auto& st = detail::state<Recipe>();
  st.config = std::make_unique<config_t>(Recipe::load_config());
  Recipe::configure_logging(*st.config);
  Recipe::apply_self_excludes(*st.config, reinterpret_cast<const void*>(&preload_on_run<Recipe>));
  Recipe::log_config(*st.config);

  st.runtime = std::make_unique<runtime_t>(Recipe::make_runtime(*st.config));
  if (!Recipe::run_main(
          *st.runtime, static_cast<QBDI::VM*>(vm), static_cast<uint64_t>(start), static_cast<uint64_t>(stop)
      )) {
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  return QBDIPRELOAD_NO_ERROR;
}

template <tracer_recipe Recipe> int preload_on_exit(int status) {
  auto& st = detail::state<Recipe>();
  if (st.runtime && st.config) {
    Recipe::on_exit(*st.runtime, *st.config, status);
  }

  st.runtime.release();
  st.config.release();
  return QBDIPRELOAD_NO_ERROR;
}

template <tracer_recipe Recipe> int preload_on_start(void* main) {
  if constexpr (detail::has_on_start<Recipe>) {
    return Recipe::on_start(main);
  }
  (void) main;
  return QBDIPRELOAD_NOT_HANDLED;
}

template <tracer_recipe Recipe> int preload_on_premain(void* gpr_ctx, void* fpu_ctx) {
  if constexpr (detail::has_on_premain<Recipe>) {
    return Recipe::on_premain(gpr_ctx, fpu_ctx);
  }
  (void) gpr_ctx;
  (void) fpu_ctx;
  return QBDIPRELOAD_NOT_HANDLED;
}

template <tracer_recipe Recipe> int preload_on_main(int argc, char** argv) {
  if constexpr (detail::has_on_main<Recipe>) {
    return Recipe::on_main(argc, argv);
  }
  (void) argc;
  (void) argv;
  return QBDIPRELOAD_NOT_HANDLED;
}

} // namespace w1::instrument
