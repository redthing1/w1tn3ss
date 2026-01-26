#pragma once

#include <optional>
#include <span>
#include <string>

#include "image_inventory.hpp"
#include "image_table_builder.hpp"
#include "w1instrument/core/module_registry.hpp"
#include "w1runtime/module_catalog.hpp"

namespace w1rewind {

class module_catalog_image_inventory final : public image_inventory_provider, public image_blob_provider {
public:
  module_catalog_image_inventory(
      w1::runtime::module_catalog& modules, w1::core::instrumented_module_policy policy = {}
  );

  void reset(const w1::rewind::arch_descriptor_record& arch) override;
  image_inventory_snapshot snapshot(uint32_t space_id) override;
  std::optional<image_inventory_event> translate_event(
      const image_inventory_source_event& event, uint32_t space_id
  ) override;
  bool emit_image_blobs(
      const w1::rewind::image_record& image, std::span<const w1::rewind::mapping_record> mappings,
      const image_blob_request& request, image_blob_sink& sink, std::string& error
  ) override;

private:
  std::optional<w1::runtime::module_info> find_module_info(const image_inventory_source_event& event) const;
  image_inventory_event make_loaded_event(const w1::runtime::module_info& module, uint64_t image_id, uint32_t space_id);
  image_inventory_event make_unloaded_event(
      const w1::runtime::module_info& module, uint64_t image_id, uint32_t space_id
  );

  w1::runtime::module_catalog* modules_ = nullptr;
  w1::core::module_registry<w1::core::instrumented_module_policy, uint64_t> registry_;
  w1::rewind::arch_descriptor_record arch_{};
  std::optional<image_metadata_cache> metadata_cache_{};
};

} // namespace w1rewind
