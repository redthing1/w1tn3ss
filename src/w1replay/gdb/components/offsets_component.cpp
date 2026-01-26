#include "w1replay/gdb/adapter_components.hpp"

namespace w1replay::gdb {

offsets_component::offsets_component(const adapter_services& services) : services_(services) {}

std::optional<gdbstub::offsets_info> offsets_component::get_offsets_info() const {
  if (!services_.session || !services_.context || !services_.image_index) {
    return std::nullopt;
  }

  uint64_t pc = services_.session->current_step().address;
  auto match = services_.image_index->find(pc, 1);
  if (!match.has_value() || !match->mapping || !match->image) {
    return std::nullopt;
  }
  const auto& image = *match->image;
  const auto* meta = services_.context->find_image_metadata(image.image_id);
  if (!meta || (meta->flags & w1::rewind::image_meta_has_link_base) == 0) {
    return std::nullopt;
  }

  uint64_t link_base = meta->link_base;
  uint64_t runtime_base = match->mapping->base;
  uint64_t mapped_base = link_base + match->mapping->image_offset;
  if (runtime_base < mapped_base) {
    return std::nullopt;
  }
  uint64_t slide = runtime_base - mapped_base;
  return gdbstub::offsets_info::section(slide, slide, slide);
}

} // namespace w1replay::gdb
