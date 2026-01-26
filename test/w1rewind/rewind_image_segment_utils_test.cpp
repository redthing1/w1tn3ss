#include "doctest/doctest.hpp"

#include "w1rewind/format/image_segment_utils.hpp"

TEST_CASE("pe_section_mem_size uses max of virtual and raw sizes") {
  CHECK(w1::rewind::pe_section_mem_size(0, 0) == 0);
  CHECK(w1::rewind::pe_section_mem_size(0x1000, 0) == 0x1000);
  CHECK(w1::rewind::pe_section_mem_size(0, 0x200) == 0x200);
  CHECK(w1::rewind::pe_section_mem_size(0x300, 0x200) == 0x300);
  CHECK(w1::rewind::pe_section_mem_size(0x100, 0x400) == 0x400);
}
