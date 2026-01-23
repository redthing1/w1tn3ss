#include "w1h00k/resolve/resolve.hpp"

#include <algorithm>
#include <cstring>
#include <dlfcn.h>
#include <string_view>

#include "w1h00k/resolve/module_match.hpp"
#if defined(__linux__)
#include <elf.h>
#include <link.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#endif

namespace w1::h00k::resolve {
namespace {

hook_error_info make_error(hook_error code, const char* detail) {
  hook_error_info info{};
  info.code = code;
  info.detail = detail;
  return info;
}

module_info module_from_dladdr(void* address) {
  module_info out{};
  Dl_info info{};
  if (address && dladdr(address, &info) != 0) {
    out.base = info.dli_fbase;
    if (info.dli_fname) {
      out.path = info.dli_fname;
    }
  }
  return out;
}

std::string find_module_path(const char* module) {
  if (!module || module[0] == '\0') {
    return {};
  }
  auto modules = enumerate_modules();
  const std::string_view requested(module);
  if (has_path_separator(requested)) {
    for (const auto& entry : modules) {
      if (module_matches(module, entry.path, module_match_mode::full_path)) {
        return entry.path;
      }
    }
    std::string fallback{};
    for (const auto& entry : modules) {
      if (module_matches(module, entry.path, module_match_mode::basename)) {
        if (!fallback.empty()) {
          return {};
        }
        fallback = entry.path;
      }
    }
    return fallback;
  }
  for (const auto& entry : modules) {
    if (module_matches(module, entry.path, module_match_mode::basename)) {
      return entry.path;
    }
  }
  return {};
}

#if defined(__linux__)
struct elf_module_snapshot {
  const dl_phdr_info* info = nullptr;
  std::string path{};
  uintptr_t base = 0;
  size_t size = 0;
};

struct elf_snapshot_view {
  const elf_module_snapshot* snapshot = nullptr;

  bool contains(const void* address, size_t size) const {
    if (!snapshot || !address || size == 0 || snapshot->base == 0 || snapshot->size == 0) {
      return false;
    }
    const uintptr_t start = reinterpret_cast<uintptr_t>(address);
    const uintptr_t base = snapshot->base;
    const uintptr_t end = base + snapshot->size;
    if (start < base || start >= end) {
      return false;
    }
    const uintptr_t last = start + size;
    if (last < start || last > end) {
      return false;
    }
    return true;
  }

  size_t max_span_from(const void* address) const {
    if (!contains(address, 1)) {
      return 0;
    }
    const uintptr_t start = reinterpret_cast<uintptr_t>(address);
    const uintptr_t end = snapshot->base + snapshot->size;
    return end > start ? static_cast<size_t>(end - start) : 0;
  }

  bool string_view_at(const char* name, std::string_view& out) const {
    return string_view_at(name, 0, out);
  }

  bool string_view_at(const char* name, size_t max_len, std::string_view& out) const {
    if (!name) {
      return false;
    }
    size_t limit = max_len;
    if (limit == 0) {
      limit = max_span_from(name);
    } else if (!contains(name, limit)) {
      return false;
    }
    if (limit == 0) {
      return false;
    }
    const void* terminator = std::memchr(name, '\0', limit);
    if (!terminator) {
      return false;
    }
    out = std::string_view(name, static_cast<const char*>(terminator) - name);
    return true;
  }

  uintptr_t resolve_ptr(ElfW(Addr) value) const {
    const uintptr_t addr = static_cast<uintptr_t>(value);
    if (contains(reinterpret_cast<const void*>(addr), 1)) {
      return addr;
    }
    if (!snapshot || !snapshot->info) {
      return addr;
    }
    return static_cast<uintptr_t>(snapshot->info->dlpi_addr) + addr;
  }

  uintptr_t module_offset(ElfW(Addr) value) const {
    if (!snapshot || !snapshot->info) {
      return static_cast<uintptr_t>(value);
    }
    return static_cast<uintptr_t>(snapshot->info->dlpi_addr) + static_cast<uintptr_t>(value);
  }

  bool table_in_module(const void* table, size_t bytes) const {
    if (!table || bytes == 0) {
      return false;
    }
    return contains(table, bytes);
  }
};

std::string resolve_linux_main_path() {
  char buffer[4096] = {};
  const ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
  if (len <= 0) {
    return {};
  }
  buffer[len] = '\0';
  return std::string(buffer);
}

elf_module_snapshot snapshot_module(const dl_phdr_info* info) {
  elf_module_snapshot snapshot{};
  snapshot.info = info;

  if (info->dlpi_name && info->dlpi_name[0] != '\0') {
    snapshot.path = info->dlpi_name;
  } else {
    snapshot.path = resolve_linux_main_path();
  }

  uintptr_t low = UINTPTR_MAX;
  uintptr_t high = 0;
  for (size_t i = 0; i < info->dlpi_phnum; ++i) {
    const ElfW(Phdr)& phdr = info->dlpi_phdr[i];
    if (phdr.p_type != PT_LOAD) {
      continue;
    }
    low = std::min(low, static_cast<uintptr_t>(phdr.p_vaddr));
    high = std::max(high, static_cast<uintptr_t>(phdr.p_vaddr + phdr.p_memsz));
  }
  if (low == UINTPTR_MAX) {
    snapshot.base = 0;
    snapshot.size = 0;
    return snapshot;
  }

  snapshot.base = static_cast<uintptr_t>(info->dlpi_addr) + low;
  snapshot.size = high - low;
  return snapshot;
}

uint32_t elf_r_sym(ElfW(Xword) info) {
#if __ELF_NATIVE_CLASS == 64
  return ELF64_R_SYM(info);
#else
  return ELF32_R_SYM(info);
#endif
}

uint32_t elf_r_type(ElfW(Xword) info) {
#if __ELF_NATIVE_CLASS == 64
  return ELF64_R_TYPE(info);
#else
  return ELF32_R_TYPE(info);
#endif
}

bool elf_symbol_matches(std::string_view candidate, std::string_view target) {
  if (candidate.empty() || target.empty()) {
    return false;
  }
  if (candidate == target) {
    return true;
  }
  const size_t at = candidate.find('@');
  if (at == std::string_view::npos) {
    return false;
  }
  return candidate.substr(0, at) == target;
}

bool elf_import_type_supported(uint32_t type) {
#if defined(__x86_64__)
  return type == R_X86_64_JUMP_SLOT || type == R_X86_64_GLOB_DAT;
#elif defined(__i386__)
  return type == R_386_JMP_SLOT || type == R_386_GLOB_DAT;
#elif defined(__aarch64__)
  return type == R_AARCH64_JUMP_SLOT || type == R_AARCH64_GLOB_DAT;
#elif defined(__arm__)
  return type == R_ARM_JUMP_SLOT || type == R_ARM_GLOB_DAT;
#else
  (void)type;
  return false;
#endif
}

bool elf_module_has_needed(const elf_snapshot_view& view, const ElfW(Dyn)* dyn, size_t dyn_count,
                           const char* strtab, size_t strtab_size, const char* needed) {
  if (!needed || needed[0] == '\0') {
    return true;
  }
  if (!dyn || !strtab || dyn_count == 0) {
    return false;
  }
  if (!view.contains(strtab, 1)) {
    return false;
  }
  if (strtab_size != 0 && !view.contains(strtab, strtab_size)) {
    return false;
  }
  if (!view.contains(dyn, dyn_count * sizeof(ElfW(Dyn)))) {
    return false;
  }
  for (size_t i = 0; i < dyn_count; ++i) {
    const ElfW(Dyn)& entry = dyn[i];
    if (entry.d_tag == DT_NULL) {
      break;
    }
    if (entry.d_tag == DT_NEEDED) {
      const size_t offset = entry.d_un.d_val;
      std::string_view name{};
      if (strtab_size != 0) {
        if (offset >= strtab_size) {
          continue;
        }
        if (!view.string_view_at(strtab + offset, strtab_size - offset, name)) {
          continue;
        }
      } else if (!view.string_view_at(strtab + offset, name)) {
        continue;
      }
      if (module_matches(needed, name, module_match_mode::basename)) {
        return true;
      }
    }
  }
  return false;
}

template <typename Reloc>
void** elf_find_import_slot(const elf_snapshot_view& view, const Reloc* relocs, size_t count,
                            const ElfW(Sym)* symtab, const char* strtab, size_t strtab_size,
                            const char* symbol, size_t sym_entry_size) {
  if (!relocs || !symtab || !strtab || !symbol || sym_entry_size == 0) {
    return nullptr;
  }
  if (!view.contains(relocs, count * sizeof(Reloc))) {
    return nullptr;
  }
  if (!view.contains(symtab, sym_entry_size) || !view.contains(strtab, 1)) {
    return nullptr;
  }
  if (strtab_size != 0 && !view.contains(strtab, strtab_size)) {
    return nullptr;
  }
  for (size_t i = 0; i < count; ++i) {
    const Reloc& reloc = relocs[i];
    const uint32_t type = elf_r_type(reloc.r_info);
    if (!elf_import_type_supported(type)) {
      continue;
    }
    const uint32_t sym_index = elf_r_sym(reloc.r_info);
    const uintptr_t sym_offset = static_cast<uintptr_t>(sym_index) * sym_entry_size;
    if (sym_offset / sym_entry_size != sym_index) {
      continue;
    }
    const uintptr_t sym_addr = reinterpret_cast<uintptr_t>(symtab) + sym_offset;
    if (!view.contains(reinterpret_cast<const void*>(sym_addr), sym_entry_size)) {
      continue;
    }
    const auto* sym = reinterpret_cast<const ElfW(Sym)*>(sym_addr);
    const size_t name_offset = sym->st_name;
    std::string_view candidate{};
    if (strtab_size != 0) {
      if (name_offset >= strtab_size) {
        continue;
      }
      if (!view.string_view_at(strtab + name_offset, strtab_size - name_offset, candidate)) {
        continue;
      }
    } else if (!view.string_view_at(strtab + name_offset, candidate)) {
      continue;
    }
    if (!elf_symbol_matches(candidate, std::string_view(symbol))) {
      continue;
    }
    const uintptr_t addr = view.module_offset(reloc.r_offset);
    return reinterpret_cast<void**>(addr);
  }
  return nullptr;
}

import_resolution resolve_import_elf(const char* symbol, const char* module, const char* import_module) {
  import_resolution result{};
  if (!symbol || symbol[0] == '\0') {
    result.error = make_error(hook_error::invalid_target, "missing_symbol");
    return result;
  }

  struct context {
    const char* symbol = nullptr;
    const char* module = nullptr;
    const char* import_module = nullptr;
    import_resolution result{};
    bool found = false;
  } ctx;
  ctx.symbol = symbol;
  ctx.module = module;
  ctx.import_module = import_module;

  auto callback = [](struct dl_phdr_info* info, size_t, void* data) -> int {
    auto* ctx = static_cast<context*>(data);
    const elf_module_snapshot snapshot = snapshot_module(info);
    const elf_snapshot_view view{&snapshot};
    const bool want_main = (!ctx->module || ctx->module[0] == '\0');
    if (want_main) {
      if (info->dlpi_name && info->dlpi_name[0] != '\0') {
        return 0;
      }
    } else {
      if (!module_matches(ctx->module, snapshot.path)) {
        return 0;
      }
    }

    const ElfW(Phdr)* dynamic_phdr = nullptr;
    for (size_t i = 0; i < info->dlpi_phnum; ++i) {
      if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
        dynamic_phdr = &info->dlpi_phdr[i];
        break;
      }
    }
    if (!dynamic_phdr) {
      return 0;
    }

    const ElfW(Dyn)* dyn = reinterpret_cast<const ElfW(Dyn)*>(info->dlpi_addr + dynamic_phdr->p_vaddr);
    const size_t dyn_bytes = dynamic_phdr->p_memsz;
    const size_t dyn_count = dyn_bytes / sizeof(ElfW(Dyn));
    if (dyn_count == 0 || !view.contains(dyn, dyn_bytes)) {
      return 0;
    }
    const ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    const void* jmprel = nullptr;
    size_t pltrelsz = 0;
    bool pltrel_rela = true;
    const ElfW(Rela)* rela = nullptr;
    size_t relasz = 0;
    size_t relaent = sizeof(ElfW(Rela));
    size_t syment = sizeof(ElfW(Sym));
    size_t strsz = 0;
    const ElfW(Rel)* rel = nullptr;
    size_t relsz = 0;
    size_t relent = sizeof(ElfW(Rel));

    for (size_t i = 0; i < dyn_count; ++i) {
      const ElfW(Dyn)& entry = dyn[i];
      if (entry.d_tag == DT_NULL) {
        break;
      }
      switch (entry.d_tag) {
        case DT_SYMTAB:
          symtab = reinterpret_cast<const ElfW(Sym)*>(view.resolve_ptr(entry.d_un.d_ptr));
          break;
        case DT_STRTAB:
          strtab = reinterpret_cast<const char*>(view.resolve_ptr(entry.d_un.d_ptr));
          break;
        case DT_JMPREL:
          jmprel = reinterpret_cast<const void*>(view.resolve_ptr(entry.d_un.d_ptr));
          break;
        case DT_PLTRELSZ:
          pltrelsz = entry.d_un.d_val;
          break;
        case DT_PLTREL:
          pltrel_rela = (entry.d_un.d_val == DT_RELA);
          break;
        case DT_RELA:
          rela = reinterpret_cast<const ElfW(Rela)*>(view.resolve_ptr(entry.d_un.d_ptr));
          break;
        case DT_RELASZ:
          relasz = entry.d_un.d_val;
          break;
        case DT_RELAENT:
          relaent = entry.d_un.d_val;
          break;
        case DT_SYMENT:
          syment = entry.d_un.d_val;
          break;
        case DT_STRSZ:
          strsz = entry.d_un.d_val;
          break;
        case DT_REL:
          rel = reinterpret_cast<const ElfW(Rel)*>(view.resolve_ptr(entry.d_un.d_ptr));
          break;
        case DT_RELSZ:
          relsz = entry.d_un.d_val;
          break;
        case DT_RELENT:
          relent = entry.d_un.d_val;
          break;
        default:
          break;
      }
    }

    if (relaent == 0) {
      relaent = sizeof(ElfW(Rela));
    }
    if (relent == 0) {
      relent = sizeof(ElfW(Rel));
    }
    if (syment < sizeof(ElfW(Sym))) {
      syment = sizeof(ElfW(Sym));
    }

    if (ctx->import_module && ctx->import_module[0] != '\0') {
      if (!strtab || !view.contains(strtab, 1)) {
        return 0;
      }
      if (!elf_module_has_needed(view, dyn, dyn_count, strtab, strsz, ctx->import_module)) {
        return 0;
      }
    }

    if (!symtab || !strtab) {
      return 0;
    }
    if (!view.contains(symtab, syment) || !view.contains(strtab, 1)) {
      return 0;
    }
    if (strsz != 0 && !view.contains(strtab, strsz)) {
      return 0;
    }

    auto table_in_module = [&](const void* table, size_t bytes) {
      return view.table_in_module(table, bytes);
    };

    void** slot = nullptr;
    if (jmprel && pltrelsz > 0 && table_in_module(jmprel, pltrelsz)) {
      if (pltrel_rela) {
        const size_t count = pltrelsz / relaent;
        slot = elf_find_import_slot(view, reinterpret_cast<const ElfW(Rela)*>(jmprel), count, symtab, strtab, strsz,
                                    ctx->symbol, syment);
      } else {
        const size_t count = pltrelsz / relent;
        slot = elf_find_import_slot(view, reinterpret_cast<const ElfW(Rel)*>(jmprel), count, symtab, strtab, strsz,
                                    ctx->symbol, syment);
      }
    }

    if (!slot && rela && relasz > 0 && table_in_module(rela, relasz)) {
      const size_t count = relasz / relaent;
      slot = elf_find_import_slot(view, rela, count, symtab, strtab, strsz, ctx->symbol, syment);
    }

    if (!slot && rel && relsz > 0 && table_in_module(rel, relsz)) {
      const size_t count = relsz / relent;
      slot = elf_find_import_slot(view, rel, count, symtab, strtab, strsz, ctx->symbol, syment);
    }

    if (slot) {
      ctx->result.slot = slot;
      ctx->result.module.base = reinterpret_cast<void*>(snapshot.base);
      ctx->result.module.size = snapshot.size;
      ctx->result.module.path = snapshot.path;
      ctx->result.error = make_error(hook_error::ok, nullptr);
      ctx->found = true;
      return 1;
    }

    return 0;
  };

  dl_iterate_phdr(callback, &ctx);

  if (!ctx.found) {
    ctx.result.error = make_error(hook_error::not_found, "import_not_found");
  }
  return ctx.result;
}
#endif

#if defined(__APPLE__)
#if defined(__LP64__)
using mach_header_t = mach_header_64;
using segment_command_t = segment_command_64;
using section_t = section_64;
using nlist_t = nlist_64;
static constexpr uint32_t kSegmentCommand = LC_SEGMENT_64;
#else
using mach_header_t = mach_header;
using segment_command_t = segment_command;
using section_t = section;
using nlist_t = nlist;
static constexpr uint32_t kSegmentCommand = LC_SEGMENT;
#endif

bool macho_range(const mach_header* header, intptr_t slide, uintptr_t& base, size_t& size) {
  const auto* mh = reinterpret_cast<const mach_header_t*>(header);
  const uint8_t* cursor = reinterpret_cast<const uint8_t*>(mh) + sizeof(mach_header_t);

  uintptr_t low = UINTPTR_MAX;
  uintptr_t high = 0;
  for (uint32_t i = 0; i < mh->ncmds; ++i) {
    const auto* lc = reinterpret_cast<const load_command*>(cursor);
    if (lc->cmd == kSegmentCommand) {
      const auto* seg = reinterpret_cast<const segment_command_t*>(cursor);
      const uintptr_t seg_start = static_cast<uintptr_t>(seg->vmaddr) + static_cast<uintptr_t>(slide);
      const uintptr_t seg_end = seg_start + static_cast<uintptr_t>(seg->vmsize);
      low = std::min(low, seg_start);
      high = std::max(high, seg_end);
    }
    cursor += lc->cmdsize;
  }

  if (low == UINTPTR_MAX || high <= low) {
    return false;
  }
  base = low;
  size = high - low;
  return true;
}

void** macho_find_symbol_ptr(const mach_header* header, intptr_t slide, const char* symbol) {
  if (!header || !symbol || symbol[0] == '\0') {
    return nullptr;
  }

  const auto* mh = reinterpret_cast<const mach_header_t*>(header);
  const uint8_t* cursor = reinterpret_cast<const uint8_t*>(mh) + sizeof(mach_header_t);

  const segment_command_t* text = nullptr;
  const segment_command_t* linkedit = nullptr;
  const struct symtab_command* symtab_cmd = nullptr;
  const struct dysymtab_command* dysymtab_cmd = nullptr;

  for (uint32_t i = 0; i < mh->ncmds; ++i) {
    const auto* lc = reinterpret_cast<const load_command*>(cursor);
    if (lc->cmd == kSegmentCommand) {
      const auto* seg = reinterpret_cast<const segment_command_t*>(cursor);
      if (std::strcmp(seg->segname, "__TEXT") == 0) {
        text = seg;
      } else if (std::strcmp(seg->segname, "__LINKEDIT") == 0) {
        linkedit = seg;
      }
    } else if (lc->cmd == LC_SYMTAB) {
      symtab_cmd = reinterpret_cast<const symtab_command*>(cursor);
    } else if (lc->cmd == LC_DYSYMTAB) {
      dysymtab_cmd = reinterpret_cast<const dysymtab_command*>(cursor);
    }
    cursor += lc->cmdsize;
  }

  if (!text || !linkedit || !symtab_cmd || !dysymtab_cmd) {
    return nullptr;
  }

  const uintptr_t slide_base = static_cast<uintptr_t>(slide);
  const uintptr_t linkedit_base =
      slide_base + static_cast<uintptr_t>(linkedit->vmaddr) - static_cast<uintptr_t>(linkedit->fileoff);
  const nlist_t* symtab = reinterpret_cast<const nlist_t*>(linkedit_base + symtab_cmd->symoff);
  const char* strtab = reinterpret_cast<const char*>(linkedit_base + symtab_cmd->stroff);
  const uint32_t* indirect_symtab =
      reinterpret_cast<const uint32_t*>(linkedit_base + dysymtab_cmd->indirectsymoff);

  cursor = reinterpret_cast<const uint8_t*>(mh) + sizeof(mach_header_t);
  for (uint32_t i = 0; i < mh->ncmds; ++i) {
    const auto* lc = reinterpret_cast<const load_command*>(cursor);
    if (lc->cmd == kSegmentCommand) {
      const auto* seg = reinterpret_cast<const segment_command_t*>(cursor);
      if (std::strcmp(seg->segname, "__DATA") != 0 && std::strcmp(seg->segname, "__DATA_CONST") != 0) {
        cursor += lc->cmdsize;
        continue;
      }
      const section_t* sect = reinterpret_cast<const section_t*>(cursor + sizeof(segment_command_t));
      for (uint32_t j = 0; j < seg->nsects; ++j) {
        const uint32_t type = sect[j].flags & SECTION_TYPE;
        if (type != S_LAZY_SYMBOL_POINTERS && type != S_NON_LAZY_SYMBOL_POINTERS) {
          continue;
        }
        const uint32_t* indices = indirect_symtab + sect[j].reserved1;
        void** bindings =
            reinterpret_cast<void**>(static_cast<uintptr_t>(slide) + static_cast<uintptr_t>(sect[j].addr));
        const uint32_t count = static_cast<uint32_t>(sect[j].size / sizeof(void*));
        for (uint32_t k = 0; k < count; ++k) {
          const uint32_t sym_index = indices[k];
          if (sym_index == INDIRECT_SYMBOL_ABS || sym_index == INDIRECT_SYMBOL_LOCAL ||
              sym_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
            continue;
          }
          const uint32_t str_offset = symtab[sym_index].n_un.n_strx;
          const char* name = strtab + str_offset;
          if (name && std::strcmp(name, symbol) == 0) {
            return &bindings[k];
          }
          if (name && name[0] == '_' && std::strcmp(name + 1, symbol) == 0) {
            return &bindings[k];
          }
        }
      }
    }
    cursor += lc->cmdsize;
  }

  return nullptr;
}

import_resolution resolve_import_macho(const char* symbol, const char* module) {
  import_resolution result{};
  if (!symbol || symbol[0] == '\0') {
    result.error = make_error(hook_error::invalid_target, "missing_symbol");
    return result;
  }

  const uint32_t count = _dyld_image_count();
  for (uint32_t i = 0; i < count; ++i) {
    const char* name = _dyld_get_image_name(i);
    if (!module || module[0] == '\0') {
      if (i != 0) {
        continue;
      }
    } else if (!module_matches(module, name ? std::string_view(name) : std::string_view{})) {
      continue;
    }
    const mach_header* header = _dyld_get_image_header(i);
    const intptr_t slide = _dyld_get_image_vmaddr_slide(i);
    void** slot = macho_find_symbol_ptr(header, slide, symbol);
    if (!slot) {
      continue;
    }
    uintptr_t base = 0;
    size_t size = 0;
    if (macho_range(header, slide, base, size)) {
      result.module.base = reinterpret_cast<void*>(base);
      result.module.size = size;
    }
    if (name) {
      result.module.path = name;
    }
    result.slot = slot;
    result.error = make_error(hook_error::ok, nullptr);
    return result;
  }

  result.error = make_error(hook_error::not_found, "import_not_found");
  return result;
}
#endif

} // namespace

std::vector<module_info> enumerate_modules() {
  std::vector<module_info> modules;
#if defined(__APPLE__)
  const uint32_t count = _dyld_image_count();
  modules.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    const mach_header* header = _dyld_get_image_header(i);
    const intptr_t slide = _dyld_get_image_vmaddr_slide(i);
    module_info info{};
    uintptr_t base = 0;
    size_t size = 0;
    if (header && macho_range(header, slide, base, size)) {
      info.base = reinterpret_cast<void*>(base);
      info.size = size;
    }
    const char* name = _dyld_get_image_name(i);
    if (name) {
      info.path = name;
    }
    modules.push_back(std::move(info));
  }
#elif defined(__linux__)
  dl_iterate_phdr(
      [](struct dl_phdr_info* info, size_t, void* data) -> int {
        auto* out = static_cast<std::vector<module_info>*>(data);
        const elf_module_snapshot snapshot = snapshot_module(info);
        module_info mod{};
        mod.base = reinterpret_cast<void*>(snapshot.base);
        mod.size = snapshot.size;
        mod.path = snapshot.path;
        out->push_back(std::move(mod));
        return 0;
      },
      &modules);
#endif
  return modules;
}

symbol_resolution resolve_symbol(const char* symbol, const char* module) {
  symbol_resolution result{};
  if (!symbol || symbol[0] == '\0') {
    result.error = make_error(hook_error::invalid_target, "missing_symbol");
    return result;
  }

  void* handle = RTLD_DEFAULT;
  if (module && module[0] != '\0') {
    const std::string path = find_module_path(module);
    if (path.empty()) {
      result.error = make_error(hook_error::not_found, "module_not_found");
      return result;
    }
    handle = dlopen(path.c_str(), RTLD_LAZY | RTLD_NOLOAD);
    if (!handle) {
      result.error = make_error(hook_error::not_found, "module_not_loaded");
      return result;
    }
  }

  void* address = dlsym(handle, symbol);
  if (handle != RTLD_DEFAULT) {
    dlclose(handle);
  }

  if (!address) {
    result.error = make_error(hook_error::not_found, "symbol_not_found");
    return result;
  }

  result.address = address;
  result.error = make_error(hook_error::ok, nullptr);
  result.module = module_from_dladdr(address);
  if (result.module.path.empty() && module && module[0] != '\0') {
    result.module.path = find_module_path(module);
  }
  if (result.module.size == 0 && !result.module.path.empty()) {
    auto modules = enumerate_modules();
    for (const auto& entry : modules) {
      if (module_matches(result.module.path.c_str(), entry.path)) {
        result.module.size = entry.size;
        if (!result.module.base) {
          result.module.base = entry.base;
        }
        break;
      }
    }
  }
  return result;
}

symbol_resolution resolve_symbol(const hook_target& target) {
  if (target.kind == hook_target_kind::address) {
    symbol_resolution result{};
    result.address = target.address;
    result.error = make_error(target.address ? hook_error::ok : hook_error::invalid_target, "address_target");
    if (result.address) {
      result.module = module_from_dladdr(result.address);
    }
    return result;
  }
  if (target.kind != hook_target_kind::symbol) {
    symbol_resolution result{};
    result.error = make_error(hook_error::invalid_target, "invalid_target_kind");
    return result;
  }
  return resolve_symbol(target.symbol, target.module);
}

import_resolution resolve_import(const char* symbol, const char* module, const char* import_module) {
#if defined(__APPLE__)
  (void)import_module;
  return resolve_import_macho(symbol, module);
#elif defined(__linux__)
  return resolve_import_elf(symbol, module, import_module);
#else
  import_resolution result{};
  result.error = make_error(hook_error::unsupported, "unsupported_platform");
  (void)symbol;
  (void)module;
  (void)import_module;
  return result;
#endif
}

import_resolution resolve_import(const hook_target& target) {
  if (target.kind != hook_target_kind::import_slot) {
    import_resolution result{};
    result.error = make_error(hook_error::invalid_target, "invalid_target_kind");
    return result;
  }
  if (target.slot) {
    import_resolution result{};
    result.slot = target.slot;
    result.error = make_error(hook_error::ok, nullptr);
    return result;
  }
  return resolve_import(target.symbol, target.module, target.import_module);
}

void* symbol_address(const char* symbol, const char* module) {
  auto resolved = resolve_symbol(symbol, module);
  return resolved.address;
}

} // namespace w1::h00k::resolve
