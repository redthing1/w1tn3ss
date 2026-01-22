#include "w1h00k/resolve/resolve.hpp"

#include <algorithm>
#include <cstring>
#include <dlfcn.h>
#include <string_view>

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

std::string_view basename_view(std::string_view path) {
  const size_t pos = path.find_last_of("/\\");
  if (pos == std::string_view::npos) {
    return path;
  }
  return path.substr(pos + 1);
}

bool module_matches(const char* requested, const std::string& path) {
  if (!requested || requested[0] == '\0') {
    return true;
  }
  if (path.empty()) {
    return false;
  }
  const std::string_view req_view(requested);
  const bool has_sep = req_view.find('/') != std::string_view::npos ||
                       req_view.find('\\') != std::string_view::npos;
  if (has_sep) {
    return path == requested;
  }
  return basename_view(path) == req_view;
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
  for (const auto& entry : modules) {
    if (module_matches(module, entry.path)) {
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

bool elf_symbol_matches(const char* candidate, const char* target) {
  if (!candidate || !target) {
    return false;
  }
  if (std::strcmp(candidate, target) == 0) {
    return true;
  }
  const char* version = std::strchr(candidate, '@');
  if (!version) {
    return false;
  }
  const size_t len = static_cast<size_t>(version - candidate);
  return std::strlen(target) == len && std::strncmp(candidate, target, len) == 0;
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

bool elf_module_has_needed(const ElfW(Dyn)* dyn, const char* strtab, const char* needed) {
  if (!needed || needed[0] == '\0') {
    return true;
  }
  if (!dyn || !strtab) {
    return false;
  }
  for (const ElfW(Dyn)* entry = dyn; entry->d_tag != DT_NULL; ++entry) {
    if (entry->d_tag == DT_NEEDED) {
      const char* name = strtab + entry->d_un.d_val;
      if (name && module_matches(needed, name)) {
        return true;
      }
    }
  }
  return false;
}

template <typename Reloc>
void** elf_find_import_slot(const elf_module_snapshot& snapshot, const Reloc* relocs, size_t count,
                            const ElfW(Sym)* symtab, const char* strtab, const char* symbol) {
  if (!relocs || !symtab || !strtab || !symbol) {
    return nullptr;
  }
  for (size_t i = 0; i < count; ++i) {
    const Reloc& reloc = relocs[i];
    const uint32_t type = elf_r_type(reloc.r_info);
    if (!elf_import_type_supported(type)) {
      continue;
    }
    const uint32_t sym_index = elf_r_sym(reloc.r_info);
    const ElfW(Sym)& sym = symtab[sym_index];
    const char* name = strtab + sym.st_name;
    if (!elf_symbol_matches(name, symbol)) {
      continue;
    }
    const uintptr_t addr = static_cast<uintptr_t>(snapshot.info->dlpi_addr) + reloc.r_offset;
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
    const ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    const void* jmprel = nullptr;
    size_t pltrelsz = 0;
    bool pltrel_rela = true;
    const ElfW(Rela)* rela = nullptr;
    size_t relasz = 0;
    size_t relaent = sizeof(ElfW(Rela));
    const ElfW(Rel)* rel = nullptr;
    size_t relsz = 0;
    size_t relent = sizeof(ElfW(Rel));

    for (const ElfW(Dyn)* entry = dyn; entry->d_tag != DT_NULL; ++entry) {
      switch (entry->d_tag) {
        case DT_SYMTAB:
          symtab = reinterpret_cast<const ElfW(Sym)*>(info->dlpi_addr + entry->d_un.d_ptr);
          break;
        case DT_STRTAB:
          strtab = reinterpret_cast<const char*>(info->dlpi_addr + entry->d_un.d_ptr);
          break;
        case DT_JMPREL:
          jmprel = reinterpret_cast<const void*>(info->dlpi_addr + entry->d_un.d_ptr);
          break;
        case DT_PLTRELSZ:
          pltrelsz = entry->d_un.d_val;
          break;
        case DT_PLTREL:
          pltrel_rela = (entry->d_un.d_val == DT_RELA);
          break;
        case DT_RELA:
          rela = reinterpret_cast<const ElfW(Rela)*>(info->dlpi_addr + entry->d_un.d_ptr);
          break;
        case DT_RELASZ:
          relasz = entry->d_un.d_val;
          break;
        case DT_RELAENT:
          relaent = entry->d_un.d_val;
          break;
        case DT_REL:
          rel = reinterpret_cast<const ElfW(Rel)*>(info->dlpi_addr + entry->d_un.d_ptr);
          break;
        case DT_RELSZ:
          relsz = entry->d_un.d_val;
          break;
        case DT_RELENT:
          relent = entry->d_un.d_val;
          break;
        default:
          break;
      }
    }

    if (!elf_module_has_needed(dyn, strtab, ctx->import_module)) {
      return 0;
    }

    void** slot = nullptr;
    if (jmprel && pltrelsz > 0 && symtab && strtab) {
      if (pltrel_rela) {
        const size_t count = pltrelsz / relaent;
        slot = elf_find_import_slot(snapshot, reinterpret_cast<const ElfW(Rela)*>(jmprel), count, symtab, strtab,
                                    ctx->symbol);
      } else {
        const size_t count = pltrelsz / relent;
        slot = elf_find_import_slot(snapshot, reinterpret_cast<const ElfW(Rel)*>(jmprel), count, symtab, strtab,
                                    ctx->symbol);
      }
    }

    if (!slot && rela && relasz > 0 && symtab && strtab) {
      const size_t count = relasz / relaent;
      slot = elf_find_import_slot(snapshot, rela, count, symtab, strtab, ctx->symbol);
    }

    if (!slot && rel && relsz > 0 && symtab && strtab) {
      const size_t count = relsz / relent;
      slot = elf_find_import_slot(snapshot, rel, count, symtab, strtab, ctx->symbol);
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
    } else if (!module_matches(module, name ? std::string(name) : std::string{})) {
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
