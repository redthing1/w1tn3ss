#include "macho_processor.hpp"

#include <iostream>
#include <memory>
#include <vector>

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <libkern/OSByteOrder.h>

#include <redlog.hpp>

namespace w1::import_insertion::backend::macos {

namespace {
auto log_processor = redlog::get_logger("w1.import_insertion.macho_processor");

// byte swapping helpers (extracted from insert_dylib)
#define IS_64_BIT(x) ((x) == MH_MAGIC_64 || (x) == MH_CIGAM_64)
#define IS_LITTLE_ENDIAN(x) ((x) == FAT_CIGAM || (x) == MH_CIGAM_64 || (x) == MH_CIGAM)
#define SWAP32(x, magic) (IS_LITTLE_ENDIAN(magic) ? OSSwapInt32(x) : (x))
#define SWAP64(x, magic) (IS_LITTLE_ENDIAN(magic) ? OSSwapInt64(x) : (x))
#define ROUND_UP(x, y) (((x) + (y) - 1) & -(y))
} // namespace

void MachOProcessor::zero_fill(std::streamoff offset, size_t len) {
  static constexpr size_t buffer_size = 512;
  static char zeros[buffer_size] = {0};

  file_.seekp(offset);
  while (len > 0) {
    size_t size = std::min(len, buffer_size);
    file_.write(zeros, size);
    len -= size;
  }
}

void MachOProcessor::memory_move(std::streamoff dst, std::streamoff src, size_t len) {
  static constexpr size_t buffer_size = 512;
  static char buffer[buffer_size];

  while (len > 0) {
    size_t size = std::min(len, buffer_size);
    file_.seekg(src);
    file_.read(buffer, size);
    file_.seekp(dst);
    file_.write(buffer, size);

    len -= size;
    src += size;
    dst += size;
  }
}

template <typename T> T MachOProcessor::peek_at(std::streamoff pos) {
  T result;
  auto current_pos = file_.tellg();
  file_.seekg(pos);
  file_.read(reinterpret_cast<char*>(&result), sizeof(T));
  file_.seekg(current_pos);
  return result;
}

bool MachOProcessor::ask_user(const std::string& question) {
  if (!ask_mode_) {
    return true;
  }

  std::cout << question << " [y/n] ";
  std::string response;
  while (true) {
    std::getline(std::cin, response);
    if (!response.empty()) {
      char c = std::tolower(response[0]);
      if (c == 'y') {
        return true;
      }
      if (c == 'n') {
        return false;
      }
    }
    std::cout << "Please enter y or n: ";
  }
}

bool MachOProcessor::check_load_commands(
    struct mach_header* mh, size_t header_offset, size_t commands_offset, const std::string& dylib_path,
    std::streamoff* slice_size
) {
  file_.seekg(commands_offset);
  uint32_t ncmds = SWAP32(mh->ncmds, mh->magic);

  log_processor.trc(
      "checking load commands", redlog::field("count", ncmds), redlog::field("commands_offset", commands_offset)
  );

  std::streamoff linkedit_32_pos = -1;
  std::streamoff linkedit_64_pos = -1;
  struct segment_command linkedit_32;
  struct segment_command_64 linkedit_64;

  for (uint32_t i = 0; i < ncmds; i++) {
    auto lc_pos = file_.tellg();
    struct load_command lc;
    file_.read(reinterpret_cast<char*>(&lc), sizeof(lc));

    uint32_t cmdsize = SWAP32(lc.cmdsize, mh->magic);
    uint32_t cmd = SWAP32(lc.cmd, mh->magic);

    log_processor.dbg(
        "processing load command", redlog::field("index", i), redlog::field("cmd", cmd), redlog::field("size", cmdsize)
    );

    switch (cmd) {
    case LC_CODE_SIGNATURE:
      log_processor.trc("found code signature", redlog::field("position", i), redlog::field("is_last", i == ncmds - 1));
      if (i == ncmds - 1) {
        if (strip_codesig_ || ask_user("LC_CODE_SIGNATURE found. Remove it?")) {
          // handle code signature removal
          log_processor.inf("removing code signature", redlog::field("size", cmdsize));
          zero_fill(lc_pos, cmdsize);
          mh->ncmds = SWAP32(ncmds - 1, mh->magic);
          mh->sizeofcmds = SWAP32(SWAP32(mh->sizeofcmds, mh->magic) - cmdsize, mh->magic);
          return true;
        } else {
          log_processor.dbg("user declined code signature removal");
          return true;
        }
      } else {
        log_processor.warn("code signature not at end, cannot remove", redlog::field("position", i));
      }
      break;

    case LC_LOAD_DYLIB:
    case LC_LOAD_WEAK_DYLIB: {
      file_.seekg(lc_pos);
      std::vector<char> cmd_data(cmdsize);
      file_.read(cmd_data.data(), cmdsize);

      auto dylib_cmd = reinterpret_cast<struct dylib_command*>(cmd_data.data());
      uint32_t name_offset = SWAP32(dylib_cmd->dylib.name.offset, mh->magic);
      std::string existing_path(cmd_data.data() + name_offset);

      log_processor.dbg(
          "found existing dylib load command", redlog::field("path", existing_path),
          redlog::field("weak", cmd == LC_LOAD_WEAK_DYLIB)
      );

      if (existing_path == dylib_path) {
        log_processor.trc("duplicate dylib detected", redlog::field("path", dylib_path));
        if (!ask_user("Binary already contains load command for " + dylib_path + ". Continue?")) {
          return false;
        }
      }
      break;
    }

    case LC_SEGMENT:
    case LC_SEGMENT_64:
      // track __LINKEDIT segment for code signature handling
      if (cmd == LC_SEGMENT) {
        file_.seekg(lc_pos);
        struct segment_command seg_cmd;
        file_.read(reinterpret_cast<char*>(&seg_cmd), sizeof(seg_cmd));
        log_processor.dbg(
            "found 32-bit segment", redlog::field("name", std::string(seg_cmd.segname, strnlen(seg_cmd.segname, 16)))
        );
        if (strncmp(seg_cmd.segname, "__LINKEDIT", 16) == 0) {
          log_processor.trc(
              "found __LINKEDIT segment (32-bit)", redlog::field("fileoff", SWAP32(seg_cmd.fileoff, mh->magic)),
              redlog::field("filesize", SWAP32(seg_cmd.filesize, mh->magic))
          );
          linkedit_32_pos = lc_pos;
          linkedit_32 = seg_cmd;
        }
      } else {
        file_.seekg(lc_pos);
        struct segment_command_64 seg_cmd;
        file_.read(reinterpret_cast<char*>(&seg_cmd), sizeof(seg_cmd));
        log_processor.dbg(
            "found 64-bit segment", redlog::field("name", std::string(seg_cmd.segname, strnlen(seg_cmd.segname, 16)))
        );
        if (strncmp(seg_cmd.segname, "__LINKEDIT", 16) == 0) {
          log_processor.trc(
              "found __LINKEDIT segment (64-bit)", redlog::field("fileoff", SWAP64(seg_cmd.fileoff, mh->magic)),
              redlog::field("filesize", SWAP64(seg_cmd.filesize, mh->magic))
          );
          linkedit_64_pos = lc_pos;
          linkedit_64 = seg_cmd;
        }
      }
      break;
    }

    file_.seekg(lc_pos + static_cast<std::streamoff>(cmdsize));
  }

  return true;
}

MachOProcessor::MachOProcessor(const std::string& filepath, bool weak, bool strip_codesig, bool ask)
    : weak_flag_(weak), strip_codesig_(strip_codesig), ask_mode_(ask) {
  file_.open(filepath, std::ios::in | std::ios::out | std::ios::binary);
  if (!file_.is_open()) {
    throw std::runtime_error("failed to open file: " + filepath);
  }
}

MachOProcessor::~MachOProcessor() {
  if (file_.is_open()) {
    file_.close();
  }
}

bool MachOProcessor::insert_dylib_load_command(const std::string& dylib_path) {
  // get file size
  file_.seekg(0, std::ios::end);
  std::streamoff file_size = file_.tellg();
  file_.seekg(0, std::ios::beg);

  // read magic number
  uint32_t magic;
  file_.read(reinterpret_cast<char*>(&magic), sizeof(magic));

  switch (magic) {
  case FAT_MAGIC:
  case FAT_CIGAM:
    return process_fat_binary(dylib_path, magic);

  case MH_MAGIC_64:
  case MH_CIGAM_64:
  case MH_MAGIC:
  case MH_CIGAM:
    return process_mach_o(dylib_path, 0, &file_size);

  default:
    log_processor.error("unknown magic number", redlog::field("magic", magic));
    return false;
  }
}

bool MachOProcessor::process_fat_binary(const std::string& dylib_path, uint32_t magic) {
  file_.seekg(0);
  struct fat_header fh;
  file_.read(reinterpret_cast<char*>(&fh), sizeof(fh));

  uint32_t nfat_arch = SWAP32(fh.nfat_arch, magic);
  log_processor.inf("processing fat binary", redlog::field("architectures", nfat_arch));
  log_processor.trc(
      "fat binary details", redlog::field("magic", magic), redlog::field("little_endian", IS_LITTLE_ENDIAN(magic))
  );

  std::vector<struct fat_arch> archs(nfat_arch);
  file_.read(reinterpret_cast<char*>(archs.data()), sizeof(struct fat_arch) * nfat_arch);

  int failures = 0;
  for (uint32_t i = 0; i < nfat_arch; i++) {
    std::streamoff offset = SWAP32(archs[i].offset, magic);
    std::streamoff slice_size = SWAP32(archs[i].size, magic);

    log_processor.trc(
        "processing architecture", redlog::field("index", i), redlog::field("offset", offset),
        redlog::field("size", slice_size), redlog::field("cputype", SWAP32(archs[i].cputype, magic))
    );

    if (!process_mach_o(dylib_path, offset, &slice_size)) {
      log_processor.error("failed to process architecture", redlog::field("arch_index", i + 1));
      failures++;
    } else {
      log_processor.dbg(
          "architecture processed successfully", redlog::field("index", i), redlog::field("new_size", slice_size)
      );
    }

    archs[i].size = SWAP32(static_cast<uint32_t>(slice_size), magic);
  }

  // update fat header
  log_processor.trc("updating fat binary header");
  file_.seekp(sizeof(struct fat_header));
  file_.write(reinterpret_cast<const char*>(archs.data()), sizeof(struct fat_arch) * nfat_arch);

  if (failures == 0) {
    log_processor.info("added dylib load command to all architectures");
    return true;
  } else if (static_cast<uint32_t>(failures) == nfat_arch) {
    log_processor.error("failed to add dylib load command to any architectures");
    return false;
  } else {
    log_processor.warn(
        "added dylib load command to some architectures", redlog::field("successful", nfat_arch - failures),
        redlog::field("total", nfat_arch)
    );
    return true;
  }
}

bool MachOProcessor::process_mach_o(
    const std::string& dylib_path, std::streamoff header_offset, std::streamoff* slice_size
) {
  file_.seekg(header_offset);
  struct mach_header mh;
  file_.read(reinterpret_cast<char*>(&mh), sizeof(mh));

  log_processor.trc(
      "processing mach-o binary", redlog::field("header_offset", header_offset), redlog::field("magic", mh.magic),
      redlog::field("is_64bit", IS_64_BIT(mh.magic))
  );

  if (mh.magic != MH_MAGIC_64 && mh.magic != MH_CIGAM_64 && mh.magic != MH_MAGIC && mh.magic != MH_CIGAM) {
    log_processor.error("unknown mach-o magic", redlog::field("magic", mh.magic));
    return false;
  }

  size_t commands_offset =
      header_offset + (IS_64_BIT(mh.magic) ? sizeof(struct mach_header_64) : sizeof(struct mach_header));

  log_processor.dbg(
      "mach-o header parsed", redlog::field("ncmds", SWAP32(mh.ncmds, mh.magic)),
      redlog::field("sizeofcmds", SWAP32(mh.sizeofcmds, mh.magic)), redlog::field("commands_offset", commands_offset)
  );

  // check existing load commands
  if (!check_load_commands(&mh, header_offset, commands_offset, dylib_path, slice_size)) {
    return false;
  }

  // create new dylib load command
  constexpr size_t path_padding = 8;
  size_t dylib_path_size = (dylib_path.length() & ~(path_padding - 1)) + path_padding;
  uint32_t cmdsize = static_cast<uint32_t>(sizeof(struct dylib_command) + dylib_path_size);

  log_processor.trc(
      "creating dylib load command", redlog::field("dylib_path", dylib_path), redlog::field("weak", weak_flag_),
      redlog::field("cmdsize", cmdsize), redlog::field("padded_path_size", dylib_path_size)
  );

  struct dylib_command dylib_cmd = {
      .cmd = SWAP32(weak_flag_ ? LC_LOAD_WEAK_DYLIB : LC_LOAD_DYLIB, mh.magic),
      .cmdsize = SWAP32(cmdsize, mh.magic),
      .dylib = {
          .name = {static_cast<uint32_t>(SWAP32(sizeof(struct dylib_command), mh.magic))},
          .timestamp = 0,
          .current_version = 0,
          .compatibility_version = 0
      }
  };

  // find insertion point
  uint32_t sizeofcmds = SWAP32(mh.sizeofcmds, mh.magic);
  std::streamoff insert_pos = commands_offset + sizeofcmds;

  // check if there's enough space
  file_.seekg(insert_pos);
  std::vector<char> space_check(cmdsize);
  file_.read(space_check.data(), cmdsize);

  bool has_space = true;
  for (char c : space_check) {
    if (c != 0) {
      has_space = false;
      break;
    }
  }

  log_processor.dbg(
      "space check at insertion point", redlog::field("position", insert_pos), redlog::field("required_size", cmdsize),
      redlog::field("has_space", has_space)
  );

  if (!has_space && !ask_user("Not enough empty space detected. Continue anyway?")) {
    log_processor.trc("user declined to continue without sufficient space");
    return false;
  }

  // write the new load command
  log_processor.trc("writing dylib load command", redlog::field("position", insert_pos));
  file_.seekp(insert_pos);
  file_.write(reinterpret_cast<const char*>(&dylib_cmd), sizeof(dylib_cmd));

  // write padded dylib path
  std::vector<char> padded_path(dylib_path_size, 0);
  std::copy(dylib_path.begin(), dylib_path.end(), padded_path.begin());
  file_.write(padded_path.data(), dylib_path_size);

  log_processor.dbg(
      "wrote dylib path", redlog::field("original_length", dylib_path.length()),
      redlog::field("padded_length", dylib_path_size)
  );

  // update mach-o header
  uint32_t new_ncmds = SWAP32(mh.ncmds, mh.magic) + 1;
  uint32_t new_sizeofcmds = sizeofcmds + cmdsize;

  mh.ncmds = SWAP32(new_ncmds, mh.magic);
  mh.sizeofcmds = SWAP32(new_sizeofcmds, mh.magic);

  log_processor.trc(
      "updating mach-o header", redlog::field("old_ncmds", SWAP32(mh.ncmds, mh.magic) - 1),
      redlog::field("new_ncmds", new_ncmds), redlog::field("new_sizeofcmds", new_sizeofcmds)
  );

  file_.seekp(header_offset);
  file_.write(reinterpret_cast<const char*>(&mh), sizeof(mh));

  return true;
}

} // namespace w1::import_insertion::backend::macos