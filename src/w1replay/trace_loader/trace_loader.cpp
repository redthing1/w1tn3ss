#include "trace_loader.hpp"

#include <filesystem>

#include <redlog.hpp>

#include "w1rewind/replay/replay_context_builder.hpp"
#include "w1rewind/trace/trace_reader.hpp"

namespace w1replay::trace_loader {

namespace {

bool path_exists(const std::filesystem::path& path) {
  std::error_code error;
  return std::filesystem::exists(path, error);
}

} // namespace

bool load_trace(const trace_load_options& options, trace_load_result& out) {
  out = trace_load_result{};
  out.error.clear();

  if (options.trace_path.empty()) {
    out.error = "trace path required";
    return false;
  }

  auto stream = std::make_shared<w1::rewind::trace_reader>(options.trace_path);
  if (!stream->open()) {
    out.error = stream->error().empty() ? "failed to open trace" : std::string(stream->error());
    return false;
  }

  w1::rewind::replay_context context;
  std::string context_error;
  if (!w1::rewind::build_replay_context(*stream, context, context_error)) {
    stream->close();
    out.error = context_error.empty() ? "failed to build replay context" : context_error;
    return false;
  }

  stream->close();

  w1::rewind::trace_index index;
  w1::rewind::trace_index_options index_options;
  if (options.index_stride != 0) {
    index_options.anchor_stride = options.index_stride;
  }
  std::string index_error;
  std::filesystem::path index_path = options.index_path.empty()
                                         ? w1::rewind::default_trace_index_path(options.trace_path)
                                         : options.index_path;
  if (!w1::rewind::ensure_trace_index(
          std::filesystem::path(options.trace_path), index_path, index_options, index,
          index_error, options.auto_build_index
      )) {
    out.error = index_error.empty() ? "failed to load trace index" : index_error;
    return false;
  }

  std::shared_ptr<w1::rewind::replay_checkpoint_index> checkpoint_ptr;
  bool wants_checkpoint = !options.checkpoint_path.empty() || options.checkpoint_stride > 0;
  if (wants_checkpoint) {
    std::filesystem::path checkpoint_path = options.checkpoint_path.empty()
                                                ? w1::rewind::default_replay_checkpoint_path(options.trace_path)
                                                : options.checkpoint_path;
    bool checkpoint_exists = path_exists(checkpoint_path);

    auto checkpoint = std::make_shared<w1::rewind::replay_checkpoint_index>();
    std::string checkpoint_error;

    if (checkpoint_exists) {
      if (!w1::rewind::load_replay_checkpoint(checkpoint_path.string(), *checkpoint, checkpoint_error)) {
        if (!options.auto_build_checkpoint || options.checkpoint_stride == 0) {
          out.error = checkpoint_error.empty() ? "failed to load checkpoints" : checkpoint_error;
          return false;
        }
        checkpoint_exists = false;
      }
    }

    if (!checkpoint_exists) {
      if (!options.auto_build_checkpoint) {
        out.error = "checkpoint file missing";
        return false;
      }
      if (options.checkpoint_stride == 0) {
        out.error = "checkpoint stride required";
        return false;
      }

      w1::rewind::replay_checkpoint_config config{};
      config.trace_path = options.trace_path;
      config.output_path = checkpoint_path.string();
      config.stride = options.checkpoint_stride;
      config.include_memory = options.checkpoint_include_memory;

      if (!w1::rewind::build_replay_checkpoint(config, checkpoint.get(), checkpoint_error)) {
        out.error = checkpoint_error.empty() ? "failed to build checkpoints" : checkpoint_error;
        return false;
      }
    }

    checkpoint_ptr = std::move(checkpoint);
  }

  out.stream = std::move(stream);
  out.index = std::make_shared<w1::rewind::trace_index>(std::move(index));
  out.checkpoint = std::move(checkpoint_ptr);
  out.context = std::move(context);
  return true;
}

} // namespace w1replay::trace_loader
