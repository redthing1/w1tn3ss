#include "output_state.hpp"

#include <chrono>
#include <iomanip>
#include <sstream>

namespace w1::tracers::script::runtime {

namespace {

std::string format_timestamp() {
  auto now = std::chrono::system_clock::now();
  auto time_t = std::chrono::system_clock::to_time_t(now);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

  std::stringstream ss;
  ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
  ss << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
  return ss.str();
}

} // namespace

output_state::output_state() : logger_(redlog::get_logger("w1.script_output")) {}

bool output_state::open(const std::string& filename, const std::string& metadata_json) {
  if (initialized_) {
    close();
  }

  writer_ = std::make_shared<w1::util::jsonl_writer>(filename);
  if (!writer_->is_open()) {
    logger_.err("failed to open output file", redlog::field("filename", filename));
    writer_.reset();
    return false;
  }

  if (!metadata_json.empty()) {
    if (!writer_->write_line(metadata_json)) {
      logger_.err("failed to write metadata", redlog::field("filename", filename));
      writer_->close();
      writer_.reset();
      return false;
    }
  }

  initialized_ = true;
  event_count_ = 0;
  logger_.inf("output initialized", redlog::field("filename", filename));
  return true;
}

bool output_state::write_event(const std::string& json_line) {
  if (!initialized_ || !writer_) {
    logger_.err("output not initialized");
    return false;
  }

  if (!writer_->write_line(json_line)) {
    return false;
  }

  event_count_++;
  if (event_count_ % 10000 == 0) {
    writer_->flush();
  }

  return true;
}

void output_state::close() {
  if (!initialized_ || !writer_) {
    return;
  }

  if (event_count_ > 0) {
    auto summary = build_summary_json();
    if (!summary.empty()) {
      writer_->write_line(summary);
    }
  }

  writer_->close();
  writer_.reset();
  initialized_ = false;

  logger_.inf("output closed", redlog::field("events", event_count_));
}

std::string output_state::build_summary_json() const {
  std::stringstream summary;
  summary << "{\"type\":\"summary\",";
  summary << "\"event_count\":" << event_count_ << ',';
  summary << "\"end_timestamp\":\"" << format_timestamp() << "\"}";
  return summary.str();
}

} // namespace w1::tracers::script::runtime
