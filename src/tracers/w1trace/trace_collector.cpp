#include "trace_collector.hpp"
#include <cstdio>
#include <stdexcept>

namespace w1trace {

trace_collector::trace_collector(const std::string& output_file, size_t buffer_size)
    : output_file_(output_file), buffer_size_(buffer_size), buffer_(std::make_unique<char[]>(buffer_size)),
      buffer_pos_(0), instruction_count_(0), flush_count_(0), log_(redlog::get_logger("w1trace.collector")),
      shutdown_called_(false) {

  log_.inf(
      "trace collector initialized", redlog::field("output_file", output_file_),
      redlog::field("buffer_size", buffer_size_)
  );
}

trace_collector::~trace_collector() {
  if (!shutdown_called_) {
    shutdown();
  }
}

void trace_collector::add_instruction_address(uint64_t address) {
  // Format: hex address + newline (up to 17 chars: "ffffffffffffffff\n")
  constexpr size_t max_line_length = 17;

  // Check if we need to flush
  if (buffer_pos_ + max_line_length >= buffer_size_) {
    flush_buffer();
  }

  // Write address as hex string to buffer
  int written = snprintf(
      buffer_.get() + buffer_pos_, buffer_size_ - buffer_pos_, "%llx\n", static_cast<unsigned long long>(address)
  );

  if (written > 0 && written < static_cast<int>(buffer_size_ - buffer_pos_)) {
    buffer_pos_ += written;
    instruction_count_++;
  } else {
    log_.wrn("failed to write instruction address to buffer", redlog::field("address", "0x%llx", address));
  }
}

void trace_collector::flush() { flush_buffer(); }

void trace_collector::flush_buffer() {
  if (buffer_pos_ == 0) {
    return; // Nothing to flush
  }

  ensure_output_file();

  if (output_stream_.is_open()) {
    output_stream_.write(buffer_.get(), buffer_pos_);
    output_stream_.flush();

    log_.vrb("flushed buffer", redlog::field("bytes", buffer_pos_), redlog::field("instructions", instruction_count_));

    buffer_pos_ = 0;
    flush_count_++;
  } else {
    log_.err("cannot flush - output file not open", redlog::field("output_file", output_file_));
  }
}

void trace_collector::ensure_output_file() {
  if (!output_stream_.is_open()) {
    output_stream_.open(output_file_, std::ios::out | std::ios::trunc);
    if (!output_stream_.is_open()) {
      log_.err("failed to open output file", redlog::field("output_file", output_file_));
      throw std::runtime_error("Cannot open trace output file: " + output_file_);
    }
    log_.inf("opened output file", redlog::field("output_file", output_file_));
  }
}

void trace_collector::shutdown() {
  if (shutdown_called_) {
    return;
  }

  log_.inf("shutting down trace collector");

  // Flush any remaining data
  flush_buffer();

  // Close output file
  if (output_stream_.is_open()) {
    output_stream_.close();
  }

  log_.inf(
      "trace collector shutdown complete", redlog::field("total_instructions", instruction_count_),
      redlog::field("total_flushes", flush_count_)
  );

  shutdown_called_ = true;
}

} // namespace w1trace