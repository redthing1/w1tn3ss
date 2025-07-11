#include "output.hpp"
#include <w1tn3ss/util/jsonl_writer.hpp>
#include <redlog.hpp>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace w1::tracers::script::bindings {

// forward declaration from utilities.cpp
std::string lua_table_to_json(const sol::table& lua_table);

namespace {

std::string get_timestamp() {
  auto now = std::chrono::system_clock::now();
  auto time_t = std::chrono::system_clock::to_time_t(now);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

  std::stringstream ss;
  ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
  ss << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
  return ss.str();
}

} // anonymous namespace

output_module::~output_module() {
  if (initialized_) {
    close();
  }
}

bool output_module::init(sol::state_view lua, const std::string& filename, sol::optional<sol::table> metadata) {
  auto logger = redlog::get_logger("w1.script_output");

  // close any existing writer
  if (initialized_) {
    close();
  }

  try {
    // create new writer
    writer_ = std::make_shared<w1::util::jsonl_writer>(filename);

    if (!writer_->is_open()) {
      logger.err("failed to open output file", redlog::field("filename", filename));
      writer_.reset();
      return false;
    }

    // write metadata if provided
    sol::table meta_table;
    if (metadata) {
      meta_table = metadata.value();
    } else {
      // create default metadata table
      meta_table = lua.create_table();
    }

    // ensure required metadata fields
    meta_table["type"] = "metadata";
    if (!meta_table["version"].valid()) {
      meta_table["version"] = "1.0";
    }
    if (!meta_table["timestamp"].valid()) {
      meta_table["timestamp"] = get_timestamp();
    }
    if (!meta_table["tracer"].valid()) {
      meta_table["tracer"] = "w1script";
    }

    // write metadata line
    std::string json_metadata = lua_table_to_json(meta_table);
    if (!writer_->write_line(json_metadata)) {
      logger.err("failed to write metadata");
      writer_->close();
      writer_.reset();
      return false;
    }

    initialized_ = true;
    event_count_ = 0;
    logger.inf("output initialized", redlog::field("filename", filename));
    return true;

  } catch (const std::exception& e) {
    logger.err("exception initializing output", redlog::field("error", e.what()));
    writer_.reset();
    return false;
  }
}

bool output_module::write_event(sol::table event) {
  auto logger = redlog::get_logger("w1.script_output");

  if (!initialized_ || !writer_) {
    logger.err("output not initialized - call w1.output.init() first");
    return false;
  }

  try {
    // ensure event has a type
    if (!event["type"].valid()) {
      event["type"] = "event";
    }

    // convert to json and write
    std::string json_event = lua_table_to_json(event);
    bool success = writer_->write_line(json_event);

    if (success) {
      event_count_++;

      // periodic flush for performance
      if (event_count_ % 10000 == 0) {
        writer_->flush();
      }
    }

    return success;

  } catch (const std::exception& e) {
    logger.err("exception writing event", redlog::field("error", e.what()));
    return false;
  }
}

void output_module::close() {
  auto logger = redlog::get_logger("w1.script_output");

  if (!initialized_ || !writer_) {
    return;
  }

  try {
    // write summary if we have events
    if (event_count_ > 0) {
      // need lua state to create table
      // this is a bit awkward - we'll handle this in the binding setup
      std::stringstream summary;
      summary << "{\"type\":\"summary\","
              << "\"event_count\":" << event_count_ << ","
              << "\"end_timestamp\":\"" << get_timestamp() << "\"}";
      writer_->write_line(summary.str());
    }

    writer_->close();
    writer_.reset();
    initialized_ = false;

    logger.inf("output closed", redlog::field("events", event_count_));

  } catch (const std::exception& e) {
    logger.err("exception closing output", redlog::field("error", e.what()));
  }
}

void setup_output(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up output module");

  // create a shared output module instance
  auto output_instance = std::make_shared<output_module>();

  // create the w1.output table
  sol::table output_table = lua.create_table();

  // bind init function
  output_table["init"] = [output_instance,
                          &lua](const std::string& filename, sol::optional<sol::table> metadata) -> bool {
    return output_instance->init(lua, filename, metadata);
  };

  // bind write_event function
  output_table["write_event"] = [output_instance](sol::table event) -> bool {
    return output_instance->write_event(event);
  };

  // bind close function
  output_table["close"] = [output_instance]() { output_instance->close(); };

  // bind status functions
  output_table["is_initialized"] = [output_instance]() -> bool { return output_instance->is_initialized(); };

  output_table["get_event_count"] = [output_instance]() -> size_t { return output_instance->get_event_count(); };

  // attach to w1 module
  w1_module["output"] = output_table;

  logger.dbg("output module setup complete");
}

} // namespace w1::tracers::script::bindings