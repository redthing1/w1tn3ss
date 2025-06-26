/**
 * @file performance_monitor.hpp
 * @brief Generic performance monitoring utilities for w1tn3ss framework
 * 
 * This component provides reusable performance tracking, statistics collection,
 * and reporting functionality that can be used by any tracer implementation.
 */

#pragma once

#include <redlog/redlog.hpp>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <string>
#include <memory>
#include <mutex>

namespace w1::framework {

/**
 * @brief Performance monitoring configuration
 */
struct performance_config {
    uint64_t report_interval = 10000;        // Report every N callbacks
    bool enable_periodic_reports = true;      // Enable automatic periodic reporting
    bool enable_detailed_timing = false;      // Enable detailed per-operation timing
    bool enable_memory_tracking = false;      // Enable memory usage tracking
};

/**
 * @brief Performance counter for tracking specific metrics
 */
class performance_counter {
public:
    performance_counter() : count_(0), total_time_(0), min_time_(UINT64_MAX), max_time_(0) {}

    void record_event(uint64_t duration_ns = 0) {
        count_.fetch_add(1, std::memory_order_relaxed);
        
        if (duration_ns > 0) {
            total_time_.fetch_add(duration_ns, std::memory_order_relaxed);
            
            // Update min/max with simple compare-and-swap
            uint64_t current_min = min_time_.load(std::memory_order_relaxed);
            while (duration_ns < current_min && 
                   !min_time_.compare_exchange_weak(current_min, duration_ns, std::memory_order_relaxed)) {
                // Keep trying
            }
            
            uint64_t current_max = max_time_.load(std::memory_order_relaxed);
            while (duration_ns > current_max && 
                   !max_time_.compare_exchange_weak(current_max, duration_ns, std::memory_order_relaxed)) {
                // Keep trying
            }
        }
    }

    uint64_t get_count() const { return count_.load(std::memory_order_relaxed); }
    uint64_t get_total_time_ns() const { return total_time_.load(std::memory_order_relaxed); }
    uint64_t get_min_time_ns() const { 
        uint64_t min_val = min_time_.load(std::memory_order_relaxed);
        return min_val == UINT64_MAX ? 0 : min_val;
    }
    uint64_t get_max_time_ns() const { return max_time_.load(std::memory_order_relaxed); }
    
    double get_average_time_ns() const {
        uint64_t count = get_count();
        return count > 0 ? static_cast<double>(get_total_time_ns()) / count : 0.0;
    }

private:
    std::atomic<uint64_t> count_;
    std::atomic<uint64_t> total_time_;
    std::atomic<uint64_t> min_time_;
    std::atomic<uint64_t> max_time_;
};

/**
 * @brief RAII timer for measuring operation duration
 */
class scoped_timer {
public:
    explicit scoped_timer(performance_counter& counter) 
        : counter_(counter), start_time_(std::chrono::high_resolution_clock::now()) {}
    
    ~scoped_timer() {
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time_);
        counter_.record_event(duration.count());
    }

private:
    performance_counter& counter_;
    std::chrono::high_resolution_clock::time_point start_time_;
};

/**
 * @brief Macro for easy timing of operations
 */
#define PERFORMANCE_TIME_OPERATION(monitor, operation_name) \
    auto _timer = (monitor).create_scoped_timer(operation_name)

/**
 * @brief Comprehensive performance monitoring system
 */
class performance_monitor {
public:
    explicit performance_monitor(const performance_config& config = {})
        : log_(redlog::get_logger("w1tn3ss.performance"))
        , config_(config)
        , monitoring_active_(false)
        , start_time_(0)
        , last_report_time_(0) {
        
        log_.debug("performance monitor created", 
                  redlog::field("report_interval", config_.report_interval));
    }

    ~performance_monitor() {
        if (monitoring_active_) {
            generate_final_report();
        }
        log_.debug("performance monitor destroyed");
    }

    /**
     * @brief Start performance monitoring
     */
    void start_monitoring() {
        if (monitoring_active_) {
            log_.warn("performance monitoring already active");
            return;
        }

        auto now = std::chrono::steady_clock::now();
        start_time_ = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        last_report_time_.store(start_time_);
        monitoring_active_ = true;

        log_.info("performance monitoring started", redlog::field("start_time", start_time_));
    }

    /**
     * @brief Stop performance monitoring
     */
    void stop_monitoring() {
        if (!monitoring_active_) {
            return;
        }

        monitoring_active_ = false;
        generate_final_report();
        
        log_.info("performance monitoring stopped");
    }

    /**
     * @brief Record a simple event (e.g., callback invocation)
     */
    void record_event(const std::string& event_name = "default") {
        if (!monitoring_active_) {
            return;
        }

        get_or_create_counter(event_name).record_event();
        
        // Check if we should generate a periodic report
        if (config_.enable_periodic_reports) {
            uint64_t total_events = get_total_events();
            if (total_events % config_.report_interval == 0) {
                generate_periodic_report();
            }
        }
    }

    /**
     * @brief Record a timed event
     */
    void record_timed_event(const std::string& event_name, uint64_t duration_ns) {
        if (!monitoring_active_) {
            return;
        }

        get_or_create_counter(event_name).record_event(duration_ns);
    }

    /**
     * @brief Create a scoped timer for automatic timing
     */
    std::unique_ptr<scoped_timer> create_scoped_timer(const std::string& event_name) {
        if (!monitoring_active_ || !config_.enable_detailed_timing) {
            return nullptr;
        }

        return std::make_unique<scoped_timer>(get_or_create_counter(event_name));
    }

    /**
     * @brief Get performance statistics
     */
    struct performance_stats {
        uint64_t total_events = 0;
        uint64_t elapsed_time_ms = 0;
        double events_per_second = 0.0;
        std::unordered_map<std::string, uint64_t> event_counts;
        std::unordered_map<std::string, double> average_times_us;
    };

    performance_stats get_statistics() const {
        performance_stats stats;
        
        if (!monitoring_active_) {
            return stats;
        }

        auto now = std::chrono::steady_clock::now();
        uint64_t current_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        
        stats.elapsed_time_ms = current_time - start_time_;
        
        for (const auto& [name, counter] : counters_) {
            uint64_t count = counter->get_count();
            stats.total_events += count;
            stats.event_counts[name] = count;
            
            if (config_.enable_detailed_timing) {
                stats.average_times_us[name] = counter->get_average_time_ns() / 1000.0;
            }
        }

        if (stats.elapsed_time_ms > 0) {
            stats.events_per_second = (stats.total_events * 1000.0) / stats.elapsed_time_ms;
        }

        return stats;
    }

    /**
     * @brief Generate periodic performance report
     */
    void generate_periodic_report() {
        if (!monitoring_active_) {
            return;
        }

        auto now = std::chrono::steady_clock::now();
        uint64_t current_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        uint64_t last_report = last_report_time_.exchange(current_time);
        
        auto stats = get_statistics();
        uint64_t interval_time = current_time - last_report;
        
        log_.info("performance report",
                 redlog::field("total_events", stats.total_events),
                 redlog::field("elapsed_ms", stats.elapsed_time_ms),
                 redlog::field("interval_ms", interval_time),
                 redlog::field("events_per_sec", stats.events_per_second));

        // Log detailed event breakdown if enabled
        for (const auto& [event_name, count] : stats.event_counts) {
            log_.debug("event statistics",
                      redlog::field("event", event_name),
                      redlog::field("count", count));
        }
    }

    /**
     * @brief Generate final performance report
     */
    void generate_final_report() {
        auto stats = get_statistics();
        
        log_.info("final performance report",
                 redlog::field("total_events", stats.total_events),
                 redlog::field("total_time_ms", stats.elapsed_time_ms),
                 redlog::field("average_events_per_sec", stats.events_per_second));

        // Detailed breakdown
        for (const auto& [event_name, count] : stats.event_counts) {
            if (config_.enable_detailed_timing && stats.average_times_us.count(event_name)) {
                log_.info("event final statistics",
                         redlog::field("event", event_name),
                         redlog::field("count", count),
                         redlog::field("avg_time_us", stats.average_times_us.at(event_name)));
            } else {
                log_.info("event final statistics",
                         redlog::field("event", event_name),
                         redlog::field("count", count));
            }
        }
    }

    /**
     * @brief Check if monitoring is active
     */
    bool is_monitoring_active() const { return monitoring_active_; }

private:
    redlog::logger log_;
    performance_config config_;
    bool monitoring_active_;
    uint64_t start_time_;
    std::atomic<uint64_t> last_report_time_;
    
    // Thread-safe storage for performance counters
    mutable std::unordered_map<std::string, std::unique_ptr<performance_counter>> counters_;
    mutable std::mutex counters_mutex_;

    performance_counter& get_or_create_counter(const std::string& name) {
        std::lock_guard<std::mutex> lock(counters_mutex_);
        
        auto it = counters_.find(name);
        if (it != counters_.end()) {
            return *it->second;
        }

        auto counter = std::make_unique<performance_counter>();
        performance_counter& ref = *counter;
        counters_[name] = std::move(counter);
        
        return ref;
    }

    uint64_t get_total_events() const {
        std::lock_guard<std::mutex> lock(counters_mutex_);
        uint64_t total = 0;
        for (const auto& [name, counter] : counters_) {
            total += counter->get_count();
        }
        return total;
    }
};

} // namespace w1::framework