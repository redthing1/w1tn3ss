#pragma once

/**
 * @file interval_tree.hpp
 * @brief A high-performance, header-only, immutable interval tree for C++17.
 *
 * @par Description
 * This file contains a modern C++17 implementation of an interval tree. The tree
 * is constructed from a collection of intervals and provides fast queries for
 * finding intervals that overlap a given point or another interval. The tree is
 * immutable; once constructed, it cannot be modified. This design simplifies
 * the data structure and makes it inherently thread-safe for concurrent reads.
 *
 * The implementation uses a center-point partitioning strategy, choosing the
 * median of all interval endpoints to ensure the tree is well-balanced.
 *
 * @par Time Complexity
 * - **Construction:** O(N log N)
 * - **Query:** O(log N + K), where N is the total number of intervals and K is
 *   the number of reported results.
 *
 * @par Interval Convention
 * All intervals are treated as half-open: `[start, stop)`. This means the
 * start point is inclusive, and the stop point is exclusive.
 *
 * @par API
 * The primary class is `interval_tree::interval_tree<Scalar, Value>`.
 * It can be constructed from any iterator pair or an `std::initializer_list`.
 *
 * Two types of query methods are provided:
 * 1.  `find_*` methods: Return a `std::vector` of matching intervals. Convenient
 *     but involves memory allocation.
 * 2.  `visit_*` methods: Take a callable (e.g., a lambda) and invoke it for
 *     each matching interval. This is a higher-performance alternative that
 *     avoids allocating a result vector.
 *
 * @par Example
 * @code
 * #include "interval_tree.hpp"
 * #include <iostream>
 * #include <string>
 * #include <vector>
 *
 * int main() {
 *     using tree_t = interval_tree::interval_tree<int, std::string>;
 *     using interval_t = tree_t::interval_type;
 *
 *     std::vector<interval_t> intervals = {{5, 10, "A"}, {12, 18, "B"}};
 *     tree_t tree(intervals.begin(), intervals.end());
 *
 *     // Find intervals overlapping the point 7.
 *     auto results = tree.find_overlapping(7);
 *     for (const auto& r : results) {
 *         std::cout << r << std::endl; // Prints "interval[5, 10): A"
 *     }
 *
 *     // Use a visitor to find intervals overlapping the range [9, 13).
 *     tree.visit_overlapping(9, 13, [](const interval_t& r) {
 *         std::cout << "Visitor found: " << r << std::endl;
 *     });
 *     // Prints "Visitor found: interval[5, 10): A"
 *     // Prints "Visitor found: interval[12, 18): B"
 * }
 * @endcode
 */

#include <algorithm>
#include <cassert>
#include <chrono>
#include <functional>
#include <iostream>
#include <iterator>
#include <memory>
#include <numeric>
#include <vector>

namespace interval_tree {

template <typename Scalar, typename Value> struct interval {
  using scalar_type = Scalar;
  using value_type = Value;

  scalar_type start;
  scalar_type stop;
  value_type value;

  interval(const scalar_type& s, const scalar_type& e, const value_type& v)
      : start(std::min(s, e)), stop(std::max(s, e)), value(std::move(v)) {}

  [[nodiscard]] scalar_type length() const noexcept { return stop - start; }

  [[nodiscard]] bool contains(const scalar_type& point) const noexcept { return point >= start && point < stop; }

  [[nodiscard]] bool overlaps(const interval& other) const noexcept { return start < other.stop && stop > other.start; }
};

template <typename Scalar, typename Value>
std::ostream& operator<<(std::ostream& os, const interval<Scalar, Value>& i) {
  os << "interval[" << i.start << ", " << i.stop << "): " << i.value;
  return os;
}

template <typename Scalar, typename Value> class interval_tree {
public:
  using interval_type = interval<Scalar, Value>;
  using scalar_type = Scalar;
  using value_type = Value;
  using size_type = std::size_t;

private:
  static constexpr size_type MAX_DEPTH = 32;
  static constexpr size_type LEAF_NODE_THRESHOLD = 64;

public:
  interval_tree() noexcept = default;

  template <typename FwdIt> interval_tree(FwdIt first, FwdIt last) {
    std::vector<interval_type> intervals(first, last);
    size_ = intervals.size();
    if (!intervals.empty()) {
      build_tree(std::move(intervals), 0);
    }
  }

  interval_tree(std::initializer_list<interval_type> ilist) : interval_tree(ilist.begin(), ilist.end()) {}

  interval_tree(const interval_tree& other)
      : center_(other.center_), size_(other.size_), intervals_by_start_(other.intervals_by_start_),
        intervals_by_stop_(other.intervals_by_stop_),
        left_(other.left_ ? std::make_unique<interval_tree>(*other.left_) : nullptr),
        right_(other.right_ ? std::make_unique<interval_tree>(*other.right_) : nullptr) {}

  interval_tree& operator=(const interval_tree& other) {
    if (this == &other) {
      return *this;
    }
    center_ = other.center_;
    size_ = other.size_;
    intervals_by_start_ = other.intervals_by_start_;
    intervals_by_stop_ = other.intervals_by_stop_;
    left_ = other.left_ ? std::make_unique<interval_tree>(*other.left_) : nullptr;
    right_ = other.right_ ? std::make_unique<interval_tree>(*other.right_) : nullptr;
    return *this;
  }

  interval_tree(interval_tree&& other) noexcept = default;
  interval_tree& operator=(interval_tree&& other) noexcept = default;
  ~interval_tree() = default;

  [[nodiscard]] std::vector<interval_type> find_overlapping(const scalar_type& point) const {
    std::vector<interval_type> result;
    visit_overlapping(point, [&](const interval_type& interval) { result.push_back(interval); });
    return result;
  }

  [[nodiscard]] std::vector<interval_type> find_overlapping(const scalar_type& start, const scalar_type& stop) const {
    std::vector<interval_type> result;
    if (start < stop) {
      visit_overlapping(start, stop, [&](const interval_type& interval) { result.push_back(interval); });
    }
    return result;
  }

  [[nodiscard]] std::vector<interval_type> find_contained(const scalar_type& start, const scalar_type& stop) const {
    std::vector<interval_type> result;
    if (start < stop) {
      visit_contained(start, stop, [&](const interval_type& interval) { result.push_back(interval); });
    }
    return result;
  }

  template <typename Visitor> void visit_overlapping(const scalar_type& point, Visitor visitor) const {
    if (empty()) {
      return;
    }
    visit_point_impl(point, visitor);
  }

  /**
   * @brief Visits all intervals that overlap a given query interval [start, stop).
   * @pre `start <= stop`.
   */
  template <typename Visitor>
  void visit_overlapping(const scalar_type& start, const scalar_type& stop, Visitor visitor) const {
    if (empty() || start >= stop) {
      return;
    }
    visit_overlapping_impl(start, stop, visitor);
  }

  /**
   * @brief Visits all intervals that are completely contained within a query interval.
   * @pre `start <= stop`.
   */
  template <typename Visitor>
  void visit_contained(const scalar_type& start, const scalar_type& stop, Visitor visitor) const {
    if (empty() || start >= stop) {
      return;
    }
    visit_contained_impl(start, stop, visitor);
  }

  template <typename Visitor> void visit_all(Visitor visitor) const {
    if (left_) {
      left_->visit_all(visitor);
    }
    for (const auto& interval : intervals_by_start_) {
      visitor(interval);
    }
    if (right_) {
      right_->visit_all(visitor);
    }
  }

  [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

  [[nodiscard]] size_type size() const noexcept { return size_; }

private:
  scalar_type center_{};
  size_type size_ = 0;
  std::vector<interval_type> intervals_by_start_;
  std::vector<interval_type> intervals_by_stop_;
  std::unique_ptr<interval_tree> left_ = nullptr;
  std::unique_ptr<interval_tree> right_ = nullptr;

  interval_tree(std::vector<interval_type>&& intervals, size_type depth) {
    size_ = intervals.size();
    build_tree(std::move(intervals), depth);
  }

  void build_tree(std::vector<interval_type>&& intervals, size_type depth);

  template <typename Visitor> void visit_point_impl(const scalar_type& point, Visitor& visitor) const;

  template <typename Visitor>
  void visit_overlapping_impl(const scalar_type& query_start, const scalar_type& query_stop, Visitor& visitor) const;

  template <typename Visitor>
  void visit_contained_impl(const scalar_type& query_start, const scalar_type& query_stop, Visitor& visitor) const;
};

template <typename S, typename V>
void interval_tree<S, V>::build_tree(std::vector<interval_type>&& intervals, size_type depth) {
  if (depth >= MAX_DEPTH || intervals.size() <= LEAF_NODE_THRESHOLD) {
    intervals_by_start_ = std::move(intervals);
    std::sort(intervals_by_start_.begin(), intervals_by_start_.end(), [](const auto& a, const auto& b) {
      return a.start < b.start;
    });
    intervals_by_stop_ = intervals_by_start_;
    std::sort(intervals_by_stop_.begin(), intervals_by_stop_.end(), [](const auto& a, const auto& b) {
      return a.stop < b.stop;
    });
    return;
  }

  std::vector<scalar_type> coords;
  coords.reserve(intervals.size() * 2);
  for (const auto& i : intervals) {
    coords.push_back(i.start);
    coords.push_back(i.stop);
  }
  auto median_it = coords.begin() + coords.size() / 2;
  std::nth_element(coords.begin(), median_it, coords.end());
  center_ = *median_it;

  std::vector<interval_type> left_intervals;
  std::vector<interval_type> right_intervals;

  for (auto& interval : intervals) {
    if (interval.stop < center_) {
      left_intervals.push_back(std::move(interval));
    } else if (interval.start > center_) {
      right_intervals.push_back(std::move(interval));
    } else {
      intervals_by_start_.push_back(std::move(interval));
    }
  }
  intervals.clear();

  std::sort(intervals_by_start_.begin(), intervals_by_start_.end(), [](const auto& a, const auto& b) {
    return a.start < b.start;
  });
  intervals_by_stop_ = intervals_by_start_;
  std::sort(intervals_by_stop_.begin(), intervals_by_stop_.end(), [](const auto& a, const auto& b) {
    return a.stop < b.stop;
  });

  if (!left_intervals.empty()) {
    left_.reset(new interval_tree(std::move(left_intervals), depth + 1));
  }
  if (!right_intervals.empty()) {
    right_.reset(new interval_tree(std::move(right_intervals), depth + 1));
  }
}

template <typename S, typename V>
template <typename Visitor>
void interval_tree<S, V>::visit_point_impl(const scalar_type& point, Visitor& visitor) const {
  for (const auto& interval : intervals_by_start_) {
    if (interval.start > point) {
      break;
    }
    if (interval.stop > point) {
      visitor(interval);
    }
  }

  if (left_ && point < center_) {
    left_->visit_point_impl(point, visitor);
  }
  if (right_ && point >= center_) {
    right_->visit_point_impl(point, visitor);
  }
}

template <typename S, typename V>
template <typename Visitor>
void interval_tree<S, V>::visit_overlapping_impl(
    const scalar_type& query_start, const scalar_type& query_stop, Visitor& visitor
) const {
  for (const auto& interval : intervals_by_start_) {
    if (interval.start >= query_stop) {
      break;
    }
    // The interval must not be empty (start < stop) for it to overlap.
    if (interval.stop > query_start && interval.start < interval.stop) {
      visitor(interval);
    }
  }

  if (left_ && query_start < center_) {
    left_->visit_overlapping_impl(query_start, query_stop, visitor);
  }
  if (right_ && query_stop > center_) {
    right_->visit_overlapping_impl(query_start, query_stop, visitor);
  }
}

template <typename S, typename V>
template <typename Visitor>
void interval_tree<S, V>::visit_contained_impl(
    const scalar_type& query_start, const scalar_type& query_stop, Visitor& visitor
) const {
  for (const auto& interval : intervals_by_start_) {
    if (interval.start >= query_stop) {
      break;
    }
    if (interval.start >= query_start && interval.stop <= query_stop) {
      visitor(interval);
    }
  }

  if (left_ && query_start < center_) {
    left_->visit_contained_impl(query_start, query_stop, visitor);
  }
  if (right_ && query_stop > center_) {
    right_->visit_contained_impl(query_start, query_stop, visitor);
  }
}

} // namespace interval_tree