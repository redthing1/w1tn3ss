/*
graphvizdot.hpp

A modern, header-only C++17 library for generating Graphviz DOT language files.

This library provides a fluent and expressive interface for programmatically creating
graph structures and serializing them to the DOT format. It handles object lifecycle
management and DOT syntax details, such as quoting, automatically. The design
prioritizes a clean API, ease of use, and deterministic output.

Usage Example:

// Create a directed graph with a specified ID.
graphvizdot::graph my_graph("example_graph", graphvizdot::graph_type::directed);

// Set a global graph attribute using a type-safe enum.
my_graph.set_rank_dir(graphvizdot::rank_dir::left_to_right);

// Add nodes and chain attribute settings for a fluent configuration.
my_graph.add_node("Start").set("shape", "Mdiamond").set("color", "green");
my_graph.add_node("End").set("shape", "Msquare").set("color", "red");

// Add an edge connecting two nodes and set its label.
my_graph.add_edge("Start", "End").set("label", "initial transition");

// Generate and print the DOT file content to standard output.
std::cout << my_graph.to_string() << std::endl;

// Alternatively, write the output directly to a file.
my_graph.write_to_file("example.dot");

*/

#ifndef GRAPHVIZDOT_HPP_
#define GRAPHVIZDOT_HPP_

#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <set>
#include <optional>
#include <fstream>
#include <sstream>
#include <stdexcept>

// - main library namespace
namespace graphvizdot {

// - forward declarations
// forward declarations are necessary to resolve the circular dependencies
// between graph, subgraph, and writer within a single header file.
class attribute_set;
class node;
class edge;
class subgraph;
class graph;
class writer;

// - internal helper functions
namespace internal {

// checks if a string is a valid dot language id or if it requires quoting.
// a valid id is alphanumeric or a numeral, but cannot start with a numeral unless
// it is a number. this is a simplified, safer check that quotes anything that
// is not strictly alphanumeric (plus underscore). it also handles escaping
// quotes within the string.
inline std::string quote_if_needed(std::string_view str) {
  if (str.empty()) {
    return "\"\"";
  }

  bool needs_quoting = false;
  for (char c : str) {
    if (!std::isalnum(c) && c != '_') {
      needs_quoting = true;
      break;
    }
  }

  if (!needs_quoting) {
    // check for keywords
    if (str == "graph" || str == "digraph" || str == "subgraph" || str == "node" || str == "edge" || str == "strict") {
      needs_quoting = true;
    }
  }

  if (!needs_quoting) {
    return std::string(str);
  }

  std::string result = "\"";
  for (char c : str) {
    if (c == '"') {
      result += "\\\"";
    } else {
      result += c;
    }
  }
  result += '"';
  return result;
}

} // namespace internal

// - library enumerations
enum class graph_type { directed, undirected };

enum class rank_dir { top_to_bottom, bottom_to_top, left_to_right, right_to_left };

// - attribute management
// a class to manage a set of key-value string attributes.
// uses std::map to ensure deterministic, sorted output of attributes.
class attribute_set {
public:
  attribute_set() = default;

  // sets an attribute key-value pair. returns a reference to self for chaining.
  inline attribute_set& set(std::string_view key, std::string_view value);

  // gets an attribute value by its key, if it exists.
  inline std::optional<std::string> get(std::string_view key) const;

  // checks if a specific attribute key exists.
  inline bool has(std::string_view key) const;

  // checks if there are any attributes in the set.
  inline bool is_empty() const;

  // provides direct access to the underlying map for iteration.
  inline const std::map<std::string, std::string>& get_all() const;

private:
  std::map<std::string, std::string> _attributes;
};

// - graph components
// represents a single node in the graph.
class node {
public:
  // constructs a node with a given id. id is stored internally.
  node(std::string_view id) : _id(id) {}

  // sets an attribute for this node.
  inline node& set(std::string_view key, std::string_view value);

  inline const std::string& get_id() const { return _id; }
  inline const attribute_set& get_attributes() const { return _attributes; }

private:
  std::string _id;
  attribute_set _attributes;
};

// represents a single edge between two nodes.
class edge {
public:
  // constructs an edge between two nodes, identified by their ids.
  edge(std::string_view from_id, std::string_view to_id) : _from_id(from_id), _to_id(to_id) {}

  // sets an attribute for this edge.
  inline edge& set(std::string_view key, std::string_view value);

  inline const std::string& get_from_id() const { return _from_id; }
  inline const std::string& get_to_id() const { return _to_id; }
  inline const attribute_set& get_attributes() const { return _attributes; }

private:
  std::string _from_id;
  std::string _to_id;
  attribute_set _attributes;
};

// - graph containers
// forward-declared graph is required for subgraph's pointer.
class graph;

// represents a subgraph, which can contain nodes and other subgraphs.
// nodes are not owned by the subgraph, but by the root graph. the subgraph
// only stores the ids of the nodes it contains.
class subgraph {
public:
  // subgraphs must be constructed with a reference to the root graph and an id.
  subgraph(graph* root_graph, std::string_view id) : _root_graph(root_graph), _id(id) {
    if (!_root_graph) {
      throw std::invalid_argument("subgraph must have a valid root graph.");
    }
  }

  // sets an attribute for the subgraph itself (e.g., label, bgcolor).
  inline subgraph& set(std::string_view key, std::string_view value);

  // adds a node to this subgraph by its id.
  // if the node does not exist in the root graph, it will be created.
  inline node& add_node(std::string_view id);

  // adds a nested subgraph.
  inline subgraph& add_subgraph(std::string_view id);

  inline const std::string& get_id() const { return _id; }
  inline const attribute_set& get_attributes() const { return _attributes; }
  inline const std::vector<std::string>& get_node_ids() const { return _node_ids; }
  inline const std::map<std::string, subgraph>& get_subgraphs() const { return _subgraphs; }

private:
  graph* _root_graph; // non-owning pointer to the root graph.
  std::string _id;
  attribute_set _attributes;
  std::vector<std::string> _node_ids;
  std::map<std::string, subgraph> _subgraphs;
};

// represents the main graph document.
// this class is the central owner of all nodes, edges, and top-level subgraphs.
class graph {
public:
  // constructs a graph with a given id and type.
  graph(std::string_view id, graph_type type = graph_type::directed) : _id(id), _type(type) {}

  // - graph structure configuration

  // adds a node to the graph. if a node with this id already exists,
  // a reference to the existing node is returned.
  inline node& add_node(std::string_view id);

  // adds an edge to the graph.
  // if the `from` or `to` nodes do not exist, they are implicitly created.
  inline edge& add_edge(std::string_view from_id, std::string_view to_id);

  // adds a top-level subgraph to the graph.
  inline subgraph& add_subgraph(std::string_view id);

  // - attribute configuration

  // sets an attribute for the graph itself (e.g., rankdir, label).
  inline graph& set(std::string_view key, std::string_view value);

  // sets a type-safe rankdir attribute for the graph.
  inline graph& set_rank_dir(rank_dir dir);

  // sets a default attribute for all nodes in the graph.
  inline graph& set_default_node_attribute(std::string_view key, std::string_view value);

  // sets a default attribute for all edges in the graph.
  inline graph& set_default_edge_attribute(std::string_view key, std::string_view value);

  // - output generation

  // generates the full dot language string representation of the graph.
  inline std::string to_string() const;

  // writes the dot language representation of the graph to a file.
  inline void write_to_file(const std::string& filepath) const;

  // - accessors

  inline const std::string& get_id() const { return _id; }
  inline graph_type get_graph_type() const { return _type; }
  inline const attribute_set& get_attributes() const { return _attributes; }
  inline const attribute_set& get_default_node_attributes() const { return _default_node_attributes; }
  inline const attribute_set& get_default_edge_attributes() const { return _default_edge_attributes; }
  inline const std::map<std::string, node>& get_nodes() const { return _nodes; }
  inline const std::vector<edge>& get_edges() const { return _edges; }
  inline const std::map<std::string, subgraph>& get_subgraphs() const { return _subgraphs; }

private:
  friend class subgraph; // allows subgraph to call add_node on the root.

  std::string _id;
  graph_type _type;
  attribute_set _attributes;
  attribute_set _default_node_attributes;
  attribute_set _default_edge_attributes;

  // the graph maintains ownership of all nodes and edges.
  std::map<std::string, node> _nodes;
  std::vector<edge> _edges;
  std::map<std::string, subgraph> _subgraphs;
};

// - writer implementation
// class responsible for serializing the graph object model into a dot string.
class writer {
public:
  writer(const graph& g) : _graph(g) {}

  // generates and returns the dot string.
  inline std::string to_string() {
    write_graph_header();
    write_body();
    write_footer();
    return _ss.str();
  }

private:
  inline void write_graph_header() {
    _ss << (_graph.get_graph_type() == graph_type::directed ? "digraph " : "graph ")
        << internal::quote_if_needed(_graph.get_id()) << " {\n";
    _indent++;
  }

  inline void write_body() {
    write_attributes(_graph.get_attributes());
    write_default_attributes("node", _graph.get_default_node_attributes());
    write_default_attributes("edge", _graph.get_default_edge_attributes());

    for (const auto& [id, sg] : _graph.get_subgraphs()) {
      write_subgraph(sg);
    }

    // write nodes that are not part of any subgraph
    for (const auto& [id, n] : _graph.get_nodes()) {
      if (_written_node_ids.find(id) == _written_node_ids.end()) {
        write_node(n);
      }
    }

    for (const auto& e : _graph.get_edges()) {
      write_edge(e);
    }
  }

  inline void write_subgraph(const subgraph& sg) {
    do_indent();
    _ss << "subgraph " << internal::quote_if_needed(sg.get_id()) << " {\n";
    _indent++;

    write_attributes(sg.get_attributes());

    for (const auto& [id, nested_sg] : sg.get_subgraphs()) {
      write_subgraph(nested_sg);
    }

    for (const auto& node_id : sg.get_node_ids()) {
      auto it = _graph.get_nodes().find(node_id);
      if (it != _graph.get_nodes().end()) {
        write_node(it->second);
        _written_node_ids.insert(node_id);
      }
    }

    _indent--;
    do_indent();
    _ss << "}\n";
  }

  inline void write_attributes(const attribute_set& attrs) {
    if (attrs.is_empty()) {
      return;
    }

    for (const auto& [key, val] : attrs.get_all()) {
      do_indent();
      _ss << key << " = " << internal::quote_if_needed(val) << ";\n";
    }
  }

  inline void write_default_attributes(std::string_view target, const attribute_set& attrs) {
    if (attrs.is_empty()) {
      return;
    }
    do_indent();
    _ss << target << " ";
    write_attribute_list(attrs);
    _ss << ";\n";
  }

  inline void write_node(const node& n) {
    do_indent();
    _ss << internal::quote_if_needed(n.get_id());
    if (!n.get_attributes().is_empty()) {
      _ss << " ";
      write_attribute_list(n.get_attributes());
    }
    _ss << ";\n";
  }

  inline void write_edge(const edge& e) {
    do_indent();
    const char* edge_op = _graph.get_graph_type() == graph_type::directed ? " -> " : " -- ";
    _ss << internal::quote_if_needed(e.get_from_id()) << edge_op << internal::quote_if_needed(e.get_to_id());

    if (!e.get_attributes().is_empty()) {
      _ss << " ";
      write_attribute_list(e.get_attributes());
    }
    _ss << ";\n";
  }

  inline void write_attribute_list(const attribute_set& attrs) {
    _ss << "[";
    bool first = true;
    for (const auto& [key, val] : attrs.get_all()) {
      if (!first) {
        _ss << ", ";
      }
      _ss << key << "=" << internal::quote_if_needed(val);
      first = false;
    }
    _ss << "]";
  }

  inline void write_footer() {
    _indent--;
    _ss << "}\n";
  }

  inline void do_indent() {
    for (int i = 0; i < _indent; ++i) {
      _ss << "    ";
    }
  }

  const graph& _graph;
  std::stringstream _ss;
  int _indent = 0;
  std::set<std::string> _written_node_ids;
};

// - method implementations

// attribute_set
inline attribute_set& attribute_set::set(std::string_view key, std::string_view value) {
  _attributes[std::string(key)] = std::string(value);
  return *this;
}

inline std::optional<std::string> attribute_set::get(std::string_view key) const {
  auto it = _attributes.find(std::string(key));
  if (it != _attributes.end()) {
    return it->second;
  }
  return std::nullopt;
}

inline bool attribute_set::has(std::string_view key) const { return _attributes.count(std::string(key)); }

inline bool attribute_set::is_empty() const { return _attributes.empty(); }

inline const std::map<std::string, std::string>& attribute_set::get_all() const { return _attributes; }

// node
inline node& node::set(std::string_view key, std::string_view value) {
  _attributes.set(key, value);
  return *this;
}

// edge
inline edge& edge::set(std::string_view key, std::string_view value) {
  _attributes.set(key, value);
  return *this;
}

// subgraph
inline subgraph& subgraph::set(std::string_view key, std::string_view value) {
  _attributes.set(key, value);
  return *this;
}

inline node& subgraph::add_node(std::string_view id) {
  _node_ids.emplace_back(id);
  return _root_graph->add_node(id);
}

inline subgraph& subgraph::add_subgraph(std::string_view id) {
  auto it = _subgraphs.find(std::string(id));
  if (it == _subgraphs.end()) {
    it = _subgraphs.emplace(std::piecewise_construct, std::forward_as_tuple(id), std::forward_as_tuple(_root_graph, id))
             .first;
  }
  return it->second;
}

// graph
inline node& graph::add_node(std::string_view id) {
  auto it = _nodes.find(std::string(id));
  if (it == _nodes.end()) {
    // emplace returns a pair of <iterator, bool>, we want the iterator's second (the value)
    it = _nodes.emplace(std::piecewise_construct, std::forward_as_tuple(id), std::forward_as_tuple(id)).first;
  }
  return it->second;
}

inline edge& graph::add_edge(std::string_view from_id, std::string_view to_id) {
  add_node(from_id); // ensure nodes exist
  add_node(to_id);
  return _edges.emplace_back(from_id, to_id);
}

inline subgraph& graph::add_subgraph(std::string_view id) {
  auto it = _subgraphs.find(std::string(id));
  if (it == _subgraphs.end()) {
    it = _subgraphs.emplace(std::piecewise_construct, std::forward_as_tuple(id), std::forward_as_tuple(this, id)).first;
  }
  return it->second;
}

inline graph& graph::set(std::string_view key, std::string_view value) {
  _attributes.set(key, value);
  return *this;
}

inline graph& graph::set_rank_dir(rank_dir dir) {
  std::string_view val;
  switch (dir) {
  case rank_dir::top_to_bottom:
    val = "TB";
    break;
  case rank_dir::bottom_to_top:
    val = "BT";
    break;
  case rank_dir::left_to_right:
    val = "LR";
    break;
  case rank_dir::right_to_left:
    val = "RL";
    break;
  }
  _attributes.set("rankdir", val);
  return *this;
}

inline graph& graph::set_default_node_attribute(std::string_view key, std::string_view value) {
  _default_node_attributes.set(key, value);
  return *this;
}

inline graph& graph::set_default_edge_attribute(std::string_view key, std::string_view value) {
  _default_edge_attributes.set(key, value);
  return *this;
}

inline std::string graph::to_string() const {
  writer w(*this);
  return w.to_string();
}

inline void graph::write_to_file(const std::string& filepath) const {
  std::ofstream out_file(filepath);
  if (!out_file) {
    throw std::runtime_error("failed to open file for writing: " + filepath);
  }
  out_file << to_string();
}

} // namespace graphvizdot

#endif // GRAPHVIZDOT_HPP_