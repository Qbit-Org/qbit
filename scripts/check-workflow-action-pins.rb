#!/usr/bin/env ruby
# frozen_string_literal: true

require "pathname"
require "psych"

WORKFLOW_DIR = Pathname(".github/workflows")
SHA_PIN_RE = /\A[^@\s]+@[0-9a-fA-F]{40}\z/
SEQUENCE_ITEM = :sequence_item

def workflow_paths(args)
  return args.map { |arg| Pathname(arg) } unless args.empty?

  unless WORKFLOW_DIR.directory?
    warn "workflow directory not found: #{WORKFLOW_DIR}; run from the repository root or pass workflow file paths"
    exit 1
  end

  paths = WORKFLOW_DIR.children
                      .select { |path| path.file? && [".yml", ".yaml"].include?(path.extname) }
                      .sort
  if paths.empty?
    warn "no workflow files found under #{WORKFLOW_DIR}"
    exit 1
  end

  paths
end

def external_action?(ref)
  !ref.start_with?("./", "docker://")
end

def register_anchor(node, anchors)
  return if node.is_a?(Psych::Nodes::Alias)
  return unless node.respond_to?(:anchor) && node.anchor

  anchors[node.anchor] = [node, anchors.dup]
end

def scalar_value(node, anchors, seen = [])
  case node
  when Psych::Nodes::Scalar
    node.value.to_s.strip
  when Psych::Nodes::Alias
    return nil if seen.include?(node.anchor)

    target, target_anchors = anchors[node.anchor]
    target ? scalar_value(target, target_anchors.dup, seen + [node.anchor]) : nil
  end
end

def action_uses_context?(path)
  job_level = path.length == 2 && path[0] == "jobs"
  step_level = path.length == 4 &&
               path[0] == "jobs" &&
               path[-2] == "steps" &&
               path[-1] == SEQUENCE_ITEM
  job_level || step_level
end

def collect_uses_refs(node, workflow_path, traversal_path, refs, anchors, seen_aliases = [])
  if node.is_a?(Psych::Nodes::Alias)
    return if seen_aliases.include?(node.anchor)

    target, target_anchors = anchors[node.anchor]
    if target
      collect_uses_refs(target, workflow_path, traversal_path, refs, target_anchors.dup, seen_aliases + [node.anchor])
    end
    return
  end

  register_anchor(node, anchors)

  case node
  when Psych::Nodes::Stream
    node.children.each { |child| collect_uses_refs(child, workflow_path, traversal_path, refs, anchors, seen_aliases) }
  when Psych::Nodes::Sequence
    node.children.each do |child|
      collect_uses_refs(child, workflow_path, traversal_path + [SEQUENCE_ITEM], refs, anchors, seen_aliases)
    end
  when Psych::Nodes::Document
    collect_uses_refs(node.root, workflow_path, traversal_path, refs, anchors, seen_aliases) if node.root
  when Psych::Nodes::Mapping
    node.children.each_slice(2) do |key_node, value_node|
      register_anchor(key_node, anchors)
      key = scalar_value(key_node, anchors)
      if key == "uses" && action_uses_context?(traversal_path)
        line = key_node.start_line + 1
        register_anchor(value_node, anchors)
        ref = scalar_value(value_node, anchors).to_s
        refs << [workflow_path, line, ref]
      else
        next_path = key ? traversal_path + [key] : traversal_path
        collect_uses_refs(value_node, workflow_path, next_path, refs, anchors, seen_aliases)
      end
    end
  end
end

def check_file(path)
  refs = []
  tree = Psych.parse_file(path.to_s)
  if tree
    anchors = {}
    collect_uses_refs(tree, path, [], refs, anchors)
  end

  errors = []
  refs.each do |workflow_path, line, ref|
    if ref.empty?
      errors << "#{workflow_path}:#{line}: active uses ref is empty"
    elsif external_action?(ref) && !SHA_PIN_RE.match?(ref)
      errors << "#{workflow_path}:#{line}: active uses ref must be pinned to a full commit SHA: #{ref}"
    end
  end
  errors
rescue Psych::SyntaxError => e
  ["#{path}:#{e.line}: YAML parse error: #{e.problem}"]
rescue Errno::ENOENT
  ["#{path}: file not found"]
end

paths = workflow_paths(ARGV)
errors = paths.flat_map { |path| check_file(path) }

if errors.empty?
  puts "checked #{paths.length} workflow file(s); all external uses refs are SHA-pinned"
  exit 0
end

warn errors.join("\n")
exit 1
