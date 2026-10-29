#!/usr/bin/env ruby
# frozen_string_literal: true

# Native Ruby syntax and Cucumber witness helper. `analyze` uses Ripper for
# dependency syntax. RubyVM AST supplies exact CRuby block spans and positional
# arity. `run` executes Cucumber without interpreting its patterns.
require "json"
require "optparse"
require "ripper"
require "rbconfig"

SCHEMA = "r2t.rbsyntax/1"
# Cucumber-Ruby exposes And/But aliases too; the pinned project uses four And
# declarations. Their runtime matching remains keyword-agnostic.
DSL = %i[Given When Then And But].freeze

def token_name(node)
  return nil unless node.is_a?(Array)
  return node[1] if %i[@ident @const].include?(node[0])
  return token_name(node[1]) if %i[fcall vcall command method_add_arg].include?(node[0])
  nil
end

def arguments(node)
  return [] unless node.is_a?(Array)
  case node[0]
  when :command then arguments(node[2])
  when :method_add_arg then arguments(node[2])
  when :arg_paren then arguments(node[1])
  when :args_add_block then node[1] || []
  else []
  end
end

def literal_string(node)
  return nil unless node.is_a?(Array) && node[0] == :string_literal
  content = node[1]
  return "" if content == [:string_content]
  return nil unless content.is_a?(Array) && content[0] == :string_content
  pieces = content.drop(1)
  return nil unless pieces.all? { |piece| piece.is_a?(Array) && piece[0] == :@tstring_content }
  pieces.map { |piece| piece[1] }.join
end

def constant_name(node)
  return nil unless node.is_a?(Array)
  case node[0]
  when :var_ref then token_name(node[1])
  when :const_path_ref
    left = constant_name(node[1]); right = token_name(node[2])
    left && right ? "#{left}::#{right}" : nil
  when :top_const_ref
    name = token_name(node[1]); name && "::#{name}"
  end
end

def walk_sexp(node, out)
  return unless node.is_a?(Array)
  name = token_name(node)
  # Only complete call nodes own arguments. Recursing into their :fcall or
  # token children and treating those as calls would emit a second,
  # spuriously-dynamic require for every literal require.
  if %i[command method_add_arg].include?(node[0]) &&
     %w[require require_relative World].include?(name)
    args = arguments(node)
    pos = node.flatten.each_cons(2).find { |a, b| a.is_a?(Integer) && b.is_a?(Integer) }
    line = pos && pos[0]
    if name == "World"
      out[:worlds] << { "module" => constant_name(args.first), "line" => line }
    else
      value = literal_string(args.first)
      out[:requires] << { "kind" => name, "value" => value,
                          "literal" => !value.nil?, "line" => line }
    end
  end
  node.each { |child| walk_sexp(child, out) if child.is_a?(Array) }
end

def positional_arity(args)
  return 0 if args.nil?
  c = args.children
  required, optional, post, rest, keywords, kwrest, block = c[0], c[2], c[4], c[6], c[7], c[8], c[9]
  unless required.is_a?(Integer) && post.is_a?(Integer) && optional.nil? &&
         post.zero? && rest.nil? && keywords.nil? && kwrest.nil? && block.nil?
    raise "unsupported optional/rest/keyword/block parameters"
  end
  required
end

def position_in_span?(position, first, last)
  (position <=> first) >= 0 && (position <=> last) < 0
end

def heredoc_spans(source)
  pending = []
  spans = []
  Ripper.lex(source).each do |position, type, text, _state|
    if type == :on_heredoc_beg
      pending << position
    elsif type == :on_heredoc_end
      raise "heredoc terminator has no opener" if pending.empty?
      opener = pending.shift
      # Keep the terminator's line ending: replacing the block interior with
      # `nil` then leaves the closing `end` on its original line. Columns and
      # bytesizes are both byte-oriented on the pinned CRuby parser.
      terminator = text.sub(/\r?\n\z/, "")
      spans << [opener, [position[0], position[1] + terminator.bytesize]]
    end
  end
  raise "heredoc opener has no terminator" unless pending.empty?
  spans
end

def walk_ast(node, definitions, errors, heredocs)
  return unless node.is_a?(RubyVM::AbstractSyntaxTree::Node)
  if node.type == :ITER
    call, scope = node.children
    name = call.children[0] if call&.type == :FCALL
    if DSL.include?(name)
      body = scope.children[2]
      begin
        raise "step block has no body" unless body
        first = [body.first_lineno, body.first_column]
        last = [body.last_lineno, body.last_column]
        # RubyVM reports a heredoc expression only through the opener line.
        # Ripper owns the literal geometry; extend only for openers inside this
        # block body so literals before or after the definition stay untouched.
        heredocs.each do |opener, terminator_end|
          last = [last, terminator_end].max if position_in_span?(opener, first, last)
        end
        definitions << {
          "line" => node.first_lineno, "dsl" => name.to_s,
          "arity" => positional_arity(scope.children[1]),
          "body" => { "start_line" => first[0],
                       "start_column" => first[1],
                       "end_line" => last[0],
                       "end_column" => last[1] }
        }
      rescue StandardError => e
        errors << "line #{node.first_lineno}: #{e.message}"
      end
    end
  end
  node.children.each { |child| walk_ast(child, definitions, errors, heredocs) }
end

def analyze_source(source, path)
  sexp = Ripper.sexp(source, path)
  return { "path" => path, "error" => "Ripper rejected the source" } unless sexp
  syntax = { requires: [], worlds: [] }
  walk_sexp(sexp, syntax)
  definitions = []; errors = []
  begin
    spans = heredoc_spans(source)
    walk_ast(RubyVM::AbstractSyntaxTree.parse(source), definitions, errors, spans)
  rescue SyntaxError => e
    return { "path" => path, "error" => e.message }
  rescue StandardError => e
    return { "path" => path, "error" => e.message }
  end
  { "path" => path, "requires" => syntax[:requires].uniq,
    "worlds" => syntax[:worlds].uniq,
    "definitions" => definitions.sort_by { |d| [d["line"], d["dsl"]] },
    "errors" => errors }
end

def analyze
  request = JSON.parse($stdin.read)
  root = File.expand_path(request.fetch("root", "."))
  docs = request.fetch("sources", {}).map { |path, source| analyze_source(source, path) }
  request.fetch("files", []).each do |path|
    full = File.join(root, path)
    docs << analyze_source(File.binread(full).force_encoding("UTF-8"), path)
  rescue StandardError => e
    docs << { "path" => path, "error" => "#{e.class}: #{e.message}" }
  end
  puts JSON.generate({ "schema" => SCHEMA, "ruby_version" => RUBY_VERSION,
                       "files" => docs })
end

def run_cucumber(argv)
  options = { messages: nil, meta: nil }
  OptionParser.new do |p|
    p.on("--messages PATH") { |v| options[:messages] = v }
    p.on("--meta PATH") { |v| options[:meta] = v }
  end.order!(argv)
  argv.shift if argv.first == "--"
  raise "--messages and --meta are required" unless options.values.all?
  raise "a Cucumber command is required" if argv.empty?
  ok = system(*argv)
  exit_code = ok ? 0 : ($?&.exitstatus || 1)
  meta = { "schema" => "r2t.rbmatches-witness/1",
           "docker_env" => File.exist?("/.dockerenv"),
           "ruby_version" => RUBY_VERSION, "ruby_executable" => RbConfig.ruby,
           "cucumber_exit" => exit_code, "command" => argv,
           "messages_present" => File.file?(options[:messages]) }
  File.write(options[:meta], JSON.pretty_generate(meta) + "\n")
  exit(meta["messages_present"] ? 0 : 2)
end

case ARGV.shift
when "analyze" then analyze
when "run" then run_cucumber(ARGV)
else
  warn "usage: match_steps.rb analyze | run --messages P --meta P -- COMMAND"
  exit 2
end
