# frozen_string_literal: true
# Source-only Ruby step-body facts for TARGET_INTERFACES_SPEC section 3.2.
require 'json'
require 'ripper'

module R2T
  module Interfaces
    SCHEMA = 'r2t.rbinterfaces-syntax/1'
    DSL = %w[Given When Then And But].freeze
    DYNAMIC_LOOKUPS = %w[const_get const_defined? autoload? constantize safe_constantize].freeze

    module_function

    def token_name(node)
      return nil unless node.is_a?(Array)
      return node[1] if node[0].is_a?(Symbol) && node[0].to_s.start_with?('@')
      token_name(node[1]) if %i[fcall vcall command method_add_arg].include?(node[0])
    end

    def constant_name(node)
      return nil unless node.is_a?(Array)
      case node[0]
      when :var_ref, :const_ref
        node[1][1] if node[1]&.first == :@const
      when :top_const_ref
        name = node[1][1] if node[1]&.first == :@const
        "::#{name}" if name
      when :const_path_ref
        left = constant_name(node[1])
        "#{left}::#{node[2][1]}" if left && node[2]&.first == :@const
      end
    end

    def qualify(name, scope)
      return nil unless name
      return name.delete_prefix('::') if name.start_with?('::') || scope.nil? || scope.empty?
      "#{scope}::#{name}"
    end

    def arguments(node)
      return [] unless node.is_a?(Array)
      case node[0]
      when :command then arguments(node[2])
      when :command_call then arguments(node[4])
      when :method_add_arg then arguments(node[2])
      when :arg_paren then arguments(node[1])
      when :args_add_block then node[1] || []
      when :args_add then arguments(node[1]) + [node[2]]
      else []
      end
    end

    def invocation_name(node)
      return nil unless node.is_a?(Array)
      case node[0]
      when :method_add_arg, :method_add_block then invocation_name(node[1])
      when :command, :fcall, :vcall then token_name(node[1])
      when :call, :command_call then token_name(node[3])
      end
    end

    def invocation_line(node)
      return nil unless node.is_a?(Array)
      case node[0]
      when :method_add_arg, :method_add_block then invocation_line(node[1])
      when :command, :fcall, :vcall then node[1]&.[](2)&.[](0)
      when :call, :command_call then node[3]&.[](2)&.[](0)
      end
    end

    def body_of(block)
      return nil unless block.is_a?(Array) && %i[do_block brace_block].include?(block[0])
      block[2]
    end

    def self_receiver?(node)
      node.is_a?(Array) && node[0] == :var_ref && node[1]&.first == :@kw && node[1][1] == 'self'
    end

    def facts_assignment_target(node, scope, out)
      return unless node.is_a?(Array)
      case node[0]
      when :var_field, :const_path_field, :top_const_field
        # The assigned constant/local itself is a definition, not a read.
        return
      when :field
        facts(node[1], scope, out)
        return
      when :aref_field
        facts(node[1], scope, out)
        facts(node[2], scope, out)
        return
      end
      node.each do |child|
        facts_assignment_target(child, scope, out) if child.is_a?(Array)
      end
    end

    def facts(node, scope, out = { 'constants' => [], 'calls' => [] })
      return out unless node.is_a?(Array)
      type = node[0]
      if %i[symbol_literal dyna_symbol].include?(type)
        return out
      elsif %i[assign opassign massign].include?(type)
        facts_assignment_target(node[1], scope, out)
        rhs = type == :opassign ? node[3] : node[2]
        facts(rhs, scope, out)
        return out
      elsif %i[class module].include?(type)
        nested = qualify(constant_name(node[1]), scope)
        facts(node[2], scope, out) if type == :class
        facts(node[-1], nested || scope, out)
        return out
      end

      name = constant_name(node)
      if name
        out['constants'] << { 'name' => name, 'scope' => scope }
        return out
      end

      if %i[method_add_arg call command_call].include?(type) && DYNAMIC_LOOKUPS.include?(invocation_name(node))
        return out
      end
      if %i[vcall fcall command].include?(type)
        called = invocation_name(node)
        out['calls'] << called if called && !%w[step steps].include?(called)
      elsif %i[call command_call].include?(type)
        if self_receiver?(node[1])
          called = token_name(node[3])
          out['calls'] << called if called && !%w[step steps].include?(called)
        end
        facts(node[1], scope, out)
        facts(node[4], scope, out) if type == :command_call
        return out
      end
      node.each { |child| facts(child, scope, out) if child.is_a?(Array) }
      out['constants'].uniq!
      out['calls'].uniq!
      out
    end

    def discover(node, scope, out)
      return unless node.is_a?(Array)
      case node[0]
      when :class, :module
        nested = qualify(constant_name(node[1]), scope)
        discover(node[-1], nested || scope, out)
        return
      when :def
        ident = node[1]
        body = node[3]
        out['helpers'] << {
          'owner' => scope || '<top-level>', 'name' => ident[1],
          'line' => ident[2][0], **facts(body, scope)
        }
        return
      when :defs, :sclass
        return
      when :method_add_block
        if DSL.include?(invocation_name(node))
          body = body_of(node[2])
          out['steps'] << {
            'line' => invocation_line(node), 'scope' => scope,
            **facts(body, scope)
          }
          return
        end
      when :method_add_arg, :command
        if invocation_name(node) == 'World'
          arguments(node).each do |arg|
            name = constant_name(arg)
            out['worlds'] << { 'name' => name, 'scope' => scope } if name
          end
        end
      end
      node.each { |child| discover(child, scope, out) if child.is_a?(Array) }
    end

    def analyze_source(source, path)
      raise 'invalid UTF-8' unless source.valid_encoding?
      tree = Ripper.sexp(source, path)
      raise 'Ripper rejected the source' unless tree
      out = { 'path' => path, 'steps' => [], 'helpers' => [], 'worlds' => [] }
      discover(tree, nil, out)
      out['steps'].sort_by! { |row| row['line'] }
      out['helpers'].sort_by! { |row| [row['owner'], row['name'], row['line']] }
      out['worlds'].uniq!
      out
    end

    def run
      request = JSON.parse($stdin.read)
      root = File.expand_path(request.fetch('root'))
      files = request.fetch('files').uniq.sort
      rows = files.map do |path|
        full = File.expand_path(path, root)
        raise "source path outside root: #{path}" unless full.start_with?(root + '/')
        raise "symlink source input: #{path}" unless File.realpath(full) == full
        analyze_source(File.binread(full).force_encoding('UTF-8'), path)
      rescue StandardError => error
        { 'path' => path, 'error' => error.message }
      end
      puts JSON.generate({ 'schema' => SCHEMA,
                           'parser' => "ripper stdlib; #{RUBY_DESCRIPTION}",
                           'files' => rows })
    end
  end
end

R2T::Interfaces.run if $PROGRAM_NAME == __FILE__
