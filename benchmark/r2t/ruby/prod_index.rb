# frozen_string_literal: true
# Source-only Ruby API declarations. Never evaluate or require subject code.
require 'ripper'
require 'json'
require 'optparse'
require 'pathname'

module R2T
  module ProductionIndex
    SCHEMA = 'r2t.rb_prod_index/1'
    class Parser < Ripper::SexpBuilder
      attr_reader :ends
      def initialize(source)
        super(source)
        @ends = {}
      end
      %i[def defs class module sclass command method_add_arg method_add_block alias].each do |event|
        define_method("on_#{event}") do |*args|
          node = super(*args)
          @ends[node.object_id] = lineno
          node
        end
      end
    end

    class Builder
      attr_reader :errors, :unsupported
      def initialize(root)
        @root = File.expand_path(root)
        @rows, @aliases, @visibility, @ancestors = [], [], [], {}
        @declarations = []
        @errors, @unsupported, @files = {}, [], []
        @sequence = 0
        @declared = []
      end

      def leaves(node)
        return [] unless node.is_a?(Array)
        return [node] if node[0].is_a?(Symbol) && node[0].to_s.start_with?('@')
        node.flat_map { |child| leaves(child) }
      end

      def literal(node)
        return nil unless node.is_a?(Array)
        if node[0] == :symbol_literal
          leaf = node[1]&.first == :symbol ? node[1][1] : node[1]
          leaf[1] if leaf.is_a?(Array) && %i[@ident @op @kw @const].include?(leaf[0])
        elsif %i[string_literal dyna_symbol].include?(node[0])
          parts = leaves(node)
          parts.map { |part| part[1] }.join if parts.all? { |part| part[0] == :@tstring_content && !part[1].include?('\\') } &&
                                                       !contains?(node, :string_embexpr)
        end
      end

      def contains?(node, type)
        node.is_a?(Array) && (node[0] == type || node.any? { |child| contains?(child, type) })
      end

      def constant(node, scope = nil)
        return nil unless node.is_a?(Array)
        case node[0]
        when :const_ref, :var_ref
          leaf = node[1]
          leaf[1] if leaf&.first == :@const
        when :top_const_ref
          '::' + node[1][1]
        when :const_path_ref
          left = constant(node[1], scope)
          "#{left}::#{node[2][1]}" if left
        end
      end

      def assignment_constant(node)
        return nil unless node.is_a?(Array)
        case node[0]
        when :var_field
          leaf = node[1]
          leaf[1] if leaf&.first == :@const
        when :top_const_field
          "::#{node[1][1]}" if node[1]&.first == :@const
        when :const_path_field
          left = constant(node[1])
          "#{left}::#{node[2][1]}" if left
        end
      end

      def direct_type_assignment(node, scope)
        return nil unless node.is_a?(Array) && node[0] == :assign
        name = assignment_constant(node[1])
        rhs = node[2]
        rhs = rhs[1] while rhs.is_a?(Array) && %i[method_add_arg method_add_block].include?(rhs[0])
        return nil unless name && rhs.is_a?(Array) && rhs[0] == :call && rhs[3]&.[](1) == 'new'
        factory = constant(rhs[1])&.delete_prefix('::')
        return nil unless %w[Class Module Struct].include?(factory)
        full = if name.start_with?('::') || !scope
                 name.delete_prefix('::')
               else
                 "#{scope}::#{name}"
               end
        [full, factory.downcase, leaves(node[1]).map { |leaf| leaf[2][0] }.min]
      end

      def declaration_line(node, keyword)
        first = leaves(node[1]).map { |leaf| leaf[2] }.min
        token = @tokens.select do |position, type, text, _state|
          type == :on_kw && text == keyword && (!first || (position <=> first) == -1)
        end.last
        token ? token[0][0] : leaves(node).map { |leaf| leaf[2][0] }.min
      end

      def add_declaration(file, name, kind, line)
        @declarations << { file: file, name: name, kind: kind, line: line }
      end

      def resolve_ref(name, scope)
        return name.delete_prefix('::') if name.start_with?('::')
        parts = scope.to_s.split('::')
        until parts.empty?
          candidate = (parts + [name]).join('::')
          return candidate if @declared.include?(candidate)
          parts.pop
        end
        name
      end

      def owner_name(node, scope)
        name = constant(node)
        return nil unless name
        return name.delete_prefix('::') if name.start_with?('::') || !scope
        return "#{scope}::#{name}" unless name.include?('::')
        prefix, _, leaf = name.rpartition('::')
        "#{resolve_ref(prefix, scope)}::#{leaf}"
      end

      def arguments(node)
        return [] if node.nil? || node == false || node == [:args_new]
        return arguments(node[1]) if %i[arg_paren args_add_block].include?(node[0])
        return arguments(node[1]) + [node[2]] if node[0] == :args_add
        [node]
      end

      def call(node)
        return nil unless node.is_a?(Array)
        case node[0]
        when :vcall, :fcall
          [node[1][1], [], node[1][2][0]]
        when :command
          [node[1][1], arguments(node[2]), node[1][2][0]]
        when :method_add_arg
          target = call(node[1])
          [target[0], arguments(node[2]), target[2]] if target
        end
      end

      def diagnostic(file, node, reason)
        @unsupported << { file: file, line: leaves(node).map { |leaf| leaf[2][0] }.min,
                          reason: reason }
      end

      def add(file, owner, kind, name, line, finish, public, provenance = nil)
        row = { file: file, owner: owner, method_kind: kind, name: name,
                start: line, end: finish, decl: line, public: public,
                sequence: @sequence, declaration: provenance || { file: file, start: line, end: finish } }
        @rows << row
        row
      end

      def statements(node)
        return [] unless node.is_a?(Array)
        return statements(node[1]) if %i[program bodystmt].include?(node[0])
        return statements(node[1]) + [node[2]] if node[0] == :stmts_add
        node[0] == :stmts_new ? [] : [node]
      end

      def walk(body, file, owner = nil, kind = 'instance')
        visibility = !owner.nil?
        statements(body).each do |node|
          next unless node.is_a?(Array)
          @sequence += 1
          finish = @parser.ends[node.object_id] || leaves(node).map { |leaf| leaf[2][0] }.max || 1
          if (declaration = direct_type_assignment(node, owner))
            add_declaration(file, *declaration)
          end
          case node[0]
          when :class, :module
            name = owner_name(node[1], owner)
            unless name
              diagnostic(file, node, 'dynamic_class_or_module')
              next
            end
            @declared << name unless @declared.include?(name)
            add_declaration(file, name, node[0].to_s,
                            declaration_line(node, node[0].to_s))
            if node[0] == :class && node[2]
              parent = constant(node[2])
              @ancestors[[name, 'instance']] ||= []
              @ancestors[[name, 'singleton']] ||= []
              if parent
                @ancestors[[name, 'instance']] << [parent, 'instance']
                @ancestors[[name, 'singleton']] << [parent, 'singleton']
              else
                diagnostic(file, node[2], 'dynamic_superclass')
              end
            end
            walk(node[-1], file, name)
          when :sclass
            if owner && node[1][0] == :var_ref && node[1][1][1] == 'self'
              walk(node[2], file, owner, 'singleton')
            else
              diagnostic(file, node, 'dynamic_singleton_owner')
            end
          when :def, :defs
            target_kind = node[0] == :defs ? 'singleton' : kind
            target_owner = owner || 'Object'
            if node[0] == :defs && !(node[1][0] == :var_ref && node[1][1][1] == 'self')
              receiver = constant(node[1])
              target_owner = receiver && resolve_ref(receiver, owner)
            end
            if !target_owner
              diagnostic(file, node, 'unresolved_method_owner')
              next
            end
            ident = node[node[0] == :defs ? 3 : 1]
            public = node[0] == :defs ? true : visibility
            public = false if target_kind == 'instance' && %w[initialize initialize_copy initialize_dup initialize_clone].include?(ident[1])
            declaration = @tokens.select { |position, type, text, _state| type == :on_kw && text == 'def' && (position <=> ident[2]) == -1 }.last
            add(file, target_owner, target_kind, ident[1], declaration[0][0], finish, public)
          when :alias
            names = node[1, 2].map { |arg| literal(arg) }
            if owner && names.all?
              @aliases << [file, owner, kind, *names, leaves(node).map { |leaf| leaf[2][0] }.min, finish, @sequence]
            else
              diagnostic(file, node, 'dynamic_alias')
            end
          else
            block = node[0] == :method_add_block ? node[2] : nil
            invoked = call(block ? node[1] : node)
            unless invoked
              diagnostic(file, node, 'unsupported_declaration_context') unless node[0] == :void_stmt
              next
            end
            method, args, line = invoked
            names = args.map { |arg| literal(arg) }
            case method
            when 'private', 'protected', 'public'
              if args.empty?
                visibility = method == 'public'
              elsif names.all?
                names.each { |name| @visibility << [owner, kind, name, method == 'public', file, line, @sequence] }
              elsif args.length == 1 && %i[def defs].include?(args[0][0])
                before = @rows.length
                walk(args[0], file, owner, kind)
                @rows[before..].each { |row| row[:public] = method == 'public' }
              else
                diagnostic(file, node, 'dynamic_visibility')
              end
            when 'private_class_method', 'public_class_method'
              if names.all? && !names.empty?
                names.each { |name| @visibility << [owner, 'singleton', name, method == 'public_class_method', file, line, @sequence] }
              else
                diagnostic(file, node, 'dynamic_visibility')
              end
            when 'attr_reader', 'attr_writer', 'attr_accessor'
              if owner && names.all? && !names.empty?
                names.each do |name|
                  add(file, owner, kind, name, line, finish, visibility) unless method == 'attr_writer'
                  add(file, owner, kind, name + '=', line, finish, visibility) unless method == 'attr_reader'
                end
              else
                diagnostic(file, node, 'dynamic_accessor')
              end
            when 'alias_method'
              if owner && names.length == 2 && names.all?
                @aliases << [file, owner, kind, *names, line, finish, @sequence]
              else
                diagnostic(file, node, 'dynamic_alias')
              end
            when 'define_method'
              if owner && block && names.length == 1 && names.first
                # source_location names the inline block opener, not its first statement.
                call_end = leaves(node[1]).map { |leaf| leaf[2] }.max
                body_first = leaves(block).map { |leaf| leaf[2] }.min
                openers = @tokens.select do |position, type, text, _state|
                  position[0] <= finish && (position <=> call_end) == 1 && (!body_first || (position <=> body_first) <= 0) &&
                    (type == :on_lbrace || (type == :on_kw && text == 'do'))
                end
                if !openers.empty?
                  add(file, owner, kind, names.first, openers.first[0][0], finish, visibility,
                      { file: file, start: line, end: finish })
                else
                  diagnostic(file, node, 'unresolved_inline_block')
                end
              else
                diagnostic(file, node, 'dynamic_define_method')
              end
            when 'include', 'prepend', 'extend'
              parents = args.map { |arg| constant(arg) }
              if owner && parents.all? && !parents.empty?
                target_kind = method == 'extend' ? 'singleton' : kind
                @ancestors[[owner, target_kind]] ||= []
                @ancestors[[owner, target_kind]].unshift(*parents.reverse.map { |parent| [parent, 'instance'] })
              else
                diagnostic(file, node, 'dynamic_ancestor')
              end
            else
              diagnostic(file, node, "unsupported_macro:#{method}")
            end
          end
        end
      end

      def lookup(owner, kind, name, seen = [])
        key = [owner, kind]
        return [] if seen.include?(key)
        rows = @rows.select { |row| row.values_at(:owner, :method_kind, :name) == [owner, kind, name] }
        return rows unless rows.empty?
        (@ancestors[key] || []).each do |parent, parent_kind|
          candidates = lookup(resolve_ref(parent, owner), parent_kind, name, seen + [key])
          return candidates unless candidates.empty?
        end
        []
      end

      def build(paths)
        selected = paths.flat_map do |rel|
          full = File.expand_path(rel, @root)
          raise 'index path outside repository' unless full.start_with?(@root + '/')
          File.directory?(full) ? Dir.glob(File.join(full, '**', '*.rb')) : [full]
        end.uniq.sort
        selected.each do |full|
          file = Pathname.new(full).relative_path_from(Pathname.new(@root)).to_s
          next unless file.end_with?('.rb')
          raise 'symlink Ruby index input' unless File.realpath(full) == full
          @files << file
          begin
            source = File.read(full, encoding: 'UTF-8')
            raise 'invalid UTF-8' unless source.valid_encoding?
            @parser = Parser.new(source)
            tree = @parser.parse
            raise 'Ripper syntax error' if @parser.error? || !tree
            @tokens = Ripper.lex(source)
            walk(tree, file)
          rescue StandardError => error
            @errors[file] = error.message
            @rows.reject! { |row| row[:file] == file }
            @declarations.reject! { |row| row[:file] == file }
          end
        end
        pending = @aliases.dup
        loop do
          completed = []
          pending.each do |file, owner, kind, name, target, line, finish, sequence|
            rows = lookup(owner, kind, target)
            next unless rows.length == 1
            body = rows.first
            prior = @visibility.select { |o, k, n, _public, _f, _l, seq| [o, k, n] == body.values_at(:owner, :method_kind, :name) && seq < sequence && seq > body[:sequence] }.max_by(&:last)
            @sequence = sequence
            add(body[:file], owner, kind, name, body[:decl], body[:end], prior ? prior[3] : body[:public],
                { file: file, start: line, end: finish })
            completed << [file, owner, kind, name, target, line, finish, sequence]
          end
          break if completed.empty?
          pending -= completed
        end
        pending.each { |file, owner, kind, name, target, line, _finish| @unsupported << {file: file, line: line, reason: "unresolved_alias:#{owner}:#{kind}:#{name}:#{target}"} }
        @visibility.each do |owner, kind, name, public, file, line, sequence|
          rows = @rows.select { |row| row.values_at(:owner, :method_kind, :name) == [owner, kind, name] }
          if rows.empty?
            @unsupported << {file: file, line: line, reason: "unresolved_visibility:#{owner}:#{kind}:#{name}"}
          else
            rows.each { |row| row[:public] = public if row[:sequence] < sequence }
          end
        end
        files = @files.to_h { |file| [file, {classes: [], declarations: []}] }
        @rows.group_by { |row| [row[:file], row[:owner]] }.sort.each do |(file, owner), rows|
          files[file][:classes] << { name: owner, methods: rows.map { |row| row.reject { |key, _| %i[file owner sequence].include?(key) } }.sort_by { |row| [row[:decl], row[:method_kind], row[:name]] } }
        end
        @declarations.group_by { |row| row[:file] }.each do |file, rows|
          files[file][:declarations] = rows.map { |row| row.reject { |key, _| key == :file } }
                                            .sort_by { |row| [row[:line], row[:kind], row[:name]] }
        end
        { schema: SCHEMA, language: 'ruby', root: @root, parser: "ripper stdlib; #{RUBY_DESCRIPTION}",
          files: files, errors: @errors, unsupported: @unsupported.sort_by { |row| [row[:file], row[:line] || 0, row[:reason]] },
          counts: {files: files.length, methods: @rows.length, public_methods: @rows.count { |row| row[:public] }, errors: @errors.length, unsupported: @unsupported.length} }
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  options = {paths: []}
  OptionParser.new do |parser|
    parser.on('--root DIR') { |value| options[:root] = value }
    parser.on('--path REL') { |value| options[:paths] << value }
  end.parse!
  doc = R2T::ProductionIndex::Builder.new(options.fetch(:root)).build(options[:paths].empty? ? %w[app lib] : options[:paths])
  puts JSON.pretty_generate(doc)
  exit(doc[:errors].empty? ? 0 : 1)
end
