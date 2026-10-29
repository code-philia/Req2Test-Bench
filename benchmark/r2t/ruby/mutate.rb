#!/usr/bin/env ruby
# Ripper-only, offline v2 enumeration and authenticated single-splice application.
require 'ripper'
require 'json'
require 'optparse'
require 'pathname'

module R2TMutate
  ENGINE = "r2t-mutate-rb"
  ENGINE_VERSION = "1.0"
  ENUMERATOR_REV = "r2t-mutate-rb/operators-v2-3"
  EXCLUDED = %w[.git vendor node_modules _bench tmp log coverage app/assets/builds public/assets].freeze
  CALLS = %i[vcall fcall call command command_call method_add_arg method_add_block].freeze
  BOUNDARY = {'<' => '<=', '<=' => '<', '>' => '>=', '>=' => '>'}.freeze
  NEGATE = {'==' => '!=', '!=' => '==', '<' => '>=', '>=' => '<', '>' => '<=', '<=' => '>'}.freeze
  ARITHMETIC = {'+' => '-', '-' => '+', '*' => '/', '/' => '*', '%' => '*'}.freeze
  CONNECTOR = {'&&' => '||', '||' => '&&', 'and' => 'or', 'or' => 'and'}.freeze
  IGNORED = %i[on_sp on_ignored_sp on_nl on_ignored_nl on_comment on_embdoc_beg on_embdoc on_embdoc_end].freeze
  class Refused < StandardError; end

  def self.parser_version
    "ripper stdlib; #{RUBY_DESCRIPTION}"
  end

  def self.terminal?(node)
    node.is_a?(Array) && node[0].is_a?(Symbol) && node[0].to_s.start_with?('@')
  end

  # Compare every syntax role and leaf spelling; only locations are omitted.
  def self.normal(node, path = [], replacement = nil, with_node = nil)
    return with_node if path == replacement
    return node unless node.is_a?(Array)
    return node[0, 2] if terminal?(node)
    if replacement
      node.each_with_index.map { |child, i| normal(child, path + [i], replacement, with_node) }
    else
      # Ordinary comparison omits locations; it has no replacement path to
      # track. Avoid copying every ancestor path at every parsed-tree node.
      node.map { |child| normal(child) }
    end
  end

  def self.empty_return?(node)
    args = node[1]
    return false unless args.is_a?(Array) && args[0] == :args_add_block && args[2] == false
    one = args[1]
    return false unless one.is_a?(Array) && one[0] == :args_add && one[1] == [:args_new]
    value = one[2]
    while value.is_a?(Array) && value[0] == :paren
      statements = value[1]
      return false unless statements.is_a?(Array) && statements[0] == :stmts_add && statements[1] == [:stmts_new]
      value = statements[2]
    end
    normal(value) == [:var_ref, [:@kw, 'nil']] || value == [:void_stmt]
  end

  class Source
    attr_reader :bytes, :tree
    def initialize(bytes)
      @bytes = bytes.b
      text = @bytes.dup.force_encoding(Encoding::UTF_8)
      raise Refused, 'source is not valid UTF-8' unless text.valid_encoding?
      raise Refused, 'bare CR is not a supported physical line ending' if @bytes.match?(/\r(?!\n)/)
      @lines = [0]
      @bytes.each_byte.with_index { |b, i| @lines << i + 1 if b == 10 }
      @tree = Ripper.sexp_raw(text)
      raise Refused, 'Ripper syntax error' unless @tree
      @tokens = Ripper.lex(text).map do |position, type, value, _state|
        start = offset(position)
        raise Refused, 'Ripper token does not match source bytes' unless @bytes.byteslice(start, value.bytesize) == value.b
        finish = start + value.bytesize
        # The terminator belongs to its expression; its line ending does not.
        finish -= value[/\r?\n\z/].to_s.bytesize if type == :on_heredoc_end
        [start, finish, type, value]
      end.sort_by { |token| [token[0], token[1]] }
      @leaves = []
      visit(@tree) { |node, path| @leaves << [path, *leaf_span(node)] if R2TMutate.terminal?(node) }
      @spans = {}
    end

    def offset(position)
      line, col = position
      raise Refused, 'Ripper position outside source' unless line.is_a?(Integer) && line.between?(1, @lines.length)
      @lines[line - 1] + col
    end

    def coordinate(byte)
      line = @lines.bsearch_index { |start| start > byte } || @lines.length
      [line, byte - @lines[line - 1] + 1]
    end

    def leaf_span(node)
      start = offset(node[2])
      raise Refused, 'Ripper leaf does not match source bytes' unless @bytes.byteslice(start, node[1].bytesize) == node[1].b
      [start, start + node[1].bytesize]
    end

    def visit(node, path = [], &block)
      return unless node.is_a?(Array)
      yield node, path if node[0].is_a?(Symbol)
      return if R2TMutate.terminal?(node)
      node.each_with_index { |child, i| visit(child, path + [i], &block) }
    end

    def splice(start, finish, replacement)
      @bytes.byteslice(0, start) + replacement.b + @bytes.byteslice(finish, @bytes.bytesize - finish)
    end

    def valid?(candidate)
      !Ripper.sexp_raw(candidate.dup.force_encoding(Encoding::UTF_8)).nil?
    end

    # Ripper omits nonterminal closing positions. Lexer boundaries bound the
    # search; markers on BOTH sides of the original must add exactly one
    # known AST enclosure, including all literal/block/heredoc delimiters.
    # A trailing marker alone cannot distinguish an enclosing begin keyword
    # from the first call in its body: the two nested begins can trade places.
    # Keeping the original during this proof preserves lexical local bindings;
    # deleting an assignment here could otherwise turn a later / into a regexp
    # and incorrectly report an invalid candidate as an unbound source file.
    # The newline before ;nil keeps a heredoc terminator on its own line.
    # This never evaluates Ruby or uses RubyVM's different AST/geometry.
    def span(node, path)
      return leaf_span(node) if R2TMutate.terminal?(node)
      return @spans[path] if @spans.key?(path)
      inside, outside = @leaves.partition { |p, _s, _e| p[0, path.length] == path }
      if inside.empty?
        lower = 0
        upper = @bytes.bytesize
        first = upper
        last = lower
      else
        first = inside.map { |_p, s, _e| s }.min
        last = inside.map { |_p, _s, e| e }.max
        lower = outside.filter_map { |_p, s, e| e if e <= first }.max || 0
        upper = outside.filter_map { |_p, s, _e| s if s >= last }.min || @bytes.bytesize
      end
      # Semicolons terminate statements and never belong to an expression.
      significant = @tokens.reject { |t| IGNORED.include?(t[2]) || t[2] == :on_semicolon }
      starts = significant.select { |s, _e, _t, _v| s >= lower && s <= first }.map(&:first)
      starts.select! { |s| @tokens.any? { |t| t[0] == s && t[2] == :on_kw && t[3] == 'return' } } if node[0] == :return
      ends = significant.select { |_s, e, _t, _v| e >= last && e <= upper }.map { |t| t[1] }.uniq.sort
      marker = [:var_ref, [:@kw, 'nil']]
      statements = [:stmts_add, [:stmts_add, [:stmts_add, [:stmts_new], marker], R2TMutate.normal(node)], marker]
      enclosure = [:begin, [:bodystmt, statements, nil, nil, nil]]
      expected = R2TMutate.normal(@tree, [], path, enclosure)
      matches = []
      # A leafless operand such as bare super has a whole-file window. Do not
      # form every start/end pair only to reject intervals crossing another
      # node's leaf. For one start, the first not-yet-ended outside leaf is
      # exactly the upper bound imposed by that same overlap predicate.
      barriers = outside.map { |_p, s, e| [s, e] }.sort
      barrier = 0
      starts.each do |start|
        barrier += 1 while barrier < barriers.length && barriers[barrier][1] <= start
        limit = barrier < barriers.length ? barriers[barrier][0] : upper
        next unless limit > start
        index = ends.bsearch_index { |finish| finish > start }
        next unless index
        while index < ends.length && ends[index] <= limit
          finish = ends[index]
          enclosed = 'begin nil; ' + @bytes.byteslice(start, finish - start) + "\n;nil;end"
          parsed = Ripper.sexp_raw(splice(start, finish, enclosed).force_encoding(Encoding::UTF_8))
          matches << [start, finish] if parsed && R2TMutate.normal(parsed) == expected
          index += 1
        end
      end
      raise Refused, "#{node[0]} has #{matches.length} complete span bindings at AST #{path.join('.')}" unless matches.length == 1
      @spans[path] = matches.first
    end

    def token_between(value, lower, upper)
      matches = @tokens.select { |s, e, type, text| s >= lower && e <= upper && %i[on_op on_kw].include?(type) && text == value }
      raise Refused, "operator #{value.inspect} has #{matches.length} token bindings" unless matches.length == 1
      matches.first[0, 2]
    end

    def enumerate(validate: true)
      rows = []
      emit = lambda do |operator, range, replacement|
        start, finish = range
        original = @bytes.byteslice(start, finish - start).force_encoding(Encoding::UTF_8)
        return if original == replacement
        rows << {start: start, finish: finish, operator: operator, original: original, mutated: replacement}
      end
      visit(@tree) do |node, path|
        case node[0]
        when :binary
          op = node[2].to_s
          mappings = [['ConditionalBoundary', BOUNDARY], ['NegateConditional', NEGATE], ['ArithmeticOperator', ARITHMETIC], ['LogicalConnector', CONNECTOR]]
          next unless mappings.any? { |_name, mapping| mapping.key?(op) }
          left = span(node[1], path + [1])
          right = span(node[3], path + [3])
          range = token_between(op, left[1], right[0])
          mappings.each { |name, mapping| emit.call(name, range, mapping[op]) if mapping.key?(op) }
        when :opassign
          op = node[2]
          rhs = node[3]
          if R2TMutate.terminal?(op) && %w[+= -=].include?(op[1]) && rhs.is_a?(Array) && %i[@int @float].include?(rhs[0])
            emit.call('Increment', leaf_span(op), op[1] == '+=' ? '-=' : '+=')
          end
        when :var_ref
          leaf = node[1]
          if R2TMutate.terminal?(leaf) && leaf[0] == :@kw && %w[true false].include?(leaf[1])
            emit.call(leaf[1] == 'true' ? 'TrueValue' : 'FalseValue', leaf_span(leaf), leaf[1] == 'true' ? 'false' : 'true')
          end
        when :return
          emit.call('ReturnValue', span(node, path), 'return nil') unless R2TMutate.empty_return?(node)
        when :unary
          op = node[1].to_s
          if %w[! not].include?(op)
            whole = span(node, path)
            operand = span(node[2], path + [2])
            emit.call('RemoveNegation', token_between(op, whole[0], operand[0]), '')
          end
        when :@int
          value = node[1]
          # A leading zero with further digits is Ruby's octal spelling.
          if value.match?(/\A(?:0|[1-9][0-9]*(?:_[0-9]+)*)\z/)
            emit.call('ConstantReplacement', leaf_span(node), (Integer(value.delete('_'), 10) + 1).to_s)
          end
        end
      end
      statement_calls(@tree) { |node, path| emit.call('MethodCallRemoval', span(node, path), 'nil') }
      rows = rows.uniq.sort_by { |r| [r[:start], r[:finish], r[:operator]] }
      invalid = 0
      if validate
        rows = rows.select do |row|
          good = valid?(splice(row[:start], row[:finish], row[:mutated]))
          invalid += 1 unless good
          good
        end
      end
      [rows, invalid]
    end

    # A statement list in a callable body has its own value context, even
    # when the callback itself is assigned/passed as a value. Walk value
    # contexts to discover those scopes without removing their operand calls.
    def statement_calls(node, path = [], statements = false, &block)
      return unless node.is_a?(Array)
      type = node[0]
      case type
      when :stmts_add
        statement_calls(node[1], path + [1], statements, &block)
        stmt = node[2]
        yield stmt, path + [2] if statements && stmt.is_a?(Array) && CALLS.include?(stmt[0])
        statement_calls(stmt, path + [2], statements, &block)
      when :program
        statement_calls(node[1], path + [1], true, &block)
      when :def, :defs, :class, :module, :sclass
        (1...node.length - 1).each { |i| statement_calls(node[i], path + [i], false, &block) }
        statement_calls(node[-1], path + [node.length - 1], true, &block)
      when :lambda, :do_block, :brace_block
        statement_calls(node[1], path + [1], false, &block)
        statement_calls(node[2], path + [2], true, &block)
      when :bodystmt
        (1...node.length).each { |i| statement_calls(node[i], path + [i], statements, &block) }
      when :begin
        statement_calls(node[1], path + [1], statements, &block)
      when :method_add_block
        statement_calls(node[1], path + [1], false, &block)
        statement_calls(node[2], path + [2], true, &block)
      when :if, :unless, :elsif, :while, :until
        statement_calls(node[1], path + [1], false, &block)
        statement_calls(node[2], path + [2], statements, &block)
        statement_calls(node[3], path + [3], statements, &block) if %i[if unless elsif].include?(type)
      when :for
        statement_calls(node[1], path + [1], false, &block)
        statement_calls(node[2], path + [2], false, &block)
        statement_calls(node[3], path + [3], statements, &block)
      when :else, :ensure
        statement_calls(node[1], path + [1], statements, &block)
      when :rescue
        statement_calls(node[1], path + [1], false, &block)
        statement_calls(node[2], path + [2], false, &block)
        statement_calls(node[3], path + [3], statements, &block)
        statement_calls(node[4], path + [4], statements, &block)
      when :case, :when, :in
        statement_calls(node[1], path + [1], false, &block)
        (2...node.length).each { |i| statement_calls(node[i], path + [i], statements, &block) }
      else
        node.each_with_index { |child, i| statement_calls(child, path + [i], false, &block) }
      end
    end

    def descriptor(row, file)
      sl, sc = coordinate(row[:start])
      el, ec = coordinate(row[:finish] - 1)
      {'file' => file, 'start_line' => sl, 'start_col' => sc, 'end_line' => el, 'end_col' => ec,
       'operator' => row[:operator], 'original' => row[:original], 'mutated' => row[:mutated]}
    end
  end

  def self.relative(root, path)
    raise Refused, 'path must be repository-relative' if Pathname.new(path).absolute?
    clean = Pathname.new(path).cleanpath.to_s
    raise Refused, 'path escapes repository' if clean == '..' || clean.start_with?('../')
    clean.tr('\\', '/')
  end

  def self.excluded?(rel)
    EXCLUDED.any? { |prefix| rel == prefix || rel.start_with?(prefix + '/') }
  end

  def self.input(root, rel)
    raise Refused, 'input outside app/ and lib/ keep roots' unless %w[app lib].any? { |p| rel == p || rel.start_with?(p + '/') }
    raise Refused, 'input matches excluded prefix' if excluded?(rel)
    full = File.join(root, rel)
    cursor = root
    rel.split('/').each do |part|
      cursor = File.join(cursor, part)
      raise Refused, 'symlink input is not supported' if File.symlink?(cursor)
    end
    raise Refused, 'input does not exist' unless File.exist?(full)
    full
  end

  def self.main(argv)
    options = {paths: [], profile: 'v2'}
    parser = OptionParser.new do |p|
      p.on('--root DIR') { |v| options[:root] = v }
      p.on('--path REL') { |v| options[:paths] << v }
      p.on('--out FILE') { |v| options[:out] = v }
      p.on('--operator-profile PROFILE') { |v| options[:profile] = v }
      p.on('--record-enumerator-rev') {}
      p.on('--apply-file REL') { |v| options[:apply] = v }
      p.on('--start-line N', Integer) { |v| options[:line] = v }
      p.on('--start-col N', Integer) { |v| options[:col] = v }
      p.on('--operator OP') { |v| options[:operator] = v }
      p.on('--original TEXT') { |v| options[:original] = v }
      p.on('--mutated TEXT') { |v| options[:mutated] = v }
    end
    parser.parse!(argv)
    raise OptionParser::InvalidArgument, 'root and v2 profile required' unless options[:root] && options[:profile] == 'v2' && argv.empty?
    root = File.realpath(options[:root])
    if options[:apply]
      raise Refused, 'apply requires coordinates, operator, original, mutated and out' unless %i[line col operator original mutated out].all? { |k| options.key?(k) }
      rel = relative(root, options[:apply])
      full = input(root, rel)
      raise Refused, 'apply requires a regular .rb source' unless File.file?(full) && rel.end_with?('.rb')
      source = Source.new(File.binread(full))
      rows, = source.enumerate(validate: false)
      matches = rows.select do |row|
        d = source.descriptor(row, rel)
        d['start_line'] == options[:line] && d['start_col'] == options[:col] && d['operator'] == options[:operator] && d['original'] == options[:original] && d['mutated'] == options[:mutated]
      end
      raise Refused, "descriptor has #{matches.length} current bindings" unless matches.length == 1
      row = matches.first
      candidate = source.splice(row[:start], row[:finish], row[:mutated])
      raise Refused, 'selected candidate is syntactically invalid' unless source.valid?(candidate)
      output = File.expand_path(options[:out], root)
      raise Refused, 'output is a symlink or has a symlink parent' unless File.realpath(File.dirname(output)) == File.dirname(output) && !File.symlink?(output)
      File.binwrite(output, candidate)
      return 0
    end
    paths = options[:paths].empty? ? %w[app lib] : options[:paths]
    files = []
    errors = {}
    excluded = Hash.new(0)
    paths.each do |path|
      rel = relative(root, path)
      begin
        full = input(root, rel)
        if File.directory?(full)
          walk = lambda do |directory, name|
            Dir.children(directory).sort.each do |entry|
              child = name + '/' + entry
              if excluded?(child)
                excluded['prefix'] += 1
                next
              end
              child_full = File.join(root, child)
              if File.symlink?(child_full)
                errors[child] = 'symlink input is not supported'
              elsif File.directory?(child_full)
                walk.call(child_full, child)
              elsif child.end_with?('.rb')
                File.file?(child_full) ? files << child : errors[child] = 'input is not a regular file'
              else
                excluded['suffix'] += 1
              end
            end
          end
          walk.call(full, rel)
        elsif File.file?(full) && rel.end_with?('.rb')
          files << rel
        else
          raise Refused, 'input is not a regular .rb source'
        end
      rescue Refused, SystemCallError => e
        errors[rel] = e.message
      end
    end
    mutants = []
    processed = 0
    invalid = 0
    files.uniq.sort.each do |rel|
      begin
        source = Source.new(File.binread(File.join(root, rel)))
        rows, n_invalid = source.enumerate
        mutants.concat(rows.map { |row| source.descriptor(row, rel) })
        invalid += n_invalid
        processed += 1
      rescue Refused, SystemCallError => e
        errors[rel] = e.message
      end
    end
    doc = {'engine' => ENGINE, 'engine_version' => ENGINE_VERSION, 'parser' => parser_version,
           'enumerator_rev' => ENUMERATOR_REV, 'files' => processed, 'errors' => errors.sort.to_h,
           'mutants' => mutants.sort_by { |m| m.values_at('file', 'start_line', 'start_col', 'end_line', 'end_col', 'operator') }}
    doc['n_invalid'] = invalid if invalid.positive?
    warn JSON.generate(excluded_paths: excluded.sort.to_h) unless excluded.empty?
    json = JSON.pretty_generate(doc) + "\n"
    options[:out] ? File.write(options[:out], json) : $stdout.write(json)
    errors.empty? ? 0 : 1
  rescue OptionParser::ParseError => e
    warn "usage error: #{e.message}"
    2
  rescue Refused => e
    warn "REFUSED: #{e.message}"
    4
  rescue SystemCallError => e
    warn "I/O error: #{e.message}"
    3
  end
end

exit R2TMutate.main(ARGV) if $PROGRAM_NAME == __FILE__
