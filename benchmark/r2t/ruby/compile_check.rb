# frozen_string_literal: true
# Syntax only: compiling a candidate must never execute its source.
require 'json'
require 'optparse'
require 'pathname'
paths = []
OptionParser.new { |parser| parser.on('--path PATH') { |path| paths << path } }.parse!
root = File.realpath(Dir.pwd)
files = {}
errors = {}
paths.uniq.sort.each do |path|
  begin
    full = File.realpath(File.expand_path(path, root))
    raise ArgumentError, 'source path escapes workspace' unless full.start_with?(root + '/')
    raise ArgumentError, 'Ruby source path must end in .rb' unless path.end_with?('.rb')
    RubyVM::InstructionSequence.compile(File.binread(full), full, full, 1)
    files[path] = {}
  rescue SyntaxError, StandardError => error
    errors[path] = "#{error.class}: #{error.message}"[0, 2000]
  end
end
puts JSON.generate(root: root, files: files, errors: errors)
