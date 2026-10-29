# frozen_string_literal: true
# Loaded by ruby -r before Cucumber loads Rails; never inherited through RUBYOPT.
require 'coverage'
require 'pathname'

module R2T
  module ScenarioCoverage
    ROOT = File.expand_path(ENV.fetch('BENCH_REPO_ROOT', Dir.pwd))
    ENABLED = ENV['BENCH_COVERAGE'] == '1'

    def self.subject?(path)
      path && ["#{ROOT}/app/", "#{ROOT}/lib/"].any? { |prefix| File.expand_path(path).start_with?(prefix) }
    end

    def self.start
      raise 'nested Ruby coverage window' if @open
      Coverage.result(stop: false, clear: true) if ENABLED
      @open = true
      @started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end

    def self.finish
      raise 'Ruby coverage window was not opened' unless @open
      seconds = Process.clock_gettime(Process::CLOCK_MONOTONIC) - @started
      measured = ENABLED ? Coverage.result(stop: false, clear: true) : nil
      @open = false
      files = {}
      units = []
      (measured || {}).sort.each do |path, counters|
        next unless subject?(path)
        counters = counters.fetch(:lines) if counters.is_a?(Hash)
        lines = counters.each_index.select { |index| counters[index].to_i.positive? }.map { |index| index + 1 }
        next if lines.empty?
        rel = Pathname.new(File.expand_path(path)).relative_path_from(Pathname.new(ROOT)).to_s
        files[rel] = lines.length
        units.concat(lines.map { |line| "#{rel}::L#{line}" })
      end
      [ENABLED ? { files: files, units: units } : nil, seconds]
    end

    if ENABLED
      require 'simplecov'
      raise "Ruby coverage requires SimpleCov 0.22.0, got #{SimpleCov::VERSION}" unless SimpleCov::VERSION == '0.22.0'
      SimpleCov.root(ROOT)
      SimpleCov.coverage_dir(File.join(ROOT, 'tmp', 'r2t-coverage'))
      SimpleCov.use_merging(false)
      SimpleCov.at_exit {}
      SimpleCov.start
    end
  end
end
