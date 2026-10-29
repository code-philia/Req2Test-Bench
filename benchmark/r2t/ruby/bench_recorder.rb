# frozen_string_literal: true
# Native in-process source-step listener. Only terminal cases are appended.
require 'json'
require 'fileutils'
require 'pathname'
require 'cucumber/formatter/ast_lookup'

module R2T
  class Recorder
    class << self
      attr_accessor :active
    end
    RESULTS = { passed: 'passed', skipped: 'skipped', pending: 'pending',
                undefined: 'undefined', failed: 'failed', ambiguous: 'failed',
                flaky: 'failed', unknown: 'failed' }.freeze

    def initialize(config)
      @root = File.expand_path(ENV.fetch('BENCH_REPO_ROOT', Dir.pwd))
      @path = File.expand_path(ENV.fetch('BENCH_RECORD_PATH', '_bench/run_record.jsonl'), @root)
      raise 'Ruby record path must be _bench/run_record.jsonl' unless @path == File.join(@root, '_bench/run_record.jsonl')
      @ast = Cucumber::Formatter::AstLookup.new(config)
      self.class.active = self
      config.on_event :test_case_started, &method(:case_started)
      config.on_event :test_step_started, &method(:step_started)
      config.on_event :test_step_finished, &method(:step_finished)
      config.on_event :test_case_finished, &method(:case_finished)
    end

    def case_started(event)
      raise 'overlapping Ruby scenario records' if @record
      test_case = event.test_case
      uri = test_case.location.file
      feature = @ast.gherkin_document(uri).feature
      @case = test_case
      @source_step_count = test_case.test_steps.count { |step| !step.hook? }
      @started_steps = 0
      @window_complete = false
      @record = {
        feature_file: Pathname.new(File.expand_path(uri, @root)).relative_path_from(Pathname.new(@root)).to_s,
        feature_title: feature.name, scenario_title: test_case.name,
        scenario_line: test_case.location.lines.max, suite: 'cucumber_ruby',
        steps: [], coverage: nil, direct_calls: nil, seconds: 0.0,
        scenario_result: nil
      }
      @hook_errors = []
    end

    def exception_doc(result)
      exception = result.respond_to?(:exception) ? result.exception : nil
      return { class: exception.class.name, message: exception.message.to_s[0, 2000] } if exception
      return nil if %i[passed skipped undefined].include?(result.to_sym)
      { class: result.class.name, message: result.to_s[0, 2000] }
    end

    # Cucumber broadcasts this before the step's body runs, so every direct
    # call the body makes is charged to the step (TARGET_INTERFACES_V2_SPEC
    # section 4).  The counter runs over non-hook steps only, in the order
    # `step_finished` appends them to `@record[:steps]` -- Background steps
    # first, then the scenario's own -- so it IS the index in that list.
    # Hook steps never touch it, so a Before/After call carries null.
    def step_started(event)
      raise 'Ruby step started without scenario' unless @record
      return if event.test_step.hook?
      R2T::DirectCalls.step = @started_steps
      @started_steps += 1
    end

    def step_finished(event)
      raise 'Ruby step finished without scenario' unless @record
      step = event.test_step
      result = event.result
      R2T::DirectCalls.step = nil unless step.hook?
      status = RESULTS.fetch(result.to_sym, 'failed')
      exception = exception_doc(result)
      if step.hook?
        @hook_errors << { location: step.location.to_s, result: status, exception: exception } unless status == 'passed'
        return
      end
      source = @ast.step_source(step).step
      seconds = 0.0
      result.duration.tap { |duration| seconds = duration.nanoseconds / 1_000_000_000.0 } if result.respond_to?(:duration)
      @record[:steps] << { line: step.location.lines.min, keyword: source.keyword,
                           text: step.text, result: status, seconds: seconds,
                           exception: exception }
    end

    def finish_window(coverage, seconds, calls = nil)
      raise 'Ruby coverage finished without scenario' unless @record
      @record[:direct_calls] = calls
      @record[:direct_calls_schema] = R2T::DirectCalls::SCHEMA unless calls.nil?
      @record[:coverage] = coverage
      @record[:seconds] = seconds
      @window_complete = true
    end

    def case_finished(event)
      raise 'Ruby terminal event names another scenario' unless @record && event.test_case.equal?(@case)
      raise 'Ruby scenario record has incomplete source steps' unless @record[:steps].length == @source_step_count
      # A dry run has no Around window and all source steps remain skipped.
      if ENV['BENCH_COVERAGE'] == '1' && !@window_complete
        raise 'Ruby measured scenario finished without its coverage window'
      end
      result = event.result
      @record[:scenario_result] = result.to_sym == :passed ? 'passed' : 'not-passed'
      if result.to_sym != :passed && @hook_errors.empty? && @record[:steps].all? { |step| step[:result] == 'passed' }
        @hook_errors << { location: @case.location.to_s, result: RESULTS.fetch(result.to_sym, 'failed'), exception: exception_doc(result) }
      end
      @record[:hook_errors] = @hook_errors unless @hook_errors.empty?
      FileUtils.mkdir_p(File.dirname(@path))
      File.open(@path, 'a') { |stream| stream.write(JSON.generate(@record) + "\n"); stream.flush }
      @record = @case = nil
    end
  end
end
