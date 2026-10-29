# frozen_string_literal: true
# Run with the pinned bundle, passing an explicit private scratch parent.
# Exercises real Cucumber events; no Rails app, database or network is needed.
require 'json'
require 'fileutils'
require 'tmpdir'
require 'open3'
require 'rbconfig'

parent = File.realpath(ARGV.fetch(0))
Dir.mktmpdir('ruby-recorder-', parent) do |root|
  %w[_bench features/support features/step_definitions app].each { |path| FileUtils.mkdir_p(File.join(root, path)) }
  %w[bench_recorder.rb coverage_preload.rb coverage_hooks.rb compile_check.rb direct_calls.rb].each do |name|
    FileUtils.cp(File.join(__dir__, name), File.join(root, '_bench', name))
  end
  File.write(File.join(root, 'app/fixture.rb'), <<~SOURCE)
    module Subject
      def self.first
        17
      end
      def self.second
        23
      end
      def self.setup
        31
      end
      def self.teardown
        37
      end
      def self.arranged
        41
      end
      def self.acted
        43
      end
      def self.checked
        47
      end
      def self.echoed
        53
      end
      def self.shared
        59
      end
    end
  SOURCE
  File.write(File.join(root, 'features/support/env.rb'), <<~SOURCE)
    require_relative '../../app/fixture'
    Subject.first
    Before { Subject.setup }
    After { Subject.teardown }
    Before('@before_failure') { raise 'before witness' }
    After('@after_failure') { raise 'after witness' }
  SOURCE
  File.write(File.join(root, 'features/step_definitions/steps.rb'), <<~SOURCE)
    Given('first body') { raise unless Subject.first == 17 }
    Given('second body') { raise unless Subject.second == 23 }
    Given('failed body') { raise 'step witness' }
    Given('pending body') { pending('pending witness') }
    Given('ambiguous body') {}
    Given(/^ambiguous body$/) {}
    Given('row {word}') { |value| exit!(0) if value == 'stop'; Subject.first }
    Given('arranged body') { Subject.arranged }
    When('acted body') { Subject.acted; Subject.shared }
    Then('checked body') { Subject.checked; Subject.shared }
    Then('echoed body') { Subject.echoed }
  SOURCE
  File.write(File.join(root, 'features/check.feature'), <<~FEATURE)
    Feature: Ruby recorder
      Scenario: first
        Given first body
      Scenario: second
        Given second body
      Scenario: repeat first
        Given first body
      Scenario: failure
        Given failed body
      Scenario: undefined
        Given missing body
      Scenario: ambiguous
        Given ambiguous body
      @before_failure
      Scenario: setup failure
        Given first body
      @after_failure
      Scenario: teardown failure
        Given first body
      Scenario: pending
        Given pending body
  FEATURE
  File.write(File.join(root, 'features/outline.feature'), <<~FEATURE)
    Feature: Examples
      Scenario Outline: row <value>
        Given row <value>
        Examples:
          | value |
          | one |
          | two |
  FEATURE
  File.write(File.join(root, 'features/steps.feature'), <<~FEATURE)
    Feature: Per-step attribution
      Background:
        Given arranged body
      Scenario: attributed
        When acted body
        Then checked body
        And echoed body
  FEATURE
  File.write(File.join(root, 'features/incomplete.feature'), <<~FEATURE)
    Feature: Interrupted examples
      Scenario Outline: row <value>
        Given row <value>
        Examples:
          | value |
          | one |
          | stop |
  FEATURE
  cucumber = Gem.bin_path('cucumber', 'cucumber')
  command = [RbConfig.ruby, '-r', './_bench/coverage_preload.rb', '-r', './_bench/bench_recorder.rb',
             cucumber, '--no-profile', '--strict', '--publish-quiet',
             '--require', '_bench/coverage_hooks.rb', '--require', 'features', '--format', 'R2T::Recorder']
  run = lambda do |selector, measured|
    record = File.join(root, '_bench/run_record.jsonl')
    FileUtils.rm_f(record)
    stdout, stderr, status = Open3.capture3(
      { 'BENCH_REPO_ROOT' => root, 'BENCH_COVERAGE' => measured ? '1' : '0',
        'BENCH_RECORD_PATH' => record }, *command, selector, chdir: root
    )
    rows = File.exist?(record) ? File.readlines(record).map { |line| JSON.parse(line) } : []
    [status.exitstatus, rows, stdout + stderr]
  end
  code, rows, output = run.call('features/check.feature', true)
  statuses = rows.map { |row| row.fetch('steps').map { |step| step.fetch('result') } }
  expected = %w[passed passed passed failed undefined failed skipped passed pending].map { |value| [value] }
  raise "source-step statuses: #{statuses.inspect}\n#{output}" unless code == 1 && statuses == expected
  # `/2` since every event carries the step that made it: the marker moved
  # with the event shape, because the harness version alone cannot attest it.
  raise 'Ruby API marker or collection missing' unless rows.all? { |row| row['direct_calls'].is_a?(Array) && row['direct_calls_schema'] == 'r2t.ruby_direct_calls/2' }
  api_names = rows.take(3).map { |row| row['direct_calls'].map { |event| event.fetch('ruby_binding').fetch('method_name') }.sort }
  raise 'API reset or repeated body lost' unless api_names == [%w[first setup teardown], %w[second setup teardown], %w[first setup teardown]]
  first, second, repeated = rows.take(3).map { |row| row.fetch('coverage').fetch('units') }
  raise 'counter reset or repeated body lost' unless first == repeated && first.include?('app/fixture.rb::L3') && !second.include?('app/fixture.rb::L3') && second.include?('app/fixture.rb::L6')
  raise 'setup/teardown outside window' unless [first, second, repeated].all? { |units| units.include?('app/fixture.rb::L9') && units.include?('app/fixture.rb::L12') }
  raise 'hook failures lost' unless rows[6].fetch('hook_errors').any? && rows[7].fetch('hook_errors').any?
  code, trial, output = run.call('features/check.feature:2', false)
  raise "trial failed: #{output}" unless code.zero? && trial.one? && trial.first['coverage'].nil? && trial.first['direct_calls'].nil? && !trial.first.key?('direct_calls_schema')
  code, after, output = run.call('features/check.feature:18', true)
  raise "After failure lost: #{output}" unless code == 1 && after.one? && after.first['steps'].all? { |step| step['result'] == 'passed' } && after.first['scenario_result'] == 'not-passed'
  code, outline, output = run.call('features/outline.feature:2', true)
  raise "Examples identity failed: #{output}" unless code.zero? && outline.map { |row| row['scenario_line'] } == [6, 7]
  code, interrupted, output = run.call('features/incomplete.feature:2', false)
  raise "terminal flush failed: #{output}" unless code.zero? && interrupted.map { |row| row['scenario_line'] } == [6]
  # Per-step attribution (TARGET_INTERFACES_V2_SPEC section 4): the Background
  # step is index 0 because `steps` carries it first, the scenario's When/Then
  # follow in order, the And inherits Then without changing the count, and the
  # Before/After hooks call outside every step.
  code, attributed, output = run.call('features/steps.feature:4', true)
  raise "per-step run failed: #{output}" unless code.zero? && attributed.one?
  stepped = attributed.first
  keywords = stepped.fetch('steps').map { |step| step.fetch('keyword').strip }
  raise "step list: #{keywords.inspect}" unless keywords == %w[Given When Then And]
  attributed_steps = stepped.fetch('direct_calls').each_with_object({}) do |event, seen|
    (seen[event.fetch('ruby_binding').fetch('method_name')] ||= []) << event.fetch('step')
  end
  expected_steps = { 'setup' => [nil], 'teardown' => [nil], 'arranged' => [0],
                     'acted' => [1], 'checked' => [2], 'echoed' => [3],
                     'shared' => [1, 2] }
  raise "per-step attribution: #{attributed_steps.inspect}\n#{output}" unless attributed_steps == expected_steps
  File.write(File.join(root, 'safe.rb'), "File.write('MUST_NOT_EXIST', 'executed')\n")
  File.write(File.join(root, 'broken.rb'), "def missing(\n")
  stdout, stderr, status = Open3.capture3(RbConfig.ruby, '_bench/compile_check.rb', '--path', 'safe.rb', '--path', 'broken.rb', chdir: root)
  syntax = JSON.parse(stdout)
  raise "syntax gate failed: #{stderr}" unless status.success? && syntax.fetch('files').keys == ['safe.rb'] && syntax.fetch('errors').keys == ['broken.rb'] && !File.exist?(File.join(root, 'MUST_NOT_EXIST'))
  puts JSON.generate(result: 'PASS', cases: statuses, repeated_coverage: true,
                     setup_teardown_covered: true, api_windows_reset: true, trial_api_uncollected: true, examples_lines: [6, 7],
                     interrupted_lines: [6], attributed_steps: attributed_steps,
                     syntax_candidate_executed: false)
end
