# frozen_string_literal: true
require_relative 'coverage_preload'
require_relative 'bench_recorder'
require_relative 'direct_calls'

Around do |_scenario, block|
  R2T::ScenarioCoverage.start
  R2T::DirectCalls.start if R2T::ScenarioCoverage::ENABLED
  begin
    block.call
  ensure
    calls = R2T::ScenarioCoverage::ENABLED ? R2T::DirectCalls.finish : nil
    coverage, seconds = R2T::ScenarioCoverage.finish
    R2T::Recorder.active&.finish_window(coverage, seconds, calls)
  end
end
