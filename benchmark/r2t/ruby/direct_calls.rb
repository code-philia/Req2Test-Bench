# frozen_string_literal: true
# API_DIRECT_INVOCATION_SPEC Amendment 3. No application requires/autoloads.
require 'pathname'

module R2T
  module DirectCalls
    # `/2`: every event carries the step that made it (TARGET_INTERFACES_V2_SPEC
    # section 4).  Recorded even for an empty list, because a new harness can
    # execute an older seed whose recorder is substrate, so the harness version
    # alone cannot attest the event shape.
    SCHEMA = 'r2t.ruby_direct_calls/2'
    MODULE_NAME = Module.instance_method(:name)
    MODULE_DISPLAY = Module.instance_method(:to_s)
    MODULE_INSTANCE_METHOD = Module.instance_method(:instance_method)
    OBJECT_SINGLETON_CLASS = Object.instance_method(:singleton_class)
    CLASS_SINGLETON_P = Class.instance_method(:singleton_class?)
    ROOT = File.expand_path(ENV.fetch('BENCH_REPO_ROOT', Dir.pwd))

    # The 0-based index of the executing step in the record's `steps`, set by
    # the recorder's `test_step_started` and cleared at `test_step_finished`;
    # nil between steps, so a call made by a hook or by glue construction is
    # never charged to a step.  Which steps are actions or checks is decided
    # in Python from the feature text, never here.  Plain readers/writers
    # rather than attr_accessor: their bodies live in this file, so the
    # tracer's first filter drops their own activations.
    def self.step
      @step
    end

    def self.step=(value)
      @step = value
    end

    def self.subject?(path)
      path && ["#{ROOT}/app/", "#{ROOT}/lib/"].any? { |prefix| File.expand_path(path).start_with?(prefix) }
    end

    def self.relative(path)
      path && Pathname.new(File.expand_path(path)).relative_path_from(Pathname.new(ROOT)).to_s
    end

    def self.owner_identity(owner)
      return @owners[owner] if @owners.key?(owner)
      name = MODULE_NAME.bind_call(owner)
      if owner.is_a?(Class) && CLASS_SINGLETON_P.bind_call(owner)
        matches = ObjectSpace.each_object(Module).filter_map do |candidate|
          candidate_name = MODULE_NAME.bind_call(candidate)
          next if !candidate_name || candidate_name.empty?
          candidate_name if OBJECT_SINGLETON_CLASS.bind_call(candidate).equal?(owner)
        end
        value = matches.length == 1 ? [matches.first, 'singleton'] : nil
      else
        value = name && !name.empty? ? [name, 'instance'] : nil
      end
      @owners[owner] = value
    end

    def self.reflect(tp)
      key = [tp.defined_class, tp.method_id, tp.callee_id]
      return @cache[key] if @cache.key?(key)
      method = MODULE_INSTANCE_METHOD.bind_call(tp.defined_class, tp.callee_id)
      source = method.source_location
      identity = source && subject?(source[0]) ? owner_identity(method.owner) : nil
      @cache[key] = [source, identity]
    rescue NameError, TypeError
      @cache[key] = [nil, nil]
    end

    def self.start
      raise 'nested Ruby direct-call window' if @trace&.enabled?
      @cache, @owners, @events, @step = {}, {}, {}, nil
      @trace = TracePoint.new(:call, :c_call) do |tp|
        next if tp.event == :call && !subject?(tp.path)
        source, identity = reflect(tp)
        path, line = source || (tp.event == :call ? [tp.path, tp.lineno] : [nil, nil])
        next unless subject?(path)
        # Keep retrieval in this callback: :call has a Ruby callee frame;
        # :c_call does not. Never search ancestors for a removable caller.
        frames = caller_locations(0, 3)
        caller = frames[tp.event == :call ? 2 : 1]
        issue = if source.nil?
                  'unresolved_declaration'
                elsif !path.end_with?('.rb') || !line.is_a?(Integer) || line <= 0 || identity.nil?
                  'generated_method'
                end
        binding = if issue.nil?
                    { declaring_file: relative(path), declaring_line: line,
                      owner: identity[0], method_kind: identity[1], method_name: tp.callee_id.to_s }
                  end
        # Diagnostic labels must not dispatch an application override of to_s.
        # Unbound/generated owners retain the core display, including addresses.
        label = if binding
                  "#{binding[:owner]}#{binding[:method_kind] == 'singleton' ? '.' : '#'}#{binding[:method_name]}"
                else
                  "#{MODULE_DISPLAY.bind_call(tp.defined_class)}##{tp.callee_id}"
                end
        # The step is part of the event, and the event is the dedup key, so
        # the same call from two steps is two events. The API scorer collapses
        # them again; the per-step derivation needs them apart.
        event = { callee_file: relative(path), callee_line: line,
                  callee: label,
                  caller_file: relative(caller&.absolute_path || caller&.path),
                  ruby_binding: binding, ruby_binding_issue: issue,
                  step: step }
        @events[event] = true
      end
      @trace.enable
    end

    def self.finish
      raise 'Ruby direct-call window was not opened' unless @trace&.enabled?
      @trace.disable
      @events.keys.sort_by do |event|
        binding = event[:ruby_binding]
        values = event.values_at(:callee_file, :callee_line, :callee, :caller_file) +
                 (binding ? binding.values : [nil] * 5) +
                 [event[:ruby_binding_issue], event[:step]]
        values.map { |value| value.nil? ? [0, ''] : [1, value] }
      end
    ensure
      @cache = @owners = @events = nil
    end
  end
end
