// Parent-process API entries and native coverage with one shared final snapshot.
// Native fixture mechanism qualified under Go 1.25; whole-stack enablement is separate.
// The finalization is r2t.go-measurement/2: its entries name the step that made
// them. The marker moves with the shape because the harness version cannot
// attest it -- a new harness can execute an older seed whose recorder is
// substrate (TARGET_INTERFACES_V2_SPEC.md section 4).
package r2tmeasure

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const root = "/r2t-go/run/work/"
const ownerPath = "/r2t-go/run/measurement-owner.pid"
const outputPath = "/r2t-go/run/measurement.json"

// Step is the 0-based index of the executing step in the record's step list
// (the Background's steps, then the scenario's own), null for a call made
// outside any step. It is part of the event's identity, so the same call from
// two steps is two events. This recorder decides nothing about which steps
// are actions or checks; that is derived later, from the feature source.
type Event struct {
	File   string  `json:"callee_file"`
	Line   int     `json:"callee_line"`
	Name   string  `json:"callee"`
	Caller *string `json:"caller_file"`
	Step   *int    `json:"step"`
}
type Frame struct {
	Function, File string
	Line           int
	Physical       string
}
type Trace struct {
	Event   Event
	Frames  []Frame
	Skipped []string
}
type Coverage struct {
	File       string
	Counts     []uint32
	Positions  []uint32
	Statements []uint16
}

var mu sync.Mutex

// The step whose handler is running, -1 between steps. The harness sets it
// from godog's own step hooks; every entry recorded while it is negative was
// made outside a step (a hook, or glue construction) and carries null.
var currentStep = -1
var events = map[string]Event{}
var traces = map[string]Trace{}
var coverages []Coverage
var failures []string
var parent = claimParent()
var activations uint64

// Every instrumented production package imports this recorder, so its init
// precedes subject initialization and any subject-launched child. A reexecuted
// test binary observes the first process's claim rather than joining its output.
func claimParent() bool {
	f, err := os.OpenFile(ownerPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if os.IsExist(err) {
		raw, readErr := os.ReadFile(ownerPath)
		if readErr != nil {
			failures = append(failures, "cannot read parent claim: "+readErr.Error())
			return false
		}
		pid, parseErr := strconv.Atoi(strings.TrimSpace(string(raw)))
		if parseErr != nil || pid <= 0 {
			failures = append(failures, "invalid parent claim")
			return false
		}
		return pid == os.Getpid()
	}
	if err != nil {
		failures = append(failures, "cannot create parent claim: "+err.Error())
		return false
	}
	_, err = fmt.Fprintf(f, "%d\n", os.Getpid())
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		failures = append(failures, "cannot finish parent claim")
		return false
	}
	return true
}

func Register(file string, counts []uint32, positions []uint32, statements []uint16) {
	if !parent {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if len(positions) != 3*len(counts) || len(statements) != len(counts) {
		failures = append(failures, "native counter dimensions differ: "+file)
		return
	}
	for _, c := range coverages {
		if c.File == file {
			failures = append(failures, "duplicate native counters: "+file)
			return
		}
	}
	coverages = append(coverages, Coverage{file, counts, positions, statements})
}

// SetStep names the step that subsequent entries belong to, or -1 for none.
// The same mutex that linearizes entries against finalization linearizes the
// step boundary against them, so an entry never straddles two steps.
func SetStep(index int) {
	if !parent {
		return
	}
	mu.Lock()
	currentStep = index
	mu.Unlock()
}

// Hit replaces only the native instrumenter's counter increment, leaving its
// original blocks, positions, statement counts and counter storage untouched.
// The same mutex linearizes increments and API entries against finalization.
func Hit(counter *uint32) {
	if !parent {
		return
	}
	mu.Lock()
	*counter++
	mu.Unlock()
}

//go:noinline
func Enter(file string, line int, name string) {
	if !parent {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	activations++
	var pcs [16]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	var raw []Frame
	for {
		f, more := frames.Next()
		physical := ""
		if fn := runtime.FuncForPC(f.Entry); fn != nil {
			physical = fn.Name()
		}
		raw = append(raw, Frame{f.Function, f.File, f.Line, physical})
		if !more {
			break
		}
	}
	if len(raw) < 2 || raw[0].File != root+file {
		failures = append(failures, "instrumented callee source mismatch: "+file)
		return
	}
	var skipped []string
	i := 1
	for i < len(raw) && (raw[i].Function == "reflect.Value.call" || raw[i].Function == "reflect.Value.Call") {
		skipped = append(skipped, raw[i].Function)
		i++
	}
	var caller *string
	if i < len(raw) && strings.HasPrefix(raw[i].File, root) {
		rel := filepath.ToSlash(strings.TrimPrefix(raw[i].File, root))
		if rel != "" && rel != "." && !strings.HasPrefix(rel, "../") {
			caller = &rel
		}
	}
	var step *int
	if currentStep >= 0 {
		index := currentStep
		step = &index
	}
	event := Event{file, line, name, caller, step}
	key, err := json.Marshal(event)
	if err != nil {
		failures = append(failures, "cannot encode API event")
		return
	}
	events[string(key)] = event
	traces[string(key)] = Trace{event, raw, skipped}
}

// FinalizeAndExit is called after testing.M.Run. Holding the shared mutex
// through exit establishes one final cut: late coverage increments and API
// entries cannot advance either collection while its peer is being serialized.
// The native qualification leaves a background goroutine active at this cut.
// This does not wait for subject work or grant additional execution time.
func FinalizeAndExit(code int) {
	if !parent {
		os.Exit(code)
	}
	mu.Lock()
	ordered := make([]Event, 0, len(events))
	for _, e := range events {
		ordered = append(ordered, e)
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if (a.Caller == nil) != (b.Caller == nil) {
			return a.Caller == nil
		}
		if a.Caller != nil && *a.Caller != *b.Caller {
			return *a.Caller < *b.Caller
		}
		// The step orders last, so two entries that differ only in the step
		// that made them stay adjacent, the one made outside a step first.
		if (a.Step == nil) != (b.Step == nil) {
			return a.Step == nil
		}
		return a.Step != nil && *a.Step < *b.Step
	})
	orderedTraces := make([]Trace, 0, len(ordered))
	for _, e := range ordered {
		key, _ := json.Marshal(e)
		orderedTraces = append(orderedTraces, traces[string(key)])
	}
	sort.Slice(coverages, func(i, j int) bool { return coverages[i].File < coverages[j].File })
	doc := map[string]any{"schema": "r2t.go-measurement/2", "complete": len(failures) == 0,
		"pid": os.Getpid(), "exit": code, "window": "selected-parent-process-through-M.Run-cleanup",
		"direct_calls": ordered, "raw_frames": orderedTraces, "coverage": coverages, "failures": failures, "activations": activations}
	f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "r2t collection:", err)
		os.Exit(code)
	}
	if err = json.NewEncoder(f).Encode(doc); err != nil {
		fmt.Fprintln(os.Stderr, "r2t collection:", err)
	}
	if err = f.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "r2t collection:", err)
	}
	os.Exit(code)
}
