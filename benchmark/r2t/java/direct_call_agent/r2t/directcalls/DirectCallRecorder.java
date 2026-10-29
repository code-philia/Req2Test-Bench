package r2t.directcalls;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Where the agent's activations land: the callee registry, the frame walk that
 * finds each activation's caller, the set of unique (callee, caller file) tuples,
 * and the one write at JVM exit.
 *
 * <p>Section 2.4's rules, as code:
 * <ul>
 * <li>the calling frame is the first frame above the callee that is not
 *     transparent; frames of the Java platform ({@code java.}, {@code javax.},
 *     {@code jdk.}, {@code sun.}, {@code com.sun.}) and synthetic or bridge
 *     methods are transparent, and nothing else is; the walk is unbounded and a
 *     stack with no such frame yields a null caller;</li>
 * <li>a frame's source path is its class's package path joined with the
 *     {@code SourceFile} basename, under the root its code source decides --
 *     {@code target/classes} is {@code src/main/java}, {@code target/test-classes}
 *     is {@code src/test/java} -- and null when either half is missing.  No root
 *     is ever guessed: a path resolved under the wrong root would be classified
 *     production by the boundary's fall-through and would silently make every
 *     call from that file non-direct;</li>
 * <li>the recorder applies no boundary: every activation of a production method
 *     is kept whatever its caller, so the run stays re-scorable.</li>
 * </ul>
 *
 * <p>Re-entrancy: {@code enter} touches only strings, this package and classes
 * the JVM has already defined -- {@link Class#getProtectionDomain()} initialises
 * nothing -- so no path from it into an instrumented method is known.  The
 * per-thread guard exists for the case that belief is wrong somewhere in the
 * JVM: a nested activation is then a dropped event, not unbounded recursion,
 * and what it drops was reached by the recorder, not by the test.
 *
 * <p>The current step ({@link #setStep}) is JVM-GLOBAL, not per-thread, because
 * this recorder is: one fork runs one scenario, {@code EVENTS} is one
 * process-wide set, and a step that hands work to another thread must still
 * have that work charged to it.  The cost is the other direction of the same
 * fact -- work a previous step left running on another thread is charged to
 * whatever step is current when it calls.  The harness-owned Cucumber listener
 * is the only caller: it sets the index of the executing pickle step and
 * restores -1 between steps, so a call made by a hook or by glue construction
 * carries {@code null}.  Which steps are actions or checks is decided later, in
 * Python, from the feature text; nothing here knows or decides that.
 */
public final class DirectCallRecorder {

    /** The production root and the test root, spelled as the boundary spells them. */
    static final String MAIN_ROOT = "src/main/java";
    static final String TEST_ROOT = "src/test/java";

    /**
     * The output file's schema string; the harness refuses any other.  It moved
     * to {@code /2} when every event gained {@code step}: a run mounts this jar
     * read-only at a fixed path, so the harness version cannot attest which
     * recorder wrote the file and the file has to say so itself.
     */
    static final String SCHEMA = "r2t.java-direct-calls/2";

    private static final String[] PLATFORM_PREFIXES = {
        "java.", "javax.", "jdk.", "sun.", "com.sun."};

    private static final String NO_FILE = "";

    private static final class Callee {
        final String callee;
        final String file;

        Callee(String callee, String file) {
            this.callee = callee;
            this.file = file;
        }
    }

    private static final Object REGISTRY_LOCK = new Object();
    private static volatile Callee[] table = new Callee[0];

    /** {@code internalName + '.' + name + descriptor} of every synthetic or bridge method seen. */
    private static final Set<String> TRANSPARENT = ConcurrentHashMap.newKeySet();

    /**
     * {@code id + '\0' + callerFile + '\0' + step} ({@code NO_FILE} for a null
     * caller, {@code NO_STEP} for a call made outside any step).  The step is
     * part of the identity, so the same call from two steps is two events; the
     * API scorer collapses them again.
     */
    private static final Set<String> EVENTS = ConcurrentHashMap.newKeySet();

    /** {@link #setStep}'s "no step is executing" value; written as null. */
    static final int NO_STEP = -1;

    /**
     * The executing step's index in the record's step list, JVM-wide.  Not a
     * {@code ThreadLocal}: see the class comment.
     */
    private static volatile int currentStep = NO_STEP;

    /**
     * Called by the harness-owned Cucumber listener, by reflection, with the
     * 0-based index of the executing pickle step among the test case's pickle
     * steps (Background steps first), or {@link #NO_STEP} between steps.
     */
    public static void setStep(int index) {
        currentStep = index;
    }

    private static final ConcurrentHashMap<Class<?>, String> CALLER_FILES =
        new ConcurrentHashMap<>();

    private static final ThreadLocal<boolean[]> IN_HOOK =
        ThreadLocal.withInitial(() -> new boolean[1]);

    private static final StackWalker WALKER =
        StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE);

    private static final List<String> TRANSFORM_FAILURES =
        Collections.synchronizedList(new ArrayList<>());

    private static final AtomicLong ACTIVATIONS = new AtomicLong();

    private static volatile Path output;

    // Present only for a measured multi-module workspace. Unmapped dependency
    // JARs have no source attribution; the legacy suffix rule is then disabled.
    private static Map<String, SourceRoot> codeSources;
    private static Path repository;

    private static final class SourceRoot {
        final String path;
        final boolean instrument;

        SourceRoot(String path, boolean instrument) {
            this.path = path;
            this.instrument = instrument;
        }
    }

    private static void loadCodeSources(Path input) throws IOException {
        List<String> lines = Files.readAllLines(input, StandardCharsets.UTF_8);
        String[] header = lines.isEmpty() ? new String[0] : lines.get(0).split("\\t", -1);
        if (header.length != 2 || !"r2t.java-code-sources/1".equals(header[0])
                || !Paths.get(header[1]).isAbsolute()) {
            throw new IOException("invalid code-source mapping header");
        }
        repository = Paths.get(header[1]);
        Map<String, SourceRoot> mappings = new HashMap<>();
        for (int i = 1; i < lines.size(); i++) {
            String[] row = lines.get(i).split("\\t", -1);
            if (row.length != 3 || !Paths.get(row[0]).isAbsolute()
                    || row[1].isEmpty() || Paths.get(row[1]).isAbsolute()
                    || !Paths.get(row[1]).normalize().toString().equals(row[1])
                    || row[1].startsWith("../")
                    || !("production".equals(row[2]) || "test".equals(row[2]))) {
                throw new IOException("invalid code-source row " + (i + 1));
            }
            if (mappings.put(row[0], new SourceRoot(row[1], "production".equals(row[2]))) != null) {
                throw new IOException("duplicate code source " + row[0]);
            }
        }
        if (mappings.isEmpty()) {
            throw new IOException("empty code-source mapping");
        }
        codeSources = mappings;
    }

    private DirectCallRecorder() {
    }

    // ------------------------------------------------------------ agent side

    static void install(Path out) {
        String mapping = System.getProperty("r2t.code.sources");
        if (mapping != null) {
            try {
                loadCodeSources(Paths.get(mapping));
            } catch (IOException e) {
                throw new IllegalArgumentException("r2t direct-call code sources: " + e, e);
            }
        }
        output = out.toAbsolutePath();
        Runtime.getRuntime().addShutdownHook(
            new Thread(DirectCallRecorder::dump, "r2t-direct-calls-dump"));
    }

    static boolean isOwnClass(String internalName) {
        return internalName.startsWith("r2t/directcalls/")
            || internalName.startsWith("org/objectweb/asm/");
    }

    /** The platform prefixes of section 2.4, spelled for an internal name. */
    static boolean isPlatformClass(String internalName) {
        for (String prefix : PLATFORM_PREFIXES) {
            if (internalName.startsWith(prefix.replace('.', '/'))) {
                return true;
            }
        }
        return false;
    }

    /**
     * The source root a code source stands for, or null.  The location is read as
     * the URL spells it ({@code file:/work/target/classes/}); the two suffixes
     * are matched on that spelling, which is enough for the paths the harness
     * mounts and needs no filesystem call at class-load time.
     */
    private static String codeSourcePath(ProtectionDomain domain) {
        if (domain == null) {
            return null;
        }
        CodeSource source = domain.getCodeSource();
        if (source == null || source.getLocation() == null) {
            return null;
        }
        String path = source.getLocation().getPath();
        if (path == null) {
            return null;
        }
        while (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return path;
    }

    static String sourceRootOf(ProtectionDomain domain) {
        String path = codeSourcePath(domain);
        if (path == null) {
            return null;
        }
        if (codeSources != null) {
            SourceRoot root = codeSources.get(path);
            return root == null ? null : root.path;
        }
        if (path.endsWith("/target/classes")) {
            return MAIN_ROOT;
        }
        if (path.endsWith("/target/test-classes")) {
            return TEST_ROOT;
        }
        return null;
    }

    static boolean isProduction(ProtectionDomain domain) {
        if (codeSources == null) {
            return MAIN_ROOT.equals(sourceRootOf(domain));
        }
        SourceRoot root = codeSources.get(codeSourcePath(domain));
        return root != null && root.instrument;
    }

    static boolean originalSourceAvailable(String root, String internalName, String sourceFile) {
        return repository == null || (sourceFile != null
            && sourcePath(root, internalName, sourceFile) != null);
    }

    static int register(String internalName, String name, String descriptor,
                        String sourceFile, String sourceRoot) {
        String callee = internalName.replace('/', '.') + "." + name + ":" + descriptor;
        String file = sourceFile == null ? null
            : sourcePath(sourceRoot, internalName, sourceFile);
        synchronized (REGISTRY_LOCK) {
            Callee[] grown = Arrays.copyOf(table, table.length + 1);
            grown[table.length] = new Callee(callee, file);
            table = grown;
            return grown.length - 1;
        }
    }

    static void noteTransparentMethod(String internalName, String name, String descriptor) {
        TRANSPARENT.add(internalName + "." + name + descriptor);
    }

    static void noteTransformFailure(String internalName, Throwable t) {
        String note = internalName + ": " + t;
        TRANSFORM_FAILURES.add(note);
        System.err.println("r2t direct-call agent: could not instrument " + note);
    }

    /** {@code root/<package path>/<SourceFile>}; a class in the unnamed package sits at the root. */
    private static String sourcePath(String root, String internalName, String fileName) {
        int slash = internalName.lastIndexOf('/');
        String relative = slash < 0 ? root + "/" + fileName
            : root + "/" + internalName.substring(0, slash) + "/" + fileName;
        // Generated classes (for example MapStruct mappers) have SourceFile
        // metadata but no original source under this module root. Never assign
        // them a fabricated original path. Existing single-module behavior stays.
        return repository == null || Files.isRegularFile(repository.resolve(relative))
            ? relative : null;
    }

    // -------------------------------------------------------------- the hook

    /** Called by the instrumented method as its first instruction. */
    public static void enter(int id) {
        boolean[] in = IN_HOOK.get();
        if (in[0]) {
            return;
        }
        in[0] = true;
        try {
            ACTIVATIONS.incrementAndGet();
            // Frame 0 is this method, frame 1 the instrumented callee.
            Optional<StackWalker.StackFrame> caller = WALKER.walk(
                frames -> frames.skip(2)
                    .filter(f -> !isTransparent(f))
                    .findFirst());
            String file = caller.isPresent() ? callerFile(caller.get()) : NO_FILE;
            EVENTS.add(id + "\0" + file + "\0" + currentStep);
        } finally {
            in[0] = false;
        }
    }

    private static boolean isTransparent(StackWalker.StackFrame frame) {
        String className = frame.getClassName();
        for (String prefix : PLATFORM_PREFIXES) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }
        return TRANSPARENT.contains(
            className.replace('.', '/') + "." + frame.getMethodName() + frame.getDescriptor());
    }

    private static String callerFile(StackWalker.StackFrame frame) {
        Class<?> cls = frame.getDeclaringClass();
        String cached = CALLER_FILES.get(cls);
        if (cached != null) {
            return cached;
        }
        String root = sourceRootOf(cls.getProtectionDomain());
        String fileName = frame.getFileName();
        String resolved = (root == null || fileName == null) ? NO_FILE
            : sourcePath(root, cls.getName().replace('.', '/'), fileName);
        resolved = resolved == null ? NO_FILE : resolved;
        CALLER_FILES.putIfAbsent(cls, resolved);
        return resolved;
    }

    // ------------------------------------------------------------- the dump

    private static final class Event {
        final String calleeFile;
        final String callee;
        final String callerFile;
        final Integer step;

        Event(String calleeFile, String callee, String callerFile, Integer step) {
            this.calleeFile = calleeFile;
            this.callee = callee;
            this.callerFile = callerFile;
            this.step = step;
        }
    }

    private static final Comparator<String> NULL_FIRST =
        Comparator.nullsFirst(Comparator.naturalOrder());

    private static final Comparator<Integer> STEP_NULL_FIRST =
        Comparator.nullsFirst(Comparator.naturalOrder());

    /** Section 2.5's order: the tuple, with null before any string; callee_line is always null here. */
    private static final Comparator<Event> ORDER = Comparator
        .comparing((Event e) -> e.calleeFile, NULL_FIRST)
        .thenComparing(e -> e.callee)
        .thenComparing(e -> e.callerFile, NULL_FIRST)
        .thenComparing(e -> e.step, STEP_NULL_FIRST);

    static void dump() {
        Callee[] callees = table;
        List<Event> events = new ArrayList<>(EVENTS.size());
        for (String key : EVENTS) {
            // id, then the caller file (which holds no NUL), then the step.
            int split = key.indexOf('\0');
            int stepSplit = key.lastIndexOf('\0');
            Callee callee = callees[Integer.parseInt(key.substring(0, split))];
            String file = key.substring(split + 1, stepSplit);
            int step = Integer.parseInt(key.substring(stepSplit + 1));
            events.add(new Event(callee.file, callee.callee,
                                 file.isEmpty() ? null : file,
                                 step == NO_STEP ? null : Integer.valueOf(step)));
        }
        events.sort(ORDER);
        StringBuilder out = new StringBuilder(64 + 160 * events.size());
        out.append("{\"schema\":").append(Json.string(SCHEMA));
        out.append(",\"activations\":").append(ACTIVATIONS.get());
        out.append(",\"transform_failures\":[");
        List<String> failures;
        synchronized (TRANSFORM_FAILURES) {
            failures = new ArrayList<>(TRANSFORM_FAILURES);
        }
        for (int i = 0; i < failures.size(); i++) {
            out.append(i == 0 ? "" : ",").append(Json.string(failures.get(i)));
        }
        out.append("],\"events\":[");
        for (int i = 0; i < events.size(); i++) {
            Event e = events.get(i);
            out.append(i == 0 ? "\n" : ",\n");
            out.append("{\"callee_file\":").append(Json.string(e.calleeFile));
            out.append(",\"callee_line\":null");
            out.append(",\"callee\":").append(Json.string(e.callee));
            out.append(",\"caller_file\":").append(Json.string(e.callerFile));
            out.append(",\"step\":").append(e.step == null ? "null" : e.step.toString());
            out.append('}');
        }
        out.append("]}\n");
        try {
            Path target = output;
            Path parent = target.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path temp = parent.resolve(target.getFileName() + ".tmp-"
                                       + ProcessHandle.current().pid());
            Files.write(temp, out.toString().getBytes(StandardCharsets.UTF_8));
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE,
                       StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            System.err.println("r2t direct-call agent: could not write " + output + ": " + e);
        }
    }
}
