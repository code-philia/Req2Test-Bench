/*
 * Source-only bridge from the two protocol-pinned Cucumber Gherkin APIs to a
 * small, id-free AST.  It intentionally has no compile-time dependency: the
 * Python controller verifies the exact parser/message JAR digests first,
 * compiles this source with plain javac, and supplies those JARs only at run
 * time.  Reflection keeps the version-15 protobuf API and version-24 POJO API
 * in separate, explicit adapter paths without vendoring either parser.
 */
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

public final class J0GherkinBridge {
    private J0GherkinBridge() {}

    private static final class Parsed {
        private final Object document;
        private final List<Object> pickles;

        Parsed(Object document, List<Object> pickles) {
            this.document = document;
            this.pickles = pickles;
        }
    }

    private static Object call(Object target, String name, Object... args)
            throws ReflectiveOperationException {
        Method selected = null;
        outer:
        for (Method method : target.getClass().getMethods()) {
            if (!method.getName().equals(name)
                    || method.getParameterCount() != args.length) {
                continue;
            }
            Class<?>[] types = method.getParameterTypes();
            for (int i = 0; i < types.length; i++) {
                if (args[i] != null && !box(types[i]).isInstance(args[i])) {
                    continue outer;
                }
            }
            selected = method;
            break;
        }
        if (selected == null) {
            throw new NoSuchMethodException(target.getClass().getName()
                    + "." + name + "/" + args.length);
        }
        try {
            return selected.invoke(target, args);
        } catch (InvocationTargetException exc) {
            Throwable cause = exc.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw exc;
        }
    }

    private static Class<?> box(Class<?> cls) {
        if (!cls.isPrimitive()) return cls;
        if (cls == boolean.class) return Boolean.class;
        if (cls == int.class) return Integer.class;
        if (cls == long.class) return Long.class;
        if (cls == double.class) return Double.class;
        if (cls == float.class) return Float.class;
        if (cls == byte.class) return Byte.class;
        if (cls == short.class) return Short.class;
        if (cls == char.class) return Character.class;
        return cls;
    }

    private static Object unwrap(Object value) {
        if (value instanceof Optional<?>) {
            return ((Optional<?>) value).orElse(null);
        }
        return value;
    }

    private static Object get(Object target, String stem)
            throws ReflectiveOperationException {
        return unwrap(call(target, "get" + stem));
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object target, String stem)
            throws ReflectiveOperationException {
        Object value;
        try {
            value = call(target, "get" + stem);
        } catch (NoSuchMethodException exc) {
            value = call(target, "get" + stem + "List");
        }
        return (List<Object>) value;
    }

    private static Object choice(Object target, String stem)
            throws ReflectiveOperationException {
        try {
            Object present = call(target, "has" + stem);
            if (present instanceof Boolean && !((Boolean) present)) return null;
        } catch (NoSuchMethodException ignored) {
            // The version-24 API returns Optional from getX instead.
        }
        return get(target, stem);
    }

    private static long number(Object value) {
        return ((Number) value).longValue();
    }

    private static Map<String, Object> location(Object node)
            throws ReflectiveOperationException {
        Object loc = get(node, "Location");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("column", number(get(loc, "Column")));
        out.put("line", number(get(loc, "Line")));
        return out;
    }

    private static List<Object> tags(Object node)
            throws ReflectiveOperationException {
        List<Object> out = new ArrayList<>();
        for (Object tag : list(node, "Tags")) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("location", location(tag));
            item.put("name", get(tag, "Name"));
            out.add(item);
        }
        return out;
    }

    private static Map<String, Object> step(Object node)
            throws ReflectiveOperationException {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("keyword", get(node, "Keyword"));
        out.put("location", location(node));
        out.put("text", get(node, "Text"));
        return out;
    }

    private static Map<String, Object> cell(Object node)
            throws ReflectiveOperationException {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("location", location(node));
        out.put("value", get(node, "Value"));
        return out;
    }

    private static Map<String, Object> row(Object node)
            throws ReflectiveOperationException {
        Map<String, Object> out = new LinkedHashMap<>();
        List<Object> cells = new ArrayList<>();
        for (Object value : list(node, "Cells")) cells.add(cell(value));
        out.put("cells", cells);
        out.put("location", location(node));
        return out;
    }

    private static Map<String, Object> examples(Object node)
            throws ReflectiveOperationException {
        Map<String, Object> out = new LinkedHashMap<>();
        List<Object> body = new ArrayList<>();
        for (Object value : list(node, "TableBody")) body.add(row(value));
        Object header = choice(node, "TableHeader");
        out.put("description", get(node, "Description"));
        out.put("keyword", get(node, "Keyword"));
        out.put("location", location(node));
        out.put("name", get(node, "Name"));
        out.put("table_body", body);
        out.put("table_header", header == null ? null : row(header));
        out.put("tags", tags(node));
        out.put("type", "examples");
        return out;
    }

    private static List<Object> steps(Object node)
            throws ReflectiveOperationException {
        List<Object> out = new ArrayList<>();
        for (Object value : list(node, "Steps")) out.add(step(value));
        return out;
    }

    private static Map<String, Object> scenario(Object node)
            throws ReflectiveOperationException {
        Map<String, Object> out = new LinkedHashMap<>();
        List<Object> examples = new ArrayList<>();
        for (Object value : list(node, "Examples")) {
            examples.add(examples(value));
        }
        out.put("description", get(node, "Description"));
        out.put("examples", examples);
        out.put("keyword", get(node, "Keyword"));
        out.put("location", location(node));
        out.put("name", get(node, "Name"));
        out.put("steps", steps(node));
        out.put("tags", tags(node));
        out.put("type", "scenario");
        return out;
    }

    private static Map<String, Object> background(Object node)
            throws ReflectiveOperationException {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("description", get(node, "Description"));
        out.put("keyword", get(node, "Keyword"));
        out.put("location", location(node));
        out.put("name", get(node, "Name"));
        out.put("steps", steps(node));
        out.put("type", "background");
        return out;
    }

    private static Map<String, Object> rule(Object node)
            throws ReflectiveOperationException {
        Map<String, Object> out = new LinkedHashMap<>();
        List<Object> children = new ArrayList<>();
        for (Object child : list(node, "Children")) {
            Object scenario = choice(child, "Scenario");
            Object background = choice(child, "Background");
            if (scenario != null) children.add(scenario(scenario));
            else if (background != null) children.add(background(background));
            else throw new IllegalArgumentException("unknown RuleChild variant");
        }
        out.put("children", children);
        out.put("description", get(node, "Description"));
        out.put("keyword", get(node, "Keyword"));
        out.put("location", location(node));
        out.put("name", get(node, "Name"));
        out.put("tags", tags(node));
        out.put("type", "rule");
        return out;
    }

    private static Map<String, Object> feature(Object node)
            throws ReflectiveOperationException {
        Map<String, Object> out = new LinkedHashMap<>();
        List<Object> children = new ArrayList<>();
        for (Object child : list(node, "Children")) {
            Object scenario = choice(child, "Scenario");
            Object background = choice(child, "Background");
            Object rule = choice(child, "Rule");
            if (scenario != null) children.add(scenario(scenario));
            else if (background != null) children.add(background(background));
            else if (rule != null) children.add(rule(rule));
            else throw new IllegalArgumentException("unknown FeatureChild variant");
        }
        out.put("children", children);
        out.put("description", get(node, "Description"));
        out.put("keyword", get(node, "Keyword"));
        out.put("language", get(node, "Language"));
        out.put("location", location(node));
        out.put("name", get(node, "Name"));
        out.put("tags", tags(node));
        out.put("type", "feature");
        return out;
    }

    private static Object deterministicIdGenerator() throws Exception {
        Class<?> api = Class.forName("io.cucumber.messages.IdGenerator");
        AtomicLong next = new AtomicLong();
        return Proxy.newProxyInstance(api.getClassLoader(), new Class<?>[]{api},
                (proxy, method, args) -> {
                    if (method.getName().equals("newId")) {
                        return "r2t-" + next.getAndIncrement();
                    }
                    if (method.getName().equals("toString")) return "r2t-id-generator";
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private static void addAstRef(Map<String, Map<String, Object>> refs,
            Object node, String kind) throws ReflectiveOperationException {
        String id;
        try {
            id = (String) get(node, "Id");
        } catch (NoSuchMethodException ignored) {
            // Feature/Rule/Background nodes have no generated id in these
            // message versions and cannot be referenced by a Pickle.
            return;
        }
        if (id == null || id.isEmpty() || refs.containsKey(id)) {
            throw new IllegalArgumentException("missing/duplicate AST node id");
        }
        Map<String, Object> ref = new LinkedHashMap<>();
        ref.put("kind", kind);
        ref.put("location", location(node));
        refs.put(id, ref);
    }

    private static void indexSteps(Map<String, Map<String, Object>> refs,
            Object owner) throws ReflectiveOperationException {
        for (Object value : list(owner, "Steps")) addAstRef(refs, value, "Step");
    }

    private static void indexScenario(Map<String, Map<String, Object>> refs,
            Object scenario) throws ReflectiveOperationException {
        addAstRef(refs, scenario, "Scenario");
        indexSteps(refs, scenario);
        for (Object examples : list(scenario, "Examples")) {
            addAstRef(refs, examples, "Examples");
            Object header = choice(examples, "TableHeader");
            if (header != null) addAstRef(refs, header, "ExamplesHeader");
            for (Object row : list(examples, "TableBody")) {
                addAstRef(refs, row, "ExamplesRow");
            }
        }
    }

    private static void indexBackground(Map<String, Map<String, Object>> refs,
            Object background) throws ReflectiveOperationException {
        addAstRef(refs, background, "Background");
        indexSteps(refs, background);
    }

    private static void indexRule(Map<String, Map<String, Object>> refs,
            Object rule) throws ReflectiveOperationException {
        addAstRef(refs, rule, "Rule");
        for (Object child : list(rule, "Children")) {
            Object scenario = choice(child, "Scenario");
            Object background = choice(child, "Background");
            if (scenario != null) indexScenario(refs, scenario);
            else if (background != null) indexBackground(refs, background);
            else throw new IllegalArgumentException("unknown RuleChild variant");
        }
    }

    private static Map<String, Map<String, Object>> indexAstRefs(Object document)
            throws ReflectiveOperationException {
        Map<String, Map<String, Object>> refs = new HashMap<>();
        Object feature = choice(document, "Feature");
        if (feature == null) throw new IllegalArgumentException(
                "Gherkin document has no Feature");
        addAstRef(refs, feature, "Feature");
        for (Object child : list(feature, "Children")) {
            Object scenario = choice(child, "Scenario");
            Object background = choice(child, "Background");
            Object rule = choice(child, "Rule");
            if (scenario != null) indexScenario(refs, scenario);
            else if (background != null) indexBackground(refs, background);
            else if (rule != null) indexRule(refs, rule);
            else throw new IllegalArgumentException("unknown FeatureChild variant");
        }
        return refs;
    }

    private static Map<String, Object> stablePickle(Object pickle,
            Map<String, Map<String, Object>> refs)
            throws ReflectiveOperationException {
        List<Object> astRefs = new ArrayList<>();
        for (Object value : list(pickle, "AstNodeIds")) {
            if (!(value instanceof String) || !refs.containsKey((String) value)) {
                throw new IllegalArgumentException(
                        "Pickle references an unknown generated AST id");
            }
            astRefs.add(refs.get((String) value));
        }
        Collections.sort(astRefs, (left, right) ->
                canonicalJson(left).compareTo(canonicalJson(right)));
        List<String> effectiveTags = new ArrayList<>();
        for (Object value : list(pickle, "Tags")) {
            effectiveTags.add((String) get(value, "Name"));
        }
        Collections.sort(effectiveTags);
        for (int i = 1; i < effectiveTags.size(); i++) {
            if (effectiveTags.get(i - 1).equals(effectiveTags.get(i))) {
                throw new IllegalArgumentException("Pickle has duplicate effective tags");
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ast_node_refs", astRefs);
        out.put("effective_tags", effectiveTags);
        out.put("language", get(pickle, "Language"));
        out.put("name", get(pickle, "Name"));
        return out;
    }

    private static List<Object> stablePickles(Object document, List<Object> pickles)
            throws ReflectiveOperationException {
        Map<String, Map<String, Object>> refs = indexAstRefs(document);
        List<Object> out = new ArrayList<>();
        for (Object pickle : pickles) out.add(stablePickle(pickle, refs));
        Collections.sort(out, (left, right) ->
                canonicalJson(left).compareTo(canonicalJson(right)));
        return out;
    }

    private static Parsed parse15(String uri, String data) throws Exception {
        Class<?> gherkin = Class.forName(
                "io.cucumber.core.gherkin.messages.internal.gherkin.Gherkin");
        // Gherkin 15's shaded helper predates the typed Source constructor;
        // its parameter order is (data, uri), unlike Source(uri, data, ...)
        // in Messages 19/Gherkin 24.
        Object source = gherkin.getMethod("makeSourceEnvelope",
                String.class, String.class).invoke(null, data, uri);
        Method fromSources = null;
        for (Method method : gherkin.getMethods()) {
            if (method.getName().equals("fromSources")) fromSources = method;
        }
        if (fromSources == null) throw new NoSuchMethodException("fromSources");
        @SuppressWarnings("unchecked")
        Stream<Object> stream = (Stream<Object>) fromSources.invoke(null,
                Arrays.asList(source), false, true, true,
                deterministicIdGenerator());
        try (Stream<Object> closeable = stream) {
            Object[] envelopes = closeable.toArray();
            Object document = null;
            List<Object> pickles = new ArrayList<>();
            for (Object envelope : envelopes) {
                if (Boolean.TRUE.equals(call(envelope, "hasParseError"))) {
                    throw new IllegalArgumentException("Gherkin parse error: "
                            + call(envelope, "getParseError"));
                }
                if (Boolean.TRUE.equals(call(envelope, "hasGherkinDocument"))) {
                    if (document != null) throw new IllegalArgumentException(
                            "multiple Gherkin documents for one source");
                    document = call(envelope, "getGherkinDocument");
                }
                if (Boolean.TRUE.equals(call(envelope, "hasPickle"))) {
                    pickles.add(call(envelope, "getPickle"));
                }
            }
            if (document == null) throw new IllegalArgumentException(
                    "parser emitted no Gherkin document");
            return new Parsed(document, pickles);
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Parsed parse24(String uri, String data) throws Exception {
        Class<?> mediaClass = Class.forName(
                "io.cucumber.messages.types.SourceMediaType");
        Object media = Enum.valueOf((Class<Enum>) mediaClass,
                "TEXT_X_CUCUMBER_GHERKIN_PLAIN");
        Class<?> sourceClass = Class.forName("io.cucumber.messages.types.Source");
        Object source = sourceClass.getConstructor(String.class, String.class,
                mediaClass).newInstance(uri, data, media);
        Class<?> envelopeClass = Class.forName(
                "io.cucumber.messages.types.Envelope");
        Object envelope = envelopeClass.getMethod("of", sourceClass)
                .invoke(null, source);
        Class<?> parserClass = Class.forName("io.cucumber.gherkin.GherkinParser");
        Object builder = parserClass.getMethod("builder").invoke(null);
        call(builder, "includeSource", false);
        call(builder, "includeGherkinDocument", true);
        call(builder, "includePickles", true);
        call(builder, "idGenerator", deterministicIdGenerator());
        Object parser = call(builder, "build");
        Stream<Object> stream = (Stream<Object>) call(parser, "parse", envelope);
        try (Stream<Object> closeable = stream) {
            Object[] envelopes = closeable.toArray();
            Object document = null;
            List<Object> pickles = new ArrayList<>();
            for (Object value : envelopes) {
                Object error = get(value, "ParseError");
                if (error != null) throw new IllegalArgumentException(
                        "Gherkin parse error: " + error);
                Object candidate = get(value, "GherkinDocument");
                if (candidate != null) {
                    if (document != null) throw new IllegalArgumentException(
                            "multiple Gherkin documents for one source");
                    document = candidate;
                }
                Object pickle = get(value, "Pickle");
                if (pickle != null) pickles.add(pickle);
            }
            if (document == null) throw new IllegalArgumentException(
                    "parser emitted no Gherkin document");
            return new Parsed(document, pickles);
        }
    }

    private static String readUtf8(Path path) throws IOException {
        byte[] raw = Files.readAllBytes(path);
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw)).toString();
        } catch (CharacterCodingException exc) {
            throw new IOException("source is not strict UTF-8", exc);
        }
    }

    private static void jsonString(String value, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (ch < 0x20) out.append(String.format("\\u%04x", (int) ch));
                    else out.append(ch);
            }
        }
        out.append('"');
    }

    private static void json(Object value, StringBuilder out) {
        if (value == null) out.append("null");
        else if (value instanceof String) jsonString((String) value, out);
        else if (value instanceof Boolean || value instanceof Number) out.append(value);
        else if (value instanceof List<?>) {
            out.append('[');
            boolean first = true;
            for (Object item : (List<?>) value) {
                if (!first) out.append(',');
                first = false;
                json(item, out);
            }
            out.append(']');
        } else if (value instanceof Map<?, ?>) {
            out.append('{');
            boolean first = true;
            TreeMap<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                sorted.put((String) entry.getKey(), entry.getValue());
            }
            for (Map.Entry<String, Object> entry : sorted.entrySet()) {
                if (!first) out.append(',');
                first = false;
                jsonString(entry.getKey(), out);
                out.append(':');
                json(entry.getValue(), out);
            }
            out.append('}');
        } else throw new IllegalArgumentException(
                "unsupported JSON type " + value.getClass().getName());
    }

    private static String canonicalJson(Object value) {
        StringBuilder out = new StringBuilder();
        json(value, out);
        return out.toString();
    }

    public static void main(String[] args) throws Exception {
        if (args.length >= 2 && args[0].equals("tag")) {
            Class<?> parser = Class.forName(
                    "io.cucumber.tagexpressions.TagExpressionParser");
            Object expression = parser.getMethod("parse", String.class)
                    .invoke(null, args[1]);
            List<String> tags = Arrays.asList(
                    Arrays.copyOfRange(args, 2, args.length));
            Class<?> expressionApi = Class.forName(
                    "io.cucumber.tagexpressions.Expression");
            Object result = expressionApi.getMethod("evaluate", List.class)
                    .invoke(expression, tags);
            if (!(result instanceof Boolean)) {
                throw new IllegalArgumentException(
                        "tag expression returned a non-boolean result");
            }
            System.out.print(Boolean.TRUE.equals(result) ? "true\n" : "false\n");
            return;
        }
        if (args.length != 3 || !(args[0].equals("15") || args[0].equals("24"))) {
            System.err.println("usage: J0GherkinBridge 15|24 source-uri source.feature\n"
                    + "       J0GherkinBridge tag expression [tag ...]");
            System.exit(2);
        }
        String data = readUtf8(Paths.get(args[2]));
        Parsed parsed = args[0].equals("15")
                ? parse15(args[1], data) : parse24(args[1], data);
        Object featureNode = choice(parsed.document, "Feature");
        if (featureNode == null) throw new IllegalArgumentException(
                "Gherkin document has no Feature");
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("feature", feature(featureNode));
        root.put("pickles", stablePickles(parsed.document, parsed.pickles));
        root.put("schema", "r2t.j0-bridge-ast/1");
        root.put("uri", args[1]);
        StringBuilder out = new StringBuilder();
        json(root, out);
        System.out.print(out.toString());
        System.out.print("\n");
    }
}
