/* Structural source-view inventory. Uses the same JDK Tree/SourcePositions
 * approach and UTF-16 -> UTF-8 conversion as Mutate.java, stopping at parse.
 * This program never attributes, compiles or executes the supplied subject.
 */
import com.sun.source.tree.*;
import com.sun.source.util.JavacTask;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.Trees;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.tools.*;

public final class SourceView {
    private static final String BLOCK =
        "{ throw new UnsupportedOperationException(\"implementation hidden\"); }";
    private static final String VALUE = "null /* implementation hidden */";

    private static String quote(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\\') out.append('\\').append(c);
            else if (c < 32) out.append(String.format("\\u%04x", (int) c));
            else out.append(c);
        }
        return out.append('"').toString();
    }

    private static String array(List<String> rows) {
        return "[" + String.join(",", rows) + "]";
    }

    // SourcePositions counts UTF-16 units, not Python characters or UTF-8 bytes.
    // Keep the code-point conversion used by Mutate.SourceData/charToByte.
    private static int[] charToByte(String text) {
        int[] out = new int[text.length() + 1];
        int bytes = 0;
        for (int i = 0; i < text.length();) {
            out[i] = bytes;
            int cp = text.codePointAt(i);
            int chars = Character.charCount(cp);
            if (chars == 2) out[i + 1] = bytes;
            bytes += cp <= 0x7f ? 1 : cp <= 0x7ff ? 2 : cp <= 0xffff ? 3 : 4;
            i += chars;
            out[i] = bytes;
        }
        return out;
    }

    private static final class Inventory extends TreePathScanner<Void, Void> {
        final CompilationUnitTree unit;
        final SourcePositions positions;
        final int[] bytes;
        final List<String> declarations = new ArrayList<String>();
        final List<String> bodies = new ArrayList<String>();
        final List<String> unsupported = new ArrayList<String>();
        String owner;
        Set<String> collidingMethods = Collections.emptySet();

        Inventory(CompilationUnitTree unit, Trees trees, String text) {
            this.unit = unit;
            this.positions = trees.getSourcePositions();
            this.bytes = charToByte(text);
            this.owner = unit.getPackageName() == null ? "" : unit.getPackageName().toString();
        }

        int offset(long position) {
            if (position < 0 || position >= bytes.length)
                throw new IllegalArgumentException("javac source position out of range: " + position);
            return bytes[(int) position];
        }
        int start(Tree tree) { return offset(positions.getStartPosition(unit, tree)); }
        int end(Tree tree) { return offset(positions.getEndPosition(unit, tree)); }
        String fields(String id, String kind, Tree tree) {
            return "\"declaration_id\":" + quote(id) + ",\"kind\":" + quote(kind)
                + ",\"start_byte\":" + start(tree) + ",\"end_byte\":" + end(tree);
        }
        void declaration(String id, String kind, Tree tree) {
            declarations.add("{" + fields(id, kind, tree) + "}");
        }
        void body(String id, String kind, Tree tree, String replacement) {
            bodies.add("{" + fields(id, kind, tree) + ",\"replacement\":" + quote(replacement) + "}");
        }
        void refuse(String reason, Tree tree) {
            unsupported.add(quote(reason + " at byte " + start(tree)));
        }

        @Override public Void visitClass(ClassTree tree, Void ignored) {
            String previous = owner;
            Set<String> previousCollisions = collidingMethods;
            collidingMethods = new HashSet<String>();
            Set<String> seenMethods = new HashSet<String>();
            for (Tree member : tree.getMembers()) {
                if (member instanceof MethodTree) {
                    String signature = methodSignature((MethodTree) member);
                    if (!seenMethods.add(signature)) collidingMethods.add(signature);
                }
            }
            Tree parent = getCurrentPath().getParentPath().getLeaf();
            String name = tree.getSimpleName().toString();
            if (name.isEmpty()) name = "<anonymous@" + start(tree) + ">";
            else if (!(parent instanceof CompilationUnitTree) && !(parent instanceof ClassTree))
                name += "@" + start(tree); // local class; same name may occur in another scope
            owner += owner.isEmpty() ? name : (parent instanceof CompilationUnitTree ? "." : "$") + name;
            declaration(owner, tree.getKind().name().toLowerCase(Locale.ROOT), tree);
            super.visitClass(tree, ignored);
            owner = previous;
            collidingMethods = previousCollisions;
            return null;
        }

        private String methodSignature(MethodTree tree) {
            List<String> types = new ArrayList<String>();
            for (VariableTree parameter : tree.getParameters())
                types.add(parameter.getType().toString().replaceAll("\\s+", ""));
            return tree.getName() + "(" + String.join(",", types) + ")";
        }

        @Override public Void visitMethod(MethodTree tree, Void ignored) {
            String signature = methodSignature(tree);
            String id = owner + "#" + signature;
            if (collidingMethods.contains(signature)) {
                // Legal generic overloads can spell their parameters alike:
                // <E extends Serializable> f(E) and <E extends Entity> f(E).
                // Keep existing unambiguous IDs; use parsed bounds only where
                // the ordinary syntactic signature collides in this class.
                List<String> parameters = new ArrayList<String>();
                for (TypeParameterTree parameter : tree.getTypeParameters())
                    parameters.add(parameter.toString().replaceAll("\\s+", ""));
                id += "<" + String.join(",", parameters) + ">";
            }
            String kind = tree.getReturnType() == null ? "constructor" : "method";
            declaration(id, kind, tree);
            if (tree.getBody() != null) body(id, kind, tree.getBody(), BLOCK);
            return super.visitMethod(tree, ignored);
        }

        private boolean enumConstant(VariableTree tree) {
            Tree parent = getCurrentPath().getParentPath().getLeaf();
            // The enum constant's implicit type has no source end position.
            // Start equality fails for the SDK's @JsonProperty constants:
            // their declaration starts at the annotation, type at the name.
            return parent.getKind() == Tree.Kind.ENUM
                && tree.getInitializer() instanceof NewClassTree
                && positions.getEndPosition(unit, tree.getType()) == Diagnostic.NOPOS;
        }

        // Scalar literal defaults are declarations. Arrays/tables, calls,
        // constructors, arithmetic and lookups are implementation. In
        // particular Wordlist.RAW is not exempt just because it is literal.
        private boolean literal(Tree tree) {
            if (tree instanceof LiteralTree) return true;
            if (tree instanceof ParenthesizedTree)
                return literal(((ParenthesizedTree) tree).getExpression());
            if (tree.getKind() == Tree.Kind.UNARY_MINUS || tree.getKind() == Tree.Kind.UNARY_PLUS)
                return literal(((UnaryTree) tree).getExpression());
            return false;
        }

        @Override public Void visitVariable(VariableTree tree, Void ignored) {
            Tree parent = getCurrentPath().getParentPath().getLeaf();
            if (!(parent instanceof ClassTree)) return super.visitVariable(tree, ignored);
            String id = owner + "#" + tree.getName();
            ExpressionTree value = tree.getInitializer();
            if (enumConstant(tree)) {
                declaration(id, "enum_constant", tree);
                NewClassTree construction = (NewClassTree) value;
                for (ExpressionTree argument : construction.getArguments()) {
                    if (!literal(argument)) refuse("nonliteral enum contract: " + id, argument);
                }
                // Keep enum names, annotations and literal arguments. Visit
                // constant-specific class bodies to inventory their methods.
                return super.visitVariable(tree, ignored);
            }
            declaration(id, "field", tree);
            if (value != null && !literal(value)) {
                if (value instanceof NewClassTree && ((NewClassTree) value).getClassBody() != null) {
                    // Replacing the entire expression would erase nested
                    // declarations; retaining constructor arguments can leak
                    // implementation. Use the shared reviewed file omission.
                    refuse("anonymous field initializer: " + id, value);
                } else {
                    body(id, "field_initializer", value, VALUE);
                }
            }
            return super.visitVariable(tree, ignored);
        }

        @Override public Void visitBlock(BlockTree tree, Void ignored) {
            TreePath parent = getCurrentPath().getParentPath();
            if (parent != null && parent.getLeaf() instanceof ClassTree) {
                String kind = tree.isStatic() ? "static_initializer" : "instance_initializer";
                String id = owner + (tree.isStatic() ? "#<clinit>@" : "#<init-block>@") + start(tree);
                declaration(id, kind, tree);
                body(id, kind, tree, (tree.isStatic() ? "static " : "") + "{ /* implementation hidden */ }");
            }
            return super.visitBlock(tree, ignored);
        }

        @Override public Void visitLambdaExpression(LambdaExpressionTree tree, Void ignored) {
            // Not present in released117, but parseable Java 8. An enclosing
            // callable/field edit removes it; selecting it alone is unsupported.
            String id = owner + "#<lambda@" + start(tree) + ">";
            declaration(id, "lambda", tree);
            body(id, "lambda", tree.getBody(), tree.getBodyKind() == LambdaExpressionTree.BodyKind.STATEMENT
                 ? BLOCK : VALUE);
            return super.visitLambdaExpression(tree, ignored);
        }
    }

    private static String inspect(final String source, boolean parseOnly) throws IOException {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("source views require a JDK compiler");
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<JavaFileObject>();
        StandardJavaFileManager manager = compiler.getStandardFileManager(diagnostics, Locale.ROOT, StandardCharsets.UTF_8);
        try {
            JavaFileObject file = new SimpleJavaFileObject(URI.create("string:///Source.java"), JavaFileObject.Kind.SOURCE) {
                @Override public CharSequence getCharContent(boolean ignoreEncodingErrors) { return source; }
            };
            JavacTask task = (JavacTask) compiler.getTask(null, manager, diagnostics,
                Arrays.asList("-proc:none", "-encoding", "UTF-8", "-source", "8", "-Xlint:-options"),
                null, Collections.singletonList(file));
            Iterable<? extends CompilationUnitTree> units = task.parse();
            for (Diagnostic<? extends JavaFileObject> diagnostic : diagnostics.getDiagnostics()) {
                if (diagnostic.getKind() == Diagnostic.Kind.ERROR)
                    return "{\"error\":" + quote("Java syntax at line " + diagnostic.getLineNumber() + ": "
                        + diagnostic.getMessage(Locale.ROOT)) + "}";
            }
            if (parseOnly) return "{}";
            Inventory inventory = new Inventory(units.iterator().next(), Trees.instance(task), source);
            inventory.scan(inventory.unit, null);
            return "{\"declarations\":" + array(inventory.declarations)
                + ",\"bodies\":" + array(inventory.bodies)
                + ",\"contract_only_reasons\":" + array(inventory.unsupported) + "}";
        } finally { manager.close(); }
    }

    public static void main(String[] args) throws Exception {
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        PrintWriter output = new PrintWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8));
        String line;
        while ((line = input.readLine()) != null) {
            String source = new String(Base64.getDecoder().decode(line), StandardCharsets.UTF_8);
            try { output.println(inspect(source, args[0].equals("parse"))); }
            catch (IllegalArgumentException exc) { output.println("{\"error\":" + quote(exc.getMessage()) + "}"); }
        }
        output.flush();
    }
}
