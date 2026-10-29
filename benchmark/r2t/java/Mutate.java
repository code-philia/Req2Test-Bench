/*
 * r2t-mutate-java 1.0 -- deterministic Java source mutation, enumerate/apply.
 *
 * This is the Java twin of php/mutate.php and py/mutate.py, with the same
 * source-level descriptor and refusal contract: byte-exact 1-based spans,
 * sorted traversal/output, generated/vendor/scratch exclusions, compilation
 * of every pristine-byte candidate before emission, and apply only after the
 * same program re-enumerates the current file and finds the requested row.
 * It is deliberately dependency-free and offline: parsing and compilation use
 * the public JDK javac APIs (com.sun.source.tree and javax.tools).
 *
 * Java-specific deviations are intentional and part of the engine identity:
 *
 *  - v2 is the only profile this engine has ever produced; there are no Java
 *    v1 artifacts to reconstruct.
 *  - ReturnValue is statically typed from javac's attributed method return
 *    type: references -> null, integral primitives -> 0, boolean -> false,
 *    float -> 0.0f, and double -> 0.0. Already-default returns are skipped.
 *    Return statements in lambdas are skipped because their target return
 *    type is not represented by MethodTree; inventing it from the enclosing
 *    method would be unsound.
 *  - Increment means Java's ++ <-> --. MethodCallRemoval is restricted to a
 *    method invocation used as a complete expression statement, replaced by
 *    an empty statement.
 *  - javac SourcePositions are UTF-16 offsets. They are converted to UTF-8
 *    byte offsets before rows are emitted or applied; manifest columns are
 *    bytes, never Java characters.
 *  - Compilation uses -proc:none. Independent candidates may be validated in
 *    parallel, but results are collected in descriptor order so worker count
 *    cannot affect the envelope.
 *
 * Exit status: 0 success, 2 usage, 3 output failure, 4 refusal.
 */

import com.sun.source.tree.BinaryTree;
import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.ExpressionStatementTree;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.LambdaExpressionTree;
import com.sun.source.tree.LiteralTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.ParenthesizedTree;
import com.sun.source.tree.ReturnTree;
import com.sun.source.tree.Tree;
import com.sun.source.tree.TypeCastTree;
import com.sun.source.tree.UnaryTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.Trees;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.element.Element;
import javax.lang.model.element.VariableElement;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.FileObject;
import javax.tools.ForwardingJavaFileManager;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileManager;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

public final class Mutate {
    public static final String ENGINE = "r2t-mutate-java";
    public static final String ENGINE_VERSION = "1.0";
    public static final String ENUMERATOR_REV =
            "r2t-mutate-java/j1-javac-v2-2";

    private static final int EXIT_OK = 0;
    private static final int EXIT_USAGE = 2;
    private static final int EXIT_OUTPUT = 3;
    private static final int EXIT_REFUSED = 4;
    private static final int HEAD_LINES = 40;

    private static final List<String> OPERATORS = Collections.unmodifiableList(
            Arrays.asList(
                    "ConditionalBoundary", "NegateConditional", "Increment",
                    "ArithmeticOperator", "TrueValue", "FalseValue",
                    "ReturnValue", "MethodCallRemoval", "LogicalConnector",
                    "RemoveNegation", "ConstantReplacement"));

    private static final Set<String> EXCLUDED_SEGMENTS = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList(
                    "vendor", "var", ".git", ".gradle", "target", "build",
                    "out", "generated-sources")));

    private Mutate() {
    }

    private static final class Usage extends Exception {
        private static final long serialVersionUID = 1L;
        Usage(String message) { super(message); }
    }

    private static final class Refusal extends Exception {
        private static final long serialVersionUID = 1L;
        Refusal(String message) { super(message); }
        Refusal(String message, Throwable cause) { super(message, cause); }
    }

    private static final class OutputFailure extends Exception {
        private static final long serialVersionUID = 1L;
        OutputFailure(String message, Throwable cause) { super(message, cause); }
    }

    private static final class Options {
        Path root;
        Path writeRoot;
        final List<String> paths = new ArrayList<String>();
        String out;
        String applyFile;
        Integer startLine;
        Integer startCol;
        String operator;
        String original;
        String mutated;
        String classpath;
        String sourcepath;
        String modulepath;
        String sourceLevel;
        String targetLevel;
        String releaseLevel;
        int compileWorkers = 1;
        boolean recordEnumeratorRev;
    }

    public static void main(String[] argv) {
        int rc;
        try {
            Options options = parseArgs(argv);
            run(options);
            rc = EXIT_OK;
        } catch (Usage exc) {
            System.err.println(exc.getMessage());
            rc = EXIT_USAGE;
        } catch (Refusal exc) {
            System.err.println("REFUSED: " + exc.getMessage());
            rc = EXIT_REFUSED;
        } catch (OutputFailure exc) {
            System.err.println(exc.getMessage());
            rc = EXIT_OUTPUT;
        } catch (Throwable exc) {
            System.err.println("REFUSED: Java mutation engine failed: "
                    + exc.getClass().getSimpleName() + ": " + exc.getMessage());
            rc = EXIT_REFUSED;
        }
        if (rc != EXIT_OK) {
            System.exit(rc);
        }
    }

    private static Options parseArgs(String[] argv) throws Usage {
        Options out = new Options();
        for (int i = 0; i < argv.length; i++) {
            String arg = argv[i];
            if ("--record-enumerator-rev".equals(arg)) {
                out.recordEnumeratorRev = true;
                continue;
            }
            if ("--operator-profile".equals(arg)) {
                String profile = value(argv, ++i, arg);
                if (!"v2".equals(profile)) {
                    throw new Usage("--operator-profile must be v2; "
                            + "r2t-mutate-java has no historical v1 profile");
                }
                continue;
            }
            String val = value(argv, ++i, arg);
            if ("--root".equals(arg)) {
                out.root = Paths.get(val);
            } else if ("--write-root".equals(arg)) {
                out.writeRoot = Paths.get(val);
            } else if ("--path".equals(arg)) {
                out.paths.add(val);
            } else if ("--out".equals(arg)) {
                out.out = val;
            } else if ("--apply-file".equals(arg)) {
                out.applyFile = val;
            } else if ("--start-line".equals(arg)) {
                out.startLine = positiveInt(val, arg);
            } else if ("--start-col".equals(arg)) {
                out.startCol = positiveInt(val, arg);
            } else if ("--operator".equals(arg)) {
                out.operator = val;
            } else if ("--original".equals(arg)) {
                out.original = val;
            } else if ("--mutated".equals(arg)) {
                out.mutated = val;
            } else if ("--classpath".equals(arg)) {
                out.classpath = val;
            } else if ("--sourcepath".equals(arg)) {
                out.sourcepath = val;
            } else if ("--module-path".equals(arg)) {
                out.modulepath = val;
            } else if ("--source-level".equals(arg)) {
                out.sourceLevel = languageLevel(val, arg);
            } else if ("--target-level".equals(arg)) {
                out.targetLevel = languageLevel(val, arg);
            } else if ("--release-level".equals(arg)) {
                out.releaseLevel = languageLevel(val, arg);
            } else if ("--compile-workers".equals(arg)) {
                out.compileWorkers = positiveInt(val, arg);
            } else {
                throw new Usage("unknown argument: " + arg + "\n" + usage());
            }
        }
        if (out.root == null) {
            throw new Usage("--root is required\n" + usage());
        }
        if (out.classpath == null || out.sourcepath == null
                || out.modulepath == null) {
            throw new Usage("--classpath, --sourcepath, and --module-path "
                    + "are required analysis authority; empty values are "
                    + "explicit, never inherited from the launcher\n" + usage());
        }
        boolean sourceTarget = out.sourceLevel != null
                && out.targetLevel != null && out.releaseLevel == null;
        boolean release = out.sourceLevel == null && out.targetLevel == null
                && out.releaseLevel != null;
        boolean legacyDefault = out.sourceLevel == null
                && out.targetLevel == null && out.releaseLevel == null;
        if (!sourceTarget && !release && !legacyDefault) {
            throw new Usage("language level requires both --source-level and "
                    + "--target-level, or --release-level alone\n" + usage());
        }
        boolean applying = out.applyFile != null;
        if (applying) {
            if (!out.paths.isEmpty() || out.startLine == null
                    || out.startCol == null || out.operator == null
                    || out.original == null || out.mutated == null
                    || out.out == null || out.writeRoot == null
                    || out.recordEnumeratorRev) {
                throw new Usage("apply mode requires --apply-file, --start-line, "
                        + "--start-col, --operator, --original, --mutated, and "
                        + "--out, --write-root, and takes neither --path nor "
                        + "--record-enumerator-rev\n" + usage());
            }
        } else if (out.paths.isEmpty()) {
            throw new Usage("enumerate mode requires at least one --path\n"
                    + usage());
        }
        return out;
    }

    private static String value(String[] argv, int i, String flag) throws Usage {
        if (i >= argv.length) {
            throw new Usage(flag + " requires a value\n" + usage());
        }
        return argv[i];
    }

    private static int positiveInt(String value, String flag) throws Usage {
        try {
            int parsed = Integer.parseInt(value);
            if (parsed < 1) throw new NumberFormatException();
            return parsed;
        } catch (NumberFormatException exc) {
            throw new Usage(flag + " must be a positive integer");
        }
    }

    private static String languageLevel(String value, String flag)
            throws Usage {
        if (!value.matches("[1-9][0-9]*(\\.[0-9]+)*")) {
            throw new Usage(flag + " must be a numeric Java language level");
        }
        return value;
    }

    private static String usage() {
        return "usage: java Mutate --root DIR --path REL [--path REL ...] "
                + "[--compile-workers N] [--classpath CP] [--sourcepath SP] "
                + "[--module-path MP] [--source-level N --target-level N | "
                + "--release-level N] "
                + "[--record-enumerator-rev] [--out FILE]\n"
               + "       java Mutate --root DIR --apply-file REL "
                + "--write-root DIR "
                + "--start-line N --start-col N --operator NAME "
                + "--original TEXT --mutated TEXT --out REL "
                + "--classpath CP --sourcepath SP --module-path MP "
                + "[--source-level N --target-level N | --release-level N]";
    }

    private static void run(Options options)
            throws IOException, Refusal, OutputFailure {
        Path root = options.root.toAbsolutePath().normalize();
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(root)) {
            throw new Refusal("root is not a canonical non-symlink directory: "
                    + root);
        }
        root = root.toRealPath();
        options.root = root;
        if (options.applyFile != null) {
            Path writeRoot = options.writeRoot.toAbsolutePath().normalize();
            if (!Files.isDirectory(writeRoot, LinkOption.NOFOLLOW_LINKS)
                    || Files.isSymbolicLink(writeRoot)) {
                throw new Refusal("write root is not a canonical non-symlink "
                        + "directory: " + writeRoot);
            }
            options.writeRoot = writeRoot.toRealPath();
        }
        if (ToolProvider.getSystemJavaCompiler() == null) {
            throw new Refusal("no system JavaCompiler is available; run under a "
                    + "JDK, not a JRE");
        }
        if (options.applyFile != null) {
            apply(options);
        } else {
            enumerate(options);
        }
    }

    private static final class SourceData {
        final String rel;
        final byte[] bytes;
        final String text;
        final int[] charToByte;
        final int[] lineStarts;
        final List<Token> tokens;

        SourceData(String rel, byte[] bytes, String text) {
            this.rel = rel;
            this.bytes = bytes;
            this.text = text;
            this.charToByte = charToByte(text);
            this.lineStarts = lineStarts(bytes);
            this.tokens = lex(text);
        }

        int byteAtChar(long position) throws Refusal {
            if (position < 0 || position > text.length()) {
                throw new Refusal(rel + ": javac returned an out-of-range "
                        + "source position " + position);
            }
            return charToByte[(int) position];
        }

        int[] lineCol(int bytePos) throws Refusal {
            if (bytePos < 0 || bytePos > bytes.length) {
                throw new Refusal(rel + ": byte position outside source: "
                        + bytePos);
            }
            int at = Arrays.binarySearch(lineStarts, bytePos);
            int lineIndex = at >= 0 ? at : -at - 2;
            if (lineIndex < 0) lineIndex = 0;
            return new int[] {lineIndex + 1,
                    bytePos - lineStarts[lineIndex] + 1};
        }

        String sliceChars(long start, long endExclusive) throws Refusal {
            if (start < 0 || endExclusive < start || endExclusive > text.length()) {
                throw new Refusal(rel + ": invalid javac span " + start + ".."
                        + endExclusive);
            }
            return text.substring((int) start, (int) endExclusive);
        }

        Path inferredSourceRoot(Path root) {
            List<String> packageParts = new ArrayList<String>();
            for (int i = 0; i < tokens.size(); i++) {
                if (!"package".equals(tokens.get(i).text)) continue;
                for (int j = i + 1; j < tokens.size(); j++) {
                    String token = tokens.get(j).text;
                    if (";".equals(token)) break;
                    if (!".".equals(token)) packageParts.add(token);
                }
                break;
            }
            Path file = root.resolve(rel.replace('/', File.separatorChar))
                    .normalize();
            Path parent = file.getParent();
            if (parent == null) return root;
            for (int i = packageParts.size() - 1; i >= 0; i--) {
                if (parent == null || parent.getFileName() == null
                        || !packageParts.get(i).equals(
                        parent.getFileName().toString())) return root;
                parent = parent.getParent();
            }
            return parent == null ? root : parent;
        }
    }

    private static final class Token {
        final int start;
        final int end;
        final String text;
        Token(int start, int end, String text) {
            this.start = start;
            this.end = end;
            this.text = text;
        }
    }

    private static final class Mutant {
        final SourceData source;
        final int startByte;
        final int endByteExclusive;
        final int startLine;
        final int startCol;
        final int endLine;
        final int endCol;
        final String operator;
        final String original;
        final String mutated;
        final String className;
        final String methodName;

        Mutant(SourceData source, int startByte, int endByteExclusive,
               String operator, String mutated, String className,
               String methodName) throws Refusal {
            if (startByte < 0 || endByteExclusive <= startByte
                    || endByteExclusive > source.bytes.length) {
                throw new Refusal(source.rel + ": invalid byte mutation span "
                        + startByte + ".." + endByteExclusive + " for "
                        + operator);
            }
            this.source = source;
            this.startByte = startByte;
            this.endByteExclusive = endByteExclusive;
            int[] start = source.lineCol(startByte);
            int[] end = source.lineCol(endByteExclusive - 1);
            this.startLine = start[0];
            this.startCol = start[1];
            this.endLine = end[0];
            this.endCol = end[1];
            this.operator = operator;
            this.original = new String(Arrays.copyOfRange(
                    source.bytes, startByte, endByteExclusive),
                    StandardCharsets.UTF_8);
            this.mutated = mutated;
            this.className = emptyToNull(className);
            this.methodName = emptyToNull(methodName);
        }

        byte[] candidateBytes() {
            byte[] replacement = mutated.getBytes(StandardCharsets.UTF_8);
            byte[] out = new byte[source.bytes.length
                    - (endByteExclusive - startByte) + replacement.length];
            System.arraycopy(source.bytes, 0, out, 0, startByte);
            System.arraycopy(replacement, 0, out, startByte,
                    replacement.length);
            System.arraycopy(source.bytes, endByteExclusive, out,
                    startByte + replacement.length,
                    source.bytes.length - endByteExclusive);
            return out;
        }

        boolean requestedBy(Options options) {
            return startLine == options.startLine.intValue()
                    && startCol == options.startCol.intValue()
                    && operator.equals(options.operator)
                    && original.equals(options.original)
                    && mutated.equals(options.mutated);
        }
    }

    private static String emptyToNull(String value) {
        return value == null || value.length() == 0 ? null : value;
    }

    private static final Comparator<Mutant> MUTANT_ORDER =
            new Comparator<Mutant>() {
                @Override public int compare(Mutant a, Mutant b) {
                    int c = a.source.rel.compareTo(b.source.rel);
                    if (c != 0) return c;
                    c = Integer.compare(a.startByte, b.startByte);
                    if (c != 0) return c;
                    c = Integer.compare(a.endByteExclusive, b.endByteExclusive);
                    if (c != 0) return c;
                    c = a.operator.compareTo(b.operator);
                    if (c != 0) return c;
                    c = a.original.compareTo(b.original);
                    if (c != 0) return c;
                    return a.mutated.compareTo(b.mutated);
                }
            };

    private static int[] charToByte(String text) {
        int[] out = new int[text.length() + 1];
        int bytes = 0;
        int i = 0;
        while (i < text.length()) {
            out[i] = bytes;
            int cp = text.codePointAt(i);
            int chars = Character.charCount(cp);
            int encoded;
            if (cp <= 0x7f) encoded = 1;
            else if (cp <= 0x7ff) encoded = 2;
            else if (cp <= 0xffff) encoded = 3;
            else encoded = 4;
            if (chars == 2) out[i + 1] = bytes;
            bytes += encoded;
            i += chars;
            out[i] = bytes;
        }
        out[text.length()] = bytes;
        return out;
    }

    private static int[] lineStarts(byte[] data) {
        int count = 1;
        for (byte b : data) if (b == '\n') count++;
        int[] out = new int[count];
        int at = 1;
        for (int i = 0; i < data.length; i++) {
            if (data[i] == '\n') out[at++] = i + 1;
        }
        return out;
    }

    private static List<Token> lex(String text) {
        List<Token> out = new ArrayList<Token>();
        int i = 0;
        while (i < text.length()) {
            char ch = text.charAt(i);
            if (Character.isWhitespace(ch)) {
                i++;
                continue;
            }
            if (ch == '/' && i + 1 < text.length()
                    && text.charAt(i + 1) == '/') {
                i += 2;
                while (i < text.length() && text.charAt(i) != '\n'
                        && text.charAt(i) != '\r') i++;
                continue;
            }
            if (ch == '/' && i + 1 < text.length()
                    && text.charAt(i + 1) == '*') {
                i += 2;
                while (i + 1 < text.length()
                        && !(text.charAt(i) == '*'
                        && text.charAt(i + 1) == '/')) i++;
                i = Math.min(text.length(), i + 2);
                continue;
            }
            if (ch == '"' || ch == '\'') {
                char quote = ch;
                i++;
                while (i < text.length()) {
                    char inner = text.charAt(i++);
                    if (inner == '\\' && i < text.length()) {
                        i++;
                    } else if (inner == quote) {
                        break;
                    }
                }
                continue;
            }
            int start = i;
            if (Character.isJavaIdentifierStart(ch)) {
                i++;
                while (i < text.length()
                        && Character.isJavaIdentifierPart(text.charAt(i))) i++;
                out.add(new Token(start, i, text.substring(start, i)));
                continue;
            }
            if (Character.isDigit(ch)) {
                i++;
                while (i < text.length()) {
                    char n = text.charAt(i);
                    if (Character.isLetterOrDigit(n) || n == '_' || n == '.') {
                        i++;
                    } else if ((n == '+' || n == '-') && i > start
                            && (text.charAt(i - 1) == 'e'
                            || text.charAt(i - 1) == 'E'
                            || text.charAt(i - 1) == 'p'
                            || text.charAt(i - 1) == 'P')) {
                        i++;
                    } else {
                        break;
                    }
                }
                out.add(new Token(start, i, text.substring(start, i)));
                continue;
            }
            String op = null;
            for (String candidate : Arrays.asList(
                    ">>>=", "<<=", ">>=", ">>>", "<<", ">>", "<=", ">=",
                    "==", "!=", "++", "--", "&&", "||", "+=", "-=", "*=",
                    "/=", "%=", "&=", "|=", "^=", "->", "::")) {
                if (text.startsWith(candidate, i)) {
                    op = candidate;
                    break;
                }
            }
            if (op == null) op = String.valueOf(ch);
            i += op.length();
            out.add(new Token(start, i, op));
        }
        return out;
    }

    private static Token findToken(SourceData source, long from, long to,
                                   String wanted) throws Refusal {
        if (from < 0 || to < from || to > source.text.length()) {
            throw new Refusal(source.rel + ": invalid token search window "
                    + from + ".." + to + " for " + wanted);
        }
        Token found = null;
        for (Token token : source.tokens) {
            if (token.start < from || token.end > to) continue;
            if (!wanted.equals(token.text)) continue;
            if (found != null) {
                throw new Refusal(source.rel + ": ambiguous " + wanted
                        + " token in javac node at byte "
                        + source.byteAtChar(from));
            }
            found = token;
        }
        if (found == null) {
            throw new Refusal(source.rel + ": javac produced a node but its "
                    + wanted + " token was not found in the child span");
        }
        return found;
    }

    private static final class Enumerator extends TreePathScanner<Void, Void> {
        private final SourceData source;
        private final CompilationUnitTree unit;
        private final SourcePositions positions;
        private final Trees trees;
        private final List<Mutant> mutants = new ArrayList<Mutant>();
        private final List<String> classes = new ArrayList<String>();
        private final List<MethodTree> methods = new ArrayList<MethodTree>();
        private final List<Integer> methodLambdaBaselines =
                new ArrayList<Integer>();
        private int lambdaDepth;

        Enumerator(SourceData source, CompilationUnitTree unit, Trees trees) {
            this.source = source;
            this.unit = unit;
            this.trees = trees;
            this.positions = trees.getSourcePositions();
        }

        List<Mutant> rows() {
            Collections.sort(mutants, MUTANT_ORDER);
            return mutants;
        }

        private long start(Tree tree) throws Refusal {
            long value = positions.getStartPosition(unit, tree);
            if (value == Diagnostic.NOPOS) {
                throw new Refusal(source.rel + ": javac omitted a start "
                        + "position for " + tree.getKind());
            }
            return value;
        }

        private long end(Tree tree) throws Refusal {
            long value = positions.getEndPosition(unit, tree);
            if (value == Diagnostic.NOPOS) {
                throw new Refusal(source.rel + ": javac omitted an end "
                        + "position for " + tree.getKind());
            }
            return value;
        }

        private boolean positioned(Tree tree) {
            return positions.getStartPosition(unit, tree) != Diagnostic.NOPOS
                    && positions.getEndPosition(unit, tree) != Diagnostic.NOPOS;
        }

        private String className() {
            return classes.isEmpty() ? null : classes.get(classes.size() - 1);
        }

        private String methodName() {
            if (methods.isEmpty()) return null;
            return methods.get(methods.size() - 1).getName().toString();
        }

        private void emitChars(String operator, long start, long endExclusive,
                               String replacement) throws Refusal {
            int bs = source.byteAtChar(start);
            int be = source.byteAtChar(endExclusive);
            Mutant row = new Mutant(source, bs, be, operator, replacement,
                    className(), methodName());
            if (!row.original.equals(row.mutated)) mutants.add(row);
        }

        private void emitToken(String operator, Token token, String replacement)
                throws Refusal {
            emitChars(operator, token.start, token.end, replacement);
        }

        private void binary(BinaryTree tree, String token, String replacement,
                            String operator) throws Refusal {
            Token found = findToken(source, end(tree.getLeftOperand()),
                    start(tree.getRightOperand()), token);
            emitToken(operator, found, replacement);
        }

        @Override public Void visitClass(ClassTree tree, Void unused) {
            classes.add(tree.getSimpleName().toString());
            try {
                return super.visitClass(tree, unused);
            } finally {
                classes.remove(classes.size() - 1);
            }
        }

        @Override public Void visitMethod(MethodTree tree, Void unused) {
            methods.add(tree);
            methodLambdaBaselines.add(Integer.valueOf(lambdaDepth));
            try {
                return super.visitMethod(tree, unused);
            } finally {
                methodLambdaBaselines.remove(methodLambdaBaselines.size() - 1);
                methods.remove(methods.size() - 1);
            }
        }

        @Override public Void visitLambdaExpression(LambdaExpressionTree tree,
                                                    Void unused) {
            lambdaDepth++;
            try {
                return super.visitLambdaExpression(tree, unused);
            } finally {
                lambdaDepth--;
            }
        }

        @Override public Void visitBinary(BinaryTree tree, Void unused) {
            try {
                switch (tree.getKind()) {
                    case LESS_THAN:
                        binary(tree, "<", "<=", "ConditionalBoundary");
                        binary(tree, "<", ">=", "NegateConditional");
                        break;
                    case LESS_THAN_EQUAL:
                        binary(tree, "<=", "<", "ConditionalBoundary");
                        binary(tree, "<=", ">", "NegateConditional");
                        break;
                    case GREATER_THAN:
                        binary(tree, ">", ">=", "ConditionalBoundary");
                        binary(tree, ">", "<=", "NegateConditional");
                        break;
                    case GREATER_THAN_EQUAL:
                        binary(tree, ">=", ">", "ConditionalBoundary");
                        binary(tree, ">=", "<", "NegateConditional");
                        break;
                    case EQUAL_TO:
                        binary(tree, "==", "!=", "NegateConditional");
                        break;
                    case NOT_EQUAL_TO:
                        binary(tree, "!=", "==", "NegateConditional");
                        break;
                    case PLUS:
                        binary(tree, "+", "-", "ArithmeticOperator");
                        break;
                    case MINUS:
                        binary(tree, "-", "+", "ArithmeticOperator");
                        break;
                    case MULTIPLY:
                        binary(tree, "*", "/", "ArithmeticOperator");
                        break;
                    case DIVIDE:
                        binary(tree, "/", "*", "ArithmeticOperator");
                        break;
                    case REMAINDER:
                        binary(tree, "%", "*", "ArithmeticOperator");
                        break;
                    case CONDITIONAL_AND:
                        binary(tree, "&&", "||", "LogicalConnector");
                        break;
                    case CONDITIONAL_OR:
                        binary(tree, "||", "&&", "LogicalConnector");
                        break;
                    default:
                        break;
                }
            } catch (Refusal exc) {
                throw new ScanFailure(exc);
            }
            return super.visitBinary(tree, unused);
        }

        @Override public Void visitUnary(UnaryTree tree, Void unused) {
            try {
                String token = null;
                String replacement = null;
                String operator = null;
                long from = start(tree);
                long to = end(tree);
                switch (tree.getKind()) {
                    case PREFIX_INCREMENT:
                        token = "++"; replacement = "--";
                        operator = "Increment"; to = start(tree.getExpression());
                        break;
                    case PREFIX_DECREMENT:
                        token = "--"; replacement = "++";
                        operator = "Increment"; to = start(tree.getExpression());
                        break;
                    case POSTFIX_INCREMENT:
                        token = "++"; replacement = "--";
                        operator = "Increment"; from = end(tree.getExpression());
                        break;
                    case POSTFIX_DECREMENT:
                        token = "--"; replacement = "++";
                        operator = "Increment"; from = end(tree.getExpression());
                        break;
                    case LOGICAL_COMPLEMENT:
                        token = "!"; replacement = "";
                        operator = "RemoveNegation";
                        to = start(tree.getExpression());
                        break;
                    default:
                        break;
                }
                if (operator != null) {
                    emitToken(operator, findToken(source, from, to, token),
                            replacement);
                }
            } catch (Refusal exc) {
                throw new ScanFailure(exc);
            }
            return super.visitUnary(tree, unused);
        }

        @Override public Void visitLiteral(LiteralTree tree, Void unused) {
            try {
                if (tree.getKind() == Tree.Kind.BOOLEAN_LITERAL) {
                    boolean value = Boolean.TRUE.equals(tree.getValue());
                    emitChars(value ? "TrueValue" : "FalseValue",
                            start(tree), end(tree), value ? "false" : "true");
                } else if (tree.getKind() == Tree.Kind.INT_LITERAL
                        || tree.getKind() == Tree.Kind.LONG_LITERAL) {
                    emitChars("ConstantReplacement", start(tree), end(tree),
                            incrementLiteral(tree));
                }
            } catch (Refusal exc) {
                throw new ScanFailure(exc);
            }
            return super.visitLiteral(tree, unused);
        }

        private String incrementLiteral(LiteralTree tree) throws Refusal {
            Object value = tree.getValue();
            if (!(value instanceof Number)) {
                throw new Refusal(source.rel + ": javac integer literal has "
                        + "non-numeric value " + value);
            }
            BigInteger next = BigInteger.valueOf(((Number) value).longValue())
                    .add(BigInteger.ONE);
            return next.toString()
                    + (tree.getKind() == Tree.Kind.LONG_LITERAL ? "L" : "");
        }

        @Override public Void visitReturn(ReturnTree tree, Void unused) {
            try {
                if (tree.getExpression() == null || methods.isEmpty()
                        || lambdaDepth > methodLambdaBaselines.get(
                        methodLambdaBaselines.size() - 1).intValue()) {
                    return super.visitReturn(tree, unused);
                }
                MethodTree method = methods.get(methods.size() - 1);
                if (method.getReturnType() == null) {
                    return super.visitReturn(tree, unused);
                }
                TreePath returnTypePath = TreePath.getPath(
                        unit, method.getReturnType());
                TypeMirror type = returnTypePath == null
                        ? null : trees.getTypeMirror(returnTypePath);
                String replacement = defaultReturn(type);
                if (replacement != null && !alreadyDefault(
                        tree.getExpression(), type == null ? null : type.getKind())) {
                    emitChars("ReturnValue", start(tree), end(tree),
                            "return " + replacement + ";");
                }
            } catch (Refusal exc) {
                throw new ScanFailure(exc);
            }
            return super.visitReturn(tree, unused);
        }

        private String defaultReturn(TypeMirror type) {
            if (type == null) return null;
            switch (type.getKind()) {
                case BOOLEAN: return "false";
                case BYTE:
                case SHORT:
                case INT:
                case LONG:
                case CHAR: return "0";
                case FLOAT: return "0.0f";
                case DOUBLE: return "0.0";
                case ARRAY:
                case DECLARED:
                case TYPEVAR: return "null";
                default: return null;
            }
        }

        private boolean alreadyDefault(ExpressionTree expression, TypeKind kind) {
            if (kind == null) return false;
            switch (kind) {
                case BOOLEAN: return isBooleanFalse(expression);
                case BYTE:
                case SHORT:
                case INT:
                case LONG:
                case CHAR:
                case FLOAT:
                case DOUBLE: return isNumericZeroAfterConversion(
                        expression, kind);
                case ARRAY:
                case DECLARED:
                case TYPEVAR: return isNullDefault(expression);
                default: return false;
            }
        }

        private ExpressionTree unparenthesized(ExpressionTree expression) {
            ExpressionTree current = expression;
            while (current instanceof ParenthesizedTree) {
                current = ((ParenthesizedTree) current).getExpression();
            }
            return current;
        }

        private TypeKind castKind(TypeCastTree cast) {
            TreePath path = TreePath.getPath(unit, cast.getType());
            TypeMirror mirror = path == null ? null : trees.getTypeMirror(path);
            return mirror == null ? null : mirror.getKind();
        }

        private boolean isBooleanFalse(ExpressionTree expression) {
            ExpressionTree current = unparenthesized(expression);
            if (current instanceof LiteralTree) {
                return Boolean.FALSE.equals(((LiteralTree) current).getValue());
            }
            if (current instanceof TypeCastTree) {
                TypeCastTree cast = (TypeCastTree) current;
                return castKind(cast) == TypeKind.BOOLEAN
                        && isBooleanFalse(cast.getExpression());
            }
            return false;
        }

        private TypeKind expressionKind(ExpressionTree expression) {
            TreePath path = TreePath.getPath(unit, expression);
            TypeMirror mirror = path == null ? null : trees.getTypeMirror(path);
            return mirror == null ? null : mirror.getKind();
        }

        private Number asNumber(Object value) {
            if (value instanceof Character) {
                return Integer.valueOf(((Character) value).charValue());
            }
            return value instanceof Number ? (Number) value : null;
        }

        private Object numericConversion(Object value, TypeKind kind) {
            Number number = asNumber(value);
            if (number == null || kind == null) return null;
            switch (kind) {
                case BYTE: return Byte.valueOf((byte) number.intValue());
                case SHORT: return Short.valueOf((short) number.intValue());
                case CHAR: return Character.valueOf((char) number.intValue());
                case INT: return Integer.valueOf(number.intValue());
                case LONG: return Long.valueOf(number.longValue());
                case FLOAT: return Float.valueOf(number.floatValue());
                case DOUBLE: return Double.valueOf(number.doubleValue());
                default: return null;
            }
        }

        private Object binaryNumericConstant(BinaryTree tree) {
            Object leftValue = numericConstant(tree.getLeftOperand());
            Object rightValue = numericConstant(tree.getRightOperand());
            TypeKind kind = expressionKind(tree);
            Number left = asNumber(numericConversion(leftValue, kind));
            Number right = asNumber(numericConversion(rightValue, kind));
            if (left == null || right == null || kind == null) return null;
            Tree.Kind operation = tree.getKind();
            if (kind == TypeKind.DOUBLE) {
                double a = left.doubleValue(), b = right.doubleValue();
                switch (operation) {
                    case PLUS: return Double.valueOf(a + b);
                    case MINUS: return Double.valueOf(a - b);
                    case MULTIPLY: return Double.valueOf(a * b);
                    case DIVIDE: return Double.valueOf(a / b);
                    case REMAINDER: return Double.valueOf(a % b);
                    default: return null;
                }
            }
            if (kind == TypeKind.FLOAT) {
                float a = left.floatValue(), b = right.floatValue();
                switch (operation) {
                    case PLUS: return Float.valueOf(a + b);
                    case MINUS: return Float.valueOf(a - b);
                    case MULTIPLY: return Float.valueOf(a * b);
                    case DIVIDE: return Float.valueOf(a / b);
                    case REMAINDER: return Float.valueOf(a % b);
                    default: return null;
                }
            }
            if (kind == TypeKind.LONG) {
                long a = left.longValue(), b = right.longValue();
                switch (operation) {
                    case PLUS: return Long.valueOf(a + b);
                    case MINUS: return Long.valueOf(a - b);
                    case MULTIPLY: return Long.valueOf(a * b);
                    case DIVIDE: return b == 0 ? null : Long.valueOf(a / b);
                    case REMAINDER: return b == 0 ? null : Long.valueOf(a % b);
                    case LEFT_SHIFT: return Long.valueOf(a << (int) b);
                    case RIGHT_SHIFT: return Long.valueOf(a >> (int) b);
                    case UNSIGNED_RIGHT_SHIFT:
                        return Long.valueOf(a >>> (int) b);
                    case AND: return Long.valueOf(a & b);
                    case OR: return Long.valueOf(a | b);
                    case XOR: return Long.valueOf(a ^ b);
                    default: return null;
                }
            }
            if (kind == TypeKind.INT) {
                int a = left.intValue(), b = right.intValue();
                switch (operation) {
                    case PLUS: return Integer.valueOf(a + b);
                    case MINUS: return Integer.valueOf(a - b);
                    case MULTIPLY: return Integer.valueOf(a * b);
                    case DIVIDE: return b == 0 ? null : Integer.valueOf(a / b);
                    case REMAINDER: return b == 0 ? null : Integer.valueOf(a % b);
                    case LEFT_SHIFT: return Integer.valueOf(a << b);
                    case RIGHT_SHIFT: return Integer.valueOf(a >> b);
                    case UNSIGNED_RIGHT_SHIFT: return Integer.valueOf(a >>> b);
                    case AND: return Integer.valueOf(a & b);
                    case OR: return Integer.valueOf(a | b);
                    case XOR: return Integer.valueOf(a ^ b);
                    default: return null;
                }
            }
            return null;
        }

        /** Evaluate only JLS compile-time numeric forms, never runtime code. */
        private Object numericConstant(ExpressionTree expression) {
            ExpressionTree current = unparenthesized(expression);
            if (current instanceof LiteralTree) {
                Object value = ((LiteralTree) current).getValue();
                return asNumber(value) == null ? null : value;
            }
            if (current instanceof TypeCastTree) {
                TypeCastTree cast = (TypeCastTree) current;
                return numericConversion(numericConstant(cast.getExpression()),
                                         castKind(cast));
            }
            if (current instanceof UnaryTree) {
                UnaryTree unary = (UnaryTree) current;
                Object value = numericConstant(unary.getExpression());
                TypeKind kind = expressionKind(current);
                Number number = asNumber(numericConversion(value, kind));
                if (number == null || kind == null) return null;
                switch (unary.getKind()) {
                    case UNARY_PLUS: return numericConversion(number, kind);
                    case UNARY_MINUS:
                        if (kind == TypeKind.DOUBLE)
                            return Double.valueOf(-number.doubleValue());
                        if (kind == TypeKind.FLOAT)
                            return Float.valueOf(-number.floatValue());
                        if (kind == TypeKind.LONG)
                            return Long.valueOf(-number.longValue());
                        if (kind == TypeKind.INT)
                            return Integer.valueOf(-number.intValue());
                        return null;
                    case BITWISE_COMPLEMENT:
                        if (kind == TypeKind.LONG)
                            return Long.valueOf(~number.longValue());
                        if (kind == TypeKind.INT)
                            return Integer.valueOf(~number.intValue());
                        return null;
                    default: return null;
                }
            }
            if (current instanceof BinaryTree) {
                return binaryNumericConstant((BinaryTree) current);
            }
            TreePath path = TreePath.getPath(unit, current);
            Element element = path == null ? null : trees.getElement(path);
            if (element instanceof VariableElement) {
                Object value = ((VariableElement) element).getConstantValue();
                return asNumber(value) == null ? null : value;
            }
            return null;
        }

        private boolean isNumericZeroAfterConversion(
                ExpressionTree expression, TypeKind declaredKind) {
            Object converted = numericConversion(
                    numericConstant(expression), declaredKind);
            Number number = asNumber(converted);
            if (number == null) return false;
            if (declaredKind == TypeKind.FLOAT) {
                return Float.floatToRawIntBits(number.floatValue())
                        == Float.floatToRawIntBits(0.0f);
            }
            if (declaredKind == TypeKind.DOUBLE) {
                return Double.doubleToRawLongBits(number.doubleValue())
                        == Double.doubleToRawLongBits(0.0d);
            }
            return number.longValue() == 0L;
        }

        private boolean isNullDefault(ExpressionTree expression) {
            ExpressionTree current = unparenthesized(expression);
            if (current instanceof LiteralTree) {
                return ((LiteralTree) current).getValue() == null;
            }
            if (current instanceof TypeCastTree) {
                TypeCastTree cast = (TypeCastTree) current;
                TypeKind castKind = castKind(cast);
                return (castKind == TypeKind.ARRAY
                        || castKind == TypeKind.DECLARED
                        || castKind == TypeKind.TYPEVAR)
                        && isNullDefault(cast.getExpression());
            }
            return false;
        }

        @Override public Void visitExpressionStatement(
                ExpressionStatementTree tree, Void unused) {
            try {
                // Attribution inserts an implicit super() into synthetic
                // default constructors. It is not source and carries NOPOS.
                if (positioned(tree)
                        && tree.getExpression() instanceof MethodInvocationTree) {
                    emitChars("MethodCallRemoval", start(tree), end(tree), ";");
                }
            } catch (Refusal exc) {
                throw new ScanFailure(exc);
            }
            return super.visitExpressionStatement(tree, unused);
        }
    }

    private static final class ScanFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;
        final Refusal refusal;
        ScanFailure(Refusal refusal) {
            super(refusal);
            this.refusal = refusal;
        }
    }

    private static final class SourceObject extends SimpleJavaFileObject {
        private final String text;
        SourceObject(String rel, String text) {
            super(sourceUri(rel), JavaFileObject.Kind.SOURCE);
            this.text = text;
        }
        @Override public CharSequence getCharContent(boolean ignoreEncodingErrors) {
            return text;
        }
    }

    private static URI sourceUri(String rel) {
        String path = rel.replace('\\', '/');
        if (!path.startsWith("/")) path = "/" + path;
        return new File(path).toURI();
    }

    private static final class ClassObject extends SimpleJavaFileObject {
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        ClassObject(String className, JavaFileObject.Kind kind) {
            super(URI.create("mem:///" + className.replace('.', '/')
                    + kind.extension), kind);
        }
        @Override public OutputStream openOutputStream() {
            return bytes;
        }
    }

    private static final class MemoryFileManager
            extends ForwardingJavaFileManager<StandardJavaFileManager> {
        MemoryFileManager(StandardJavaFileManager delegate) {
            super(delegate);
        }
        @Override public JavaFileObject getJavaFileForOutput(
                JavaFileManager.Location location, String className,
                JavaFileObject.Kind kind, FileObject sibling) {
            return new ClassObject(className, kind);
        }
    }

    private static List<String> compilerOptions(Options options,
                                                SourceData source) {
        List<String> out = new ArrayList<String>();
        out.add("-proc:none");
        out.add("-encoding");
        out.add("UTF-8");
        // All three paths are mandatory command arguments.  In particular,
        // never fall back to java.class.path: that contains this engine's own
        // classes (and, on JDK 8, tools.jar), not the project dependencies
        // whose exact bytes minted the manifest.  The Python binding turns
        // an explicitly empty recipe into a canonical nonexistent path so
        // javac also cannot interpret an empty path element as cwd.
        out.add("-classpath");
        out.add(options.classpath);
        out.add("-sourcepath");
        out.add(options.sourcepath);
        if (options.modulepath.length() > 0) {
            // Omitted when the authenticated list is empty so this source
            // remains compilable/runnable on JDK 8, which predates modules.
            out.add("--module-path");
            out.add(options.modulepath);
        }
        if (options.releaseLevel != null) {
            out.add("--release");
            out.add(options.releaseLevel);
        } else if (options.sourceLevel != null) {
            out.add("-source");
            out.add(options.sourceLevel);
            out.add("-target");
            out.add(options.targetLevel);
        }
        out.add("-Xlint:none");
        return out;
    }

    private static final class Parsed {
        final List<Mutant> mutants;
        final String error;
        Parsed(List<Mutant> mutants, String error) {
            this.mutants = mutants;
            this.error = error;
        }
    }

    private static Parsed parseAndEnumerate(SourceData source, Options options) {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        DiagnosticCollector<JavaFileObject> diagnostics =
                new DiagnosticCollector<JavaFileObject>();
        StandardJavaFileManager standard = compiler.getStandardFileManager(
                diagnostics, Locale.ROOT, StandardCharsets.UTF_8);
        MemoryFileManager manager = new MemoryFileManager(standard);
        try {
            JavaFileObject input = new SourceObject(source.rel, source.text);
            JavacTask task = (JavacTask) compiler.getTask(
                    null, manager, diagnostics, compilerOptions(options, source), null,
                    Collections.singletonList(input));
            Iterable<? extends CompilationUnitTree> units = task.parse();
            task.analyze();
            if (hasErrors(diagnostics)) {
                return new Parsed(Collections.<Mutant>emptyList(),
                        diagnosticSummary(diagnostics));
            }
            Trees trees = Trees.instance(task);
            List<Mutant> rows = new ArrayList<Mutant>();
            try {
                for (CompilationUnitTree unit : units) {
                    Enumerator enumerator = new Enumerator(source, unit, trees);
                    enumerator.scan(unit, null);
                    rows.addAll(enumerator.rows());
                }
            } catch (ScanFailure failure) {
                return new Parsed(Collections.<Mutant>emptyList(),
                        failure.refusal.getMessage());
            }
            // Analyze is enough to attribute return types; generate completes
            // the baseline compile so a code-generation failure is a file
            // error rather than a population of candidates killed by javac.
            task.generate();
            if (hasErrors(diagnostics)) {
                return new Parsed(Collections.<Mutant>emptyList(),
                        diagnosticSummary(diagnostics));
            }
            Collections.sort(rows, MUTANT_ORDER);
            return new Parsed(rows, null);
        } catch (Throwable exc) {
            return new Parsed(Collections.<Mutant>emptyList(),
                    "javac failed: " + exc.getClass().getSimpleName() + ": "
                            + String.valueOf(exc.getMessage()));
        } finally {
            try { manager.close(); } catch (IOException ignored) { }
        }
    }

    private static boolean hasErrors(
            DiagnosticCollector<JavaFileObject> diagnostics) {
        for (Diagnostic<? extends JavaFileObject> diagnostic
                : diagnostics.getDiagnostics()) {
            if (diagnostic.getKind() == Diagnostic.Kind.ERROR) return true;
        }
        return false;
    }

    private static String diagnosticSummary(
            DiagnosticCollector<JavaFileObject> diagnostics) {
        List<String> messages = new ArrayList<String>();
        for (Diagnostic<? extends JavaFileObject> diagnostic
                : diagnostics.getDiagnostics()) {
            if (diagnostic.getKind() != Diagnostic.Kind.ERROR) continue;
            StringBuilder message = new StringBuilder();
            if (diagnostic.getLineNumber() != Diagnostic.NOPOS) {
                message.append("line ").append(diagnostic.getLineNumber())
                        .append(": ");
            }
            message.append(diagnostic.getMessage(Locale.ROOT)
                    .replace('\n', ' ').replace('\r', ' '));
            messages.add(message.toString());
            if (messages.size() == 3) break;
        }
        return messages.isEmpty() ? "javac compilation failed"
                : join(messages, " | ");
    }

    private static boolean compileCandidate(Mutant mutant, Options options)
            throws Refusal {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        DiagnosticCollector<JavaFileObject> diagnostics =
                new DiagnosticCollector<JavaFileObject>();
        StandardJavaFileManager standard = compiler.getStandardFileManager(
                diagnostics, Locale.ROOT, StandardCharsets.UTF_8);
        MemoryFileManager manager = new MemoryFileManager(standard);
        try {
            byte[] bytes = mutant.candidateBytes();
            String text = decodeUtf8(bytes, mutant.source.rel);
            JavaFileObject input = new SourceObject(mutant.source.rel, text);
            JavaCompiler.CompilationTask task = compiler.getTask(
                    null, manager, diagnostics,
                    compilerOptions(options, mutant.source), null,
                    Collections.singletonList(input));
            return Boolean.TRUE.equals(task.call()) && !hasErrors(diagnostics);
        } catch (Refusal exc) {
            throw exc;
        } catch (Throwable exc) {
            throw new Refusal(mutant.source.rel + ": javac crashed while "
                    + "validating " + mutant.operator + " at "
                    + mutant.startLine + ":" + mutant.startCol + ": "
                    + exc.getClass().getSimpleName() + ": "
                    + String.valueOf(exc.getMessage()), exc);
        } finally {
            try { manager.close(); } catch (IOException ignored) { }
        }
    }

    private static final class Validated {
        final List<Mutant> rows;
        final int invalid;
        Validated(List<Mutant> rows, int invalid) {
            this.rows = rows;
            this.invalid = invalid;
        }
    }

    private static Validated validateCandidates(List<Mutant> candidates,
                                                final Options options)
            throws Refusal {
        if (candidates.isEmpty()) {
            return new Validated(Collections.<Mutant>emptyList(), 0);
        }
        int workers = Math.min(options.compileWorkers, candidates.size());
        if (workers <= 1) {
            List<Mutant> valid = new ArrayList<Mutant>();
            int invalid = 0;
            for (Mutant candidate : candidates) {
                if (compileCandidate(candidate, options)) valid.add(candidate);
                else invalid++;
            }
            return new Validated(valid, invalid);
        }
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        try {
            List<Future<Boolean>> futures = new ArrayList<Future<Boolean>>();
            for (final Mutant candidate : candidates) {
                futures.add(pool.submit(new Callable<Boolean>() {
                    @Override public Boolean call() throws Exception {
                        return compileCandidate(candidate, options);
                    }
                }));
            }
            List<Mutant> valid = new ArrayList<Mutant>();
            int invalid = 0;
            for (int i = 0; i < candidates.size(); i++) {
                try {
                    if (Boolean.TRUE.equals(futures.get(i).get())) {
                        valid.add(candidates.get(i));
                    } else {
                        invalid++;
                    }
                } catch (InterruptedException exc) {
                    Thread.currentThread().interrupt();
                    throw new Refusal("candidate compilation was interrupted", exc);
                } catch (ExecutionException exc) {
                    Throwable cause = exc.getCause();
                    if (cause instanceof Refusal) throw (Refusal) cause;
                    throw new Refusal("candidate compilation worker failed: "
                            + cause, cause);
                }
            }
            return new Validated(valid, invalid);
        } finally {
            pool.shutdownNow();
        }
    }

    private static String decodeUtf8(byte[] bytes, String rel) throws Refusal {
        try {
            CharBuffer chars = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes));
            String text = chars.toString();
            for (int i = 0; i < text.length(); i++) {
                if (text.charAt(i) == '\r'
                        && (i + 1 >= text.length() || text.charAt(i + 1) != '\n')) {
                    throw new Refusal(rel + ": file contains a bare CR; javac "
                            + "and byte-line accounting would disagree");
                }
            }
            return text;
        } catch (CharacterCodingException exc) {
            throw new Refusal(rel + ": file is not valid UTF-8; source bytes "
                    + "cannot be carried in a UTF-8 manifest", exc);
        }
    }

    private static void enumerate(Options options)
            throws IOException, Refusal, OutputFailure {
        TreeMap<String, String> errors = new TreeMap<String, String>();
        TreeMap<String, Path> files = collectFiles(options, errors);
        List<Mutant> all = new ArrayList<Mutant>();
        int processed = 0;
        int invalid = 0;
        for (Map.Entry<String, Path> entry : files.entrySet()) {
            String rel = entry.getKey();
            if (isExcluded(rel)) continue;
            SourceData source;
            try {
                byte[] bytes = Files.readAllBytes(entry.getValue());
                String text = decodeUtf8(bytes, rel);
                if (isGenerated(text)) continue;
                source = new SourceData(rel, bytes, text);
            } catch (Refusal exc) {
                errors.put(rel, exc.getMessage());
                continue;
            } catch (IOException exc) {
                errors.put(rel, "cannot read file: " + exc.getMessage());
                continue;
            }
            Parsed parsed = parseAndEnumerate(source, options);
            if (parsed.error != null) {
                errors.put(rel, parsed.error);
                continue;
            }
            Validated validated;
            try {
                validated = validateCandidates(parsed.mutants, options);
            } catch (Refusal exc) {
                // A compiler crash or engine invariant fault is a file error,
                // never an "invalid mutant" count.
                errors.put(rel, exc.getMessage());
                continue;
            }
            processed++;
            invalid += validated.invalid;
            all.addAll(validated.rows);
        }
        Collections.sort(all, MUTANT_ORDER);
        String json = envelopeJson(processed, errors, all, invalid,
                options.recordEnumeratorRev);
        writeOutput(options, json, false);
        if (options.out != null) {
            System.err.println("enumerated " + all.size() + " mutants over "
                    + processed + " files, " + errors.size() + " errors, "
                    + invalid + " invalid -> " + options.out);
        }
    }

    private static TreeMap<String, Path> collectFiles(
            final Options options, final TreeMap<String, String> errors)
            throws IOException, Refusal {
        final TreeMap<String, Path> found = new TreeMap<String, Path>();
        for (String supplied : options.paths) {
            final Path requested;
            try {
                requested = resolveInside(options.root, supplied, true);
            } catch (Refusal exc) {
                errors.put(normalizeRel(supplied), exc.getMessage());
                continue;
            }
            if (!Files.exists(requested, LinkOption.NOFOLLOW_LINKS)) {
                errors.put(normalizeRel(supplied), "not found");
                continue;
            }
            if (Files.isSymbolicLink(requested)) {
                errors.put(normalizeRel(supplied), "symlink inputs are refused");
                continue;
            }
            if (Files.isRegularFile(requested, LinkOption.NOFOLLOW_LINKS)) {
                if (requested.getFileName().toString().toLowerCase(Locale.ROOT)
                        .endsWith(".java")) {
                    found.put(relative(options.root, requested), requested);
                }
                continue;
            }
            if (!Files.isDirectory(requested, LinkOption.NOFOLLOW_LINKS)) {
                errors.put(normalizeRel(supplied), "not a regular file or directory");
                continue;
            }
            Files.walkFileTree(requested, new SimpleFileVisitor<Path>() {
                @Override public FileVisitResult preVisitDirectory(
                        Path dir, BasicFileAttributes attrs) throws IOException {
                    if (Files.isSymbolicLink(dir)) return FileVisitResult.SKIP_SUBTREE;
                    String rel = relative(options.root, dir);
                    return isExcluded(rel) ? FileVisitResult.SKIP_SUBTREE
                            : FileVisitResult.CONTINUE;
                }

                @Override public FileVisitResult visitFile(
                        Path file, BasicFileAttributes attrs) {
                    String rel = relative(options.root, file);
                    if (Files.isSymbolicLink(file)) {
                        errors.put(rel, "symlink inputs are refused");
                    } else if (attrs.isRegularFile()
                            && file.getFileName().toString()
                            .toLowerCase(Locale.ROOT).endsWith(".java")) {
                        found.put(rel, file);
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override public FileVisitResult visitFileFailed(
                        Path file, IOException exc) {
                    errors.put(relative(options.root, file),
                            "cannot inspect file: " + exc.getMessage());
                    return FileVisitResult.CONTINUE;
                }
            });
        }
        return found;
    }

    private static Path resolveInside(Path root, String supplied,
                                      boolean requireExisting)
            throws Refusal, IOException {
        Path path = Paths.get(supplied);
        Path resolved = path.isAbsolute() ? path.normalize()
                : root.resolve(path).normalize();
        if (!resolved.startsWith(root)) {
            throw new Refusal("path escapes --root: " + supplied);
        }
        Path cursor = root;
        Path relative = root.relativize(resolved);
        for (Path component : relative) {
            cursor = cursor.resolve(component);
            if (Files.isSymbolicLink(cursor)) {
                throw new Refusal("path traverses a symlink: " + supplied);
            }
        }
        if (requireExisting && Files.exists(resolved, LinkOption.NOFOLLOW_LINKS)) {
            Path real = resolved.toRealPath();
            if (!real.startsWith(root)) {
                throw new Refusal("path resolves outside --root: " + supplied);
            }
            resolved = real;
        }
        return resolved;
    }

    private static String relative(Path root, Path path) {
        try {
            return normalizeRel(root.relativize(path.toAbsolutePath().normalize())
                    .toString());
        } catch (IllegalArgumentException exc) {
            return normalizeRel(path.toString());
        }
    }

    private static String normalizeRel(String rel) {
        String value = rel.replace('\\', '/');
        while (value.startsWith("./")) value = value.substring(2);
        return value;
    }

    private static boolean isExcluded(String rel) {
        if (rel == null || rel.length() == 0 || ".".equals(rel)) return false;
        for (String segment : normalizeRel(rel).split("/")) {
            if (EXCLUDED_SEGMENTS.contains(segment)) return true;
        }
        return false;
    }

    private static boolean isGenerated(String text) {
        int end = 0;
        int lines = 0;
        while (end < text.length() && lines < HEAD_LINES) {
            if (text.charAt(end++) == '\n') lines++;
        }
        String head = text.substring(0, end);
        return head.contains("@generated") || head.contains("GENERATED by");
    }

    private static void apply(Options options)
            throws IOException, Refusal, OutputFailure {
        if (!OPERATORS.contains(options.operator)) {
            throw new Refusal("unknown v2 operator " + options.operator);
        }
        Path target = resolveInside(options.root, options.applyFile, true);
        String rel = relative(options.root, target);
        if (isExcluded(rel)) {
            throw new Refusal("refusing to mutate excluded path " + rel);
        }
        if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(target)) {
            throw new Refusal(rel + " is not a regular non-symlink file");
        }
        byte[] bytes = Files.readAllBytes(target);
        String text = decodeUtf8(bytes, rel);
        if (isGenerated(text)) {
            throw new Refusal("refusing to mutate generated file " + rel);
        }
        SourceData source = new SourceData(rel, bytes, text);
        Parsed parsed = parseAndEnumerate(source, options);
        if (parsed.error != null) {
            throw new Refusal("cannot re-enumerate " + rel + ": " + parsed.error);
        }
        Mutant requested = null;
        // Population construction performs the batch validity gate once.
        // Apply re-enumerates descriptors without compiling every sibling in
        // the file, then compiles only the requested match below; otherwise a
        // campaign over N mutants in one file would repeat O(N^2) javac work.
        for (Mutant row : parsed.mutants) {
            if (row.requestedBy(options)) {
                if (requested != null) {
                    throw new Refusal("requested descriptor is ambiguous in " + rel);
                }
                requested = row;
            }
        }
        if (requested == null) {
            throw new Refusal("enumerating " + rel + " now yields no mutant "
                    + options.operator + " at " + options.startLine + ":"
                    + options.startCol + " with the requested exact bytes");
        }
        // The row was compiled during re-enumeration; compile it once more at
        // the write boundary so a future refactor cannot accidentally turn
        // enumeration validity into apply trust.
        if (!compileCandidate(requested, options)) {
            throw new Refusal("requested candidate is not compile-valid");
        }
        Path output = resolveInside(options.writeRoot, options.out, false);
        Path parent = output.getParent();
        if (parent == null) {
            throw new Refusal("output has no parent: " + output);
        }
        try {
            Files.createDirectories(parent);
            if (Files.isSymbolicLink(output)) {
                throw new Refusal("output is a symlink: " + output);
            }
            writeAtomic(output, requested.candidateBytes());
        } catch (Refusal exc) {
            throw exc;
        } catch (IOException exc) {
            throw new OutputFailure("cannot write " + output + ": "
                    + exc.getMessage(), exc);
        }
    }

    private static void writeAtomic(Path output, byte[] bytes) throws IOException {
        Path parent = output.getParent();
        PosixFileAttributes preserved = null;
        Integer preservedUnixMode = null;
        if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.isRegularFile(output, LinkOption.NOFOLLOW_LINKS)
                    || Files.isSymbolicLink(output)) {
                throw new IOException("output is not a regular non-symlink file");
            }
            preserved = Files.readAttributes(
                    output, PosixFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            Object unixMode = Files.getAttribute(
                    output, "unix:mode", LinkOption.NOFOLLOW_LINKS);
            if (!(unixMode instanceof Integer)) {
                throw new IOException(
                        "output filesystem has no full Unix mode attribute");
            }
            preservedUnixMode = (Integer) unixMode;
        }
        Path temporary = Files.createTempFile(parent, ".r2t-java-mutate-", ".tmp");
        boolean moved = false;
        try {
            Files.write(temporary, bytes);
            if (preserved != null) {
                Files.setOwner(temporary, preserved.owner());
                PosixFileAttributeView view = Files.getFileAttributeView(
                        temporary, PosixFileAttributeView.class,
                        LinkOption.NOFOLLOW_LINKS);
                if (view == null) {
                    throw new IOException("output filesystem has no POSIX "
                            + "mode/uid/gid attribute view");
                }
                view.setGroup(preserved.group());
                // chown/chgrp may clear set-ID bits.  Permissions therefore
                // come last, and are verified before the original pathname is
                // replaced so a metadata failure cannot strand changed bytes.
                Files.setAttribute(temporary, "unix:mode", preservedUnixMode,
                        LinkOption.NOFOLLOW_LINKS);
                PosixFileAttributes staged = Files.readAttributes(
                        temporary, PosixFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);
                Object stagedUnixMode = Files.getAttribute(
                        temporary, "unix:mode", LinkOption.NOFOLLOW_LINKS);
                if (!staged.permissions().equals(preserved.permissions())
                        || !staged.owner().equals(preserved.owner())
                        || !staged.group().equals(preserved.group())
                        || !preservedUnixMode.equals(stagedUnixMode)) {
                    throw new IOException(
                            "staged output did not preserve mode/uid/gid");
                }
            }
            try {
                Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException exc) {
                Files.move(temporary, output, StandardCopyOption.REPLACE_EXISTING);
            }
            moved = true;
            if (preserved != null) {
                PosixFileAttributes after = Files.readAttributes(
                        output, PosixFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);
                Object afterUnixMode = Files.getAttribute(
                        output, "unix:mode", LinkOption.NOFOLLOW_LINKS);
                if (!after.permissions().equals(preserved.permissions())
                        || !after.owner().equals(preserved.owner())
                        || !after.group().equals(preserved.group())
                        || !preservedUnixMode.equals(afterUnixMode)) {
                    throw new IOException(
                            "atomic output did not preserve mode/uid/gid");
                }
            }
        } finally {
            if (!moved) Files.deleteIfExists(temporary);
        }
    }

    private static void writeOutput(Options options, String json, boolean apply)
            throws OutputFailure {
        if (options.out == null) {
            System.out.print(json);
            return;
        }
        Path output = Paths.get(options.out);
        if (!output.isAbsolute()) output = options.root.resolve(output);
        output = output.toAbsolutePath().normalize();
        try {
            Path parent = output.getParent();
            if (parent == null) throw new IOException("output has no parent");
            Files.createDirectories(parent);
            if (Files.isSymbolicLink(output)) {
                throw new IOException("output is a symlink");
            }
            writeAtomic(output, json.getBytes(StandardCharsets.UTF_8));
        } catch (IOException exc) {
            throw new OutputFailure("cannot write " + output + ": "
                    + exc.getMessage(), exc);
        }
    }

    private static String envelopeJson(int files, Map<String, String> errors,
                                       List<Mutant> mutants, int invalid,
                                       boolean recordRevision) {
        StringBuilder out = new StringBuilder();
        out.append("{\n");
        jsonField(out, "engine", ENGINE, true, 2);
        jsonField(out, "engine_version", ENGINE_VERSION, true, 2);
        jsonField(out, "parser", parserVersion(), true, 2);
        numberField(out, "files", files, true, 2);
        indent(out, 2).append("\"errors\": {");
        if (!errors.isEmpty()) out.append('\n');
        int errorIndex = 0;
        for (Map.Entry<String, String> entry : errors.entrySet()) {
            indent(out, 4);
            jsonString(out, entry.getKey());
            out.append(": ");
            jsonString(out, entry.getValue());
            if (++errorIndex < errors.size()) out.append(',');
            out.append('\n');
        }
        if (!errors.isEmpty()) indent(out, 2);
        out.append("},\n");
        indent(out, 2).append("\"mutants\": [");
        if (!mutants.isEmpty()) out.append('\n');
        for (int i = 0; i < mutants.size(); i++) {
            mutantJson(out, mutants.get(i), 4);
            if (i + 1 < mutants.size()) out.append(',');
            out.append('\n');
        }
        if (!mutants.isEmpty()) indent(out, 2);
        out.append(']');
        if (invalid > 0 || recordRevision) out.append(',');
        out.append('\n');
        if (invalid > 0) {
            numberField(out, "n_invalid", invalid, recordRevision, 2);
        }
        if (recordRevision) {
            jsonField(out, "enumerator_rev", ENUMERATOR_REV, false, 2);
        }
        out.append("}\n");
        return out.toString();
    }

    private static void mutantJson(StringBuilder out, Mutant mutant, int spaces) {
        indent(out, spaces).append("{\n");
        jsonField(out, "file", mutant.source.rel, true, spaces + 2);
        numberField(out, "start_line", mutant.startLine, true, spaces + 2);
        numberField(out, "start_col", mutant.startCol, true, spaces + 2);
        numberField(out, "end_line", mutant.endLine, true, spaces + 2);
        numberField(out, "end_col", mutant.endCol, true, spaces + 2);
        jsonField(out, "operator", mutant.operator, true, spaces + 2);
        jsonField(out, "original", mutant.original, true, spaces + 2);
        boolean hasClass = mutant.className != null;
        boolean hasMethod = mutant.methodName != null;
        jsonField(out, "mutated", mutant.mutated, hasClass || hasMethod,
                spaces + 2);
        if (hasClass) {
            jsonField(out, "class", mutant.className, hasMethod, spaces + 2);
        }
        if (hasMethod) {
            jsonField(out, "method", mutant.methodName, false, spaces + 2);
        }
        indent(out, spaces).append('}');
    }

    private static void jsonField(StringBuilder out, String key, String value,
                                  boolean comma, int spaces) {
        indent(out, spaces);
        jsonString(out, key);
        out.append(": ");
        jsonString(out, value);
        if (comma) out.append(',');
        out.append('\n');
    }

    private static void numberField(StringBuilder out, String key, int value,
                                    boolean comma, int spaces) {
        indent(out, spaces);
        jsonString(out, key);
        out.append(": ").append(value);
        if (comma) out.append(',');
        out.append('\n');
    }

    private static void jsonString(StringBuilder out, String value) {
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
                    if (ch < 0x20 || ch == 0x2028 || ch == 0x2029) {
                        out.append(String.format(Locale.ROOT, "\\u%04x",
                                Integer.valueOf(ch)));
                    } else {
                        out.append(ch);
                    }
            }
        }
        out.append('"');
    }

    private static StringBuilder indent(StringBuilder out, int spaces) {
        for (int i = 0; i < spaces; i++) out.append(' ');
        return out;
    }

    private static String parserVersion() {
        // Source spans and attribution are products of the compiler bundled
        // with the runtime hosting ToolProvider. java.version alone omits the
        // vendor/build (e.g. 1.8.0_311-b11), so retain all three facts in the
        // digest-covered parser identity.
        return "javac " + System.getProperty("java.version", "unknown")
                + " [" + System.getProperty("java.vendor", "unknown")
                + "; runtime="
                + System.getProperty("java.runtime.version", "unknown") + "]";
    }

    private static String join(List<String> values, String separator) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) out.append(separator);
            out.append(values.get(i));
        }
        return out.toString();
    }
}
