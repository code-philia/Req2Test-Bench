package r2t.directcalls;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * The Java production-method index of section 2.4, read with ASM from the
 * compiled {@code target/classes}: for every method the agent could ever report
 * -- the same rule as {@link DirectCallAgent#recordable}, over methods that have
 * code -- its binary class name, name, descriptor, {@code ACC_PUBLIC} and
 * {@code ACC_STATIC} flags, source file and first and last line.
 *
 * <p>The envelope is the one {@code bench.metrics.load_prod_index} already reads
 * ({@code files -> classes -> methods} with {@code name/start/end/public}), plus
 * the {@code descriptor} the Java join needs, so a Java index is a Python index
 * with one more key per method and a different {@code schema}.  Files are keyed
 * by the {@code src/main/java/<package>/<SourceFile>} spelling the agent writes
 * as {@code callee_file}; a member, local or anonymous class is listed under its
 * own binary name beneath the file its {@code SourceFile} attribute names.
 *
 * <p>Refuses rather than indexes when a class carries no {@code SourceFile} or a
 * method no line numbers: both mean the tree was compiled without debug
 * information, and an index built over it would join nothing while looking
 * complete.  Usage: {@code java -cp <agent jar> r2t.directcalls.JavaMethodIndex
 * <target/classes> <out.json>}.
 */
public final class JavaMethodIndex {

    static final String SCHEMA = "r2t.java_prod_index/1";

    private JavaMethodIndex() {
    }

    static final class MethodRow {
        final String name;
        final String descriptor;
        final boolean isPublic;
        final boolean isStatic;
        int first = Integer.MAX_VALUE;
        int last = Integer.MIN_VALUE;

        MethodRow(int access, String name, String descriptor) {
            this.name = name;
            this.descriptor = descriptor;
            this.isPublic = (access & Opcodes.ACC_PUBLIC) != 0;
            this.isStatic = (access & Opcodes.ACC_STATIC) != 0;
        }
    }

    static final class ClassRow {
        String internalName;
        String sourceFile;
        boolean isEnum;
        final List<MethodRow> methods = new ArrayList<>();
    }

    static final class IndexVisitor extends ClassVisitor {
        final ClassRow row = new ClassRow();

        IndexVisitor() {
            super(Opcodes.ASM9);
        }

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            row.internalName = name;
            row.isEnum = (access & Opcodes.ACC_ENUM) != 0;
        }

        @Override
        public void visitSource(String source, String debug) {
            row.sourceFile = source;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            if ((access & (Opcodes.ACC_SYNTHETIC | Opcodes.ACC_BRIDGE
                           | Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0
                    || !DirectCallAgent.recordable(row.isEnum, row.internalName,
                                                   name, descriptor)) {
                return null;
            }
            final MethodRow method = new MethodRow(access, name, descriptor);
            row.methods.add(method);
            return new MethodVisitor(Opcodes.ASM9) {
                @Override
                public void visitLineNumber(int line, Label start) {
                    method.first = Math.min(method.first, line);
                    method.last = Math.max(method.last, line);
                }
            };
        }
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 2 && args.length != 4) {
            System.err.println("usage: JavaMethodIndex <target/classes> [<repo-root> <source-root>] <out.json>");
            System.exit(2);
        }
        Path classes = Paths.get(args[0]).toAbsolutePath();
        Path repository = args.length == 4 ? Paths.get(args[1]).toAbsolutePath() : null;
        String sourceRoot = args.length == 4 ? args[2] : DirectCallRecorder.MAIN_ROOT;
        if (Paths.get(sourceRoot).isAbsolute() || sourceRoot.isEmpty()
                || !Paths.get(sourceRoot).normalize().toString().equals(sourceRoot)
                || sourceRoot.equals("..") || sourceRoot.startsWith("../")) {
            throw new IllegalArgumentException("source root must be repository-relative");
        }
        List<Path> files;
        try (Stream<Path> walk = Files.walk(classes)) {
            files = walk.filter(p -> p.toString().endsWith(".class"))
                .filter(p -> !p.getFileName().toString().equals("module-info.class")
                          && !p.getFileName().toString().equals("package-info.class"))
                .sorted().collect(Collectors.toList());
        }
        List<String> refusals = new ArrayList<>();
        // file -> class binary name -> row; TreeMaps for a deterministic document.
        Map<String, Map<String, ClassRow>> byFile = new TreeMap<>();
        int methods = 0;
        int publicMethods = 0;
        int indexedClasses = 0;
        Map<String, String> skippedGenerated = new TreeMap<>();
        for (Path file : files) {
            IndexVisitor visitor = new IndexVisitor();
            new ClassReader(Files.readAllBytes(file)).accept(
                visitor, ClassReader.SKIP_FRAMES);
            ClassRow row = visitor.row;
            if (row.sourceFile == null) {
                refusals.add(row.internalName + ": no SourceFile attribute");
                continue;
            }
            int slash = row.internalName.lastIndexOf('/');
            String rel = sourceRoot + "/"
                + (slash < 0 ? "" : row.internalName.substring(0, slash) + "/")
                + row.sourceFile;
            if (repository != null && !Files.isRegularFile(repository.resolve(rel))) {
                String suffix = "src/main/java";
                String generated = sourceRoot.endsWith(suffix)
                    ? sourceRoot.substring(0, sourceRoot.length() - suffix.length())
                        + "target/generated-sources/annotations/"
                        + (slash < 0 ? "" : row.internalName.substring(0, slash) + "/")
                        + row.sourceFile
                    : null;
                if (generated == null || !Files.isRegularFile(repository.resolve(generated))) {
                    refusals.add(row.internalName + ": no original or generated source at " + rel);
                } else {
                    skippedGenerated.put(row.internalName.replace('/', '.'), generated);
                }
                continue;
            }
            for (MethodRow method : row.methods) {
                if (method.first == Integer.MAX_VALUE) {
                    refusals.add(row.internalName + "." + method.name + method.descriptor
                                 + ": no LineNumberTable");
                }
                methods++;
                if (method.isPublic) {
                    publicMethods++;
                }
            }
            if (byFile.computeIfAbsent(rel, k -> new TreeMap<>())
                    .put(row.internalName.replace('/', '.'), row) != null) {
                refusals.add(row.internalName + ": duplicate class definition");
            }
            indexedClasses++;
        }
        if (!refusals.isEmpty()) {
            for (String refusal : refusals) {
                System.err.println("REFUSED: " + refusal);
            }
            System.err.println("REFUSED: " + refusals.size()
                + " class/method(s) lack unambiguous source or debug information");
            System.exit(1);
        }
        StringBuilder out = new StringBuilder();
        out.append("{\"schema\":").append(Json.string(SCHEMA));
        out.append(",\"language\":\"java\"");
        out.append(",\"root\":").append(Json.string(sourceRoot));
        out.append(",\"counts\":{\"files\":").append(byFile.size());
        out.append(",\"classes\":").append(indexedClasses);
        out.append(",\"methods\":").append(methods);
        out.append(",\"public_methods\":").append(publicMethods).append('}');
        if (repository != null) {
            out.append(",\"skipped_generated\":{");
            boolean firstGenerated = true;
            for (Map.Entry<String, String> skipped : skippedGenerated.entrySet()) {
                out.append(firstGenerated ? "" : ",").append(Json.string(skipped.getKey()))
                    .append(":").append(Json.string(skipped.getValue()));
                firstGenerated = false;
            }
            out.append('}');
        }
        out.append(",\"files\":{");
        boolean firstFile = true;
        for (Map.Entry<String, Map<String, ClassRow>> fileEntry : byFile.entrySet()) {
            out.append(firstFile ? "\n" : ",\n").append(Json.string(fileEntry.getKey()))
                .append(":{\"classes\":[");
            firstFile = false;
            boolean firstClass = true;
            for (Map.Entry<String, ClassRow> classEntry : fileEntry.getValue().entrySet()) {
                out.append(firstClass ? "" : ",").append("{\"name\":")
                    .append(Json.string(classEntry.getKey())).append(",\"methods\":[");
                firstClass = false;
                List<MethodRow> rows = classEntry.getValue().methods;
                rows.sort((a, b) -> a.name.equals(b.name)
                          ? a.descriptor.compareTo(b.descriptor)
                          : a.name.compareTo(b.name));
                boolean firstMethod = true;
                for (MethodRow m : rows) {
                    out.append(firstMethod ? "" : ",");
                    firstMethod = false;
                    out.append("{\"name\":").append(Json.string(m.name));
                    out.append(",\"descriptor\":").append(Json.string(m.descriptor));
                    out.append(",\"public\":").append(m.isPublic);
                    out.append(",\"static\":").append(m.isStatic);
                    out.append(",\"abstract\":false");
                    out.append(",\"start\":").append(m.first);
                    out.append(",\"end\":").append(m.last).append('}');
                }
                out.append("]}");
            }
            out.append("]}");
        }
        out.append("}}\n");
        Path target = Paths.get(args[args.length - 1]).toAbsolutePath();
        if (target.getParent() != null) {
            Files.createDirectories(target.getParent());
        }
        Files.write(target, out.toString().getBytes(StandardCharsets.UTF_8));
        System.out.println("indexed " + indexedClasses + " classes, " + methods
            + " methods (" + publicMethods + " public) into " + target);
    }
}
