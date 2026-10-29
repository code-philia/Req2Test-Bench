package r2t.directcalls;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.nio.file.Paths;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * The Java direct-invocation collector of benchmark/API_DIRECT_INVOCATION_SPEC.md
 * section 2.4: a javaagent that instruments the entry of every method of a class
 * whose code source is the build's {@code target/classes} and hands the activation
 * to {@link DirectCallRecorder}, which finds the calling frame.
 *
 * <p>The one agent argument is the absolute path the recorder writes at JVM exit
 * ({@code target/r2t-direct-calls.json} of the workspace, spelled by the harness
 * so that the fork's working directory -- a per-project surefire quirk -- never
 * decides where the file lands).
 *
 * <p>What is NOT instrumented, and why, follows section 2.2: {@code <clinit>} is
 * the JVM's lazy initialisation rather than a call the test made; synthetic and
 * bridge methods (lambda bodies, generic bridges, accessors) are not method
 * activations; an enum's compiler-generated {@code values()} and
 * {@code valueOf(String)} are the enum case of the same rule.  Everything else --
 * {@code <init>} included, whatever its visibility -- is recorded, because the
 * recorder applies no boundary and no public test: both are applied at scoring on
 * the host, exactly as the Python and PHP recorders leave them.
 *
 * <p>Every class the JVM defines after {@code premain} also passes through the
 * transformer unchanged, so that its synthetic and bridge method set is known to
 * the recorder's frame walk without reflection (section 2.4: such frames are
 * transparent as callers).  Reflection would be the obvious alternative and is
 * deliberately not used: {@code Class.getDeclaredMethods()} resolves parameter
 * types, which loads classes and runs their static initialisers, and a static
 * initialiser of a production class executes production lines -- the agent would
 * then change the {@code coverage_lines} JaCoCo records, which section 8 requires
 * to be identical with and without it.
 */
public final class DirectCallAgent {

    /** Binary name of the recorder, as the inserted {@code invokestatic} spells it. */
    static final String RECORDER = "r2t/directcalls/DirectCallRecorder";

    private DirectCallAgent() {
    }

    public static void premain(String args, Instrumentation inst) {
        if (args == null || args.isEmpty()) {
            throw new IllegalArgumentException(
                "r2t direct-call agent: the output path is the one required "
                + "agent argument (-javaagent:<jar>=<absolute path>)");
        }
        DirectCallRecorder.install(Paths.get(args));
        inst.addTransformer(new Transformer(), false);
    }

    static final class Transformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String internalName,
                                Class<?> redefined, ProtectionDomain domain,
                                byte[] bytes) {
            if (internalName == null || DirectCallRecorder.isOwnClass(internalName)
                    || DirectCallRecorder.isPlatformClass(internalName)) {
                // Platform frames are transparent by prefix, so their flags
                // are never consulted; skipping the header walk for them is
                // most of the class loads a Maven fork performs.
                return null;
            }
            String root = DirectCallRecorder.sourceRootOf(domain);
            boolean production = DirectCallRecorder.isProduction(domain);
            try {
                ClassReader reader = new ClassReader(bytes);
                if (!production) {
                    // Header walk only: which of this class's methods are
                    // synthetic or bridge, for the recorder's transparency rule.
                    reader.accept(new FlagsVisitor(internalName), ClassReader.SKIP_CODE
                        | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
                    return null;
                }
                ClassWriter writer = new ClassWriter(reader, 0);
                EntryVisitor visitor = new EntryVisitor(writer, internalName, root);
                reader.accept(visitor, 0);
                return visitor.changed ? writer.toByteArray() : null;
            } catch (Throwable t) {                        // never let a class fail to load
                DirectCallRecorder.noteTransformFailure(internalName, t);
                return null;
            }
        }
    }

    /** Records the synthetic/bridge methods of a class the agent does not instrument. */
    static final class FlagsVisitor extends ClassVisitor {
        private final String internalName;

        FlagsVisitor(String internalName) {
            super(Opcodes.ASM9);
            this.internalName = internalName;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            if ((access & (Opcodes.ACC_SYNTHETIC | Opcodes.ACC_BRIDGE)) != 0) {
                DirectCallRecorder.noteTransparentMethod(internalName, name, descriptor);
            }
            return null;
        }
    }

    /** Inserts the entry hook into every recordable method of a production class. */
    static final class EntryVisitor extends ClassVisitor {
        private final String internalName;
        private boolean isEnum;
        private String sourceFile;
        private final String sourceRoot;
        boolean changed;

        EntryVisitor(ClassWriter writer, String internalName, String sourceRoot) {
            super(Opcodes.ASM9, writer);
            this.internalName = internalName;
            this.sourceRoot = sourceRoot;
        }

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            isEnum = (access & Opcodes.ACC_ENUM) != 0;
            super.visit(version, access, name, signature, superName, interfaces);
        }

        @Override
        public void visitSource(String source, String debug) {
            sourceFile = source;
            super.visitSource(source, debug);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            MethodVisitor target = super.visitMethod(access, name, descriptor,
                                                     signature, exceptions);
            boolean synthetic = (access & (Opcodes.ACC_SYNTHETIC | Opcodes.ACC_BRIDGE)) != 0;
            if (synthetic) {
                DirectCallRecorder.noteTransparentMethod(internalName, name, descriptor);
            }
            if (target == null || synthetic
                    || !DirectCallRecorder.originalSourceAvailable(sourceRoot, internalName, sourceFile)
                    || (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0
                    || !recordable(isEnum, internalName, name, descriptor)) {
                return target;
            }
            final int id = DirectCallRecorder.register(internalName, name, descriptor,
                                                       sourceFile, sourceRoot);
            changed = true;
            return new MethodVisitor(Opcodes.ASM9, target) {
                @Override
                public void visitCode() {
                    super.visitCode();
                    super.visitLdcInsn(id);
                    super.visitMethodInsn(Opcodes.INVOKESTATIC, RECORDER, "enter",
                                          "(I)V", false);
                }

                @Override
                public void visitMaxs(int maxStack, int maxLocals) {
                    // The hook pushes one int before any other instruction.
                    super.visitMaxs(Math.max(maxStack, 1), maxLocals);
                }
            };
        }
    }

    /**
     * Section 2.2's callee rule for a method that has code and is neither
     * synthetic nor bridge: everything but the class initialiser and an enum's
     * compiler-generated {@code values()} / {@code valueOf(String)}.
     */
    static boolean recordable(boolean isEnum, String internalName, String name,
                              String descriptor) {
        if ("<clinit>".equals(name)) {
            return false;
        }
        if (isEnum) {
            if ("values".equals(name) && descriptor.equals("()[L" + internalName + ";")) {
                return false;
            }
            if ("valueOf".equals(name)
                    && descriptor.equals("(Ljava/lang/String;)L" + internalName + ";")) {
                return false;
            }
        }
        return true;
    }
}
