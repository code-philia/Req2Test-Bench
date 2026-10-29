import com.sun.source.tree.*;
import com.sun.source.util.*;
import javax.lang.model.element.*;
import javax.lang.model.type.*;
import javax.lang.model.util.*;
import javax.tools.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.io.*;
import java.util.*;

/** Approved Java declared interactions and original declaration positions. No subject execution. */
public class AttributeInterfaces {
    static Trees trees;
    static Elements elements;
    static Types types;
    static SourcePositions positions;
    static Path root;
    static class Site {
        CompilationUnitTree unit;
        Tree tree;
        String kind, path, source;
        long start, end;
        Site(CompilationUnitTree u, Tree t, String k, String p, String s) {
            unit=u; tree=t; kind=k; path=p; source=s;
            start=positions.getStartPosition(u,t); end=positions.getEndPosition(u,t);
        }
        int byteAt(long pos) { return pos < 0 ? -1 : source.substring(0,(int)pos).getBytes(StandardCharsets.UTF_8).length; }
    }
    static final List<Site> sites = new ArrayList<>();
    static final Set<Tree> originalNodes = Collections.newSetFromMap(new IdentityHashMap<Tree,Boolean>());
    static String q(String s) {
        if(s==null)return "null";
        return "\""+s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r").replace("\t","\\t")+"\"";
    }
    static TypeElement owner(Element e) {
        Element x=e;
        while(x!=null && !(x instanceof TypeElement))x=x.getEnclosingElement();
        return (TypeElement)x;
    }
    static String binary(TypeElement e) { return elements.getBinaryName(e).toString(); }
    static String desc(TypeMirror t) {
        switch(t.getKind()) {
        case BOOLEAN:return "Z"; case BYTE:return "B"; case SHORT:return "S";
        case INT:return "I"; case LONG:return "J"; case CHAR:return "C";
        case FLOAT:return "F"; case DOUBLE:return "D"; case VOID:return "V";
        case ARRAY:return "["+desc(((ArrayType)t).getComponentType());
        case DECLARED:return "L"+binary((TypeElement)((DeclaredType)t).asElement()).replace('.','/')+";";
        case TYPEVAR:case WILDCARD:return desc(types.erasure(t));
        default:throw new IllegalArgumentException("unresolved type "+t+" ("+t.getKind()+")");
        }
    }
    static String signature(ExecutableElement m) {
        List<String> p=new ArrayList<>();
        for(VariableElement v:m.getParameters())p.add(v.asType().toString());
        return binary(owner(m))+"."+m.getSimpleName()+"("+String.join(",",p)+")";
    }
    static String key(ExecutableElement m) {
        TypeElement o=owner(m);StringBuilder p=new StringBuilder("(");
        if(m.getKind()==ElementKind.CONSTRUCTOR) {
            if(o.getKind()==ElementKind.ENUM)p.append("Ljava/lang/String;I");
            else if(o.getNestingKind()==NestingKind.MEMBER && !o.getModifiers().contains(Modifier.STATIC))p.append(desc(o.getEnclosingElement().asType()));
        }
        for(VariableElement v:m.getParameters())p.append(desc(types.erasure(v.asType())));
        p.append(')').append(desc(types.erasure(m.getReturnType())));
        return binary(o)+"."+m.getSimpleName()+":"+p;
    }
    static String topLevel(TypeElement e) {
        TypeElement top=e;
        for(Element p=e.getEnclosingElement();p!=null;p=p.getEnclosingElement())
            if(p instanceof TypeElement)top=(TypeElement)p;
        return top.getQualifiedName().toString();
    }
    static void declaredType(TypeMirror t, Set<String> out) {
        if(t==null)return;
        if(t.getKind()==TypeKind.ARRAY) { declaredType(((ArrayType)t).getComponentType(),out);return; }
        if(t.getKind()==TypeKind.DECLARED) {
            DeclaredType d=(DeclaredType)t;String name=topLevel((TypeElement)d.asElement());
            if(!name.isEmpty())out.add(name);
            declaredType(d.getEnclosingType(),out);
            for(TypeMirror arg:d.getTypeArguments())declaredType(arg,out);
        } else if(t.getKind()==TypeKind.WILDCARD) {
            WildcardType w=(WildcardType)t;declaredType(w.getExtendsBound(),out);declaredType(w.getSuperBound(),out);
        } else if(t.getKind()==TypeKind.ERROR)throw new IllegalArgumentException("unresolved declared type "+t);
        // An unbound type variable contributes no inferred bound or concrete type.
    }
    static String array(Collection<String> values) {
        List<String> out=new ArrayList<>();for(String v:values)out.add(q(v));return "["+String.join(",",out)+"]";
    }
    static String object(Map<String,String> values) {
        List<String> out=new ArrayList<>();for(Map.Entry<String,String> v:values.entrySet())out.add(q(v.getKey())+":"+q(v.getValue()));return "{"+String.join(",",out)+"}";
    }
    static class Surface extends TreePathScanner<Void,Void> {
        final Set<String> fields=new TreeSet<>(),explicit=new TreeSet<>(),calls=new TreeSet<>(),implicitCalls=new TreeSet<>();
        final Map<String,String> callSources=new TreeMap<>();
        @Override public Void scan(Tree t,Void v) {
            return t!=null && originalNodes.contains(t)?super.scan(t,v):null;
        }
        void reference() {
            Element e=trees.getElement(getCurrentPath());
            if(e instanceof TypeElement)declaredType(e.asType(),explicit);
            if(e!=null && (e.getKind()==ElementKind.FIELD || e.getKind()==ElementKind.ENUM_CONSTANT))declaredType(e.asType(),fields);
            if(e!=null && e.getModifiers().contains(Modifier.STATIC) && (e instanceof ExecutableElement || e instanceof VariableElement))declaredType(owner(e).asType(),explicit);
        }
        void call() {
            Element e=trees.getElement(getCurrentPath());
            if(!(e instanceof ExecutableElement))throw new IllegalArgumentException("unresolved call at "+getCurrentPath().getLeaf());
            String k=key((ExecutableElement)e);calls.add(k);
            TreePath target=trees.getPath(e);
            String path=null;
            if(target!=null) {
                Path file=Paths.get(target.getCompilationUnit().getSourceFile().toUri()).toAbsolutePath().normalize();
                if(file.startsWith(root))path=root.relativize(file).toString().replace(File.separatorChar,'/');
                if(!originalNodes.contains(target.getLeaf()) && positions.getEndPosition(target.getCompilationUnit(),target.getLeaf())<0)implicitCalls.add(k);
            }
            callSources.put(k,path);
        }
        @Override public Void visitIdentifier(IdentifierTree t,Void v){reference();return super.visitIdentifier(t,v);}
        @Override public Void visitMemberSelect(MemberSelectTree t,Void v){reference();return super.visitMemberSelect(t,v);}
        @Override public Void visitMethodInvocation(MethodInvocationTree t,Void v){call();return super.visitMethodInvocation(t,v);}
        @Override public Void visitNewClass(NewClassTree t,Void v){call();return super.visitNewClass(t,v);}
    }
    public static void main(String[] a) throws Exception {
        if(a.length!=4 && a.length!=5)throw new IllegalArgumentException("root classpath sourcepath file-list [release]");
        String release=a.length==4?"8":a[4];
        if(!release.equals("8") && !release.equals("17"))throw new IllegalArgumentException("unsupported release "+release);
        root=Paths.get(a[0]).toAbsolutePath().normalize();
        JavaCompiler compiler=ToolProvider.getSystemJavaCompiler();
        DiagnosticCollector<JavaFileObject> diagnostics=new DiagnosticCollector<>();
        StandardJavaFileManager manager=compiler.getStandardFileManager(diagnostics,Locale.ROOT,StandardCharsets.UTF_8);
        manager.setLocation(StandardLocation.MODULE_PATH, Collections.emptyList());
        List<File> files=new ArrayList<>();
        for(String p:Files.readAllLines(Paths.get(a[3]),StandardCharsets.UTF_8))files.add(root.resolve(p).toFile());
        List<String> opts=Arrays.asList("-proc:none","--release",release,"-encoding","UTF-8","-classpath",a[1],"-sourcepath",a[2],"-implicit:none");
        JavacTask task=(JavacTask)compiler.getTask(null,manager,diagnostics,opts,null,manager.getJavaFileObjectsFromFiles(files));
        trees=Trees.instance(task);positions=trees.getSourcePositions();
        List<CompilationUnitTree> units=new ArrayList<>();
        for(CompilationUnitTree u:task.parse())units.add(u);
        // Capture original positions before javac adds implicit constructors/super calls.
        for(CompilationUnitTree u:units) {
            String path=root.relativize(Paths.get(u.getSourceFile().toUri())).toString().replace(File.separatorChar,'/');
            String source=u.getSourceFile().getCharContent(true).toString();
            new TreePathScanner<Void,Void>() {
                @Override public Void scan(Tree t,Void v) { if(t!=null)originalNodes.add(t);return super.scan(t,v); }
                void add(Tree t,String kind){sites.add(new Site(u,t,kind,path,source));}
                @Override public Void visitClass(ClassTree t,Void v){add(t,"type");return super.visitClass(t,v);}
                @Override public Void visitMethod(MethodTree t,Void v){add(t,t.getReturnType()==null?"constructor":"method");return super.visitMethod(t,v);}
                @Override public Void visitVariable(VariableTree t,Void v){
                    if(getCurrentPath().getParentPath().getLeaf() instanceof ClassTree) {
                        add(t,"field");
                        if(t.getInitializer()!=null)add(t.getInitializer(),"field_initializer");
                    }
                    return super.visitVariable(t,v);
                }
                @Override public Void visitBlock(BlockTree t,Void v){
                    if(getCurrentPath().getParentPath().getLeaf() instanceof ClassTree)add(t,t.isStatic()?"static_initializer":"instance_initializer");
                    return super.visitBlock(t,v);
                }
            }.scan(u,null);
        }
        task.analyze();
        boolean errors=false;
        for(Diagnostic<? extends JavaFileObject> d:diagnostics.getDiagnostics()) if(d.getKind()==Diagnostic.Kind.ERROR) {
            errors=true;System.err.println(d.toString());
        }
        if(errors)System.exit(4);
        elements=task.getElements();types=task.getTypes();
        System.out.println("{\"record\":\"metadata\",\"java_runtime_version\":"+q(System.getProperty("java.runtime.version"))+",\"java_vendor\":"+q(System.getProperty("java.vendor"))+"}");
        for(Site s:sites) {
            TreePath p=TreePath.getPath(s.unit,s.tree);Element e=trees.getElement(p);
            if(s.kind.equals("field_initializer")) e=trees.getElement(p.getParentPath());
            TypeElement o=e==null?null:owner(e);
            if(o==null) {
                TreePath par=p.getParentPath();
                while(par!=null && !(par.getLeaf() instanceof ClassTree))par=par.getParentPath();
                if(par!=null)o=(TypeElement)trees.getElement(par);
            }
            String k=null,sig=null;
            if(e instanceof ExecutableElement) { k=key((ExecutableElement)e);sig=signature((ExecutableElement)e); }
            else if(e instanceof VariableElement)k=binary(o)+"."+e.getSimpleName();
            else if(e instanceof TypeElement)k=binary((TypeElement)e);
            String surface="";
            if(e instanceof ExecutableElement && (s.kind.equals("method") || s.kind.equals("constructor"))) {
                ExecutableElement method=(ExecutableElement)e;Set<String> declared=new TreeSet<>();
                declaredType(method.getReturnType(),declared);
                for(VariableElement param:method.getParameters())declaredType(param.asType(),declared);
                Surface body=new Surface();MethodTree mt=(MethodTree)s.tree;
                if(mt.getBody()!=null)body.scan(new TreePath(p,mt.getBody()),null);
                surface=",\"declared_types\":"+array(declared)+",\"field_types\":"+array(body.fields)
                    +",\"explicit_types\":"+array(body.explicit)+",\"calls\":"+array(body.calls)
                    +",\"call_sources\":"+object(body.callSources)+",\"implicit_calls\":"+array(body.implicitCalls);
            }
            System.out.println("{\"record\":\"declaration\",\"path\":"+q(s.path)+",\"kind\":"+q(s.kind)+",\"start_byte\":"+s.byteAt(s.start)+",\"end_byte\":"+s.byteAt(s.end)+",\"owner\":"+q(o==null?null:binary(o))+",\"key\":"+q(k)+",\"top_level_name\":"+q(o==null?null:topLevel(o))+",\"registry_location\":"+q(sig)+surface+"}");
        }
        manager.close();
    }
}
