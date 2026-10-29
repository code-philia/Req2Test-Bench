package fx.glue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.function.Supplier;
import java.util.stream.Stream;

import fx.prod.Box;
import fx.prod.Color;
import fx.prod.Impl;
import fx.prod.Outer;
import fx.prod.Prod;
import fx.prod.Sub;
import fx.prod.WithClinit;
import fx.third.Third;

/** Stands for the glue: every call shape section 8 names, made from a test-classes frame. */
public class Steps {
    /** A field initialiser: javac compiles it into this constructor. */
    Box fieldInit = new Box(1);

    public void inherited() {
        new Sub().inherited();
    }

    public void dflt() {
        Impl impl = new Impl();
        impl.dflt();
        impl.abstractOne();
    }

    public void ctorAndClinit() {
        new WithClinit().v();
    }

    public void lambda() {
        Runnable r = () -> Prod.viaLambda();
        r.run();
        Supplier<Integer> s = Prod::viaLambda;
        s.get();
    }

    public void stream() {
        Stream.of(1, 2, 3).map(Prod::viaStream).forEach(Prod::consume);
        Arrays.asList(1, 2).forEach(x -> Prod.consume(x));
    }

    public void aCallsB() {
        Prod.a();
    }

    public void bridge() {
        Comparable<Box> c = new Box(2);
        c.compareTo(new Box(3));
        Collections.sort(new ArrayList<>(Arrays.asList(new Box(5), new Box(4))));
    }

    public void nested() {
        new Outer.Inner().inner();
        Outer o = new Outer();
        o.new Member().member();
        o.anon().run();
        Outer.peek(o);
    }

    public void enums() {
        Color.valueOf("RED").lower();
        Color.values();
    }

    public void third() {
        Third.callProd();
    }
}
