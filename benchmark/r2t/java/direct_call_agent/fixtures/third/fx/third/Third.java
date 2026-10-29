package fx.third;

import fx.prod.Prod;

/** Loaded from a jar: a caller that resolves to no source root. */
public final class Third {
    private Third() {
    }

    public static int callProd() {
        return Prod.b();
    }
}
