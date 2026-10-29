package fx.prod;

public final class Prod {
    private Prod() {
    }

    /** A calls B: B's caller is this file, not the glue. */
    public static int a() {
        return b() + 1;
    }

    public static int b() {
        return 1;
    }

    public static int viaLambda() {
        return 3;
    }

    public static int viaStream(int x) {
        return x * 2;
    }

    public static void consume(int x) {
    }
}
