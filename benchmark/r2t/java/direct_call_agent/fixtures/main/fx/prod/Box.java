package fx.prod;

/** The bridge fixture: {@code compareTo(Object)} is a compiler bridge to {@code compareTo(Box)}. */
public class Box implements Comparable<Box> {
    public final int v;

    public Box(int v) {
        this.v = v;
    }

    @Override
    public int compareTo(Box o) {
        return Integer.compare(v, o.v);
    }
}
