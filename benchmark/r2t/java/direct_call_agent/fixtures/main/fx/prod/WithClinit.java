package fx.prod;

/** The class-initialiser fixture: {@code <clinit>} calls production and is itself never a callee. */
public class WithClinit {
    static final int V = Helper.fromClinit();

    public WithClinit() {
    }

    public int v() {
        return V;
    }
}
