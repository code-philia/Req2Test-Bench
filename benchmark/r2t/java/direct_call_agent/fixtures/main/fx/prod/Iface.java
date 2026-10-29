package fx.prod;

/** The interface-default fixture: the body lives in the interface. */
public interface Iface {
    default int dflt() {
        return 1;
    }

    int abstractOne();
}
