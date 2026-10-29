package fx.prod;

/** The enum fixture: {@code values()} and {@code valueOf(String)} are never callees. */
public enum Color {
    RED, GREEN;

    public String lower() {
        return name().toLowerCase();
    }
}
