package fx.glue;

import java.lang.reflect.Method;

/**
 * Drives {@link Steps} one "step" at a time, the way the harness-owned
 * Cucumber listener drives a real fork: the recorder's current step is set
 * before each call and cleared after it, by the SAME reflection route
 * (`Class.forName` + `setStep(int)`), because the agent jar is on no compile
 * classpath here either.  The glue is constructed BEFORE any step, so the
 * calls its field initialiser makes carry no step -- the fixture's stand-in
 * for a `@Before` hook or glue construction in a real run.
 */
public final class Main {
    private static final int NO_STEP = -1;

    private Main() {
    }

    private static Method setStep() {
        try {
            return Class.forName("r2t.directcalls.DirectCallRecorder")
                .getMethod("setStep", int.class);
        } catch (ClassNotFoundException | NoSuchMethodException absent) {
            return null;
        }
    }

    private static void step(Method setter, int index) throws Exception {
        if (setter != null) {
            setter.invoke(null, Integer.valueOf(index));
        }
    }

    public static void main(String[] args) throws Exception {
        Method setter = setStep();
        step(setter, NO_STEP);
        // Outside every step: the field initialiser's `new Box(1)`.
        Steps steps = new Steps();
        Runnable[] body = {
            steps::inherited, steps::dflt, steps::ctorAndClinit, steps::lambda,
            steps::stream, steps::aCallsB, steps::bridge, steps::nested,
            steps::enums, steps::third,
        };
        for (int i = 0; i < body.length; i++) {
            step(setter, i);
            body[i].run();
            step(setter, NO_STEP);
        }
        if (args.length > 0 && args[0].equals("exit")) {
            System.exit(3);
        }
    }
}
