package fx.prod;

/** Nested, member, anonymous and local classes, plus a private-access accessor at release 8. */
public class Outer {
    private int secret = 9;

    public static class Inner {
        public int inner() {
            return 5;
        }
    }

    public class Member {
        public int member() {
            return 6;
        }
    }

    public Runnable anon() {
        return new Runnable() {
            @Override
            public void run() {
                Prod.consume(1);
            }
        };
    }

    public static int peek(Outer o) {
        return new Object() {
            int read() {
                return o.secret;
            }
        }.read();
    }
}
