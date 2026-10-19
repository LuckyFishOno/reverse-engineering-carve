package carve.reference;

/** Owned protocol tests; these are separate from third-party behavior comparisons. */
public final class RuntimeProbeHarness {
    private static String quote(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' || c == '"') out.append('\\').append(c);
            else if (c < 32) out.append(String.format("\\u%04x", (int) c));
            else out.append(c);
        }
        return out.append('"').toString();
    }
    public static void main(String[] args) throws Exception {
        if (args[0].equals("echo")) System.out.println(quote(args[1]));
        else if (args[0].equals("stderr")) { System.err.println("diagnostic"); System.out.println("true"); }
        else if (args[0].equals("sleep")) { Thread.sleep(60000); System.out.println("true"); }
        else if (args[0].equals("huge")) {
            char[] chunk = new char[65536]; java.util.Arrays.fill(chunk, 'x');
            for (int i = 0; i < 17; i++) System.out.print(chunk);
        }
        else throw new IllegalStateException("Expected protocol test failure");
    }
}
