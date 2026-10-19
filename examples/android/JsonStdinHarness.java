package carve.reference;

/** Source-owned transport echo only, never a third-party behavior comparison. */
public final class JsonStdinHarness {
    public static void main(String[] args) throws Exception {
        if (args.length != 0) throw new IllegalArgumentException("JSON arrived on argv");
        java.io.ByteArrayOutputStream data = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[4096]; int size;
        while ((size = System.in.read(buffer)) != -1) {
            if (data.size() + size > 1048576) throw new IllegalArgumentException("Input budget");
            data.write(buffer, 0, size);
        }
        System.out.write(data.toByteArray());
    }
}
