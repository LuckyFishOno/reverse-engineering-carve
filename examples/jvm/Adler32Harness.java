package carve.reference;

import java.util.zip.Adler32;

/** Invocation adapter only. No checksum algorithm is compiled here.
 * Reads raw bytes from stdin; the JDK's shipped java.util.zip.Adler32 class and
 * its native updateBytes implementation compute the value printed as one JSON integer.
 */
public final class Adler32Harness {
    public static void main(String[] args) throws Exception {
        byte[] input = System.in.readAllBytes();
        Adler32 checksum = new Adler32();
        checksum.update(input, 0, input.length);
        System.out.print(checksum.getValue());
    }
}
