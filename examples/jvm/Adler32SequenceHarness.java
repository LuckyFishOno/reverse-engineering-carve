package carve.reference;

import java.util.zip.Adler32;
import java.util.ArrayList;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/** Invocation and narrow JSON transport only. All checksum/state operations use
 * the shipped java.base Adler32 object and its loaded native implementation.
 * Protocol: [[0],[1,[BYTES...]],[2]] = read/update/reset. No checksum code here. */
public final class Adler32SequenceHarness {
    private record Call(int operation, byte[] bytes) {}
    private static final class Parser {
        private final String input; private int position;
        Parser(String input) { this.input = input; }
        private void spaces() {
            while (position<input.length() && " \n\r\t".indexOf(input.charAt(position))>=0) ++position;
        }
        private boolean take(char expected) {
            spaces(); if (position<input.length() && input.charAt(position)==expected) { ++position; return true; } return false;
        }
        private void require(char expected) { if (!take(expected)) throw new IllegalArgumentException("Invalid sequence JSON"); }
        private int integer() {
            spaces(); int start = position;
            if (position<input.length() && input.charAt(position)=='-') ++position;
            int digits = position;
            while (position<input.length() && input.charAt(position)>='0' && input.charAt(position)<='9') ++position;
            if (digits==position || position-digits>1 && input.charAt(digits)=='0') throw new IllegalArgumentException("Invalid integer");
            return Integer.parseInt(input.substring(start,position));
        }
        private byte[] bytes() {
            require('['); ArrayList<Byte> values = new ArrayList<>();
            if (!take(']')) {
                do { int value = integer(); if (value<0 || value>255 || values.size()>=65536) throw new IllegalArgumentException("Byte domain"); values.add((byte)value); } while (take(','));
                require(']');
            }
            byte[] result = new byte[values.size()]; for (int i=0; i<result.length; ++i) result[i]=values.get(i); return result;
        }
        ArrayList<Call> parse() {
            require('['); ArrayList<Call> calls = new ArrayList<>();
            do {
                if (calls.size()>=64) throw new IllegalArgumentException("Step budget");
                require('['); int operation = integer(); byte[] bytes = null;
                if (operation==1) { require(','); bytes = bytes(); }
                else if (operation!=0 && operation!=2) throw new IllegalArgumentException("Operation domain");
                require(']'); calls.add(new Call(operation,bytes));
            } while (take(','));
            require(']'); spaces(); if (position!=input.length()) throw new IllegalArgumentException("Trailing input"); return calls;
        }
    }
    private static String quoted(String input) {
        return "\""+input.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r").replace("\t","\\t")+"\"";
    }
    public static void main(String[] args) throws Exception {
        if (args.length==1 && args[0].equals("--identity")) {
            byte[] bytes;
            try (var stream = Adler32.class.getResourceAsStream("/java/util/zip/Adler32.class")) { bytes=stream.readAllBytes(); }
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
            Adler32 probe = new Adler32(); probe.update(new byte[]{1,2,3},0,3);
            System.out.print("{\"classSha256\":"+quoted(digest)+",\"module\":"+quoted(Adler32.class.getModule().getName())+",\"bootstrapLoader\":"+(Adler32.class.getClassLoader()==null)+",\"javaHome\":"+quoted(System.getProperty("java.home"))+",\"probeValue\":"+probe.getValue()+"}"); return;
        }
        if (args.length!=0) throw new IllegalArgumentException("No positional arguments");
        byte[] raw = System.in.readNBytes(1048577);
        if (raw.length>1048576) throw new IllegalArgumentException("Input budget");
        String input = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(raw)).toString();
        var calls = new Parser(input).parse();
        Adler32 checksum = new Adler32(); StringBuilder output = new StringBuilder("[");
        for (int i=0; i<calls.size(); ++i) {
            Call call = calls.get(i);
            if (call.operation()==1) checksum.update(call.bytes(),0,call.bytes().length);
            else if (call.operation()==2) checksum.reset();
            if (i>0) output.append(',');
            output.append("{\"kind\":\"return\",\"value\":").append(checksum.getValue()).append('}');
        }
        System.out.print(output.append(']'));
    }
}
