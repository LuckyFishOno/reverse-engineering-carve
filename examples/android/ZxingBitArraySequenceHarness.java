package carve.reference;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/** Framing/reflection adapter only: no BitArray storage or algorithm here.
 * The class is resolved from the original shipped DEX, first on ART's classpath.
 * "new" explicitly replaces that original object; other calls reuse it.
 * Domain validation is adapter policy, not original invalid-input semantics.
 */
public final class ZxingBitArraySequenceHarness {
    private static Class<?> arrayClass, objectClass;
    private static int length(Object array) throws Exception {
        if (!arrayClass.isInstance(array)) throw new IllegalArgumentException("Expected JSON array");
        return (Integer) arrayClass.getMethod("length").invoke(array);
    }
    private static Object get(Object array, int index) throws Exception {
        return arrayClass.getMethod("get", int.class).invoke(array, index);
    }
    private static int number(Object value) {
        if (!(value instanceof Integer) && !(value instanceof Long)) throw new IllegalArgumentException("Expected integer");
        long n = ((Number) value).longValue();
        if (n < Integer.MIN_VALUE || n > Integer.MAX_VALUE) throw new IllegalArgumentException("Expected signed32 integer");
        return (int) n;
    }
    private static String quote(String value) throws Exception {
        return (String) objectClass.getMethod("quote", String.class).invoke(null, value);
    }
    private static String snapshot(Class<?> type, Object value) throws Exception {
        int size = (Integer) type.getMethod("getSize").invoke(value);
        int bytes = (Integer) type.getMethod("getSizeInBytes").invoke(value);
        Method get = type.getMethod("get", int.class);
        StringBuilder bits = new StringBuilder();
        for (int i = 0; i < size; i++) bits.append((Boolean) get.invoke(value, i) ? '1' : '0');
        return "{\"size\":" + size + ",\"sizeInBytes\":" + bytes + ",\"bits\":\"" + bits + "\"}";
    }
    public static void main(String[] args) throws Exception {
        arrayClass = Class.forName("org.json.JSONArray"); objectClass = Class.forName("org.json.JSONObject");
        Class<?> type = Class.forName("com.google.zxing.common.BitArray");
        if (args.length == 1 && args[0].equals("--identity")) {
            System.out.println("{\"className\":" + quote(type.getName()) + ",\"classLoader\":" + quote(String.valueOf(type.getClassLoader()))
                + ",\"vmName\":" + quote(System.getProperty("java.vm.name")) + ",\"vmVersion\":" + quote(System.getProperty("java.vm.version"))
                + ",\"initial\":" + snapshot(type, type.getConstructor().newInstance()) + "}"); return;
        }
        if (args.length != 0) throw new IllegalArgumentException("Sequence must arrive on stdin");
        ByteArrayOutputStream input = new ByteArrayOutputStream(); byte[] buffer = new byte[4096]; int n;
        while ((n = System.in.read(buffer)) != -1) {
            if (input.size() + n > 1048576) throw new IllegalArgumentException("Input exceeds1MiB");
            input.write(buffer, 0, n);
        }
        Object calls = arrayClass.getConstructor(String.class).newInstance(new String(input.toByteArray(), "UTF-8"));
        int count = length(calls);
        if (count < 1 || count > 64) throw new IllegalArgumentException("Expected1–64 steps");
        // Validate the entire declared domain before executing any original operations.
        Object[][] parsed = new Object[count][]; int size = 0;
        for (int i = 0; i < count; i++) {
            Object call = get(calls, i); int arity = length(call);
            if (arity < 1 || !(get(call, 0) instanceof String)) throw new IllegalArgumentException("Expected named operation");
            String op = (String) get(call, 0); int wanted;
            if (op.equals("append")) wanted = 3;
            else if (op.equals("set") || op.equals("flip")) wanted = 2;
            else if (op.equals("read") || op.equals("clear") || op.equals("reverse") || op.equals("new")) wanted = 1;
            else throw new IllegalArgumentException("Unknown operation");
            if (arity != wanted) throw new IllegalArgumentException("Wrong argument count");
            parsed[i] = new Object[arity]; parsed[i][0] = op;
            for (int j = 1; j < arity; j++) parsed[i][j] = number(get(call, j));
            if (op.equals("append")) {
                int width = (Integer) parsed[i][2];
                if (width < 0 || width > 32 || size + width > 4096) throw new IllegalArgumentException("Append outside selected domain");
                size += width;
            } else if (op.equals("set") || op.equals("flip")) {
                int index = (Integer) parsed[i][1];
                if (index < 0 || index >= size) throw new IllegalArgumentException("Index outside selected domain");
            } else if (op.equals("new")) size = 0;
        }
        Object value = type.getConstructor().newInstance(); StringBuilder output = new StringBuilder("[");
        for (int i = 0; i < count; i++) {
            if (i != 0) output.append(','); String op = (String) parsed[i][0];
            try {
                if (op.equals("new")) value = type.getConstructor().newInstance();
                else if (op.equals("append")) type.getMethod("appendBits", int.class, int.class).invoke(value, parsed[i][1], parsed[i][2]);
                else if (op.equals("set") || op.equals("flip")) type.getMethod(op, int.class).invoke(value, parsed[i][1]);
                else if (!op.equals("read")) type.getMethod(op).invoke(value);
            } catch (InvocationTargetException error) {
                Throwable cause = error.getCause();
                output.append("{\"kind\":\"throw\",\"error\":{\"name\":").append(quote(cause.getClass().getName()))
                    .append(",\"message\":").append(quote(cause.getMessage() == null ? "" : cause.getMessage())).append("}}");
                continue;
            }
            output.append("{\"kind\":\"return\",\"value\":").append(snapshot(type, value)).append('}');
        }
        System.out.println(output.append(']'));
    }
}
