package carve.reference;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/** Invocation adapter only. No contact encoding algorithm is compiled here.
 * Reads a JSON positional-argument array from stdin. Android's original
 * org.json classes parse/quote data; original shipped DEX computes the payload.
 */
public final class ZxingVCardHarness {
    private static Class<?> objectClass, arrayClass;
    private static Object jsonNull;
    private static Object field(Object object, String name) throws Exception {
        if (!(Boolean) objectClass.getMethod("has", String.class).invoke(object, name)) return null;
        Object value = objectClass.getMethod("get", String.class).invoke(object, name);
        return value == jsonNull ? null : value;
    }
    private static String text(Object object, String name) throws Exception {
        Object value = field(object, name);
        if (value != null && !(value instanceof String)) throw new IllegalArgumentException("Expected text: " + name);
        return (String) value;
    }
    private static List<String> list(Object object, String name) throws Exception {
        Object value = field(object, name); if (value == null) return null;
        if (!arrayClass.isInstance(value)) throw new IllegalArgumentException("Expected array: " + name);
        int count = (Integer) arrayClass.getMethod("length").invoke(value);
        List<String> result = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            Object item = arrayClass.getMethod("get", int.class).invoke(value, i);
            if (item == jsonNull) item = null;
            if (item != null && !(item instanceof String)) throw new IllegalArgumentException("Expected string/null element");
            result.add((String) item);
        }
        return result;
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 0) throw new IllegalArgumentException("JSON must arrive on stdin");
        ByteArrayOutputStream input = new ByteArrayOutputStream(); byte[] buffer = new byte[4096]; int n;
        while ((n = System.in.read(buffer)) != -1) {
            if (input.size() + n > 1048576) throw new IllegalArgumentException("Input exceeds1MiB");
            input.write(buffer, 0, n);
        }
        objectClass = Class.forName("org.json.JSONObject"); arrayClass = Class.forName("org.json.JSONArray");
        jsonNull = objectClass.getField("NULL").get(null);
        Object positional = arrayClass.getConstructor(String.class).newInstance(new String(input.toByteArray(), "UTF-8"));
        if ((Integer) arrayClass.getMethod("length").invoke(positional) != 1) throw new IllegalArgumentException("One contact argument required");
        Object contact = arrayClass.getMethod("getJSONObject", int.class).invoke(positional, 0);
        // Non-empty phone type metadata is outside the selected payload domain.
        Object types = field(contact, "phoneTypes");
        if (types != null) throw new IllegalArgumentException("phoneTypes must be absent/null");
        Class<?> encoderClass = Class.forName("com.google.zxing.client.android.encode.VCardContactEncoder");
        Constructor<?> constructor = encoderClass.getDeclaredConstructor(); constructor.setAccessible(true);
        Object encoder = constructor.newInstance();
        Method encode = encoderClass.getDeclaredMethod("encode", List.class, String.class, List.class,
                List.class, List.class, List.class, List.class, String.class); encode.setAccessible(true);
        String[] result = (String[]) encode.invoke(encoder, list(contact,"names"), text(contact,"organization"),
                list(contact,"addresses"), list(contact,"phones"), null, list(contact,"emails"), list(contact,"urls"), text(contact,"note"));
        // The original method also computes Android-dependent display text.
        // This boundary exposes only its payload element, without altering it.
        System.out.println(objectClass.getMethod("quote", String.class).invoke(null, result[0]));
    }
}
