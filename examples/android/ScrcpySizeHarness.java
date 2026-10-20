package carve.reference;

/** RECarve-owned invocation adapter. Calculation runs in the original released DEX. */
public final class ScrcpySizeHarness {
    public static void main(String[] args) throws Exception {
        Class<?> sizeClass = Class.forName("com.genymobile.scrcpy.model.Size");
        Class<?> constraintsClass = Class.forName("com.genymobile.scrcpy.video.VideoConstraints");
        Class<?> capabilitiesClass = Class.forName("android.media.MediaCodecInfo$VideoCapabilities");
        Object size = sizeClass.getConstructor(int.class, int.class).newInstance(
                Integer.parseInt(args[0]), Integer.parseInt(args[1]));
        Object constraints = constraintsClass.getConstructor(int.class, int.class, capabilitiesClass).newInstance(
                Integer.parseInt(args[2]), Integer.parseInt(args[3]), null);
        Object result = sizeClass.getMethod("constrain", constraintsClass, boolean.class).invoke(
                size, constraints, Boolean.parseBoolean(args[4]));
        System.out.println("[" + sizeClass.getMethod("getWidth").invoke(result) + ","
                + sizeClass.getMethod("getHeight").invoke(result) + "]");
    }
}
