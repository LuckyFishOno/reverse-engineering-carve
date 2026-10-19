package example;
public final class ParkingFeature {
    public static int parkingFee(int minutes, int member) {
        if (minutes < 0) return -1;
        if (minutes <= 15) return 0;
        int fee = ((minutes + 14) / 15) * 25;
        if (member != 0) fee = (fee * 8) / 10;
        return Math.min(fee, 300);
    }
    public static void main(String[] args) {
        System.out.println(parkingFee(Integer.parseInt(args[0]),Integer.parseInt(args[1])));
    }
}
